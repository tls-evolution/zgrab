package tls13measurements

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"gopkg.in/mgo.v2/bson"

	"github.com/zmap/zcrypto/tls"
	"laboratory.comsys.rwth-aachen.de/jost/mgotest/mdb"
)

var once sync.Once

var NotInDB = fmt.Errorf("not in database")

var TLS13_SUITES []uint16 = []uint16{
	tls.TLS_AES_128_CCM_SHA256,       // 0x1304
	tls.TLS_AES_128_CCM_8_SHA256,     // 0x1305
	tls.TLS_AES_256_GCM_SHA384,       // 0x1302 (should)
	tls.TLS_CHACHA20_POLY1305_SHA256, // 0x1303 (should)
	tls.TLS_AES_128_GCM_SHA256,       // 0x1301 (mandatory)
}

var TLS13_GROUPS []tls.CurveID = []tls.CurveID{
	tls.CurveP384, // 24
	tls.CurveP521, // 25
	tls.X448,      // 30
	tls.FFDHE2048, // 256
	tls.FFDHE3072, // 257
	tls.FFDHE4096, // 258
	tls.FFDHE6144, // 259
	tls.FFDHE8192, // 260
	tls.X25519,    // 29  (should)
	tls.CurveP256, // 23  (mandatory)
}

const (
	LEVEL_START        = iota
	LEVEL_SCAN_ALL     // remove a suite and a group each test
	LEVEL_SCAN_GROUPS  // only remove groups
	LEVEL_SCAN_SUITES  // only remove suites
	LEVEL_TEST_KS_PREF // add only a single keyshare per group
)

/*
type capsEntry struct {
	Null string `json:"null" bson:"null"`
}
*/

// fetch all caps we collected so far
type testData struct {
	Level           uint          `json:"level" bson:"level"`
	SupportedSuites []uint16      `json:"suites" bson:"suites"`
	SupportedGroups []tls.CurveID `json:"groups" bson:"groups"`
	PreferredGroups []tls.CurveID `json:"pgroups" bson:"pgroups"`
}

type testDataResult struct {
	Tests testData `json:"tests" bson:"tests"`
}

type TestContext struct {
	key     bson.M
	results testDataResult
}

func (ctx *TestContext) FinishTest(hs *tls.ServerHandshake, err error) {
	if (ctx == nil) || (hs == nil) || (hs.ServerHello == nil) {
		if err == nil {
			return // gained no more infos
		}

		errStr := err.Error()

		if strings.Contains(errStr, "tls: ") {
			level := ctx.results.Tests.Level
			switch level {
			case LEVEL_SCAN_ALL, LEVEL_SCAN_GROUPS, LEVEL_SCAN_SUITES:
				// removed either too many suites or groups, try with one only groups
				if err := mdb.Services.Update(ctx.key, bson.M{"$set": bson.M{"tests.level": level + 1}}); err != nil {
					log.Fatal(err)
				}
			}
			return
		}

		return // gained no more infos
	}

	level := ctx.results.Tests.Level
	switch level {
	case LEVEL_START:
		if err := mdb.Services.Update(ctx.key, bson.M{"$set": bson.M{"tests.level": LEVEL_SCAN_ALL}}); err != nil {
			log.Fatal(err)
		}
		fallthrough
	case LEVEL_SCAN_ALL, LEVEL_SCAN_GROUPS, LEVEL_SCAN_SUITES:
		selectedSuite := hs.ServerHello.CipherSuite
		selectedGroup := hs.ServerHello.KeyShare.Group

		// add selected suite to known supported suites
		if _, err := mdb.Services.Upsert(ctx.key, bson.M{"$addToSet": bson.M{"tests.suites": selectedSuite}}); err != nil {
			log.Fatal(err)
		}

		// add selected group to known supported groups
		if _, err := mdb.Services.Upsert(ctx.key, bson.M{"$addToSet": bson.M{"tests.groups": selectedGroup}}); err != nil {
			log.Fatal(err)
		}

		/*
			if (uint16(selectedSuite) == tls.TLS_AES_128_GCM_SHA256) && (selectedGroup == tls.CurveP256) {
				log.Print("Reached soft end condition for scan0")
			}*/
	case LEVEL_TEST_KS_PREF:
		selectedGroup := hs.ServerHello.KeyShare.Group
		if _, err := mdb.Services.Upsert(ctx.key, bson.M{"$push": bson.M{"tests.pgroups": selectedGroup}}); err != nil {
			log.Fatal(err)
		}
		if len(ctx.results.Tests.PreferredGroups)+1 == len(ctx.results.Tests.SupportedGroups) {
			// finished probing all groups
			if err := mdb.Services.Update(ctx.key, bson.M{"$set": bson.M{"tests.level": level + 1}}); err != nil {
				log.Fatal(err)
			}
		}
	}

	//
	//log.Print(hs.ServerHello)
}

func escapeDomain(dom string) string {
	return base64.StdEncoding.EncodeToString([]byte(dom))
}

func difference_uint16(slice1 []uint16, slice2 []uint16) []uint16 {
	diff := []uint16{}
	m := map[uint16]bool{}

	for _, k := range slice2 {
		m[k] = true
	}

	for _, k := range slice1 {
		if _, in2 := m[k]; !in2 {
			diff = append(diff, k)
		}
	}

	return diff
}

func difference_CurveID(slice1 []tls.CurveID, slice2 []tls.CurveID) []tls.CurveID {
	diff := []tls.CurveID{}
	m := map[tls.CurveID]bool{}

	for _, k := range slice2 {
		m[k] = true
	}

	for _, k := range slice1 {
		if _, in2 := m[k]; !in2 {
			diff = append(diff, k)
		}
	}

	return diff
}

func SetupConfig(conf *tls.Config, addr net.IP, domain string) (*TestContext, error) {
	once.Do(mdb.InitMDB)
	conf.ForceSuites = true

	ip := binary.BigEndian.Uint32(addr[12:])
	key := bson.M{"domain": escapeDomain(domain), "ip": ip}
	q := mdb.Services.Find(key)
	if c, err := q.Count(); (err != nil) || (c == 0) {
		log.Print(addr, ",", domain, " [", ip, ",", escapeDomain(domain), "] not in db, skipping!")

		// temp add plink.cs.uwaterloo.ca [2170636812,cGxpbmsuY3MudXdhdGVybG9vLmNh] for testing!
		// temp add bran [2130706433,YnJhbg==]
		// temp add enabled.tls13.com [1745911330,ZW5hYmxlZC50bHMxMy5jb20=]
		// temp add rustls.jbp.io [2319743400,cnVzdGxzLmpicC5pbw==]
		// temp add img-one.com [1746863257,aW1nLW9uZS5jb20=]
		// temp add powerstresser.com [1746863527,cG93ZXJzdHJlc3Nlci5jb20=] -> 5a96dd633e03ef961b8eb0f8

		res, _ := mdb.Services.Upsert(key, bson.M{"$set": bson.M{"testOnly": 1}})
		log.Print(res)

		return nil, NotInDB
	}

	ctx := &TestContext{key: key}

	if err := q.Select(bson.M{"tests": 1}).One(&ctx.results); err != nil {
		return nil, err
	}

	level := ctx.results.Tests.Level
	switch level {
	case LEVEL_START:
		conf.CipherSuites = TLS13_SUITES
		conf.CurvePreferences = TLS13_GROUPS
		//conf.KeysharesFor = &conf.CurvePreferences // add KS for all groups
		conf.KeysharesFor = &[]tls.CurveID{} // force HRR

		return ctx, nil
	case LEVEL_SCAN_ALL, LEVEL_SCAN_GROUPS, LEVEL_SCAN_SUITES:
		if level == LEVEL_SCAN_GROUPS {
			conf.CipherSuites = TLS13_SUITES
		} else {
			conf.CipherSuites = difference_uint16(TLS13_SUITES, ctx.results.Tests.SupportedSuites)
		}

		if level == LEVEL_SCAN_SUITES {
			conf.CurvePreferences = TLS13_GROUPS
		} else {
			conf.CurvePreferences = difference_CurveID(TLS13_GROUPS, ctx.results.Tests.SupportedGroups)
		}

		/*
			if (len(conf.CipherSuites) == 0) || (conf.CipherSuites[len(conf.CipherSuites)-1] != tls.TLS_AES_128_GCM_SHA256) {
				conf.CipherSuites = append(conf.CipherSuites, tls.TLS_AES_128_GCM_SHA256)
			}
			if (len(conf.CurvePreferences) == 0) || (conf.CurvePreferences[len(conf.CurvePreferences)-1] != tls.CurveP256) {
				conf.CurvePreferences = append(conf.CurvePreferences, tls.CurveP256)
			}*/

		//conf.KeysharesFor = &conf.CurvePreferences
		conf.KeysharesFor = &[]tls.CurveID{} // force HRR

		log.Print("Curves: ", conf.CurvePreferences)
		log.Print("Shares: ", conf.KeysharesFor)
		return ctx, nil
	case LEVEL_TEST_KS_PREF:
		group := ctx.results.Tests.SupportedGroups[len(ctx.results.Tests.PreferredGroups)]

		conf.CipherSuites = TLS13_SUITES
		conf.KeysharesFor = &[]tls.CurveID{group}

		// re-append selected keyshared group with least priority
		conf.CurvePreferences = append(difference_CurveID(TLS13_GROUPS, *conf.KeysharesFor), group)
		log.Print("Curves: ", conf.CurvePreferences)
		log.Print("Shares: ", conf.KeysharesFor)

		return ctx, nil
	}

	log.Print(ctx.results)

	return nil, NotInDB
}
