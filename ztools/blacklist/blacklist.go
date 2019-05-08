package blacklist

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zmap/zgrab/ztools/zlog"
)

var (
	BlacklistError = errors.New("blacklisted")
	blacklistNets  []*net.IPNet
	once           sync.Once
	domLock        sync.RWMutex
	ipLock         sync.RWMutex
	domRex         *regexp.Regexp
)

func updateBlacklist(blacklist string) {
	ipLock.Lock()
	defer ipLock.Unlock()

	response, err := http.Get(blacklist)
	if err != nil {
		return // no blacklist active
	}

	scanner := bufio.NewScanner(response.Body)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		addr := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])

		if addr == "" {
			continue
		}
		if _, ipv4Net, err := net.ParseCIDR(addr); err == nil {
			blacklistNets = append(blacklistNets, ipv4Net)
		} else if _, ipv4Net, err := net.ParseCIDR(addr + "/32"); err == nil {
			blacklistNets = append(blacklistNets, ipv4Net)
		}

	}
}

func updateBlacklistDom() {
	domLock.Lock()
	defer domLock.Unlock()
	data := BLACKLIST_DATA // query this from server

	entrys := strings.Split(data, "\n")
	var exp string
	for _, entry := range entrys {
		ereal := strings.TrimSpace(strings.SplitN(entry, "#", 2)[0])
		if len(ereal) > 0 {
			ieof := strings.IndexRune(ereal, '$')
			if ieof >= 0 {
				ereal = ".*" + ereal[0:ieof]
			} else {
				ereal = ".*" + ereal + ".*"
			}
			exp = exp + "|(" + ereal + ")"
		}
	}
	if len(exp) > 0 {
		exp = exp[1:]
	}
	if rex, err := regexp.CompilePOSIX(exp); err == nil {
		domRex = rex
	} else {
		zlog.Warn("Domain blacklist cannot be compiled as regex")
	}
}

func Init(uriIP string) {
	once.Do(func() {
		updateBlacklist(uriIP)
		updateBlacklistDom()
		ticker := time.NewTicker(time.Hour * 24)
		go func() {
			for _ = range ticker.C {
				// reload the blacklists
				updateBlacklist(uriIP)
				updateBlacklistDom()
			}
		}()
	})
}

func IsBlacklisted(ip net.IP) bool {
	ipLock.RLock()
	defer ipLock.RUnlock()
	for _, i4net := range blacklistNets {
		if i4net.Contains(ip) {
			return true
		}
	}
	return false
}

func IsBlacklistedDom(dom string) bool {
	domLock.RLock()
	defer domLock.RUnlock()
	if domRex == nil {
		return false
	}
	return domRex.MatchString(dom)
}
