package tls13measurements

import (
	"github.com/zmap/zcrypto/tls"
)

var TLS13_SUITES []uint16 = []uint16{
	tls.TLS_AES_128_GCM_SHA256,       // 0x1301 (mandatory)
	tls.TLS_AES_256_GCM_SHA384,       // 0x1302 (should)
	tls.TLS_CHACHA20_POLY1305_SHA256, // 0x1303 (should)
	tls.TLS_AES_128_CCM_SHA256,       // 0x1304
	tls.TLS_AES_128_CCM_8_SHA256,     // 0x1305
}

var TLS13_GROUPS []tls.CurveID = []tls.CurveID{
	tls.CurveP256, // 23  (mandatory)
	tls.CurveP384, // 24
	tls.CurveP521, // 25
	tls.X25519,    // 29  (should)
	tls.X448,      // 30
	tls.FFDHE2048, // 256
	tls.FFDHE3072, // 257
	tls.FFDHE4096, // 258
	tls.FFDHE6144, // 259
	tls.FFDHE8192, // 260
}

// config *Config
func SetupConfig(conf *tls.Config) {
	conf.CipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_128_CCM_SHA256,
		tls.TLS_AES_128_CCM_8_SHA256,
	}
	conf.ForceSuites = true
	conf.CurvePreferences = []tls.CurveID{
		tls.CurveP256,
		//tls.X448,
		//tls.FFDHE2048,
		//tls.FFDHE3072,
		//tls.FFDHE4096,
		//tls.FFDHE6144,
		//tls.FFDHE8192,
	}
	//conf.CurvePreferences = []tls.CurveID{tls.CurveP256}
	conf.CurvePreferences = TLS13_GROUPS
}
