package fingerprint

import (
	"fmt"

	utls "github.com/bogdanfinn/utls"
)

// NameTable maps human-readable profile names to utls ClientHelloID presets.
var NameTable = map[string]utls.ClientHelloID{
	"chrome-120":    utls.HelloChrome_120,
	"chrome-120-pq": utls.HelloChrome_120_PQ,
	"firefox-120":   utls.HelloFirefox_120,
	"safari-16":     utls.HelloSafari_16_0,
	"edge-106":      utls.HelloEdge_106,
}

// Table maps known JA4-TLS fingerprint hashes to utls ClientHelloID presets.
//
// Hashes are measured empirically against tlsinfo.me using cmd/probe — they
// reflect what the utls preset actually emits, not captures from real browsers.
// Re-run cmd/probe after upgrading the utls dependency to verify they still match.
//
// Note: JA4 does not distinguish key_share entries, so Chrome_120, Chrome_120_PQ,
// and Chrome_131 all produce the same hash. Use the preset directly in dialTarget
// if you need a specific variant (e.g. HelloChrome_120_PQ for PQ key exchange).
// Similarly, Safari_15_6_1, Safari_16_0, and all iOS variants share one hash.
var Table = map[string]utls.ClientHelloID{
	"t13d1516h2_8daaf6152771_02713d6af862": utls.HelloChrome_131,
	"t13d1516h2_8daaf6152771_d8a2da3f94cd": utls.HelloChrome_133,
	"t13d1715h2_5b57614c22b0_5c2c66f702b0": utls.HelloFirefox_120,
	"t13d2014h2_a09f3c656075_14788d8d241b": utls.HelloSafari_16_0,
	"t13d1516h2_8daaf6152771_e5627efa2ab1": utls.HelloEdge_106,
}

func Lookup(ja4 string) (utls.ClientHelloID, bool) {
	id, ok := Table[ja4]
	return id, ok
}

type TLSFingerprint struct {
	name string
	id   utls.ClientHelloID
}

func ByName(name string) (*TLSFingerprint, error) {
	id, ok := NameTable[name]
	if !ok {
		return nil, fmt.Errorf("unknown TLS fingerprint profile %q", name)
	}
	return &TLSFingerprint{name: name, id: id}, nil
}

func (f *TLSFingerprint) Name() string {
	return f.name
}

func (f *TLSFingerprint) ClientHelloID() utls.ClientHelloID {
	return f.id
}
