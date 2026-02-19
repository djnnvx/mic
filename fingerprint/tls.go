package fingerprint

import (
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// Table maps known JA4-TLS fingerprint hashes to utls ClientHelloID presets.
// JA4 hashes are computed from real traffic captures; verify against current
// browser versions when adding new entries.
// Table maps JA4-TLS hashes to utls ClientHelloID presets.
//
// Hashes are measured empirically against tlsinfo.me using cmd/probe — they
// reflect what the utls preset actually emits, not captures from real browsers.
// Re-run cmd/probe after upgrading the utls dependency to verify they still match.
//
// Note: HelloChrome_120_PQ produces the same JA4 as HelloChrome_120 because the
// post-quantum key share (X25519MLKEM768) falls in a key_share extension entry
// that JA4 does not distinguish. Use HelloChrome_120_PQ directly in dialTarget
// if you specifically need the PQ key exchange behaviour.
var Table = map[string]utls.ClientHelloID{
	"t13d1516h2_8daaf6152771_02713d6af862": utls.HelloChrome_120,
	"t13d1715h2_5b57614c22b0_5c2c66f702b0": utls.HelloFirefox_120,
	"t13d2014h2_a09f3c656075_14788d8d241b": utls.HelloSafari_16_0,
	"t13d1516h2_8daaf6152771_e5627efa2ab1": utls.HelloEdge_106,
}

// Lookup returns the utls.ClientHelloID for the given JA4 hash.
func Lookup(ja4 string) (utls.ClientHelloID, bool) {
	id, ok := Table[ja4]
	return id, ok
}

// TLSFingerprint implements TLSApplier for a specific JA4 hash.
type TLSFingerprint struct {
	ja4 string
	id  utls.ClientHelloID
}

// NewTLS creates a TLSFingerprint for the given JA4 hash.
// Returns an error if the hash is not in the built-in table.
func NewTLS(ja4 string) (*TLSFingerprint, error) {
	id, ok := Lookup(ja4)
	if !ok {
		return nil, fmt.Errorf("unknown JA4-TLS fingerprint %q", ja4)
	}
	return &TLSFingerprint{ja4: ja4, id: id}, nil
}

// Name returns a human-readable identifier including the JA4 hash.
func (f *TLSFingerprint) Name() string {
	return "tls:" + f.ja4
}

// ClientHelloID returns the utls preset for this fingerprint.
func (f *TLSFingerprint) ClientHelloID() utls.ClientHelloID {
	return f.id
}
