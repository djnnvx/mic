package fingerprint

import (
	"fmt"

	utls "github.com/refraction-networking/utls"
)

// Table maps known JA4-TLS fingerprint hashes to utls ClientHelloID presets.
// JA4 hashes are computed from real traffic captures; verify against current
// browser versions when adding new entries.
var Table = map[string]utls.ClientHelloID{
	// Chrome 120
	"t13d1516h2_8daaf6152771_b0da82dd1658": utls.HelloChrome_120,
	// Chrome 120 with post-quantum key exchange
	"t13d1516h2_8daaf6152771_e5627efa2ab1": utls.HelloChrome_120_PQ,
	// Firefox 120
	"t13d1517h2_8daaf6152771_b1ff8ab2d16f": utls.HelloFirefox_120,
	// Safari 16.0
	"t13d1516h2_8daaf6152771_4aeede8da0ac": utls.HelloSafari_16_0,
	// Edge 106
	"t13d1516h2_8daaf6152771_f5b4b24de8b1": utls.HelloEdge_106,
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
