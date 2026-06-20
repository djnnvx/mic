package fingerprint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
)

// buildClientHello synthesizes a TLS handshake record carrying a ClientHello,
// returned as raw bytes ready for ParseClientHello. extensions is the
// wire-encoded extensions block (use ext() + the *Data helpers below).
func buildClientHello(legacyVer uint16, ciphers []uint16, extensions []byte) []byte {
	var body bytes.Buffer

	binary.Write(&body, binary.BigEndian, legacyVer)
	body.Write(make([]byte, 32)) // random
	body.WriteByte(0x00)         // session_id length = 0

	binary.Write(&body, binary.BigEndian, uint16(len(ciphers)*2))
	for _, c := range ciphers {
		binary.Write(&body, binary.BigEndian, c)
	}

	body.WriteByte(0x01) // compression_methods length
	body.WriteByte(0x00) // null

	binary.Write(&body, binary.BigEndian, uint16(len(extensions)))
	body.Write(extensions)

	hsLen := body.Len()
	hs := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, body.Bytes()...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func sniData(host string) []byte {
	name := []byte(host)
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	return append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
}

func alpnData(protos ...string) []byte {
	var list []byte
	for _, p := range protos {
		list = append(list, byte(len(p)))
		list = append(list, p...)
	}
	return append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
}

// clientSuppVerData uses the ClientHello 1-byte list length (the ServerHello
// variant is a bare uint16).
func clientSuppVerData(vers ...uint16) []byte {
	out := []byte{byte(len(vers) * 2)}
	for _, v := range vers {
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

func sigAlgsData(algs ...uint16) []byte {
	out := []byte{byte(len(algs) * 2 >> 8), byte(len(algs) * 2)}
	for _, a := range algs {
		out = append(out, byte(a>>8), byte(a))
	}
	return out
}

func realisticClientHello() []byte {
	var exts []byte
	exts = append(exts, ext(0x0000, sniData("example.com"))...)
	exts = append(exts, ext(0x002b, clientSuppVerData(0x0304))...)
	exts = append(exts, ext(0x0010, alpnData("h2"))...)
	exts = append(exts, ext(0x000d, sigAlgsData(0x0403, 0x0804))...)
	exts = append(exts, ext(0x0033, []byte{})...) // key_share, empty
	return buildClientHello(0x0303, []uint16{0x1301, 0x1302, 0x1303}, exts)
}

func TestParseClientHello_Fields(t *testing.T) {
	ch, err := ParseClientHello(realisticClientHello())
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.LegacyVersion != 0x0303 {
		t.Errorf("legacy version = 0x%04x; want 0x0303", ch.LegacyVersion)
	}
	if want := []uint16{0x1301, 0x1302, 0x1303}; !equalU16(ch.CipherSuites, want) {
		t.Errorf("ciphers = %v; want %v", ch.CipherSuites, want)
	}
	if want := []uint16{0x0000, 0x002b, 0x0010, 0x000d, 0x0033}; !equalU16(ch.Extensions, want) {
		t.Errorf("extensions = %v; want %v", ch.Extensions, want)
	}
	if ch.SNIHost != "example.com" || ch.SNIIsIP {
		t.Errorf("SNI = %q (ip=%v); want example.com (ip=false)", ch.SNIHost, ch.SNIIsIP)
	}
	if want := []uint16{0x0304}; !equalU16(ch.SupportedVersions, want) {
		t.Errorf("supported versions = %v; want %v", ch.SupportedVersions, want)
	}
	if len(ch.ALPNValues) != 1 || ch.ALPNValues[0] != "h2" {
		t.Errorf("alpn = %v; want [h2]", ch.ALPNValues)
	}
	if want := []uint16{0x0403, 0x0804}; !equalU16(ch.SigAlgs, want) {
		t.Errorf("sig algs = %v; want %v", ch.SigAlgs, want)
	}
}

func TestParseClientHello_SNI_IP(t *testing.T) {
	exts := ext(0x0000, sniData("192.0.2.1"))
	ch, err := ParseClientHello(buildClientHello(0x0303, []uint16{0x1301}, exts))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if ch.SNIHost != "192.0.2.1" || !ch.SNIIsIP {
		t.Errorf("SNI = %q (ip=%v); want 192.0.2.1 (ip=true)", ch.SNIHost, ch.SNIIsIP)
	}
}

func TestParseClientHello_GREASEFiltered(t *testing.T) {
	exts := ext(0x1a1a, []byte{}) // GREASE extension
	exts = append(exts, ext(0x002b, clientSuppVerData(0x0304))...)
	ch, err := ParseClientHello(buildClientHello(0x0303, []uint16{0x0a0a, 0x1301}, exts))
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	if want := []uint16{0x1301}; !equalU16(ch.CipherSuites, want) {
		t.Errorf("ciphers = %v; want %v (GREASE filtered)", ch.CipherSuites, want)
	}
	if want := []uint16{0x002b}; !equalU16(ch.Extensions, want) {
		t.Errorf("extensions = %v; want %v (GREASE filtered)", ch.Extensions, want)
	}
}

func TestParseClientHello_Errors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x16, 0x03}},
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}},
		{"wrong handshake type (ServerHello)", []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}},
		{"truncated record", []byte{0x16, 0x03, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseClientHello(tc.raw); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

// TestComputeJA4_KnownFixture pins the JA4 of realisticClientHello(). JA4_a is
// human-readable. The two hashes are checked against their spec preimages,
// independently verifiable with: printf '%s' '<preimage>' | sha256sum.
func TestComputeJA4_KnownFixture(t *testing.T) {
	ch, err := ParseClientHello(realisticClientHello())
	if err != nil {
		t.Fatalf("ParseClientHello: %v", err)
	}
	got := ComputeJA4(ch)

	const wantA = "t13d0305h2" // tls1.3, domain SNI, 3 ciphers, 5 exts, alpn h2
	wantB := sha256Hex12("1301,1302,1303")
	wantC := sha256Hex12("000d,002b,0033_0403,0804") // exts sans SNI+ALPN, sorted; then sig algs

	want := wantA + "_" + wantB + "_" + wantC
	if got != want {
		t.Errorf("JA4 = %q; want %q", got, want)
	}
}

func TestComputeJA4_a_Indicators(t *testing.T) {
	tests := []struct {
		name       string
		legacyVer  uint16
		ciphers    []uint16
		exts       []byte
		wantPrefix string
	}{
		{
			name:       "no SNI, no versions ext, no alpn",
			legacyVer:  0x0303,
			ciphers:    []uint16{0x1301, 0x1302},
			exts:       ext(0x0033, []byte{}),
			wantPrefix: "t12n0201", // legacy 1.2, no SNI -> n, 2 ciphers, 1 ext, alpn 00
		},
		{
			name:       "supported_versions max wins over legacy",
			legacyVer:  0x0301,
			ciphers:    []uint16{0x1301},
			exts:       ext(0x002b, clientSuppVerData(0x0303, 0x0304)),
			wantPrefix: "t13n0101", // max(1.2,1.3)=1.3
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := ParseClientHello(buildClientHello(tc.legacyVer, tc.ciphers, tc.exts))
			if err != nil {
				t.Fatalf("ParseClientHello: %v", err)
			}
			a := ComputeJA4(ch)[:len(tc.wantPrefix)]
			if a != tc.wantPrefix {
				t.Errorf("JA4_a = %q; want %q", a, tc.wantPrefix)
			}
		})
	}
}

func equalU16(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sha256Hex12(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:12]
}
