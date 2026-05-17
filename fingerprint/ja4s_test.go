package fingerprint

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"
)

// buildServerHello synthesizes a minimal TLS handshake record carrying a
// ServerHello, returned as raw bytes ready for ParseServerHello.
//
// extensions is the wire-encoded extensions block (type + len + data tuples),
// pre-built so each test can choose exactly what to include and in what order.
func buildServerHello(legacyVer uint16, sessionIDLen int, cipher uint16, extensions []byte) []byte {
	var body bytes.Buffer

	binary.Write(&body, binary.BigEndian, legacyVer)
	body.Write(make([]byte, 32)) // random

	body.WriteByte(byte(sessionIDLen))
	body.Write(make([]byte, sessionIDLen))

	binary.Write(&body, binary.BigEndian, cipher)
	body.WriteByte(0x00) // compression_method = null

	binary.Write(&body, binary.BigEndian, uint16(len(extensions)))
	body.Write(extensions)

	// handshake header: type(0x02) + 3-byte length
	hsLen := body.Len()
	hs := []byte{0x02, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	hs = append(hs, body.Bytes()...)

	// record header: type(0x16) + version(0x0303) + 2-byte length
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func ext(t uint16, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(out[0:2], t)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(data)))
	copy(out[4:], data)
	return out
}

func TestParseServerHello_TLS13_Minimal(t *testing.T) {
	// TLS 1.3 ServerHello: supported_versions(0x002b) carries the chosen 0x0304,
	// plus key_share(0x0033) with empty data.
	var exts []byte
	exts = append(exts, ext(0x002b, []byte{0x03, 0x04})...) // chosen version
	exts = append(exts, ext(0x0033, []byte{})...)           // key_share (data irrelevant)

	raw := buildServerHello(0x0303, 32, 0x1301, exts)

	sh, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}

	if sh.CipherSuite != 0x1301 {
		t.Errorf("cipher = 0x%04x; want 0x1301", sh.CipherSuite)
	}
	if got := len(sh.Extensions); got != 2 {
		t.Errorf("extension count = %d; want 2", got)
	}
	if len(sh.SupportedVersions) != 1 || sh.SupportedVersions[0] != 0x0304 {
		t.Errorf("supported versions = %v; want [0x0304]", sh.SupportedVersions)
	}
	if len(sh.ALPNValues) != 0 {
		t.Errorf("alpn = %v; want none", sh.ALPNValues)
	}
}

func TestParseServerHello_TLS13_WithALPN_h2(t *testing.T) {
	// ALPN extension carrying a single chosen protocol "h2".
	alpnList := []byte{0x00, 0x03, 0x02, 'h', '2'}

	var exts []byte
	exts = append(exts, ext(0x002b, []byte{0x03, 0x04})...)
	exts = append(exts, ext(0x0010, alpnList)...)
	exts = append(exts, ext(0x0033, []byte{})...)

	raw := buildServerHello(0x0303, 0, 0x1302, exts)

	sh, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if len(sh.ALPNValues) != 1 || sh.ALPNValues[0] != "h2" {
		t.Fatalf("alpn = %v; want [h2]", sh.ALPNValues)
	}
}

func TestParseServerHello_TLS12_NoSupportedVersions(t *testing.T) {
	// TLS 1.2 ServerHello: legacy_version is the chosen version. No
	// supported_versions extension. Often has session_ticket(0x0023) etc.
	exts := ext(0x0023, []byte{}) // session_ticket, empty
	raw := buildServerHello(0x0303, 32, 0xc02f, exts)

	sh, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if sh.LegacyVersion != 0x0303 {
		t.Errorf("legacy version = 0x%04x; want 0x0303", sh.LegacyVersion)
	}
	if len(sh.SupportedVersions) != 0 {
		t.Errorf("supported_versions present in TLS 1.2 fixture: %v", sh.SupportedVersions)
	}
	if sh.CipherSuite != 0xc02f {
		t.Errorf("cipher = 0x%04x; want 0xc02f", sh.CipherSuite)
	}
}

func TestParseServerHello_GREASEFiltered(t *testing.T) {
	// GREASE extension type 0x0a0a should not appear in the parsed list.
	var exts []byte
	exts = append(exts, ext(0x0a0a, []byte{})...) // GREASE
	exts = append(exts, ext(0x002b, []byte{0x03, 0x04})...)
	exts = append(exts, ext(0x0033, []byte{})...)

	raw := buildServerHello(0x0303, 0, 0x1301, exts)

	sh, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	for _, e := range sh.Extensions {
		if e == 0x0a0a {
			t.Errorf("GREASE extension 0x0a0a leaked into parsed extensions")
		}
	}
	if len(sh.Extensions) != 2 {
		t.Errorf("extension count = %d; want 2 (GREASE filtered)", len(sh.Extensions))
	}
}

func TestParseServerHello_Errors(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x16, 0x03}},
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}},
		{"wrong handshake type (ClientHello)", []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}},
		{"truncated record", []byte{0x16, 0x03, 0x03, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseServerHello(tc.raw); err == nil {
				t.Errorf("expected error, got nil")
			}
		})
	}
}

func TestComputeJA4S_Shape(t *testing.T) {
	// Synthesize a typical TLS 1.3 ServerHello with [supported_versions, key_share]
	// and assert the output shape: t<ver><nn><alpn>_<cipher>_<12hex>
	sh := &ServerHelloFields{
		LegacyVersion:     0x0303,
		CipherSuite:       0x1301,
		Extensions:        []uint16{0x002b, 0x0033},
		SupportedVersions: []uint16{0x0304},
		ALPNValues:        nil,
	}
	got := ComputeJA4S(sh)

	re := regexp.MustCompile(`^t1302(00|[a-z0-9]{2})_[0-9a-f]{4}_[0-9a-f]{12}$`)
	if !re.MatchString(got) {
		t.Errorf("JA4S = %q; does not match expected shape", got)
	}
}

func TestComputeJA4S_KnownFixture(t *testing.T) {
	// Pinned value computed from this exact input. Acts as a regression guard
	// against accidental changes to the hashing/format.
	sh := &ServerHelloFields{
		LegacyVersion:     0x0303,
		CipherSuite:       0x1301,
		Extensions:        []uint16{0x002b, 0x0033},
		SupportedVersions: []uint16{0x0304},
	}
	got := ComputeJA4S(sh)
	const want = "t130200_1301_" // prefix; suffix is the 12-hex hash we pin below
	if got[:len(want)] != want {
		t.Errorf("JA4S prefix = %q; want prefix %q", got, want)
	}
	// Hash of "002b,0033". Pinned: if this changes, the algorithm is wrong.
	const wantHash = "a56c5b993250"
	if got[len(want):] != wantHash {
		t.Errorf("JA4S ext hash = %q; want %q", got[len(want):], wantHash)
	}
}

func TestComputeJA4S_ALPN_h2(t *testing.T) {
	sh := &ServerHelloFields{
		LegacyVersion:     0x0303,
		CipherSuite:       0x1301,
		Extensions:        []uint16{0x002b, 0x0010, 0x0033},
		SupportedVersions: []uint16{0x0304},
		ALPNValues:        []string{"h2"},
	}
	got := ComputeJA4S(sh)
	// nn=03, alpn=h2
	const wantPrefix = "t1303h2_1301_"
	if got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("JA4S = %q; want prefix %q", got, wantPrefix)
	}
}
