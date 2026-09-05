package fingerprint

import (
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"
)

// buildServerHello synthesizes a TLS handshake record carrying a ServerHello.
// extensions is the wire-encoded extensions block (type + len + data tuples).
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
	if sh.SupportedVersion != 0x0304 {
		t.Errorf("supported version = 0x%04x; want 0x0304", sh.SupportedVersion)
	}
	if sh.ALPN != "" {
		t.Errorf("alpn = %q; want none", sh.ALPN)
	}
}

func TestParseServerHello_TLS13_WithALPN_h2(t *testing.T) {
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
	if sh.ALPN != "h2" {
		t.Fatalf("alpn = %q; want h2", sh.ALPN)
	}
}

func TestParseServerHello_TLS12_NoSupportedVersions(t *testing.T) {
	// Pre-1.3, legacy_version is the chosen version.
	exts := ext(0x0023, []byte{}) // session_ticket, empty
	raw := buildServerHello(0x0303, 32, 0xc02f, exts)

	sh, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello: %v", err)
	}
	if sh.LegacyVersion != 0x0303 {
		t.Errorf("legacy version = 0x%04x; want 0x0303", sh.LegacyVersion)
	}
	if sh.SupportedVersion != 0 {
		t.Errorf("supported_version present in TLS 1.2 fixture: 0x%04x", sh.SupportedVersion)
	}
	if sh.CipherSuite != 0xc02f {
		t.Errorf("cipher = 0x%04x; want 0xc02f", sh.CipherSuite)
	}
}

func TestParseServerHello_GREASEFiltered(t *testing.T) {
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
		name    string
		raw     []byte
		wantErr bool
	}{
		{"empty", nil, true},
		{"too short", []byte{0x16, 0x03}, true},
		{"wrong content type", []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, true},
		{"wrong handshake type (ClientHello)", []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}, true},
		{"truncated record", []byte{0x16, 0x03, 0x03, 0x00, 0xff, 0x02, 0x00, 0x00, 0x00}, true},
		// Positive control: without it, a parser that always errors keeps this table green.
		{"valid ServerHello", buildServerHello(0x0303, 32, 0x1301, ext(0x002b, []byte{0x03, 0x04})), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseServerHello(tc.raw)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestComputeJA4S_Shape(t *testing.T) {
	// Shape: t<ver><nn><alpn>_<cipher>_<12hex>
	sh := &ServerHelloFields{
		LegacyVersion:    0x0303,
		CipherSuite:      0x1301,
		Extensions:       []uint16{0x002b, 0x0033},
		SupportedVersion: 0x0304,
	}
	got := ComputeJA4S(sh)

	re := regexp.MustCompile(`^t1302(00|[a-z0-9]{2})_[0-9a-f]{4}_[0-9a-f]{12}$`)
	if !re.MatchString(got) {
		t.Errorf("JA4S = %q; does not match expected shape", got)
	}
}

func TestComputeJA4S_KnownFixture(t *testing.T) {
	// The extension list is DESCENDING on purpose. JA4S hashes wire order and
	// must not sort; an ascending fixture cannot tell the two apart.
	sh := &ServerHelloFields{
		LegacyVersion:    0x0303,
		CipherSuite:      0x1301,
		Extensions:       []uint16{0x0033, 0x002b},
		SupportedVersion: 0x0304,
	}
	got := ComputeJA4S(sh)
	const want = "t130200_1301_"
	if got[:len(want)] != want {
		t.Errorf("JA4S prefix = %q; want prefix %q", got, want)
	}
	// sha256("0033,002b")[:12]. Sorting would give sha256("002b,0033")[:12]
	// = a56c5b993250 instead, which this pin rejects.
	const wantHash = "234ea6891581"
	if got[len(want):] != wantHash {
		t.Errorf("JA4S ext hash = %q; want %q", got[len(want):], wantHash)
	}
}

func TestComputeJA4S_EmptyExtensions(t *testing.T) {
	// Pre-TLS-1.3 ServerHello with no extensions block: JA4S_c is all zeroes,
	// not sha256("").
	sh := &ServerHelloFields{LegacyVersion: 0x0303, CipherSuite: 0xc02f}
	if got := ComputeJA4S(sh); got != "t120000_c02f_000000000000" {
		t.Errorf("JA4S = %q; want t120000_c02f_000000000000", got)
	}
}

func TestJA4SALPNCode(t *testing.T) {
	cases := []struct {
		alpn string
		want string
	}{
		{"", "00"},
		{"h2", "h2"},
		{"http/1.1", "h1"},
		{"h", "hh"},
		{"h3", "h3"},
		{"\xab", "ab"},
		{"\x20", "20"},
		{"\xab\xcd", "ad"},
		{"\x20\x61", "21"},
		{"\x30\xab", "3b"},
		{"\x61\x20", "60"},
		{"\x30\x31\xab\xcd", "3d"},
		// Both end bytes are alphanumeric, so the hex fallback must NOT trigger.
		{"\x30\xab\xcd\x31", "01"},
	}
	for _, tc := range cases {
		if got := ja4sALPNCode(tc.alpn); got != tc.want {
			t.Errorf("ja4sALPNCode(%q) = %q; want %q", tc.alpn, got, tc.want)
		}
	}
}

func TestComputeJA4S_ALPN_h2(t *testing.T) {
	sh := &ServerHelloFields{
		LegacyVersion:    0x0303,
		CipherSuite:      0x1301,
		Extensions:       []uint16{0x002b, 0x0010, 0x0033},
		SupportedVersion: 0x0304,
		ALPN:             "h2",
	}
	got := ComputeJA4S(sh)
	// nn=03, alpn=h2
	const wantPrefix = "t1303h2_1301_"
	if got[:len(wantPrefix)] != wantPrefix {
		t.Errorf("JA4S = %q; want prefix %q", got, wantPrefix)
	}
}
