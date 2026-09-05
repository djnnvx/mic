package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ServerHelloFields holds the parsed TLS ServerHello data used to compute JA4S.
type ServerHelloFields struct {
	LegacyVersion    uint16
	CipherSuite      uint16   // single chosen suite
	Extensions       []uint16 // non-GREASE extension types, wire order
	SupportedVersion uint16   // from ext 0x002b, single chosen version (0 if absent)
	ALPN             string   // from ext 0x0010, single chosen protocol ("" if absent)
}

// ParseServerHello parses the first TLS handshake record from raw, expecting
// a ServerHello. raw must start with a handshake record header (content type 0x16).
func ParseServerHello(raw []byte) (*ServerHelloFields, error) {
	r, err := handshakeBody(raw, 0x02, "ja4s")
	if err != nil {
		return nil, err
	}

	fields := &ServerHelloFields{}

	if len(r) < 2 {
		return nil, fmt.Errorf("ja4s: too short for legacy version")
	}
	fields.LegacyVersion = binary.BigEndian.Uint16(r[:2])
	r = r[2:]

	if len(r) < 32 {
		return nil, fmt.Errorf("ja4s: too short for random")
	}
	r = r[32:]

	if len(r) < 1 {
		return nil, fmt.Errorf("ja4s: too short for session_id_echo length")
	}
	sidLen := int(r[0])
	r = r[1:]
	if len(r) < sidLen {
		return nil, fmt.Errorf("ja4s: too short for session_id_echo")
	}
	r = r[sidLen:]

	if len(r) < 2 {
		return nil, fmt.Errorf("ja4s: too short for cipher suite")
	}
	fields.CipherSuite = binary.BigEndian.Uint16(r[:2])
	r = r[2:]

	if len(r) < 1 {
		return nil, fmt.Errorf("ja4s: too short for compression method")
	}
	r = r[1:]

	// Pre-TLS-1.3 ServerHellos may omit the extensions block entirely.
	if len(r) < 2 {
		return fields, nil
	}
	extsLen := int(binary.BigEndian.Uint16(r[:2]))
	r = r[2:]
	if len(r) < extsLen {
		return nil, fmt.Errorf("ja4s: extensions block truncated")
	}
	exts := r[:extsLen]

	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < extLen {
			return nil, fmt.Errorf("ja4s: extension 0x%04x data truncated", extType)
		}
		extData := exts[:extLen]
		exts = exts[extLen:]

		if isGREASE(extType) {
			continue
		}
		fields.Extensions = append(fields.Extensions, extType)

		switch extType {
		case 0x002b:
			if len(extData) >= 2 {
				if v := binary.BigEndian.Uint16(extData[:2]); !isGREASE(v) {
					fields.SupportedVersion = v
				}
			}
		case 0x0010:
			parseServerALPN(extData, fields)
		}
	}

	return fields, nil
}

// parseServerALPN reads the single protocol the server selected. Wire format
// matches ClientHello, but the server lists exactly one.
func parseServerALPN(data []byte, f *ServerHelloFields) {
	if len(data) < 3 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen || listLen < 1 {
		return
	}
	pLen := int(data[0])
	if 1+pLen > listLen || len(data) < 1+pLen {
		return
	}
	f.ALPN = string(data[1 : 1+pLen])
}

// ComputeJA4S builds the JA4S hash from a parsed ServerHello.
// Format: t<version><nn><alpn>_<cipher>_<exthash>
// Always "t" for TCP; QUIC is not produced by mic.
func ComputeJA4S(sh *ServerHelloFields) string {
	return buildJA4Sa(sh) + "_" + fmt.Sprintf("%04x", sh.CipherSuite) + "_" + buildJA4Sc(sh.Extensions)
}

func buildJA4Sa(sh *ServerHelloFields) string {
	ver := tlsVersionStr(sh.LegacyVersion)
	if sh.SupportedVersion != 0 {
		ver = tlsVersionStr(sh.SupportedVersion)
	}

	nn := min99(len(sh.Extensions))

	return fmt.Sprintf("t%s%02d%s", ver, nn, ja4sALPNCode(sh.ALPN))
}

// ja4sALPNCode encodes the negotiated ALPN as the JA4 two-character code: first
// and last byte of the value. If either end byte is not ASCII alphanumeric,
// hex-encode the whole value and take the first and last hex characters instead.
func ja4sALPNCode(v string) string {
	if v == "" {
		return "00"
	}
	b := []byte(v)
	first, last := b[0], b[len(b)-1]
	if !ja4sIsAlnum(first) || !ja4sIsAlnum(last) {
		h := hex.EncodeToString(b)
		return string(h[0]) + string(h[len(h)-1])
	}
	return string(first) + string(last)
}

func ja4sIsAlnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// buildJA4Sc hashes ServerHello extension types in wire order. JA4_c sorts, this
// must not.
func buildJA4Sc(exts []uint16) string {
	if len(exts) == 0 {
		return "000000000000"
	}
	parts := make([]string, len(exts))
	for i, e := range exts {
		parts[i] = fmt.Sprintf("%04x", e)
	}
	h := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return fmt.Sprintf("%x", h)[:12]
}
