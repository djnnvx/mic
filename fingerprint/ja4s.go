package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

// ServerHelloFields holds the parsed TLS ServerHello data used to compute JA4S.
type ServerHelloFields struct {
	LegacyVersion     uint16
	CipherSuite       uint16   // single chosen suite
	Extensions        []uint16 // non-GREASE extension types, wire order
	SupportedVersions []uint16 // from ext 0x002b: in ServerHello, the single chosen version
	ALPNValues        []string // from ext 0x0010: in ServerHello, the single chosen protocol
}

// ParseServerHello parses the first TLS handshake record from raw, expecting
// a ServerHello. raw must start with a handshake record header (content type 0x16).
func ParseServerHello(raw []byte) (*ServerHelloFields, error) {
	if len(raw) < 5 {
		return nil, fmt.Errorf("ja4s: record too short (%d bytes)", len(raw))
	}
	if raw[0] != 0x16 {
		return nil, fmt.Errorf("ja4s: not a handshake record (type=0x%02x)", raw[0])
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recLen {
		return nil, fmt.Errorf("ja4s: record body truncated (need %d, have %d)", 5+recLen, len(raw))
	}
	hs := raw[5 : 5+recLen]

	if len(hs) < 4 {
		return nil, fmt.Errorf("ja4s: handshake header too short")
	}
	if hs[0] != 0x02 {
		return nil, fmt.Errorf("ja4s: not a ServerHello (handshake type=0x%02x)", hs[0])
	}
	shLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+shLen {
		return nil, fmt.Errorf("ja4s: ServerHello body truncated")
	}
	r := hs[4 : 4+shLen]

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
			parseServerSupportedVersion(extData, fields)
		case 0x0010:
			parseServerALPN(extData, fields)
		}
	}

	return fields, nil
}

// parseServerSupportedVersion reads the single chosen TLS version (2 bytes).
// Unlike the ClientHello variant which carries a list, the ServerHello variant
// is a bare uint16.
func parseServerSupportedVersion(data []byte, f *ServerHelloFields) {
	if len(data) < 2 {
		return
	}
	v := binary.BigEndian.Uint16(data[:2])
	if !isGREASE(v) {
		f.SupportedVersions = append(f.SupportedVersions, v)
	}
}

// parseServerALPN reads the ALPN extension as the server emits it. Wire format
// is the same as in ClientHello, but the server only ever lists one protocol.
func parseServerALPN(data []byte, f *ServerHelloFields) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return
	}
	data = data[:listLen]
	for len(data) >= 1 {
		pLen := int(data[0])
		data = data[1:]
		if len(data) < pLen {
			break
		}
		f.ALPNValues = append(f.ALPNValues, string(data[:pLen]))
		data = data[pLen:]
	}
}

// ComputeJA4S builds the JA4S hash from a parsed ServerHello.
// Format: t<version><nn><alpn>_<cipher>_<exthash>
// Always "t" for TCP; QUIC is not produced by mic.
func ComputeJA4S(sh *ServerHelloFields) string {
	return buildJA4Sa(sh) + "_" + buildJA4Sb(sh.CipherSuite) + "_" + buildJA4Sc(sh.Extensions)
}

func buildJA4Sa(sh *ServerHelloFields) string {
	ver := tlsVersionStr(sh.LegacyVersion)
	if len(sh.SupportedVersions) > 0 {
		ver = tlsVersionStr(sh.SupportedVersions[0])
	}

	nn := min99(len(sh.Extensions))

	alpn := "00"
	if len(sh.ALPNValues) > 0 {
		v := sh.ALPNValues[0]
		switch {
		case len(v) >= 2:
			alpn = v[:2]
		case len(v) == 1:
			alpn = v + "0"
		}
	}

	return fmt.Sprintf("t%s%02d%s", ver, nn, alpn)
}

func buildJA4Sb(cipher uint16) string {
	return fmt.Sprintf("%04x", cipher)
}

// buildJA4Sc hashes ServerHello extension types in wire order (no sort).
// This is the difference from JA4_c, which sorts.
func buildJA4Sc(exts []uint16) string {
	parts := make([]string, len(exts))
	for i, e := range exts {
		parts[i] = fmt.Sprintf("%04x", e)
	}
	h := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return fmt.Sprintf("%x", h)[:12]
}
