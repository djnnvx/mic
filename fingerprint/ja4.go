package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

// ClientHelloFields holds the parsed TLS ClientHello data used to compute JA4.
type ClientHelloFields struct {
	LegacyVersion     uint16
	CipherSuites      []uint16 // non-GREASE, wire order
	Extensions        []uint16 // non-GREASE extension types, wire order
	SNIHost           string
	SNIIsIP           bool
	SupportedVersions []uint16 // from ext 0x002b, non-GREASE
	ALPNValues        []string // from ext 0x0010
	SigAlgs           []uint16 // from ext 0x000d, wire order
}

// isGREASE reports whether v is a GREASE value (RFC 8701).
// The pattern: high byte == low byte, low nibble of each == 0xA.
func isGREASE(v uint16) bool {
	return v&0x0f == 0x0a && v>>8 == v&0xff
}

// ParseClientHello parses the first TLS handshake record from raw.
// raw must start with a handshake record header (content type 0x16).
func ParseClientHello(raw []byte) (*ClientHelloFields, error) {
	if len(raw) < 5 {
		return nil, fmt.Errorf("ja4: record too short (%d bytes)", len(raw))
	}
	if raw[0] != 0x16 {
		return nil, fmt.Errorf("ja4: not a handshake record (type=0x%02x)", raw[0])
	}
	recLen := int(binary.BigEndian.Uint16(raw[3:5]))
	if len(raw) < 5+recLen {
		return nil, fmt.Errorf("ja4: record body truncated (need %d, have %d)", 5+recLen, len(raw))
	}
	hs := raw[5 : 5+recLen]

	if len(hs) < 4 {
		return nil, fmt.Errorf("ja4: handshake header too short")
	}
	if hs[0] != 0x01 {
		return nil, fmt.Errorf("ja4: not a ClientHello (handshake type=0x%02x)", hs[0])
	}
	// Handshake length is 3 bytes, unlike most other TLS length fields.
	chLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+chLen {
		return nil, fmt.Errorf("ja4: ClientHello body truncated")
	}
	r := hs[4 : 4+chLen]

	fields := &ClientHelloFields{}

	if len(r) < 2 {
		return nil, fmt.Errorf("ja4: too short for legacy version")
	}
	fields.LegacyVersion = binary.BigEndian.Uint16(r[:2])
	r = r[2:]

	if len(r) < 32 {
		return nil, fmt.Errorf("ja4: too short for random")
	}
	r = r[32:]

	if len(r) < 1 {
		return nil, fmt.Errorf("ja4: too short for session ID length")
	}
	sidLen := int(r[0])
	r = r[1:]
	if len(r) < sidLen {
		return nil, fmt.Errorf("ja4: too short for session ID")
	}
	r = r[sidLen:]

	if len(r) < 2 {
		return nil, fmt.Errorf("ja4: too short for cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(r[:2]))
	r = r[2:]
	if len(r) < csLen || csLen%2 != 0 {
		return nil, fmt.Errorf("ja4: cipher suites truncated or odd length")
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(r[i : i+2])
		if !isGREASE(cs) {
			fields.CipherSuites = append(fields.CipherSuites, cs)
		}
	}
	r = r[csLen:]

	if len(r) < 1 {
		return nil, fmt.Errorf("ja4: too short for compression methods length")
	}
	cmLen := int(r[0])
	r = r[1:]
	if len(r) < cmLen {
		return nil, fmt.Errorf("ja4: too short for compression methods")
	}
	r = r[cmLen:]

	// Extensions are absent in very old TLS. Not an error.
	if len(r) < 2 {
		return fields, nil
	}
	extsLen := int(binary.BigEndian.Uint16(r[:2]))
	r = r[2:]
	if len(r) < extsLen {
		return nil, fmt.Errorf("ja4: extensions block truncated")
	}
	exts := r[:extsLen]

	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < extLen {
			return nil, fmt.Errorf("ja4: extension 0x%04x data truncated", extType)
		}
		extData := exts[:extLen]
		exts = exts[extLen:]

		if isGREASE(extType) {
			continue
		}
		fields.Extensions = append(fields.Extensions, extType)

		switch extType {
		case 0x0000:
			parseSNI(extData, fields)
		case 0x0010:
			parseALPN(extData, fields)
		case 0x002b:
			parseSupportedVersions(extData, fields)
		case 0x000d:
			parseSigAlgs(extData, fields)
		}
	}

	return fields, nil
}

func parseSNI(data []byte, f *ClientHelloFields) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen {
		return
	}
	data = data[:listLen]
	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			break
		}
		name := string(data[:nameLen])
		data = data[nameLen:]
		if nameType == 0 { // host_name (the only defined type)
			f.SNIHost = name
			f.SNIIsIP = net.ParseIP(name) != nil
			return
		}
	}
}

func parseALPN(data []byte, f *ClientHelloFields) {
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

func parseSupportedVersions(data []byte, f *ClientHelloFields) {
	// ClientHello supported_versions uses a 1-byte list length, unlike most extensions.
	if len(data) < 1 {
		return
	}
	listLen := int(data[0])
	data = data[1:]
	if len(data) < listLen || listLen%2 != 0 {
		return
	}
	for i := 0; i < listLen; i += 2 {
		v := binary.BigEndian.Uint16(data[i : i+2])
		if !isGREASE(v) {
			f.SupportedVersions = append(f.SupportedVersions, v)
		}
	}
}

func parseSigAlgs(data []byte, f *ClientHelloFields) {
	if len(data) < 2 {
		return
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	data = data[2:]
	if len(data) < listLen || listLen%2 != 0 {
		return
	}
	for i := 0; i < listLen; i += 2 {
		f.SigAlgs = append(f.SigAlgs, binary.BigEndian.Uint16(data[i:i+2]))
	}
}

func ComputeJA4(ch *ClientHelloFields) string {
	return buildJA4a(ch) + "_" + buildJA4b(ch.CipherSuites) + "_" + buildJA4c(ch.Extensions, ch.SigAlgs)
}

func buildJA4a(ch *ClientHelloFields) string {
	tlsVer := tlsVersionStr(ch.LegacyVersion)
	if len(ch.SupportedVersions) > 0 {
		max := uint16(0)
		for _, v := range ch.SupportedVersions {
			if v > max {
				max = v
			}
		}
		tlsVer = tlsVersionStr(max)
	}

	sniChar := "n"
	if ch.SNIHost != "" {
		if ch.SNIIsIP {
			sniChar = "i"
		} else {
			sniChar = "d"
		}
	}

	nc := min99(len(ch.CipherSuites))
	ne := min99(len(ch.Extensions))

	alpn := "00"
	if len(ch.ALPNValues) > 0 {
		v := ch.ALPNValues[0]
		switch {
		case len(v) >= 2:
			alpn = v[:2]
		case len(v) == 1:
			alpn = v + "0"
		}
	}

	return fmt.Sprintf("t%s%s%02d%02d%s", tlsVer, sniChar, nc, ne, alpn)
}

// min99 caps n at 99, the maximum that fits in the two-digit JA4_a counter.
func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

func tlsVersionStr(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	default:
		return "00"
	}
}

func buildJA4b(ciphers []uint16) string {
	sorted := make([]uint16, len(ciphers))
	copy(sorted, ciphers)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	parts := make([]string, len(sorted))
	for i, c := range sorted {
		parts[i] = fmt.Sprintf("%04x", c)
	}
	h := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return fmt.Sprintf("%x", h)[:12]
}

// buildJA4c hashes sorted extension types (excluding SNI and ALPN, which vary
// per-connection) then signature algorithms in wire order. Sorting is what
// distinguishes JA4 from the raw JA4_r variant.
func buildJA4c(exts []uint16, sigAlgs []uint16) string {
	var filtered []uint16
	for _, e := range exts {
		if e != 0x0000 && e != 0x0010 {
			filtered = append(filtered, e)
		}
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })

	extParts := make([]string, len(filtered))
	for i, e := range filtered {
		extParts[i] = fmt.Sprintf("%04x", e)
	}

	sigParts := make([]string, len(sigAlgs))
	for i, s := range sigAlgs {
		sigParts[i] = fmt.Sprintf("%04x", s)
	}

	h := sha256.Sum256([]byte(strings.Join(extParts, ",") + "_" + strings.Join(sigParts, ",")))
	return fmt.Sprintf("%x", h)[:12]
}
