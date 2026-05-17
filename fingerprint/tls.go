package fingerprint

import (
	"fmt"

	utls "github.com/bogdanfinn/utls"
)

// NameTable maps human-readable profile names to utls ClientHelloID presets.
var NameTable = map[string]utls.ClientHelloID{
	"chrome-120":        utls.HelloChrome_120,
	"chrome-120-pq":     utls.HelloChrome_120_PQ,
	"chrome-131":        utls.HelloChrome_131,
	"chrome-133":        utls.HelloChrome_133,
	"firefox-120":       utls.HelloFirefox_120,
	"safari-16":         utls.HelloSafari_16_0,
	"ios-16":            utls.HelloIOS_16_0,
	"edge-85":           utls.HelloEdge_85,
	"edge-106":          utls.HelloEdge_106,
	"opera-91":          utls.HelloOpera_91,
	"android-11-okhttp": utls.HelloAndroid_11_OkHttp,
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
