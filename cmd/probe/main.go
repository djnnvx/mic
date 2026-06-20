// probe dials tlsinfo.me/json with each known utls preset and prints the
// JA4 hash that the server observes. Run once to populate the fingerprint table.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	utls "github.com/bogdanfinn/utls"
	"golang.org/x/net/http2"
)

var presets = []struct {
	name string
	id   utls.ClientHelloID
}{
	// Chrome
	{"HelloChrome_120", utls.HelloChrome_120},
	{"HelloChrome_120_PQ", utls.HelloChrome_120_PQ},
	{"HelloChrome_131", utls.HelloChrome_131},
	{"HelloChrome_133", utls.HelloChrome_133},
	// Firefox
	{"HelloFirefox_120", utls.HelloFirefox_120},
	// Safari / iOS
	{"HelloSafari_15_6_1", utls.HelloSafari_15_6_1},
	{"HelloSafari_16_0", utls.HelloSafari_16_0},
	{"HelloIOS_15_5", utls.HelloIOS_15_5},
	{"HelloIOS_15_6", utls.HelloIOS_15_6},
	{"HelloIOS_16_0", utls.HelloIOS_16_0},
	// Edge
	{"HelloEdge_85", utls.HelloEdge_85},
	{"HelloEdge_106", utls.HelloEdge_106},
	// Opera
	{"HelloOpera_89", utls.HelloOpera_89},
	{"HelloOpera_90", utls.HelloOpera_90},
	{"HelloOpera_91", utls.HelloOpera_91},
	// Android
	{"HelloAndroid_11_OkHttp", utls.HelloAndroid_11_OkHttp},
}

func dialUTLS(ctx context.Context, id utls.ClientHelloID) (*utls.UConn, error) {
	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "tlsinfo.me:443")
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(tcpConn, &utls.Config{ServerName: "tlsinfo.me"}, id, false, false, false)
	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return uconn, nil
}

func decodeJA4(body io.Reader) (string, error) {
	var result struct {
		JA4 string `json:"ja4"`
	}
	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return "", err
	}
	return result.JA4, nil
}

func probe(id utls.ClientHelloID) (string, error) {
	ctx := context.Background()
	uconn, err := dialUTLS(ctx, id)
	if err != nil {
		return "", err
	}
	defer uconn.Close()

	if uconn.ConnectionState().NegotiatedProtocol == "h2" {
		// Reuse the already-established uconn rather than letting the Transport
		// dial again. The first handshake is the one that produced the JA4 we
		// want to measure.
		cc, err := (&http2.Transport{}).NewClientConn(uconn)
		if err != nil {
			return "", err
		}
		req, _ := http.NewRequest("GET", "https://tlsinfo.me/json", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		return decodeJA4(resp.Body)
	}

	req, _ := http.NewRequest("GET", "/json", nil)
	req.Host = "tlsinfo.me"
	req.Header.Set("Connection", "close")
	if err := req.Write(uconn); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(bufio.NewReader(uconn), req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return decodeJA4(resp.Body)
}

func main() {
	for _, p := range presets {
		ja4, err := probe(p.id)
		if err != nil {
			fmt.Printf("%-22s  ERROR: %v\n", p.name, err)
			continue
		}
		fmt.Printf("%-22s  %s\n", p.name, ja4)
	}
}
