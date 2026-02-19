// probe dials tlsinfo.me/json with each known utls preset and prints the
// JA4 hash that the server observes. Run once to populate the fingerprint table.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

var presets = []struct {
	name string
	id   utls.ClientHelloID
}{
	{"HelloChrome_120", utls.HelloChrome_120},
	{"HelloChrome_120_PQ", utls.HelloChrome_120_PQ},
	{"HelloFirefox_120", utls.HelloFirefox_120},
	{"HelloSafari_16_0", utls.HelloSafari_16_0},
	{"HelloEdge_106", utls.HelloEdge_106},
}

func dialUTLS(ctx context.Context, id utls.ClientHelloID) (*utls.UConn, error) {
	tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", "tlsinfo.me:443")
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(tcpConn, &utls.Config{ServerName: "tlsinfo.me"}, id)
	if err := uconn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, err
	}
	return uconn, nil
}

func decodeJA4(body interface{ Read([]byte) (int, error) }) (string, error) {
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

	proto := uconn.ConnectionState().NegotiatedProtocol

	if proto == "h2" {
		// Use http2.Transport with the already-dialed connection.
		h2t := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialUTLS(ctx, id)
			},
		}
		// Discard the first connection — the Transport dials its own.
		uconn.Close()
		client := &http.Client{Transport: h2t}
		resp, err := client.Get("https://tlsinfo.me/json")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		return decodeJA4(resp.Body)
	}

	// http/1.1 path: reuse the already-established connection.
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
