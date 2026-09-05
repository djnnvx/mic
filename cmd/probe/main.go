// probe prints the JA4 hash tlsinfo.me observes for each mic profile, to
// populate the fingerprint table.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"

	utls "github.com/bogdanfinn/utls"
	"golang.org/x/net/http2"

	"github.com/djnnvx/mic/fingerprint"
)

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
		// Reuse the handshaked uconn. A Transport redial would measure a different handshake.
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
	for _, name := range slices.Sorted(maps.Keys(fingerprint.NameTable)) {
		ja4, err := probe(fingerprint.NameTable[name])
		if err != nil {
			fmt.Printf("%-22s  ERROR: %v\n", name, err)
			continue
		}
		fmt.Printf("%-22s  %s\n", name, ja4)
	}
}
