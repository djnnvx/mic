//go:build integration

package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/djnnvx/mic/fingerprint"
)

// Values measured empirically via cmd/probe against
// tlsinfo.me). chrome-120-pq is absent: it emits the same JA4 as chrome-120
// because JA4 does not distinguish the X25519MLKEM768 key share.
var expectedJA4 = map[string]string{
	"chrome-120":  "t13d1516h2_8daaf6152771_02713d6af862",
	"firefox-120": "t13d1715h2_5b57614c22b0_5c2c66f702b0",
	"safari-16":   "t13d2014h2_a09f3c656075_14788d8d241b",
	"edge-106":    "t13d1516h2_8daaf6152771_e5627efa2ab1",
}

// TestClientFront_JA4 verifies that each fingerprint profile produces the
// expected JA4 on outbound connections in client-front (HTTP CONNECT) mode.
//
//	test client → TCP CONNECT → proxy (HttpsHandler) → uTLS(profile) → captureJA4Server
func TestClientFront_JA4(t *testing.T) {
	for name, want := range expectedJA4 {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			captureAddr, capturePool, ja4s := captureJA4Server(t)

			fp, err := fingerprint.ByName(name)
			if err != nil {
				t.Fatalf("fingerprint.ByName(%q): %v", name, err)
			}

			proxyAddr := serveHandler(t, &Proxy{CAPool: capturePool, Fingerprint: fp}, HttpsHandler)

			conn, err := net.DialTimeout("tcp", proxyAddr, testTimeout)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck

			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", captureAddr, captureAddr)
			if status, err := readHTTPStatus(bufio.NewReader(conn)); err != nil || status != 200 {
				t.Fatalf("CONNECT: status=%d err=%v", status, err)
			}

			// Send a plain HTTP request through the uTLS tunnel the proxy established.
			fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", captureAddr)
			io.Copy(io.Discard, conn) //nolint:errcheck

			if got := receiveJA4(t, ja4s); got != want {
				t.Errorf("JA4 mismatch for %s:\n  got  %s\n  want %s", name, got, want)
			}
		})
	}
}

// TestServerFront_JA4 verifies that each fingerprint profile produces the
// expected JA4 on outbound connections in server-front (TLS termination) mode.
//
//	test client → TLS → proxy (ServerFrontHandler) → uTLS(profile) → captureJA4Server
func TestServerFront_JA4(t *testing.T) {
	for name, want := range expectedJA4 {
		name, want := name, want
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			captureAddr, capturePool, ja4s := captureJA4Server(t)
			proxyCertFile, proxyKeyFile, proxyPool := writeTempCertKey(t)

			fp, err := fingerprint.ByName(name)
			if err != nil {
				t.Fatalf("fingerprint.ByName(%q): %v", name, err)
			}

			p := &Proxy{BackendAddr: captureAddr, CAPool: capturePool, Fingerprint: fp}
			proxyAddr := serveHandler(t, p, ServerFrontHandler(proxyCertFile, proxyKeyFile))

			tlsConn, err := tls.DialWithDialer(
				&net.Dialer{Timeout: testTimeout},
				"tcp", proxyAddr,
				&tls.Config{RootCAs: proxyPool, ServerName: "localhost"},
			)
			if err != nil {
				t.Fatalf("tls.Dial to proxy: %v", err)
			}
			defer tlsConn.Close()
			tlsConn.SetDeadline(time.Now().Add(testTimeout)) //nolint:errcheck

			fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			io.Copy(io.Discard, tlsConn) //nolint:errcheck

			if got := receiveJA4(t, ja4s); got != want {
				t.Errorf("JA4 mismatch for %s:\n  got  %s\n  want %s", name, got, want)
			}
		})
	}
}

func readHTTPStatus(r *bufio.Reader) (int, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, err
	}
	var proto string
	var status int
	fmt.Sscanf(line, "%s %d", &proto, &status)
	for {
		h, err := r.ReadString('\n')
		if err != nil || h == "\r\n" {
			break
		}
	}
	return status, nil
}

func receiveJA4(t *testing.T, ja4s <-chan string) string {
	t.Helper()
	select {
	case ja4 := <-ja4s:
		return ja4
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for captured JA4")
		return ""
	}
}
