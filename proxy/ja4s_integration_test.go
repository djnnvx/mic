//go:build integration

package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/djnnvx/mic/fingerprint"
)

// JA4S well-formed shape: t<2-digit ver><2-digit ext-count><alpn>_<4-hex cipher>_<12-hex hash>
var ja4sShape = regexp.MustCompile(`^t\d{2}\d{2}[a-z0-9]{2}_[0-9a-f]{4}_[0-9a-f]{12}$`)

// Baselines pinned from stdlib crypto/tls (Go 1.25). Drift means stdlib TLS
// behavior changed or the parser broke. Verify the captured value before
// updating.
const (
	baselineJA4S_ServerFront = "t130200_1301_a56c5b993250"
	baselineJA4S_ClientFront = "t130200_1301_a56c5b993250"
)

// test client → TLS → mic (ServerFrontHandler, tls.Server) → httptest backend
func TestServerFront_JA4S_Baseline(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	defer backend.Close()

	backendPool := backend.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	certFile, keyFile, proxyPool := writeTempCertKey(t)

	handler, err := ServerFrontHandler(certFile, keyFile)
	if err != nil {
		t.Fatalf("ServerFrontHandler: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	p := &Proxy{BackendAddr: backend.Listener.Addr().String(), CAPool: backendPool}
	ja4sCh := captureJA4SListener(ln, p, handler)

	go func() {
		tlsConn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: testTimeout},
			"tcp", ln.Addr().String(),
			&tls.Config{RootCAs: proxyPool, ServerName: "localhost"},
		)
		if err != nil {
			return
		}
		defer tlsConn.Close()
		fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
		_, _ = bufio.NewReader(tlsConn).ReadString('\n')
	}()

	select {
	case got := <-ja4sCh:
		t.Logf("server-front JA4S: %s", got)
		if !ja4sShape.MatchString(got) {
			t.Errorf("JA4S = %q; does not match expected shape", got)
		}
		if got != baselineJA4S_ServerFront {
			t.Errorf("JA4S drift: got %q, baseline %q (update baseline if stdlib behavior changed intentionally)",
				got, baselineJA4S_ServerFront)
		}
	case <-time.After(testTimeout):
		t.Fatal("timeout waiting for JA4S")
	}
}

// test client → TCP CONNECT → mic (HttpsHandler, tls.Server with issued cert) → upstream
func TestClientFront_JA4S_Baseline(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	}))
	defer upstream.Close()

	upstreamPool := upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	micCAPool := x509.NewCertPool()
	if !micCAPool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatalf("failed to append mic CA to pool")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	// Pin a deterministic upstream fingerprint so dialTarget never picks a
	// randomized ClientHello with curves the test backend can't negotiate.
	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("fingerprint.ByName: %v", err)
	}

	p := &Proxy{CAPool: upstreamPool, LocalCA: ca, Fingerprint: fp}
	ja4sCh := captureJA4SListener(ln, p, HttpsHandler)

	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), testTimeout)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(testTimeout))

		upstreamAddr := upstream.Listener.Addr().String()
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)

		reader := bufio.NewReader(conn)
		if _, err := http.ReadResponse(reader, nil); err != nil {
			return
		}

		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "127.0.0.1",
			RootCAs:    micCAPool,
		})
		_ = tlsConn.Handshake()
	}()

	select {
	case got := <-ja4sCh:
		t.Logf("client-front JA4S: %s", got)
		if !ja4sShape.MatchString(got) {
			t.Errorf("JA4S = %q; does not match expected shape", got)
		}
		if got != baselineJA4S_ClientFront {
			t.Errorf("JA4S drift: got %q, baseline %q (update baseline if stdlib behavior changed intentionally)",
				got, baselineJA4S_ClientFront)
		}
	case <-time.After(testTimeout):
		t.Fatal("timeout waiting for JA4S")
	}
}
