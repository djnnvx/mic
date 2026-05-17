//go:build integration

package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/djnnvx/mic/fingerprint"
)

const testTimeout = 10 * time.Second

func serveHandler(t *testing.T, p *Proxy, h Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h(conn, p)
		}
	}()

	return ln.Addr().String()
}

func writeTempCertKey(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()

	pool, tlsCert := generateSelfSignedCert(t)

	cf, err := os.CreateTemp("", "mic-cert-*.pem")
	if err != nil {
		t.Fatalf("creating cert temp file: %v", err)
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: tlsCert.Certificate[0]})
	cf.Close()
	certFile = cf.Name()

	// PKCS8 format is required: tls.LoadX509KeyPair accepts "PRIVATE KEY" blocks.
	keyBytes, err := x509.MarshalPKCS8PrivateKey(tlsCert.PrivateKey)
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	kf, err := os.CreateTemp("", "mic-key-*.pem")
	if err != nil {
		t.Fatalf("creating key temp file: %v", err)
	}
	pem.Encode(kf, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	kf.Close()
	keyFile = kf.Name()

	t.Cleanup(func() {
		os.Remove(certFile)
		os.Remove(keyFile)
	})

	return certFile, keyFile, pool
}

// TestClientFront_Integration tests the full client-front (HTTP CONNECT) flow:
//
//	client → TCP CONNECT → proxy → uTLS(Chrome120) → httptest.TLSServer
func TestClientFront_Integration(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "client-front integration OK")
	}))
	defer ts.Close()

	caPool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("fingerprint.ByName: %v", err)
	}

	p := &Proxy{CAPool: caPool, Fingerprint: fp}
	proxyAddr := serveHandler(t, p, HttpsHandler)

	conn, err := net.DialTimeout("tcp", proxyAddr, testTimeout)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(testTimeout))

	targetAddr := ts.Listener.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status: %d; want 200", resp.StatusCode)
	}

	// The proxy has already done uTLS to the target; raw bytes we send here are
	// wrapped in that TLS connection on our behalf.
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr)

	resp, err = http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading GET response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET status: %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	t.Logf("response body: %s", body)
}

// TestServerFront_Integration tests the server-front flow:
//
//	client → TLS → proxy (terminates TLS) → uTLS(Chrome120) → httptest.TLSServer
func TestServerFront_Integration(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "server-front integration OK")
	}))
	defer backend.Close()

	backendCAPool := backend.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	certFile, keyFile, proxyCertPool := writeTempCertKey(t)

	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("fingerprint.ByName: %v", err)
	}

	p := &Proxy{
		BackendAddr: backend.Listener.Addr().String(),
		CAPool:      backendCAPool,
		Fingerprint: fp,
	}
	handler, err := ServerFrontHandler(certFile, keyFile)
	if err != nil {
		t.Fatalf("ServerFrontHandler: %v", err)
	}
	proxyAddr := serveHandler(t, p, handler)

	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: testTimeout},
		"tcp", proxyAddr,
		&tls.Config{RootCAs: proxyCertPool, ServerName: "localhost"},
	)
	if err != nil {
		t.Fatalf("tls.Dial to proxy: %v", err)
	}
	defer tlsConn.Close()
	tlsConn.SetDeadline(time.Now().Add(testTimeout))

	// The proxy decrypts our TLS and re-encrypts with the configured fingerprint
	// before forwarding to the backend.
	fmt.Fprintf(tlsConn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: %d; want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	t.Logf("response body: %s", body)
}
