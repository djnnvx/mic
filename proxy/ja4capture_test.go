//go:build integration

package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/djnnvx/mic/fingerprint"
)

// teeConn tees all bytes read from it into an io.Writer, letting us capture
// the raw ClientHello while tls.Server reads from the connection normally.
type teeConn struct {
	net.Conn
	r io.Reader
}

func (tc *teeConn) Read(b []byte) (int, error) { return tc.r.Read(b) }

// captureJA4Server starts a TLS listener that captures the JA4 fingerprint
// from each incoming connection's ClientHello and sends it on the returned channel.
// The server also serves a minimal HTTP/1.1 200 response so callers can complete
// their request without stalling.
//
// The returned addr is "localhost:PORT" (not "127.0.0.1:PORT") so that
// dialTarget uses a hostname SNI rather than an IP address. This matches the
// "d" (domain) indicator in the stored JA4 fingerprint table, which was
// measured against tlsinfo.me — also a hostname.
func captureJA4Server(t *testing.T) (addr string, certPool *x509.CertPool, ja4s <-chan string) {
	t.Helper()

	pool, tlsCert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("captureJA4Server: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	ch := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveCapture(conn, tlsCfg, ch)
		}
	}()

	return "localhost:" + port, pool, ch
}

func serveCapture(conn net.Conn, cfg *tls.Config, ch chan<- string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck

	var buf bytes.Buffer
	tc := &teeConn{Conn: conn, r: io.TeeReader(conn, &buf)}

	srv := tls.Server(tc, cfg)
	if err := srv.Handshake(); err != nil {
		if ja4, err2 := captureToJA4(buf.Bytes()); err2 == nil {
			ch <- ja4
		}
		return
	}

	if ja4, err := captureToJA4(buf.Bytes()); err == nil {
		ch <- ja4
	}

	reader := bufio.NewReader(srv)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	fmt.Fprintf(srv, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nOK\n")
}

func captureToJA4(raw []byte) (string, error) {
	ch, err := fingerprint.ParseClientHello(raw)
	if err != nil {
		return "", err
	}
	return fingerprint.ComputeJA4(ch), nil
}
