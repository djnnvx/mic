package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/bogdanfinn/utls"
	"github.com/djnnvx/mic/fingerprint"
)

func generateSelfSignedCert(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return pool, tlsCert
}

func TestDialTarget_HandshakeSucceeds(t *testing.T) {
	pool, tlsCert := generateSelfSignedCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	fp, err := fingerprint.ByName("chrome-120")
	if err != nil {
		t.Fatalf("fingerprint.ByName: %v", err)
	}

	p := &Proxy{
		ListenAddr:  "127.0.0.1:0",
		CAPool:      pool,
		Fingerprint: fp,
	}

	conn, err := p.dialTarget(ln.Addr().String())
	if err != nil {
		t.Fatalf("dialTarget(%q): %v", ln.Addr().String(), err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("writing to connection: %v", err)
	}
}

func TestDialTarget_FallbackToRandomized(t *testing.T) {
	pool, tlsCert := generateSelfSignedCert(t)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
	}()

	p := &Proxy{
		ListenAddr: "127.0.0.1:0",
		CAPool:     pool,
	}

	conn, err := p.dialTarget(ln.Addr().String())
	if err != nil {
		// HelloRandomized sometimes picks a curve the local TLS stack rejects.
		if !strings.Contains(err.Error(), "CurvePreferences includes unsupported curve") {
			t.Fatalf("dialTarget with randomized preset: %v", err)
		}
		return
	}
	defer conn.Close()

	if got := conn.ClientHelloID.Str(); got != utls.HelloRandomized.Str() {
		t.Fatalf("ClientHelloID: got %q, want %q", got, utls.HelloRandomized.Str())
	}
}

func TestServe_ReturnsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}

	p := &Proxy{Handler: func(conn net.Conn, _ *Proxy) { conn.Close() }}

	done := make(chan error, 1)
	go func() { done <- p.Serve(ln) }()

	time.Sleep(50 * time.Millisecond)
	ln.Close()

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after the listener was closed")
	}
}

func TestPipe_HalfCloseDeliversResponse(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen backend: %v", err)
	}
	defer backend.Close()

	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(io.Discard, conn)
		time.Sleep(100 * time.Millisecond)
		conn.Write([]byte("PONG"))
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen front: %v", err)
	}
	defer front.Close()

	go func() {
		conn, err := front.Accept()
		if err != nil {
			return
		}
		upstream, err := net.Dial("tcp", backend.Addr().String())
		if err != nil {
			conn.Close()
			return
		}
		pipe(conn, upstream)
	}()

	client, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial front: %v", err)
	}
	defer client.Close()

	if _, err := client.Write([]byte("PING")); err != nil {
		t.Fatalf("writing request: %v", err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	if string(got) != "PONG" {
		t.Fatalf("response: got %q, want %q", got, "PONG")
	}
}
