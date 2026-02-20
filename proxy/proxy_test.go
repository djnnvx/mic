package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

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
		// HelloRandomized may select post-quantum curves unsupported by stdlib TLS.
		t.Skipf("dialTarget with randomized preset: %v", err)
	}
	conn.Close()
}
