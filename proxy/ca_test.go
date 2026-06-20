package proxy

import (
	"bytes"
	"crypto/x509"
	"net"
	"testing"
)

func TestIssueCert_SignedChain_DNS(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}

	if len(cert.Certificate) != 2 {
		t.Fatalf("chain length = %d; want 2 (leaf + CA)", len(cert.Certificate))
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   "example.com",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("leaf does not verify against CA: %v", err)
	}

	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v; want [example.com]", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v; want none for a hostname", leaf.IPAddresses)
	}
}

func TestIssueCert_IP(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert, err := ca.issueCert("192.0.2.1")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   "192.0.2.1",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("leaf does not verify for IP SAN: %v", err)
	}

	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("IPAddresses = %v; want [192.0.2.1]", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNSNames = %v; want none for an IP", leaf.DNSNames)
	}
}

func TestIssueCert_Caches(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	first, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}
	second, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert (cached): %v", err)
	}

	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Error("second issueCert for same host returned a different cert; cache miss")
	}
	if _, err := ca.issueCert("other.com"); err != nil {
		t.Fatalf("issueCert other host: %v", err)
	}
	if len(ca.cache) != 2 {
		t.Errorf("cache size = %d; want 2", len(ca.cache))
	}
}
