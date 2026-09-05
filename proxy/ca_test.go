package proxy

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
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

// A MitM leaf must never be usable as a CA: the leaf key could then mint certs
// for any host.
func TestIssueCert_LeafIsNotACA(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cert, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	if leaf.IsCA {
		t.Error("leaf has IsCA = true; a MitM leaf must not be a CA")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("leaf KeyUsage includes CertSign; a MitM leaf must not sign certs")
	}
	if leaf.KeyUsage&x509.KeyUsageCRLSign != 0 {
		t.Error("leaf KeyUsage includes CRLSign")
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("leaf KeyUsage = %v; want DigitalSignature only", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("leaf ExtKeyUsage = %v; want [ServerAuth]", leaf.ExtKeyUsage)
	}
}

func TestIssueCert_ReissuesExpiredLeaf(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	first, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}

	ca.mu.Lock()
	entry := ca.cache["example.com"]
	entry.notAfter = time.Now().Add(-time.Second)
	ca.cache["example.com"] = entry
	ca.mu.Unlock()

	second, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert after expiry: %v", err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("expired cached leaf was served again instead of being re-issued")
	}
	leaf, err := x509.ParseCertificate(second.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if !time.Now().Before(leaf.NotAfter) {
		t.Errorf("re-issued leaf NotAfter = %v; already expired", leaf.NotAfter)
	}
}

func TestIssueCert_ReissuesLeafInsideRenewMargin(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	first, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert: %v", err)
	}

	ca.mu.Lock()
	entry := ca.cache["example.com"]
	entry.notAfter = time.Now().Add(leafRenewMargin / 2)
	ca.cache["example.com"] = entry
	ca.mu.Unlock()

	second, err := ca.issueCert("example.com")
	if err != nil {
		t.Fatalf("issueCert inside margin: %v", err)
	}
	if bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Error("leaf expiring inside the renew margin was served again")
	}
}

func TestSave_KeyIsNotWorldReadable(t *testing.T) {
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	t.Run("fresh file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "ca.key")
		if err := ca.Save(filepath.Join(dir, "ca.pem"), keyPath); err != nil {
			t.Fatalf("Save: %v", err)
		}
		assertKeyPerm(t, keyPath)
	})

	t.Run("overwrites pre-existing world readable file", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "ca.key")
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE, 0o666)
		if err != nil {
			t.Fatalf("pre-create key: %v", err)
		}
		f.Close()
		if err := os.Chmod(keyPath, 0o666); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if err := ca.Save(filepath.Join(dir, "ca.pem"), keyPath); err != nil {
			t.Fatalf("Save: %v", err)
		}
		assertKeyPerm(t, keyPath)
	})
}

func assertKeyPerm(t *testing.T, keyPath string) {
	t.Helper()
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("CA key mode on disk = %#o; group/other must have no access", perm)
	}
	if _, err := loadCA(filepath.Join(filepath.Dir(keyPath), "ca.pem"), keyPath); err != nil {
		t.Errorf("saved CA does not load back: %v", err)
	}
}

func TestLoadOrGenerateCA_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	first, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (generate): %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert was not written: %v", err)
	}

	second, err := LoadOrGenerateCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA (load): %v", err)
	}
	if !bytes.Equal(first.derCert, second.derCert) {
		t.Error("second call did not load the CA written by the first")
	}
}

func TestLoadOrGenerateCA_CorruptCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.WriteFile(certPath, []byte("not a certificate\n"), 0o644); err != nil {
		t.Fatalf("corrupt cert: %v", err)
	}

	if _, err := LoadOrGenerateCA(certPath, keyPath); err == nil {
		t.Fatal("LoadOrGenerateCA accepted a corrupt cert file")
	}
}

func TestLoadOrGenerateCA_HalfSpecifiedPairRefused(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadOrGenerateCA(filepath.Join(dir, "ca.pem"), ""); err == nil {
		t.Error("cert path without key path was accepted; want an error")
	}
	if _, err := LoadOrGenerateCA("", filepath.Join(dir, "ca.key")); err == nil {
		t.Error("key path without cert path was accepted; want an error")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); !os.IsNotExist(err) {
		t.Error("a refused half-specified pair still wrote a cert file")
	}

	if _, err := LoadOrGenerateCA("", ""); err != nil {
		t.Errorf("both paths empty must stay valid (ephemeral CA): %v", err)
	}
}
