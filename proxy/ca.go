package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const (
	leafLifetime = 24 * time.Hour
	// Re-issue this long before expiry so a leaf cannot expire mid-handshake.
	leafRenewMargin = time.Minute
)

type cachedLeaf struct {
	cert     tls.Certificate
	notAfter time.Time
}

// LocalCA is a self-signed CA used to issue per-host certificates for
// MitM TLS interception in client-front mode.
type LocalCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	derCert []byte // raw DER, appended as chain in issued certs

	mu    sync.Mutex
	cache map[string]cachedLeaf
}

func GenerateCA() (*LocalCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return buildCA(key)
}

// LoadOrGenerateCA loads the CA from certPath + keyPath. If the files do not
// exist it generates a new CA and writes it to those paths. Pass empty strings
// for both to get an ephemeral in-memory CA.
func LoadOrGenerateCA(certPath, keyPath string) (*LocalCA, error) {
	if certPath == "" && keyPath == "" {
		return GenerateCA()
	}
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("CA cert path and key path must both be set or both be empty")
	}

	ca, err := loadCA(certPath, keyPath)
	if err == nil {
		return ca, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading CA: %w", err)
	}

	ca, err = GenerateCA()
	if err != nil {
		return nil, err
	}
	if err := ca.Save(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("saving CA: %w", err)
	}
	return ca, nil
}

func loadCA(certPath, keyPath string) (*LocalCA, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA private key must be ECDSA")
	}
	return &LocalCA{
		cert:    cert,
		key:     key,
		derCert: pair.Certificate[0],
		cache:   make(map[string]cachedLeaf),
	}, nil
}

func buildCA(key *ecdsa.PrivateKey) (*LocalCA, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mic local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &LocalCA{
		cert:    cert,
		key:     key,
		derCert: der,
		cache:   make(map[string]cachedLeaf),
	}, nil
}

func (ca *LocalCA) Save(certPath, keyPath string) error {
	cf, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: ca.derCert}); err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return err
	}
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer kf.Close()
	// O_CREATE's mode is ignored for an existing file and masked by umask for a
	// new one, so set 0600 explicitly.
	if err := kf.Chmod(0o600); err != nil {
		return err
	}
	return pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

// CertPEM returns the CA certificate as PEM for curl --cacert or a trust store.
func (ca *LocalCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.derCert})
}

// issueCert returns a cached leaf for host, re-issuing when it is unseen or
// near expiry.
func (ca *LocalCA) issueCert(host string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if c, ok := ca.cache[host]; ok && time.Now().Before(c.notAfter.Add(-leafRenewMargin)) {
		return c.cert, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	notAfter := time.Now().Add(leafLifetime)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der, ca.derCert}, // CA appended so clients can verify the chain
		PrivateKey:  key,
	}
	ca.cache[host] = cachedLeaf{cert: cert, notAfter: notAfter}
	return cert, nil
}
