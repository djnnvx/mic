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

// LocalCA is a self-signed CA used to issue per-host certificates for
// MitM TLS interception in client-front mode.
type LocalCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	derCert []byte // raw DER of CA cert, appended as chain in issued certs

	mu    sync.Mutex
	cache map[string]tls.Certificate
}

// GenerateCA creates a fresh in-memory self-signed CA.
func GenerateCA() (*LocalCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return buildCA(key)
}

// LoadOrGenerateCA loads the CA from certPath + keyPath. If the files do not
// exist, it generates a new CA and writes it to those paths. Pass empty strings
// to get an ephemeral in-memory CA.
func LoadOrGenerateCA(certPath, keyPath string) (*LocalCA, error) {
	if certPath == "" || keyPath == "" {
		return GenerateCA()
	}

	ca, err := loadCA(certPath, keyPath)
	if err == nil {
		return ca, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading CA: %w", err)
	}

	// Files don't exist — generate a new CA and persist it.
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
		cache:   make(map[string]tls.Certificate),
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
		cache:   make(map[string]tls.Certificate),
	}, nil
}

// Save writes the CA certificate and private key to PEM files.
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
	kf, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer kf.Close()
	return pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
}

// CertPEM returns the CA certificate as a PEM block, ready to be imported
// into a trust store (e.g. curl --cacert, system store).
func (ca *LocalCA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.derCert})
}

// issueCert generates (and caches) a leaf certificate for host, signed by the CA.
func (ca *LocalCA) issueCert(host string) (tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if c, ok := ca.cache[host]; ok {
		return c, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
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
		// Include the CA cert so clients that load the CA can verify the chain.
		Certificate: [][]byte{der, ca.derCert},
		PrivateKey:  key,
	}
	ca.cache[host] = cert
	return cert, nil
}
