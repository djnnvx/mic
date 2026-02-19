package config_test

import (
	"os"
	"testing"

	"github.com/djnnvx/mic/config"
)

const validTOML = `
mode = "client-front"

[listen]
addr = ":8080"

[backend]
addr = "127.0.0.1:443"

[fingerprint]
[fingerprint.tls]
ja4 = "t13d1516h2_8daaf6152771_b0da82dd1658"

[fingerprint.tls.termination]
cert = "/path/to/cert.pem"
key  = "/path/to/key.pem"

[ca]
cert = "/path/to/ca.pem"
`

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "mic-config-*.toml")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}
	return f.Name()
}

func TestLoad_Valid(t *testing.T) {
	path := writeTempFile(t, validTOML)
	defer os.Remove(path)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Mode != "client-front" {
		t.Errorf("Mode = %q; want %q", cfg.Mode, "client-front")
	}
	if cfg.Listen.Addr != ":8080" {
		t.Errorf("Listen.Addr = %q; want %q", cfg.Listen.Addr, ":8080")
	}
	if cfg.Backend.Addr != "127.0.0.1:443" {
		t.Errorf("Backend.Addr = %q; want %q", cfg.Backend.Addr, "127.0.0.1:443")
	}
	if cfg.Fingerprint.TLS.JA4 != "t13d1516h2_8daaf6152771_b0da82dd1658" {
		t.Errorf("Fingerprint.TLS.JA4 = %q; want %q",
			cfg.Fingerprint.TLS.JA4, "t13d1516h2_8daaf6152771_b0da82dd1658")
	}
	if cfg.Fingerprint.TLS.Termination.Cert != "/path/to/cert.pem" {
		t.Errorf("Termination.Cert = %q; want %q",
			cfg.Fingerprint.TLS.Termination.Cert, "/path/to/cert.pem")
	}
	if cfg.Fingerprint.TLS.Termination.Key != "/path/to/key.pem" {
		t.Errorf("Termination.Key = %q; want %q",
			cfg.Fingerprint.TLS.Termination.Key, "/path/to/key.pem")
	}
	if cfg.CA.Cert != "/path/to/ca.pem" {
		t.Errorf("CA.Cert = %q; want %q", cfg.CA.Cert, "/path/to/ca.pem")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := config.Load("/nonexistent/path/to/config.toml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	path := writeTempFile(t, "this is not valid = toml [[[")
	defer os.Remove(path)

	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML, got nil")
	}
}
