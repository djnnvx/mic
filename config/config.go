package config

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

type Config struct {
	Mode        string  `toml:"mode"`
	Listen      Listen  `toml:"listen"`
	Backend     Backend `toml:"backend"`
	Fingerprint FpConf  `toml:"fingerprint"`
	CA          CAConf  `toml:"ca"`
}

type Listen struct {
	Addr string `toml:"addr"`
}

type Backend struct {
	Addr string `toml:"addr"`
}

type CAConf struct {
	Cert      string          `toml:"cert"`      // upstream CA cert for verifying targets
	Intercept InterceptCAConf `toml:"intercept"` // client-front: local MitM CA
}

type InterceptCAConf struct {
	Cert string `toml:"cert"` // path to local CA cert (created if absent)
	Key  string `toml:"key"`  // path to local CA key  (created if absent)
}

type FpConf struct {
	TLS TLSConf `toml:"tls"`
}

type TLSConf struct {
	JA4         string         `toml:"ja4"`
	Termination TLSTermination `toml:"termination"`
}

type TLSTermination struct {
	Cert string `toml:"cert"`
	Key  string `toml:"key"`
}

// Load reads and parses a TOML config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	return &cfg, nil
}
