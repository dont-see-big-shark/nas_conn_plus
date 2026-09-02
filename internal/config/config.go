package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultConfigPath = "/etc/nasconnplus/config.json"
	LocalConfigPath   = "./config.json"
)

type HTTPSPort struct {
	Name  string `json:"name"`
	HTTP  int    `json:"http"`
	HTTPS int    `json:"https"`
}

type RelayCfg struct {
	Auto    bool  `json:"auto"`
	Exclude []int `json:"exclude"`
}

type ACMEConfig struct {
	Enabled  bool   `json:"enabled"`
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CacheDir string `json:"cache_dir"`
}

type Config struct {
	PollSeconds    int         `json:"poll_seconds"`
	GracePolls     int         `json:"grace_polls"`
	CertConfigPath string      `json:"cert_config_path"`
	CertHost       string      `json:"cert_host"`
	FallbackSelf   *bool       `json:"fallback_selfsigned"`
	SelfDir        string      `json:"selfsigned_dir"`
	IdleSeconds    int         `json:"idle_seconds"`
	ACME           ACMEConfig  `json:"acme"`
	HTTPSAuto      *bool       `json:"https_auto"`    // Default: true (Zero-config auto HTTP discovery & +1 upgrade)
	HTTPSOffset    int         `json:"https_offset"`  // Default: 1 (e.g. 8080 -> 8081)
	HTTPSExclude   []int       `json:"https_exclude"` // Ports excluded from auto HTTPS upgrade
	HTTPS          []HTTPSPort `json:"https"`          // Explicit custom rules (optional overrides)
	Relay          RelayCfg    `json:"relay"`
}

// DefaultConfigText provides a streamlined JSON template for first-time setup
func DefaultConfigText() string {
	return `{
  "cert_host": "nas.local",
  "relay": {
    "auto": true,
    "exclude": [22, 53]
  },
  "https_auto": true,
  "https_exclude": [22, 53]
}
`
}

// ResolveConfigPath locates an existing config file or returns the default target path
func ResolveConfigPath(specified string) string {
	if specified != "" {
		return specified
	}
	if _, err := os.Stat(LocalConfigPath); err == nil {
		return LocalConfigPath
	}
	return DefaultConfigPath
}

// LoadConfig reads and parses the configuration file. If it doesn't exist, it creates a default one.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			dir := filepath.Dir(path)
			if dir != "." && dir != "" {
				if e := os.MkdirAll(dir, 0o755); e != nil {
					return nil, fmt.Errorf("failed to create config directory %s: %w", dir, e)
				}
			}
			if e := os.WriteFile(path, []byte(DefaultConfigText()), 0o644); e != nil {
				return nil, fmt.Errorf("failed to write default config to %s: %w", path, e)
			}
			b = []byte(DefaultConfigText())
		} else {
			return nil, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	// Apply defaults
	if cfg.PollSeconds <= 0 {
		cfg.PollSeconds = 5
	}
	if cfg.GracePolls <= 0 {
		cfg.GracePolls = 2
	}
	if cfg.CertHost == "" {
		cfg.CertHost = "nas.local"
	}
	if cfg.SelfDir == "" {
		cfg.SelfDir = "/etc/nasconnplus/tls"
	}
	if cfg.FallbackSelf == nil {
		trueVal := true
		cfg.FallbackSelf = &trueVal
	}
	if cfg.IdleSeconds <= 0 {
		cfg.IdleSeconds = 900
	}
	if cfg.ACME.CacheDir == "" {
		cfg.ACME.CacheDir = "/etc/nasconnplus/acme_cache"
	}

	// HTTPS Auto Discovery defaults
	if cfg.HTTPSAuto == nil {
		trueVal := true
		cfg.HTTPSAuto = &trueVal
	}
	if cfg.HTTPSOffset <= 0 {
		cfg.HTTPSOffset = 1
	}

	// Validate mappings
	seenHTTPS := map[int]string{}
	for _, p := range cfg.HTTPS {
		if p.HTTP <= 0 || p.HTTP > 65535 || p.HTTPS <= 0 || p.HTTPS > 65535 || p.HTTP == p.HTTPS {
			return nil, fmt.Errorf("invalid https mapping: %+v (port must be 1-65535 and http != https)", p)
		}
		if n, dup := seenHTTPS[p.HTTPS]; dup {
			return nil, fmt.Errorf("duplicate https port %d (%s and %s)", p.HTTPS, n, p.Name)
		}
		seenHTTPS[p.HTTPS] = p.Name
	}

	for _, e := range cfg.Relay.Exclude {
		if e <= 0 || e > 65535 {
			return nil, fmt.Errorf("invalid relay exclude port: %d (must be 1-65535)", e)
		}
	}

	return &cfg, nil
}
