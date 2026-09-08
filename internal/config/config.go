package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultConfigPath = "/etc/nasconnplus/config.json"
	LocalConfigPath   = "./config.json"
)

// DefaultExcludePorts contains common management, database, and infrastructure ports
// that should not be automatically exposed or proxied without explicit intent.
var DefaultExcludePorts = []int{
	22,    // SSH
	23,    // Telnet
	53,    // DNS
	111,   // rpcbind
	135,   // MS RPC
	137,   // NetBIOS Name Service
	138,   // NetBIOS Datagram
	139,   // NetBIOS Session
	445,   // SMB
	2049,  // NFS
	2375,  // Docker API (plain)
	2376,  // Docker API (TLS)
	3306,  // MySQL / MariaDB
	3389,  // RDP
	5432,  // PostgreSQL
	6379,  // Redis
	9200,  // Elasticsearch
	11211, // Memcached
	27017, // MongoDB
}

type HTTPSPort struct {
	Name  string `json:"name"`
	HTTP  int    `json:"http"`
	HTTPS int    `json:"https"`
}

type RelayCfg struct {
	Auto     bool   `json:"auto"`
	Mode     string `json:"mode"` // "auto" (default) or "whitelist"
	ZeroCopy *bool  `json:"zero_copy"`
	Exclude  []int  `json:"exclude"`
	Allow    []int  `json:"allow"`
}

// IsZeroCopy reports whether Linux kernel splice(2) zero-copy relaying is enabled.
// Defaults to true when unspecified.
func (r RelayCfg) IsZeroCopy() bool {
	if r.ZeroCopy == nil {
		return true
	}
	return *r.ZeroCopy
}

type ACMEConfig struct {
	Enabled  bool   `json:"enabled"`
	Domain   string `json:"domain"`
	Email    string `json:"email"`
	CacheDir string `json:"cache_dir"`
}

type HSTSConfig struct {
	Enabled           bool `json:"enabled"`
	MaxAge            int  `json:"max_age"`
	IncludeSubdomains bool `json:"include_subdomains"`
}

type Config struct {
	PollSeconds             int         `json:"poll_seconds"`
	GracePolls              int         `json:"grace_polls"`
	CertConfigPath          string      `json:"cert_config_path"`
	CertHost                string      `json:"cert_host"`
	FallbackSelf            *bool       `json:"fallback_selfsigned"`
	AutoTrustLocalCA        *bool       `json:"auto_trust_local_ca"`
	SelfDir                 string      `json:"selfsigned_dir"`
	IdleSeconds             int         `json:"idle_seconds"`
	ACME                    ACMEConfig  `json:"acme"`
	HSTS                    HSTSConfig  `json:"hsts"`
	HTTPSAuto               *bool       `json:"https_auto"`    // Default: true (Zero-config auto HTTP discovery & +1 upgrade)
	HTTPSMode               string      `json:"https_mode"`    // "auto" (default) or "whitelist"
	HTTPSOffset             int         `json:"https_offset"`  // Default: 1 (e.g. 8080 -> 8081)
	HTTPSExclude            []int       `json:"https_exclude"` // Ports excluded from auto HTTPS upgrade
	HTTPSAllow              []int       `json:"https_allow"`   // Optional whitelist for auto HTTPS
	HTTPS                   []HTTPSPort `json:"https"`         // Explicit custom rules (optional overrides)
	Relay                   RelayCfg    `json:"relay"`
	MaxConnsPerListener     int         `json:"max_conns_per_listener"`
	SocketPath                   string      `json:"socket_path"`
	OverrideDefaultExcludes      bool        `json:"override_default_excludes"`
	ResponseHeaderTimeoutSeconds int         `json:"response_header_timeout_seconds"` // Default: 300 (seconds)

	relayExcludeSet map[int]struct{} `json:"-"`
	httpsExcludeSet map[int]struct{} `json:"-"`
	relayAllowSet   map[int]struct{} `json:"-"`
	httpsAllowSet   map[int]struct{} `json:"-"`
}

func buildSet(list []int) map[int]struct{} {
	s := make(map[int]struct{}, len(list))
	for _, v := range list {
		s[v] = struct{}{}
	}
	return s
}

// IsRelayExcluded O(1) precomputed lookup with slice fallback for hand-built configs.
func (c *Config) IsRelayExcluded(port int) bool {
	if c == nil {
		return false
	}
	if c.relayExcludeSet != nil {
		_, ok := c.relayExcludeSet[port]
		return ok
	}
	for _, v := range c.Relay.Exclude {
		if v == port {
			return true
		}
	}
	return false
}

// IsHTTPSExcluded O(1) precomputed lookup with slice fallback for hand-built configs.
func (c *Config) IsHTTPSExcluded(port int) bool {
	if c == nil {
		return false
	}
	if c.httpsExcludeSet != nil {
		_, ok := c.httpsExcludeSet[port]
		return ok
	}
	for _, v := range c.HTTPSExclude {
		if v == port {
			return true
		}
	}
	return false
}

// IsExcluded reports true if port is excluded from either relay or https auto.
func (c *Config) IsExcluded(port int) bool {
	return c.IsRelayExcluded(port) || c.IsHTTPSExcluded(port)
}

func (c *Config) inRelayAllow(port int) bool {
	if c.relayAllowSet != nil {
		_, ok := c.relayAllowSet[port]
		return ok
	}
	for _, v := range c.Relay.Allow {
		if v == port {
			return true
		}
	}
	return false
}

func (c *Config) inHTTPSAllow(port int) bool {
	if c.httpsAllowSet != nil {
		_, ok := c.httpsAllowSet[port]
		return ok
	}
	for _, v := range c.HTTPSAllow {
		if v == port {
			return true
		}
	}
	return false
}

// IsRelayAllowed O(1) allow check with slice fallback for hand-built configs.
func (c *Config) IsRelayAllowed(port int) bool {
	if c == nil {
		return true
	}
	if c.Relay.Mode == "whitelist" {
		if len(c.Relay.Allow) == 0 {
			return false
		}
		return c.inRelayAllow(port)
	}
	if len(c.Relay.Allow) > 0 {
		return c.inRelayAllow(port)
	}
	return true
}

// IsHTTPSAllowed O(1) allow check with slice fallback for hand-built configs.
func (c *Config) IsHTTPSAllowed(port int) bool {
	if c == nil {
		return true
	}
	if c.HTTPSMode == "whitelist" {
		if len(c.HTTPSAllow) == 0 {
			return false
		}
		return c.inHTTPSAllow(port)
	}
	if len(c.HTTPSAllow) > 0 {
		return c.inHTTPSAllow(port)
	}
	return true
}

func unionPorts(base []int, extra []int) []int {
	seen := make(map[int]bool, len(base)+len(extra))
	var res []int
	for _, p := range base {
		if !seen[p] {
			seen[p] = true
			res = append(res, p)
		}
	}
	for _, p := range extra {
		if !seen[p] {
			seen[p] = true
			res = append(res, p)
		}
	}
	return res
}

// DefaultConfigText provides a streamlined JSON template for first-time setup.
// The embedded exclude list is generated from DefaultExcludePorts so the file
// on disk never drifts from the effective built-in deny list (P1 fix: the old
// static "[22, 53]" misled readers while 19 ports were enforced at runtime).
func DefaultConfigText() string {
	excl, _ := json.Marshal(DefaultExcludePorts)
	return fmt.Sprintf(`{
  "_comment": "relay.exclude / https_exclude omitted => built-in %d-port deny list applies; set override_default_excludes:true to replace it entirely",
  "cert_host": "nas.local",
  "relay": {
    "auto": true,
    "zero_copy": true,
    "exclude": %s
  },
  "https_auto": true,
  "https_exclude": %s
}
`, len(DefaultExcludePorts), excl, excl)
}

// untrustedCWD reports whether dir is a world-writable rendezvous such as /tmp
// where a local user could have planted a ./config.json to hijack a daemon
// started via `sudo nasconnplus` (L4). Matches exact dirs and their children
// (so /tmpfoo is NOT flagged, /tmp/evil IS), and covers the macOS symlinked
// physical paths (/private/tmp, /private/var/tmp) plus /dev/shm.
func untrustedCWD(dir string) bool {
	clean := filepath.Clean(dir)
	bases := []string{"/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm"}
	for _, b := range bases {
		if clean == b || strings.HasPrefix(clean, b+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ResolveConfigPath locates an existing config file or returns the default target path.
// It avoids loading relative ./config.json from world-writable directories such as /tmp for security.
func ResolveConfigPath(specified string) string {
	if specified != "" {
		return filepath.Clean(specified)
	}
	if _, err := os.Stat(DefaultConfigPath); err == nil {
		return DefaultConfigPath
	}
	if _, err := os.Stat(LocalConfigPath); err == nil {
		wd, err := os.Getwd()
		if err == nil && !untrustedCWD(wd) {
			return LocalConfigPath
		}
	}
	return DefaultConfigPath
}

// EnsureDefaultConfig creates parent dirs and a default config file if missing.
// It is the only function with write side effects; LoadConfigFile is pure.
func EnsureDefaultConfig(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("invalid config path %q", path)
	}
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", fmt.Errorf("failed to create config directory %q: %w", dir, err)
		}
	}
	if _, err := os.Stat(cleanPath); err == nil {
		return cleanPath, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	defText := DefaultConfigText()
	if err := os.WriteFile(cleanPath, []byte(defText), 0o600); err != nil {
		return "", fmt.Errorf("failed to create default config %q: %w", cleanPath, err)
	}
	return cleanPath, nil
}

// LoadConfigFile reads and parses config without creating files (no side effects).
func LoadConfigFile(path string) (*Config, error) {
	if path == "" || path == "." {
		return nil, fmt.Errorf("invalid config path %q", path)
	}
	cleanPath := filepath.Clean(path)
	if _, err := os.Stat(cleanPath); err != nil {
		return nil, err
	}
	return LoadConfig(cleanPath)
}

// LoadConfig reads and parses the configuration file. If it doesn't exist, it creates a default one.
func LoadConfig(path string) (*Config, error) {
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("invalid config path %q: contains \"..\" traversal", path)
	}
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid config path %q: contains \"..\" traversal", path)
	}
	if cleanPath == "." || cleanPath == "" {
		return nil, fmt.Errorf("invalid config path %q", path)
	}

	// #nosec G304 - cleanPath is validated against traversal and cleaned
	b, err := os.ReadFile(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			dir := filepath.Dir(cleanPath)
			if dir != "" && dir != "." {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					return nil, fmt.Errorf("failed to create config directory %q: %w", dir, err)
				}
			}
			defText := DefaultConfigText()
			if err := os.WriteFile(cleanPath, []byte(defText), 0o600); err != nil {
				return nil, fmt.Errorf("failed to create default config %q: %w", cleanPath, err)
			}
			b = []byte(defText)
		} else {
			return nil, err
		}
	}

	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %q: %w", cleanPath, err)
	}

	if cfg.PollSeconds <= 0 {
		cfg.PollSeconds = 5
	}
	if cfg.GracePolls <= 0 {
		cfg.GracePolls = 2
	}
	// P1: an unbounded GracePolls disables listener GC forever (stale
	// listeners pin ports/fds). 120 polls is already generous (up to hours).
	if cfg.GracePolls > 120 {
		cfg.GracePolls = 120
	}
	if cfg.CertHost == "" {
		cfg.CertHost = "nas.local"
	}
	if cfg.SelfDir == "" {
		cfg.SelfDir = "/etc/nasconnplus/tls"
	}
	if cfg.ACME.CacheDir == "" {
		cfg.ACME.CacheDir = "/etc/nasconnplus/acme_cache"
	}
	if cfg.IdleSeconds <= 0 {
		cfg.IdleSeconds = 900
	}
	if cfg.FallbackSelf == nil {
		trueVal := true
		cfg.FallbackSelf = &trueVal
	}
	if cfg.AutoTrustLocalCA == nil {
		trueVal := true
		cfg.AutoTrustLocalCA = &trueVal
	}
	if cfg.HTTPSAuto == nil {
		trueVal := true
		cfg.HTTPSAuto = &trueVal
	}
	if cfg.Relay.ZeroCopy == nil {
		trueVal := true
		cfg.Relay.ZeroCopy = &trueVal
	}
	if cfg.HTTPSOffset <= 0 {
		cfg.HTTPSOffset = 1
	}
	if cfg.MaxConnsPerListener <= 0 {
		cfg.MaxConnsPerListener = 2048
	}
	if cfg.MaxConnsPerListener > 4096 {
		cfg.MaxConnsPerListener = 4096
	}
	if cfg.PollSeconds < 1 {
		cfg.PollSeconds = 1
	} else if cfg.PollSeconds > 3600 {
		cfg.PollSeconds = 3600
	}
	if cfg.IdleSeconds < 60 {
		cfg.IdleSeconds = 60
	} else if cfg.IdleSeconds > 86400 {
		cfg.IdleSeconds = 86400
	}
	if cfg.HTTPSOffset < 1 {
		cfg.HTTPSOffset = 1
	} else if cfg.HTTPSOffset > 100 {
		cfg.HTTPSOffset = 100
	}
	if cfg.HSTS.Enabled && cfg.HSTS.MaxAge <= 0 {
		cfg.HSTS.MaxAge = 31536000
	}

	if !cfg.OverrideDefaultExcludes {
		cfg.Relay.Exclude = unionPorts(DefaultExcludePorts, cfg.Relay.Exclude)
		cfg.HTTPSExclude = unionPorts(DefaultExcludePorts, cfg.HTTPSExclude)
	} else {
		if cfg.Relay.Exclude == nil {
			cfg.Relay.Exclude = []int{}
		}
		if cfg.HTTPSExclude == nil {
			cfg.HTTPSExclude = []int{}
		}
	}

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
	for _, e := range cfg.HTTPSExclude {
		if e <= 0 || e > 65535 {
			return nil, fmt.Errorf("invalid https exclude port: %d (must be 1-65535)", e)
		}
	}
	for _, a := range cfg.Relay.Allow {
		if a <= 0 || a > 65535 {
			return nil, fmt.Errorf("invalid relay allow port: %d (must be 1-65535)", a)
		}
	}
	for _, a := range cfg.HTTPSAllow {
		if a <= 0 || a > 65535 {
			return nil, fmt.Errorf("invalid https allow port: %d (must be 1-65535)", a)
		}
	}
	if cfg.ACME.Enabled && cfg.ACME.Domain == "" {
		return nil, fmt.Errorf("invalid acme config: enabled requires domain")
	}

	// P1: daemon runs as root and creates/removes files at these locations
	// (socket, cert dirs). Reject ".." to prevent accidental or planted
	// escapes; legitimate values are always plain absolute paths.
	for _, p := range []string{cfg.SocketPath, cfg.CertConfigPath, cfg.SelfDir, cfg.ACME.CacheDir} {
		if strings.Contains(p, "..") {
			return nil, fmt.Errorf("invalid path %q: contains \"..\" traversal", p)
		}
	}

	if cfg.Relay.Mode == "" {
		cfg.Relay.Mode = "auto"
	} else if cfg.Relay.Mode != "auto" && cfg.Relay.Mode != "whitelist" {
		return nil, fmt.Errorf("invalid relay.mode %q: must be 'auto' or 'whitelist'", cfg.Relay.Mode)
	}

	if cfg.HTTPSMode == "" {
		cfg.HTTPSMode = "auto"
	} else if cfg.HTTPSMode != "auto" && cfg.HTTPSMode != "whitelist" {
		return nil, fmt.Errorf("invalid https_mode %q: must be 'auto' or 'whitelist'", cfg.HTTPSMode)
	}

	cfg.relayExcludeSet = buildSet(cfg.Relay.Exclude)
	cfg.httpsExcludeSet = buildSet(cfg.HTTPSExclude)
	cfg.relayAllowSet = buildSet(cfg.Relay.Allow)
	cfg.httpsAllowSet = buildSet(cfg.HTTPSAllow)

	return &cfg, nil
}
