package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_DefaultAndCreate(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "config.json")

	cfg, err := LoadConfig(tempFile)
	if err != nil {
		t.Fatalf("expected no error loading from non-existent file, got: %v", err)
	}

	if cfg.PollSeconds != 5 {
		t.Errorf("expected PollSeconds=5, got %d", cfg.PollSeconds)
	}

	if cfg.CertHost != "nas.local" {
		t.Errorf("expected CertHost='nas.local', got %s", cfg.CertHost)
	}

	// Verify file was written to disk
	if _, err := os.Stat(tempFile); err != nil {
		t.Errorf("expected config file to be created on disk, got: %v", err)
	}
}

func TestLoadConfig_Validation(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "invalid.json")

	// Invalid HTTP port (same as HTTPS)
	invalidJSON := `{
		"https": [{"name": "bad", "http": 8080, "https": 8080}]
	}`
	if err := os.WriteFile(tempFile, []byte(invalidJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(tempFile)
	if err == nil {
		t.Fatal("expected error for duplicate http/https port, got nil")
	}
}

func TestLoadConfig_MinimalStreamlined(t *testing.T) {
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "minimal.json")

	minimalJSON := `{
		"cert_host": "nas.local",
		"relay": {
			"auto": true,
			"exclude": [22, 53]
		},
		"https_auto": true,
		"https_exclude": [22, 53]
	}`
	if err := os.WriteFile(tempFile, []byte(minimalJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tempFile)
	if err != nil {
		t.Fatalf("unexpected error loading minimal config: %v", err)
	}

	if cfg.PollSeconds != 5 {
		t.Errorf("expected default PollSeconds=5, got %d", cfg.PollSeconds)
	}
	if cfg.GracePolls != 2 {
		t.Errorf("expected default GracePolls=2, got %d", cfg.GracePolls)
	}
	if cfg.IdleSeconds != 900 {
		t.Errorf("expected default IdleSeconds=900, got %d", cfg.IdleSeconds)
	}
	if cfg.FallbackSelf == nil || !*cfg.FallbackSelf {
		t.Errorf("expected default FallbackSelf=true")
	}
	if cfg.SelfDir != "/etc/nasconnplus/tls" {
		t.Errorf("expected default SelfDir='/etc/nasconnplus/tls', got %s", cfg.SelfDir)
	}
	if cfg.HTTPSAuto == nil || !*cfg.HTTPSAuto {
		t.Errorf("expected HTTPSAuto=true")
	}
	if cfg.HTTPSOffset != 1 {
		t.Errorf("expected default HTTPSOffset=1, got %d", cfg.HTTPSOffset)
	}
}

func TestResolveConfigPath(t *testing.T) {
	// 1. Specified path explicitly
	specified := "/custom/path/config.json"
	if got := ResolveConfigPath(specified); got != specified {
		t.Errorf("expected %s, got %s", specified, got)
	}

	// 2. Empty specified path
	got := ResolveConfigPath("")
	if got == "" {
		t.Error("expected non-empty resolved path")
	}
}

func TestLoadConfig_ErrorsAndValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Malformed JSON
	badJSONFile := filepath.Join(tempDir, "bad.json")
	_ = os.WriteFile(badJSONFile, []byte("{broken json..."), 0o644)
	if _, err := LoadConfig(badJSONFile); err == nil {
		t.Error("expected error for malformed json")
	}

	// Invalid relay exclude
	badExcludeFile := filepath.Join(tempDir, "bad_exclude.json")
	_ = os.WriteFile(badExcludeFile, []byte(`{"relay": {"exclude": [99999]}}`), 0o644)
	if _, err := LoadConfig(badExcludeFile); err == nil {
		t.Error("expected error for exclude port > 65535")
	}

	// Duplicate HTTPS ports
	dupFile := filepath.Join(tempDir, "dup_https.json")
	_ = os.WriteFile(dupFile, []byte(`{
		"https": [
			{"name": "app1", "http": 8080, "https": 8443},
			{"name": "app2", "http": 8081, "https": 8443}
		]
	}`), 0o644)
	if _, err := LoadConfig(dupFile); err == nil {
		t.Error("expected error for duplicate https port")
	}

	// Invalid HTTP port bounds
	invalidPortFile := filepath.Join(tempDir, "invalid_port.json")
	_ = os.WriteFile(invalidPortFile, []byte(`{
		"https": [
			{"name": "app1", "http": 0, "https": 8443}
		]
	}`), 0o644)
	if _, err := LoadConfig(invalidPortFile); err == nil {
		t.Error("expected error for port 0")
	}

	// Invalid HTTPS exclude
	invalidHTTPSExclude := filepath.Join(tempDir, "invalid_https_exclude.json")
	_ = os.WriteFile(invalidHTTPSExclude, []byte(`{"https_exclude": [70000]}`), 0o644)
	if _, err := LoadConfig(invalidHTTPSExclude); err == nil {
		t.Error("expected error for https_exclude > 65535")
	}

	// Invalid allow port
	invalidAllow := filepath.Join(tempDir, "invalid_allow.json")
	_ = os.WriteFile(invalidAllow, []byte(`{"relay": {"allow": [-1]}}`), 0o644)
	if _, err := LoadConfig(invalidAllow); err == nil {
		t.Error("expected error for relay allow < 0")
	}
	invalidHTTPSAllow := filepath.Join(tempDir, "invalid_https_allow.json")
	_ = os.WriteFile(invalidHTTPSAllow, []byte(`{"https_allow": [0]}`), 0o644)
	if _, err := LoadConfig(invalidHTTPSAllow); err == nil {
		t.Error("expected error for https_allow 0")
	}
}

func TestLoadConfig_UnionAndOverrides(t *testing.T) {
	tempDir := t.TempDir()

	// 1. User config specifies only [8080, 8081] - verify DefaultExcludePorts are union-merged!
	userFile := filepath.Join(tempDir, "user_union.json")
	_ = os.WriteFile(userFile, []byte(`{
		"relay": {
			"auto": true,
			"zero_copy": true,
			"exclude": [8080]
		},
		"https_exclude": [8081]
	}`), 0o644)

	cfg, err := LoadConfig(userFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if !cfg.Relay.IsZeroCopy() {
		t.Error("expected ZeroCopy=true")
	}

	// 8080 and 3306 (MySQL default) must both be present in cfg.Relay.Exclude!
	has8080 := false
	has3306 := false
	for _, p := range cfg.Relay.Exclude {
		if p == 8080 {
			has8080 = true
		}
		if p == 3306 {
			has3306 = true
		}
	}
	if !has8080 || !has3306 {
		t.Errorf("expected union of [8080] and DefaultExcludePorts (3306), got %v", cfg.Relay.Exclude)
	}

	// 2. Test OverrideDefaultExcludes=true
	overrideFile := filepath.Join(tempDir, "user_override.json")
	_ = os.WriteFile(overrideFile, []byte(`{
		"override_default_excludes": true,
		"relay": {
			"exclude": [8080]
		},
		"https_exclude": [8081]
	}`), 0o644)

	cfg2, err := LoadConfig(overrideFile)
	if err != nil {
		t.Fatalf("failed to load override config: %v", err)
	}

	if len(cfg2.Relay.Exclude) != 1 || cfg2.Relay.Exclude[0] != 8080 {
		t.Errorf("expected only [8080] with OverrideDefaultExcludes=true, got %v", cfg2.Relay.Exclude)
	}
}

func TestLoadConfig_AllowAndHSTS(t *testing.T) {
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "allow_hsts.json")
	_ = os.WriteFile(testFile, []byte(`{
		"max_conns_per_listener": 4096,
		"socket_path": "/tmp/custom.sock",
		"relay": {
			"allow": [80, 443]
		},
		"https_allow": [8080],
		"hsts": {
			"enabled": true
		}
	}`), 0o644)

	cfg, err := LoadConfig(testFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.MaxConnsPerListener != 4096 {
		t.Errorf("expected max conns 4096, got %d", cfg.MaxConnsPerListener)
	}
	if cfg.SocketPath != "/tmp/custom.sock" {
		t.Errorf("expected socket path /tmp/custom.sock, got %q", cfg.SocketPath)
	}
	if len(cfg.Relay.Allow) != 2 || cfg.Relay.Allow[0] != 80 {
		t.Errorf("unexpected relay allow: %v", cfg.Relay.Allow)
	}
	if len(cfg.HTTPSAllow) != 1 || cfg.HTTPSAllow[0] != 8080 {
		t.Errorf("unexpected https allow: %v", cfg.HTTPSAllow)
	}
	if !cfg.HSTS.Enabled || cfg.HSTS.MaxAge != 31536000 {
		t.Errorf("expected default HSTS MaxAge 31536000, got %d", cfg.HSTS.MaxAge)
	}
	if cfg.Relay.Mode != "auto" {
		t.Errorf("expected default relay mode 'auto', got %q", cfg.Relay.Mode)
	}
	if cfg.HTTPSMode != "auto" {
		t.Errorf("expected default https mode 'auto', got %q", cfg.HTTPSMode)
	}

	// Test invalid modes
	invalidRelayMode := filepath.Join(tempDir, "invalid_relay_mode.json")
	_ = os.WriteFile(invalidRelayMode, []byte(`{"relay": {"mode": "invalid"}}`), 0o600)
	if _, err := LoadConfig(invalidRelayMode); err == nil {
		t.Error("expected error for invalid relay.mode")
	}

	invalidHTTPSMode := filepath.Join(tempDir, "invalid_https_mode.json")
	_ = os.WriteFile(invalidHTTPSMode, []byte(`{"https_mode": "invalid"}`), 0o600)
	if _, err := LoadConfig(invalidHTTPSMode); err == nil {
		t.Error("expected error for invalid https_mode")
	}

	invalidACME := filepath.Join(tempDir, "invalid_acme.json")
	_ = os.WriteFile(invalidACME, []byte(`{"acme": {"enabled": true}}`), 0o600)
	if _, err := LoadConfig(invalidACME); err == nil {
		t.Error("expected error for enabled ACME without domain")
	}
}

func TestLoadConfig_ZeroCopyDefaults(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Omitted in config => defaults to true
	p1 := filepath.Join(tempDir, "default.json")
	_ = os.WriteFile(p1, []byte(`{"relay": {"auto": true}}`), 0o600)
	c1, err := LoadConfig(p1)
	if err != nil {
		t.Fatal(err)
	}
	if !c1.Relay.IsZeroCopy() {
		t.Errorf("expected omitted zero_copy to default to true")
	}

	// 2. Explicitly false => stays false
	p2 := filepath.Join(tempDir, "false.json")
	_ = os.WriteFile(p2, []byte(`{"relay": {"zero_copy": false}}`), 0o600)
	c2, err := LoadConfig(p2)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Relay.IsZeroCopy() {
		t.Errorf("expected explicit false to be false")
	}

	// 3. Explicitly true => stays true
	p3 := filepath.Join(tempDir, "true.json")
	_ = os.WriteFile(p3, []byte(`{"relay": {"zero_copy": true}}`), 0o600)
	c3, err := LoadConfig(p3)
	if err != nil {
		t.Fatal(err)
	}
	if !c3.Relay.IsZeroCopy() {
		t.Errorf("expected explicit true to be true")
	}
}
