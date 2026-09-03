package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSetsAndAllow(t *testing.T) {
	p := writeTempConfig(t, `{"relay":{"mode":"whitelist","allow":[8080],"exclude":[22]},"https_mode":"whitelist","https_allow":[8443],"https_exclude":[22]}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsRelayExcluded(22) || cfg.IsRelayExcluded(80) {
		t.Fatal("relay exclude set wrong")
	}
	if !cfg.IsHTTPSExcluded(22) || cfg.IsHTTPSExcluded(80) {
		t.Fatal("https exclude set wrong")
	}
	if !cfg.IsExcluded(22) || cfg.IsExcluded(80) {
		t.Fatal("excluded union wrong")
	}
	if !cfg.IsRelayAllowed(8080) || cfg.IsRelayAllowed(9090) {
		t.Fatal("relay whitelist wrong")
	}
	if !cfg.IsHTTPSAllowed(8443) || cfg.IsHTTPSAllowed(9443) {
		t.Fatal("https whitelist wrong")
	}
}

func TestAllowAutoMode(t *testing.T) {
	p := writeTempConfig(t, `{"relay":{"mode":"auto"},"https_mode":"auto"}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsRelayAllowed(8080) || !cfg.IsHTTPSAllowed(8443) {
		t.Fatal("auto empty allow should permit all")
	}
}

func TestDefaultConfigTextMatchesDenyList(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gen.json")
	if err := os.WriteFile(p, []byte(DefaultConfigText()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(p)
	if err != nil {
		t.Fatalf("generated template must parse: %v", err)
	}
	// Template-embedded excludes must equal the built-in deny list exactly;
	// union with defaults must be a no-op (no drift between file and runtime).
	if len(cfg.Relay.Exclude) != len(DefaultExcludePorts) {
		t.Fatalf("template relay.exclude len %d != deny list %d", len(cfg.Relay.Exclude), len(DefaultExcludePorts))
	}
	for _, port := range DefaultExcludePorts {
		if !cfg.IsRelayExcluded(port) || !cfg.IsHTTPSExcluded(port) {
			t.Fatalf("deny-list port %d missing from generated template", port)
		}
	}
}

func TestConfigExampleMatchesDenyList(t *testing.T) {
	examplePath, err := filepath.Abs(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(examplePath); err != nil {
		t.Skip("config.example.json not found from test cwd")
	}
	cfg, err := LoadConfigFile(examplePath)
	if err != nil {
		t.Fatalf("config.example.json must parse cleanly: %v", err)
	}
	if len(cfg.Relay.Exclude) != len(DefaultExcludePorts) {
		t.Fatalf("config.example.json relay.exclude len %d != deny list %d", len(cfg.Relay.Exclude), len(DefaultExcludePorts))
	}
	for _, port := range DefaultExcludePorts {
		if !cfg.IsRelayExcluded(port) || !cfg.IsHTTPSExcluded(port) {
			t.Fatalf("deny-list port %d missing from config.example.json", port)
		}
	}
}

func TestUntrustedCWD(t *testing.T) {
	for _, d := range []string{"/tmp", "/tmp/evil", "/var/tmp", "/private/tmp/x", "/dev/shm", "/private/var/tmp"} {
		if !untrustedCWD(d) {
			t.Errorf("expected untrusted: %s", d)
		}
	}
	for _, d := range []string{"/", "/etc/nasconnplus", "/home/u", "/tmpfoo", "/vartmp", "/private/tmpx"} {
		if untrustedCWD(d) {
			t.Errorf("false positive: %s", d)
		}
	}
}

func TestGracePollsClamped(t *testing.T) {
	p := writeTempConfig(t, `{"grace_polls": 1000000}`)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GracePolls != 120 {
		t.Fatalf("expected GracePolls clamped to 120, got %d", cfg.GracePolls)
	}
}

func TestTraversalPathsRejected(t *testing.T) {
	for _, content := range []string{
		`{"socket_path": "/run/../evil.sock"}`,
		`{"cert_config_path": "/etc/../evil.json"}`,
		`{"selfsigned_dir": "/etc/nasconnplus/../../tmp"}`,
		`{"acme": {"cache_dir": "/var/../tmp/x"}}`,
	} {
		p := writeTempConfig(t, content)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("expected traversal rejection for %s", content)
		}
	}
}

func TestEnsureAndLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "config.json")
	got, err := EnsureDefaultConfig(p)
	if err != nil || got == "" {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFile(p)
	if err != nil || cfg == nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
	var nilCfg *Config
	if !nilCfg.IsRelayAllowed(80) || !nilCfg.IsHTTPSAllowed(80) || nilCfg.IsExcluded(80) {
		t.Fatal("nil config defaults wrong")
	}
	hand := &Config{Relay: RelayCfg{Exclude: []int{22}}, HTTPSExclude: []int{53}}
	if !hand.IsRelayExcluded(22) || !hand.IsHTTPSExcluded(53) {
		t.Fatal("hand-built fallback wrong")
	}
}
