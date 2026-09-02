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
}

