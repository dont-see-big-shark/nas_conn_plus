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

