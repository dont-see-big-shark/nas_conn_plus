package cert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertManager_SelfSigned(t *testing.T) {
	tempDir := t.TempDir()

	cm := NewManager("", "test.example.com", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("expected Refresh to succeed with self-signed, got: %v", err)
	}

	cur := cm.Current()
	if cur == nil {
		t.Fatal("expected loaded certificate to be non-nil")
	}

	crtPath := filepath.Join(tempDir, "selfsigned.crt")
	keyPath := filepath.Join(tempDir, "selfsigned.key")

	if _, err := os.Stat(crtPath); err != nil {
		t.Errorf("expected selfsigned.crt to exist, got: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected selfsigned.key to exist, got: %v", err)
	}

	// Second refresh should load the existing cert without errors
	if err := cm.Refresh(); err != nil {
		t.Fatalf("expected second Refresh to reload existing cert, got: %v", err)
	}
}
