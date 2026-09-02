package ipc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/proxy"
)

func TestIPC_QueryAndRender(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "test.sock")

	srv, err := StartServer(sockPath, func() StatusReport {
		return StatusReport{
			Version:       "1.0.0",
			UptimeSeconds: 3600,
			Timestamp:     time.Now(),
			Listeners: []proxy.ListenerMetrics{
				{
					Kind:       "https",
					Name:       "1panel",
					Port:       18091,
					Backend:    18090,
					ActiveConn: 2,
					TotalConn:  105,
					BytesIn:    1024 * 1024 * 15,
					BytesOut:   1024 * 1024 * 50,
					StartedAt:  time.Now().Add(-time.Hour),
				},
			},
		}
	})
	if err != nil {
		t.Fatalf("start ipc server: %v", err)
	}
	defer srv.Close()

	report, err := QueryStatus(sockPath)
	if err != nil {
		t.Fatalf("query status: %v", err)
	}

	if report.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", report.Version)
	}
	if len(report.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(report.Listeners))
	}

	output := RenderStatus(report)
	if !strings.Contains(output, "1panel") {
		t.Errorf("expected output to contain '1panel', got:\n%s", output)
	}
	if !strings.Contains(output, "18091") {
		t.Errorf("expected output to contain port '18091', got:\n%s", output)
	}
	if !strings.Contains(output, "1h") {
		t.Errorf("expected output to contain uptime, got:\n%s", output)
	}
}

func TestIPC_SanitizeString(t *testing.T) {
	evil := "\x1b[31;1mDanger\x1b[0m\x00\x07\tTab"
	cleaned := sanitizeString(evil)

	if strings.Contains(cleaned, "\x1b") {
		t.Errorf("ANSI escape sequences were not stripped: %q", cleaned)
	}
	if strings.Contains(cleaned, "\x00") || strings.Contains(cleaned, "\x07") {
		t.Errorf("Control characters were not stripped: %q", cleaned)
	}
}

func TestIPC_SocketPermissions(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "perm.sock")

	srv, err := StartServer(sockPath, func() StatusReport {
		return StatusReport{Version: "test"}
	})
	if err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer srv.Close()

	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}

	// Perm should be 0600 (owner read/write only)
	perm := fi.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("Expected socket permissions 0600, got %04o (M2 regression)", perm)
	}
}

func TestIPC_CloseIdempotent(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "idempotent.sock")

	srv, err := StartServer(sockPath, func() StatusReport {
		return StatusReport{}
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Multiple calls to Close should not panic
	if err := srv.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}

func TestIPC_DefaultSocketPath(t *testing.T) {
	p := DefaultSocketPath()
	if p == "" {
		t.Error("expected non-empty socket path")
	}
}
