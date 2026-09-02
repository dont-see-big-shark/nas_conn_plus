package ipc

import (
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
