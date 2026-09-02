package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/proxy"
)

// DefaultSocketPath returns the secure Unix domain socket location.
// It prioritizes /run/nasconnplus.sock when running as root, or isolates per-user under TempDir.
func DefaultSocketPath() string {
	if _, err := os.Stat("/run"); err == nil && os.Getuid() == 0 {
		return "/run/nasconnplus.sock"
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("nasconnplus-%d.sock", os.Getuid()))
}

type StatusReport struct {
	Version       string                  `json:"version"`
	UptimeSeconds int64                   `json:"uptime_seconds"`
	Timestamp     time.Time               `json:"timestamp"`
	Listeners     []proxy.ListenerMetrics `json:"listeners"`
}
