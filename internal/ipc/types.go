package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/proxy"
)

// DefaultSocketPath returns the secure Unix domain socket location.
// Preference: XDG_RUNTIME_DIR (per-user 0700) > /run/nasconnplus.sock for root > per-uid isolated dir under TempDir (0700) with 0600 socket.
func DefaultSocketPath() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		dir = filepath.Clean(dir)
		return filepath.Join(dir, "nasconnplus.sock")
	}
	if _, err := os.Stat("/run"); err == nil && os.Getuid() == 0 {
		return "/run/nasconnplus.sock"
	}
	uid := os.Getuid()
	base := filepath.Join(os.TempDir(), fmt.Sprintf("nasconnplus-%d", uid))
	return filepath.Join(base, "nasconnplus.sock")
}

type StatusReport struct {
	Version       string                  `json:"version"`
	UptimeSeconds int64                   `json:"uptime_seconds"`
	Timestamp     time.Time               `json:"timestamp"`
	Listeners     []proxy.ListenerMetrics `json:"listeners"`
}
