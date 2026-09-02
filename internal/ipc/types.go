package ipc

import (
	"time"

	"github.com/jadenjoe/nasconnplus/internal/proxy"
)

const DefaultSocketPath = "/tmp/nasconnplus.sock"

type StatusReport struct {
	Version       string                  `json:"version"`
	UptimeSeconds int64                   `json:"uptime_seconds"`
	Timestamp     time.Time               `json:"timestamp"`
	Listeners     []proxy.ListenerMetrics `json:"listeners"`
}
