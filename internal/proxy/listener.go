package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"syscall"
	"time"
)

type ListenerMetrics struct {
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	Port       int       `json:"port"`
	Backend    int       `json:"backend"`
	ActiveConn int64     `json:"active_conn"`
	TotalConn  uint64    `json:"total_conn"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	StartedAt  time.Time `json:"started_at"`
}

type listenerState struct {
	kind       string // "https" | "relay"
	name       string
	port       int
	backend    int
	ln         net.Listener
	httpServer *http.Server
	conflict   bool
	stop       chan struct{}

	// Lock-free performance metrics
	activeConn atomic.Int64
	totalConn  atomic.Uint64
	bytesIn    atomic.Uint64
	bytesOut   atomic.Uint64
	startedAt  time.Time
}

func (st *listenerState) Metrics() ListenerMetrics {
	return ListenerMetrics{
		Kind:       st.kind,
		Name:       st.name,
		Port:       st.port,
		Backend:    st.backend,
		ActiveConn: st.activeConn.Load(),
		TotalConn:  st.totalConn.Load(),
		BytesIn:    st.bytesIn.Load(),
		BytesOut:   st.bytesOut.Load(),
		StartedAt:  st.startedAt,
	}
}

type want struct {
	kind    string
	name    string
	port    int
	backend int
	tls     bool
}

// listenV6Only creates a TCP listener bound specifically to IPv6 wildcard [::] with IPV6_V6ONLY=1.
// This ensures the relay socket does not also claim 0.0.0.0:* on hosts with
// net.ipv6.bindv6only=0, avoiding spurious EADDRINUSE with HTTPS dual-stack
// listeners and keeping relay/CAD distinct at the OS level.
func listenV6Only(port int) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
			})
			return serr
		},
	}
	return lc.Listen(context.Background(), "tcp6", fmt.Sprintf("[::]:%d", port))
}

func (s *Service) tryListen(w want) *listenerState {
	st := &listenerState{
		kind:      w.kind,
		name:      w.name,
		port:      w.port,
		backend:   w.backend,
		stop:      make(chan struct{}),
		startedAt: time.Now(),
	}

	var ln net.Listener
	var err error

	if w.kind == "https" {
		ln, err = net.Listen("tcp", fmt.Sprintf(":%d", w.port))
	} else {
		ln, err = listenV6Only(w.port)
	}

	if err != nil {
		return nil
	}

	st.ln = ln
	return st
}
