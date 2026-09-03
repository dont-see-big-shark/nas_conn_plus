package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
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
	ErrorCount uint64    `json:"error_count"`
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
	errorCount atomic.Uint64
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
		ErrorCount: st.errorCount.Load(),
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

// limitListener wraps a net.Listener to limit concurrent connections.
// P0-1 FIX: acquire is interruptible via done so Shutdown/Close never hangs
// when the semaphore is full (slowloris holding maxConns). Close unblocks all
// waiters with net.ErrClosed, which both acceptRelayLoop and http.Server treat
// as terminal.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, maxConns int) net.Listener {
	if maxConns <= 0 {
		return ln
	}
	return &limitListener{
		Listener: ln,
		sem:      make(chan struct{}, maxConns),
		done:     make(chan struct{}),
	}
}

// acquire reports false when the listener is closed while waiting for a slot.
func (l *limitListener) acquire() bool {
	select {
	case l.sem <- struct{}{}:
		return true
	case <-l.done:
		return false
	}
}
func (l *limitListener) release() { <-l.sem }

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

func (l *limitListener) Accept() (net.Conn, error) {
	if !l.acquire() {
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		l.release()
		// If we were closed while in underlying Accept, normalize to ErrClosed
		// so callers can errors.Is-check instead of string-matching.
		select {
		case <-l.done:
			return nil, net.ErrClosed
		default:
			return nil, err
		}
	}
	return &limitListenerConn{Conn: conn, release: l.release}, nil
}

type limitListenerConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// Unwrap returns the underlying net.Conn (typically *net.TCPConn),
// enabling pure in-kernel splice(2) zero-copy in tcpproxy.
func (c *limitListenerConn) Unwrap() net.Conn {
	return c.Conn
}

// Release releases the concurrency slot on the parent limitListener.
func (c *limitListenerConn) Release() {
	c.once.Do(c.release)
}

// listenV6Only creates a TCP listener bound specifically to IPv6 wildcard [::] with IPV6_V6ONLY=1.
// This ensures the relay socket does not also claim 0.0.0.0:* on hosts with
// net.ipv6.bindv6only=0, avoiding spurious EADDRINUSE with HTTPS dual-stack
// listeners and keeping relay/CAD distinct at the OS level.
func listenV6Only(port int) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	return lc.Listen(context.Background(), "tcp6", fmt.Sprintf("[::]:%d", port))
}

func (s *Service) tryListen(w want) (*listenerState, error) {
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

	// P1: surface the real errno. Callers log it so EADDRINUSE (neighbour
	// restart, retry helps) is distinguishable from EACCES (low port without
	// CAP_NET_BIND_SERVICE, retry won't help) and EAFNOSUPPORT.
	if err != nil {
		return nil, fmt.Errorf("listen %s %s: %w", w.kind, s.addrOf(w.kind, w.port), err)
	}

	maxConns := s.cfg.MaxConnsPerListener
	if maxConns <= 0 {
		maxConns = 2048
	}
	st.ln = newLimitListener(ln, maxConns)
	return st, nil
}
