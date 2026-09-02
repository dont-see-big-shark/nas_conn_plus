package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/inetaf/tcpproxy"
	"github.com/jadenjoe/nasconnplus/internal/cert"
	"github.com/jadenjoe/nasconnplus/internal/config"
	"github.com/jadenjoe/nasconnplus/internal/logger"
	"github.com/jadenjoe/nasconnplus/internal/scanner"
)

// Zero-allocation buffer pool for reverse proxy to minimize GC churn
type bytePool struct {
	pool sync.Pool
}

func newBytePool() *bytePool {
	return &bytePool{
		pool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 32*1024)
				return b
			},
		},
	}
}

func (p *bytePool) Get() []byte {
	return p.pool.Get().([]byte)
}

func (p *bytePool) Put(b []byte) {
	p.pool.Put(b)
}

type Service struct {
	cfg        *config.Config
	log        *logger.Logger
	certs      *cert.Manager
	tlsCfg     *tls.Config
	bufferPool *bytePool
	transport  *http.Transport

	mu        sync.Mutex
	listeners map[string]*listenerState // key: kind:port
	missing   map[string]int
}

func key(kind string, port int) string {
	return fmt.Sprintf("%s:%d", kind, port)
}

// NewService initializes the proxy service with optimized transport and buffer pooling
func NewService(cfg *config.Config, log *logger.Logger, certs *cert.Manager) *Service {
	s := &Service{
		cfg:        cfg,
		log:        log,
		certs:      certs,
		bufferPool: newBytePool(),
		listeners:  make(map[string]*listenerState),
		missing:    make(map[string]int),
	}

	// High performance connection pooling: prevents TCP handshakes and port exhaustion
	s.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // Pass-through compression to preserve NAS CPU
	}

	s.tlsCfg = &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certs.GetCertificate,
	}

	return s
}

// GetMetricsSnapshot returns a real-time status and throughput report of all active listeners
func (s *Service) GetMetricsSnapshot() []ListenerMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := make([]ListenerMetrics, 0, len(s.listeners))
	for _, st := range s.listeners {
		if !st.conflict {
			res = append(res, st.Metrics())
		}
	}
	return res
}

// Reconcile synchronizes active listeners with the current scan result
func (s *Service) Reconcile(res *scanner.Result) {
	s.mu.Lock()
	defer s.mu.Unlock()

	excludeRelay := make(map[int]bool)
	for _, p := range s.cfg.Relay.Exclude {
		excludeRelay[p] = true
	}

	// 1. Build desired listeners
	wants := make(map[string]want)

	// 1. Explicit HTTPS rules from config (highest priority)
	explicitBackends := make(map[int]bool)
	for _, p := range s.cfg.HTTPS {
		explicitBackends[p.HTTP] = true
		if res.V4Wild[p.HTTP] || res.V6Any[p.HTTP] {
			wants[key("https", p.HTTPS)] = want{
				kind:    "https",
				name:    p.Name,
				port:    p.HTTPS,
				backend: p.HTTP,
				tls:     true,
			}
		}
	}

	// 2. Automatic Zero-Config HTTP Discovery & +1 HTTPS Upgrade
	if s.cfg.HTTPSAuto != nil && *s.cfg.HTTPSAuto {
		excludeHTTPS := make(map[int]bool)
		for _, p := range s.cfg.HTTPSExclude {
			excludeHTTPS[p] = true
		}

		allActivePorts := make(map[int]bool)
		for port := range res.V4Wild {
			allActivePorts[port] = true
		}
		for port := range res.V6Any {
			allActivePorts[port] = true
		}

		// Prune cache for closed ports
		scanner.CleanProbeCache(allActivePorts)

		for port := range allActivePorts {
			if explicitBackends[port] || excludeHTTPS[port] {
				continue
			}

			targetPort := port + s.cfg.HTTPSOffset
			if targetPort > 65535 || excludeHTTPS[targetPort] {
				continue
			}

			// Don't conflict if targetPort is already natively occupied by another process
			if (res.V4Wild[targetPort] || res.V6Any[targetPort]) && !s.isOurListener(targetPort) {
				continue
			}

			// Active probing: check if port speaks HTTP
			if scanner.ProbeHTTP(port) {
				name := res.Names[port]
				if name == "" {
					name = fmt.Sprintf("http-%d", port)
				}
				wants[key("https", targetPort)] = want{
					kind:    "https",
					name:    fmt.Sprintf("%s-tls", name),
					port:    targetPort,
					backend: port,
					tls:     true,
				}
			}
		}
	}

	// 3. Relay: auto-mirror v4-only ports to IPv6
	if s.cfg.Relay.Auto {
		for port := range res.V4Wild {
			if excludeRelay[port] || res.V6Others[port] {
				continue
			}
			wants[key("relay", port)] = want{
				kind:    "relay",
				name:    fmt.Sprintf("relay:%d", port),
				port:    port,
				backend: port,
				tls:     false,
			}
		}
	}

	// 2. Start new listeners
	for k, w := range wants {
		if _, exists := s.listeners[k]; exists {
			continue
		}

		if st := s.tryListen(w); st != nil {
			s.listeners[k] = st
			s.missing[k] = 0
			s.log.Add("%s: %s -> 127.0.0.1:%d", w.kind, s.addrOf(w.kind, w.port), w.backend)

			if w.kind == "https" {
				s.startHTTPServer(st, w)
			} else {
				go s.acceptRelayLoop(st)
			}
		} else {
			s.listeners[k] = &listenerState{
				kind:     w.kind,
				name:     w.name,
				port:     w.port,
				backend:  w.backend,
				conflict: true,
			}
			s.log.Warn("%s: cannot listen %s (port occupied, retrying)", w.name, s.addrOf(w.kind, w.port))
		}
	}

	// 3. Maintain and garbage collect listeners
	for k, st := range s.listeners {
		w, wantIt := wants[k]
		port := st.port

		if !wantIt {
			if st.conflict {
				delete(s.listeners, k)
				delete(s.missing, k)
				continue
			}

			s.missing[k]++
			if s.missing[k] >= s.cfg.GracePolls {
				s.log.Stop("%s: %s stopped (backend down)", st.kind, s.addr(st))
				s.stopListener(st)
				delete(s.listeners, k)
				delete(s.missing, k)
			}
			continue
		}

		if st.conflict {
			if st2 := s.tryListen(w); st2 != nil {
				s.listeners[k] = st2
				s.missing[k] = 0
				s.log.Add("%s: %s -> 127.0.0.1:%d (conflict resolved)", w.kind, s.addrOf(w.kind, w.port), w.backend)
				if w.kind == "https" {
					s.startHTTPServer(st2, w)
				} else {
					go s.acceptRelayLoop(st2)
				}
			}
			continue
		}

		// Relay Handover: native dual-stack listening detected from original backend
		if st.kind == "relay" && res.V6Others[port] {
			s.log.Info("native dual-stack detected on :%d, yielding listener", port)
			s.stopListener(st)
			delete(s.listeners, k)
			delete(s.missing, k)
			continue
		}

		s.missing[k] = 0
	}
}

func (s *Service) startHTTPServer(st *listenerState, w want) {
	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", w.backend))
	rp := httputil.NewSingleHostReverseProxy(targetURL)

	// Inject custom buffer pool and optimized transport
	rp.BufferPool = s.bufferPool
	rp.Transport = s.transport

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Port", strconv.Itoa(w.port))
		req.Header.Set("X-Forwarded-Host", req.Host)
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			req.Header.Set("X-Real-IP", clientIP)
		}
	}

	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		rw.WriteHeader(http.StatusBadGateway)
	}

	// Wrapper handler to track lock-free metrics (active connections, total, traffic)
	wrappedHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		st.activeConn.Add(1)
		st.totalConn.Add(1)
		defer st.activeConn.Add(-1)

		crw := &countingResponseWriter{ResponseWriter: rw, written: &st.bytesOut}
		if req.Body != nil {
			req.Body = &countingReadCloser{ReadCloser: req.Body, read: &st.bytesIn}
		}
		rp.ServeHTTP(crw, req)
	})

	server := &http.Server{
		Handler:     wrappedHandler,
		TLSConfig:   s.tlsCfg,
		IdleTimeout: time.Duration(s.cfg.IdleSeconds) * time.Second,
	}
	st.httpServer = server

	go func() {
		if err := server.ServeTLS(st.ln, "", ""); err != nil && err != http.ErrServerClosed {
			s.log.Warn("HTTPS %s server closed: %v", w.name, err)
		}
	}()
}

func (s *Service) acceptRelayLoop(st *listenerState) {
	dialProxy := tcpproxy.To(fmt.Sprintf("127.0.0.1:%d", st.backend))
	dialProxy.DialTimeout = 10 * time.Second
	dialProxy.KeepAlivePeriod = 30 * time.Second

	var tempDelay time.Duration
	for {
		conn, err := st.ln.Accept()
		if err != nil {
			select {
			case <-st.stop:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}

			if tempDelay == 0 {
				tempDelay = 5 * time.Millisecond
			} else {
				tempDelay *= 2
			}
			if tempDelay > time.Second {
				tempDelay = time.Second
			}
			time.Sleep(tempDelay)
			continue
		}
		tempDelay = 0

		st.activeConn.Add(1)
		st.totalConn.Add(1)

		cConn := &countingConn{
			Conn:   conn,
			active: &st.activeConn,
			in:     &st.bytesIn,
			out:    &st.bytesOut,
		}

		go dialProxy.HandleConn(cConn)
	}
}

// countingConn tracks bytes in/out and active connection count for TCP connections
type countingConn struct {
	net.Conn
	active *atomic.Int64
	in     *atomic.Uint64
	out    *atomic.Uint64
	closed atomic.Bool
}

func (c *countingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.in.Add(uint64(n))
	}
	return
}

func (c *countingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.out.Add(uint64(n))
	}
	return
}

func (c *countingConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.active.Add(-1)
	}
	return c.Conn.Close()
}

type countingResponseWriter struct {
	http.ResponseWriter
	written *atomic.Uint64
}

func (w *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	if n > 0 {
		w.written.Add(uint64(n))
	}
	return n, err
}

type countingReadCloser struct {
	io.ReadCloser
	read *atomic.Uint64
}

func (r *countingReadCloser) Read(b []byte) (int, error) {
	n, err := r.ReadCloser.Read(b)
	if n > 0 {
		r.read.Add(uint64(n))
	}
	return n, err
}

func (s *Service) stopListener(st *listenerState) {
	if st.stop != nil {
		select {
		case <-st.stop:
		default:
			close(st.stop)
		}
	}
	if st.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = st.httpServer.Shutdown(ctx)
	}
	if st.ln != nil {
		_ = st.ln.Close()
	}
}

func (s *Service) addrOf(kind string, port int) string {
	if kind == "https" {
		return fmt.Sprintf("https :%d", port)
	}
	return fmt.Sprintf("[::]:%d", port)
}

func (s *Service) addr(st *listenerState) string {
	return s.addrOf(st.kind, st.port)
}

func (s *Service) isOurListener(port int) bool {
	for _, st := range s.listeners {
		if st.port == port && !st.conflict {
			return true
		}
	}
	return false
}

// Shutdown gracefully stops all active listeners
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, st := range s.listeners {
		s.stopListener(st)
	}
}
