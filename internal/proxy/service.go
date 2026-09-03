package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
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
				return &b
			},
		},
	}
}

func (p *bytePool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

func (p *bytePool) Put(b []byte) {
	p.pool.Put(&b)
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

	warnMu         sync.Mutex
	warnedConflict map[string]time.Time
}

func key(kind string, port int) string {
	return fmt.Sprintf("%s:%d", kind, port)
}

// NewService initializes the proxy service with optimized transport and buffer pooling
func NewService(cfg *config.Config, log *logger.Logger, certs *cert.Manager) *Service {
	s := &Service{
		cfg:            cfg,
		log:            log,
		certs:          certs,
		bufferPool:     newBytePool(),
		listeners:      make(map[string]*listenerState),
		missing:        make(map[string]int),
		warnedConflict: make(map[string]time.Time),
	}

	// High performance connection pooling: tuned for NAS low-memory devices
	// MaxIdleConns reduced from 1024 to 256 to avoid fd exhaustion on 512M NAS
	s.transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   64,
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

func (s *Service) isExcluded(port int) bool {
	for _, p := range s.cfg.Relay.Exclude {
		if p == port {
			return true
		}
	}
	for _, p := range s.cfg.HTTPSExclude {
		if p == port {
			return true
		}
	}
	return false
}

func (s *Service) isRelayAllowed(port int) bool {
	if len(s.cfg.Relay.Allow) > 0 {
		for _, a := range s.cfg.Relay.Allow {
			if a == port {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Service) isHTTPSAllowed(port int) bool {
	if len(s.cfg.HTTPSAllow) > 0 {
		for _, a := range s.cfg.HTTPSAllow {
			if a == port {
				return true
			}
		}
		return false
	}
	return true
}

func (s *Service) isOurListenerPortLocked(port int) bool {
	for _, st := range s.listeners {
		if st.port == port && !st.conflict {
			return true
		}
	}
	return false
}

func (s *Service) isOurListener(kind string, port int) bool {
	st, exists := s.listeners[key(kind, port)]
	return exists && !st.conflict
}

// Reconcile synchronizes active listeners with the current scan result
func (s *Service) Reconcile(res *scanner.Result) {
	// Pre-pass: run HTTP probes outside s.mu lock to avoid blocking IPC queries or other workers
	var portsToProbe []int
	if s.cfg.HTTPSAuto != nil && *s.cfg.HTTPSAuto {
		s.mu.Lock()
		activeCandidatePorts := make(map[int]bool)
		for port := range res.V4Wild {
			if !s.isOurListenerPortLocked(port) && !s.isExcluded(port) {
				activeCandidatePorts[port] = true
			}
		}
		for port := range res.V6Any {
			if !s.isOurListenerPortLocked(port) && !s.isExcluded(port) {
				activeCandidatePorts[port] = true
			}
		}
		s.mu.Unlock()

		scanner.CleanProbeCache(activeCandidatePorts)
		for port := range activeCandidatePorts {
			portsToProbe = append(portsToProbe, port)
		}
	}

	if len(portsToProbe) > 0 {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 8)
		for _, p := range portsToProbe {
			wg.Add(1)
			sem <- struct{}{}
			go func(port int) {
				defer func() {
					<-sem
					wg.Done()
				}()
				_ = scanner.ProbeHTTP(port)
			}(p)
		}
		wg.Wait()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
		allActivePorts := make(map[int]bool)
		for port := range res.V4Wild {
			// CRITICAL: Never treat our own listener ports as new HTTP targets to upgrade!
			if !s.isOurListenerPortLocked(port) && !s.isExcluded(port) && s.isHTTPSAllowed(port) {
				allActivePorts[port] = true
			}
		}
		for port := range res.V6Any {
			// CRITICAL: Never treat our own listener ports as new HTTP targets to upgrade!
			if !s.isOurListenerPortLocked(port) && !s.isExcluded(port) && s.isHTTPSAllowed(port) {
				allActivePorts[port] = true
			}
		}

		for port := range allActivePorts {
			if explicitBackends[port] || !s.isHTTPSAllowed(port) {
				continue
			}

			targetPort := port + s.cfg.HTTPSOffset
			if targetPort > 65535 || s.isExcluded(targetPort) {
				continue
			}

			// P0-2 FIX: Do not pre-check V4Wild/V6Any wildcard tables here — they miss
			// specific binds like 127.0.0.1:P and would still spuriously succeed due to
			// SO_REUSEADDR. Rely on tryListen() EADDRINUSE to detect real occupancy;
			// conflict entries are kept and retried next Reconcile so temporary
			// neighbour restarts don't cause permanent port steal.
			// M1: avoid creating https on a port already owned by a different
			// kind of our listeners (e.g. relay [::]:P vs https :P). The two
			// cannot coexist at OS level, so we must not mark it as conflict:true
			// but simply skip. If it's already our https listener, keep it.
			if s.isOurListenerPortLocked(targetPort) && !s.isOurListener("https", targetPort) {
				continue
			}

			wKey := key("https", targetPort)
			// Explicit rules take precedence
			if _, exists := wants[wKey]; exists {
				continue
			}

			// Active probing: check if port speaks plain HTTP (cached from pre-pass)
			if scanner.ProbeHTTP(port) {
				name := res.Names[port]
				if name == "" {
					name = fmt.Sprintf("http-%d", port)
				}
				wants[wKey] = want{
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
			if s.isExcluded(port) || !s.isRelayAllowed(port) || res.V6Others[port] {
				continue
			}
			// Do not relay our own listener ports
			if s.isOurListenerPortLocked(port) {
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
			s.warnMu.Lock()
			delete(s.warnedConflict, k)
			s.warnMu.Unlock()
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
			s.warnMu.Lock()
			lastWarn, exists := s.warnedConflict[k]
			now := time.Now()
			shouldWarn := !exists || now.Sub(lastWarn) > 60*time.Second
			if shouldWarn {
				s.warnedConflict[k] = now
			}
			s.warnMu.Unlock()

			if shouldWarn {
				s.log.Warn("%s: cannot listen %s (port occupied, retrying)", w.name, s.addrOf(w.kind, w.port))
			}
		}
	}

	// 3. Maintain and garbage collect listeners
	for k, st := range s.listeners {
		port := st.port

		// Relay Handover: native dual-stack listening detected from original backend -> immediate yield!
		if st.kind == "relay" && res.V6Others[port] {
			s.log.Info("native dual-stack detected on :%d, yielding listener", port)
			s.stopListener(st)
			delete(s.listeners, k)
			delete(s.missing, k)
			continue
		}

		w, wantIt := wants[k]

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
				s.warnMu.Lock()
				delete(s.warnedConflict, k)
				s.warnMu.Unlock()
				s.log.Add("%s: %s -> 127.0.0.1:%d (conflict resolved)", w.kind, s.addrOf(w.kind, w.port), w.backend)
				if w.kind == "https" {
					s.startHTTPServer(st2, w)
				} else {
					go s.acceptRelayLoop(st2)
				}
			}
			continue
		}

		s.missing[k] = 0
	}
}

func (s *Service) startHTTPServer(st *listenerState, w want) {
	targetURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", w.backend))
	rp := &httputil.ReverseProxy{
		BufferPool: s.bufferPool,
		Transport:  s.transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Port", strconv.Itoa(w.port))
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set("X-Real-IP", clientIP)
			} else {
				pr.Out.Header.Del("X-Real-IP")
			}
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			st.errorCount.Add(1)
			s.log.Warn("HTTPS %s proxy error: %v", w.name, err)
			rw.WriteHeader(http.StatusBadGateway)
		},
	}

	// Wrapper handler to track lock-free metrics (active connections, total, traffic)
	wrappedHandler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		st.activeConn.Add(1)
		st.totalConn.Add(1)
		defer st.activeConn.Add(-1)

		if s.cfg.HSTS.Enabled {
			host := req.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			// RFC 6797: do not apply HSTS to bare IP addresses
			if net.ParseIP(host) == nil && s.certs != nil && s.certs.Current() != nil {
				hstsVal := fmt.Sprintf("max-age=%d", s.cfg.HSTS.MaxAge)
				if s.cfg.HSTS.IncludeSubdomains {
					hstsVal += "; includeSubDomains"
				}
				rw.Header().Set("Strict-Transport-Security", hstsVal)
			}
		}

		crw := &countingResponseWriter{ResponseWriter: rw, written: &st.bytesOut}
		if req.Body != nil {
			req.Body = &countingReadCloser{ReadCloser: req.Body, read: &st.bytesIn}
		}
		rp.ServeHTTP(crw, req)
	})

	server := &http.Server{
		Handler:           wrappedHandler,
		TLSConfig:         s.tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       time.Duration(s.cfg.IdleSeconds) * time.Second,
		MaxHeaderBytes:    64 << 10,
		// WriteTimeout intentionally 0 (no timeout) to support websockets and
		// long-lived hijacked connections; timeout is enforced via IdleTimeout
		// and transport limits instead. See Go issue 62015.
	}
	st.httpServer = server

	if st.ln != nil {
		go func() {
			if err := server.ServeTLS(st.ln, "", ""); err != nil && err != http.ErrServerClosed {
				s.log.Warn("HTTPS %s server closed: %v", w.name, err)
			}
		}()
	}
}

func (s *Service) acceptRelayLoop(st *listenerState) {
	dialProxy := tcpproxy.To(fmt.Sprintf("127.0.0.1:%d", st.backend))
	dialProxy.DialTimeout = 10 * time.Second
	dialProxy.KeepAlivePeriod = 30 * time.Second

	var lastErrTime time.Time
	var errCount int
	dialProxy.OnDialError = func(src net.Conn, err error) {
		st.errorCount.Add(1)
		now := time.Now()
		if now.Sub(lastErrTime) > 5*time.Second {
			s.log.Warn("relay %s dial error: %v (suppressed %d occurrences)", st.name, err, errCount)
			lastErrTime = now
			errCount = 0
		} else {
			errCount++
		}
		_ = src.Close()
	}

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

		if s.cfg.Relay.ZeroCopy {
			zcConn := &activeCountingConn{
				Conn:   conn,
				active: &st.activeConn,
			}
			go dialProxy.HandleConn(zcConn)
		} else {
			cConn := &countingConn{
				Conn:   conn,
				active: &st.activeConn,
				in:     &st.bytesIn,
				out:    &st.bytesOut,
			}
			go dialProxy.HandleConn(cConn)
		}
	}
}

// activeCountingConn manages connection lifecycle and enables direct Linux kernel splice(2) zero-copy
type activeCountingConn struct {
	net.Conn
	active *atomic.Int64
	once   sync.Once
}

func (c *activeCountingConn) UnderlyingConn() net.Conn {
	return c.Conn
}

func (c *activeCountingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		if c.active != nil {
			c.active.Add(-1)
		}
	})
	return err
}

// countingConn tracks bytes in/out and implements net.Conn, UnderlyingConn, and TCP extension interfaces
// to enable Linux kernel splice(2) zero-copy and keepalive in tcpproxy.
type countingConn struct {
	net.Conn
	active *atomic.Int64
	in     *atomic.Uint64
	out    *atomic.Uint64
	closed atomic.Bool
}

func (c *countingConn) UnderlyingConn() net.Conn {
	return c.Conn
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

func (c *countingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *countingConn) SetKeepAlive(keepalive bool) error {
	if ka, ok := c.Conn.(interface{ SetKeepAlive(bool) error }); ok {
		return ka.SetKeepAlive(keepalive)
	}
	return nil
}

func (c *countingConn) SetKeepAlivePeriod(d time.Duration) error {
	if kap, ok := c.Conn.(interface{ SetKeepAlivePeriod(time.Duration) error }); ok {
		return kap.SetKeepAlivePeriod(d)
	}
	return nil
}

func (c *countingConn) SyscallConn() (syscall.RawConn, error) {
	if sc, ok := c.Conn.(syscall.Conn); ok {
		return sc.SyscallConn()
	}
	return nil, errors.New("underlying conn does not implement syscall.Conn")
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

// Shutdown gracefully stops all active listeners concurrently
// R5 FIX: snapshot listeners under lock then unlock before Wait to avoid blocking GetMetricsSnapshot/Reconcile
func (s *Service) Shutdown() {
	s.mu.Lock()
	snapshot := make([]*listenerState, 0, len(s.listeners))
	for _, st := range s.listeners {
		snapshot = append(snapshot, st)
	}
	// Clear maps while still holding lock so new Reconcile won't race
	s.listeners = make(map[string]*listenerState)
	s.missing = make(map[string]int)
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, l := range snapshot {
		wg.Add(1)
		go func(ls *listenerState) {
			defer wg.Done()
			s.stopListener(ls)
		}(l)
	}
	wg.Wait()
}
