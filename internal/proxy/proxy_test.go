package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/cert"
	"github.com/jadenjoe/nasconnplus/internal/config"
	"github.com/jadenjoe/nasconnplus/internal/logger"
	"github.com/jadenjoe/nasconnplus/internal/scanner"
)

func TestProxy_HTTPS_ReverseProxyHeaders(t *testing.T) {
	tempDir := t.TempDir()

	// Backend server checking for injected headers
	var gotProto, gotHost, gotPort string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotPort = r.Header.Get("X-Forwarded-Port")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port
	httpsPort := backendPort + 1

	trueVal := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &trueVal,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		HTTPS: []config.HTTPSPort{
			{Name: "test-web", HTTP: backendPort, HTTPS: httpsPort},
		},
		Relay: config.RelayCfg{Auto: false},
	}

	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("refresh cert: %v", err)
	}

	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	// Trigger reconcile with the backend port active
	res := &scanner.Result{
		V4Wild:   map[int]bool{backendPort: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{},
		Names:    map[int]string{},
	}
	srv.Reconcile(res)
	time.Sleep(100 * time.Millisecond)

	// Make request to the HTTPS port
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/test", httpsPort))
	if err != nil {
		t.Fatalf("GET https failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("expected 'backend response', got %q", string(body))
	}

	if gotProto != "https" {
		t.Errorf("expected X-Forwarded-Proto='https', got %q", gotProto)
	}
	if gotPort != fmt.Sprintf("%d", httpsPort) {
		t.Errorf("expected X-Forwarded-Port='%d', got %q", httpsPort, gotPort)
	}
	if gotHost != fmt.Sprintf("127.0.0.1:%d", httpsPort) {
		t.Errorf("expected X-Forwarded-Host='127.0.0.1:%d', got %q", httpsPort, gotHost)
	}
}

func TestProxy_AutoHTTPDiscovery(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Acquire verified free port pair for backend and https
	var lBackend net.Listener
	var backendPort, targetHTTPSPort int
	for i := 0; i < 50; i++ {
		l1, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		p1 := l1.Addr().(*net.TCPAddr).Port
		l2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p1+1))
		if err != nil {
			_ = l1.Close()
			continue
		}
		_ = l2.Close()
		lBackend = l1
		backendPort = p1
		targetHTTPSPort = p1 + 1
		break
	}
	if lBackend == nil {
		t.Fatal("failed to find adjacent free ports")
	}

	backend := &httptest.Server{
		Listener: lBackend,
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("auto-discovered HTTP!"))
			}),
		},
	}
	backend.Start()
	defer backend.Close()

	// Config has EMPTY https rules! Only https_auto: true!
	autoTrue := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &autoTrue,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		HTTPSAuto:    &autoTrue,
		HTTPSOffset:  1,
		HTTPS:        []config.HTTPSPort{}, // NO manual rules!
		Relay:        config.RelayCfg{Auto: false},
	}

	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("refresh cert: %v", err)
	}

	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	res := &scanner.Result{
		V4Wild:   map[int]bool{backendPort: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{backendPort: 1234},
		Names:    map[int]string{backendPort: "my-docker-app"},
	}

	// Trigger Reconcile -> It should actively probe backendPort, detect HTTP, and spin up targetHTTPSPort!
	srv.Reconcile(res)
	time.Sleep(150 * time.Millisecond)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/ping", targetHTTPSPort))
	if err != nil {
		t.Fatalf("Failed to connect to auto-discovered HTTPS port %d: %v", targetHTTPSPort, err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "auto-discovered HTTP!" {
		t.Errorf("expected 'auto-discovered HTTP!', got %q", string(body))
	}
}

func TestProxy_Reconcile_NoInfiniteCascadingLoop(t *testing.T) {
	tempDir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port
	targetHTTPSPort := backendPort + 1

	autoTrue := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   2,
		FallbackSelf: &autoTrue,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		HTTPSAuto:    &autoTrue,
		HTTPSOffset:  1,
		HTTPS:        []config.HTTPSPort{},
		Relay:        config.RelayCfg{Auto: false},
	}

	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("refresh cert: %v", err)
	}

	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	// Initial scan: backend is active
	res := &scanner.Result{
		V4Wild:   map[int]bool{backendPort: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{backendPort: 1234},
		Names:    map[int]string{backendPort: "backend-service"},
	}

	// 1st Reconcile: creates targetHTTPSPort
	srv.Reconcile(res)

	// Simulate 20 successive scan cycles where Linux procfs reports the new HTTPS port
	// as active in V6Any (since net.Listen("tcp", ":P") binds dual-stack [::]:P)
	for round := 1; round <= 20; round++ {
		resRound := &scanner.Result{
			V4Wild:   map[int]bool{backendPort: true, targetHTTPSPort: true},
			V6Any:    map[int]bool{targetHTTPSPort: true},
			V6Others: map[int]bool{},
			PIDs:     map[int]int{backendPort: 1234, targetHTTPSPort: 9999},
			Names:    map[int]string{backendPort: "backend-service", targetHTTPSPort: "nasconnplus"},
		}
		srv.Reconcile(resRound)
	}

	// Verify listener count: MUST BE EXACTLY 1!
	// If P0-1 bug exists, there would be 21 listeners cascading from backendPort+1 to backendPort+21!
	srv.mu.Lock()
	listenerCount := len(srv.listeners)
	srv.mu.Unlock()

	if listenerCount != 1 {
		t.Fatalf("Cascading loop detected! Expected exactly 1 listener, got %d", listenerCount)
	}

	// Ensure no ports above targetHTTPSPort were ever created
	srv.mu.Lock()
	for k := range srv.listeners {
		if k != fmt.Sprintf("https:%d", targetHTTPSPort) {
			t.Errorf("Unexpected rogue listener created: %s", k)
		}
	}
	srv.mu.Unlock()
}

func TestProxy_ReverseProxy_HeaderInjectionDefense(t *testing.T) {
	tempDir := t.TempDir()

	var receivedProto, receivedRealIP, receivedXFF string
	var connectionHdr string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		receivedRealIP = r.Header.Get("X-Real-IP")
		receivedXFF = r.Header.Get("X-Forwarded-For")
		connectionHdr = r.Header.Get("Connection")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secure-backend"))
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port
	httpsPort := backendPort + 1

	trueVal := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &trueVal,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		HTTPS: []config.HTTPSPort{
			{Name: "secure-test", HTTP: backendPort, HTTPS: httpsPort},
		},
		Relay: config.RelayCfg{Auto: false},
	}

	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("refresh cert: %v", err)
	}

	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	srv.Reconcile(&scanner.Result{
		V4Wild:   map[int]bool{backendPort: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{},
		Names:    map[int]string{},
	})
	time.Sleep(100 * time.Millisecond)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://127.0.0.1:%d/test", httpsPort), nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}

	// Malicious client tries to inject / strip headers via Connection header (CVE-style attack)
	req.Header.Set("Connection", "X-Forwarded-Proto, X-Real-IP")
	req.Header.Set("X-Forwarded-Proto", "http")       // Trying to deceive backend into thinking it's unencrypted
	req.Header.Set("X-Real-IP", "203.0.113.195")     // Spoofed IP
	req.Header.Set("X-Forwarded-For", "198.51.100.1") // Spoofed forward chain

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do failed: %v", err)
	}
	defer resp.Body.Close()

	if receivedProto != "https" {
		t.Errorf("Security regression (H1): expected X-Forwarded-Proto='https', got %q", receivedProto)
	}
	if receivedRealIP != "127.0.0.1" {
		t.Errorf("Security regression (H1): expected X-Real-IP='127.0.0.1', got %q", receivedRealIP)
	}
	if connectionHdr != "" {
		t.Errorf("Hop-by-hop Connection header leaked to backend: %q", connectionHdr)
	}
	_ = receivedXFF
}

func TestProxy_CountingConn_Interfaces(t *testing.T) {
	// Create a real loopback TCP connection pair
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.Close()
	<-done

	cConn := &countingConn{
		Conn: clientConn,
	}

	// Test UnderlyingConn (critical for tcpproxy splice zero-copy unwrapping)
	type underlying interface {
		UnderlyingConn() net.Conn
	}
	u, ok := interface{}(cConn).(underlying)
	if !ok || u.UnderlyingConn() != clientConn {
		t.Errorf("countingConn must implement UnderlyingConn() net.Conn")
	}

	// Test TCP extension interfaces
	if err := cConn.SetKeepAlive(true); err != nil {
		t.Logf("SetKeepAlive: %v", err)
	}
	if err := cConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
		t.Logf("SetKeepAlivePeriod: %v", err)
	}
	if sc, err := cConn.SyscallConn(); err != nil || sc == nil {
		t.Errorf("SyscallConn() failed: %v", err)
	}
}

func TestProxy_ExplicitRule_PriorityOverAuto(t *testing.T) {
	tempDir := t.TempDir()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("explicit"))
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port
	explicitHTTPSPort := backendPort + 10 // explicitly map to +10 instead of default +1

	autoTrue := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &autoTrue,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		HTTPSAuto:    &autoTrue,
		HTTPSOffset:  1, // Auto discovery would choose backendPort + 1
		HTTPS: []config.HTTPSPort{
			{Name: "my-explicit-rule", HTTP: backendPort, HTTPS: explicitHTTPSPort},
		},
		Relay: config.RelayCfg{Auto: false},
	}

	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	if err := cm.Refresh(); err != nil {
		t.Fatalf("refresh cert: %v", err)
	}

	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	srv.Reconcile(&scanner.Result{
		V4Wild:   map[int]bool{backendPort: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{backendPort: 123},
		Names:    map[int]string{backendPort: "service"},
	})

	srv.mu.Lock()
	_, hasExplicit := srv.listeners[fmt.Sprintf("https:%d", explicitHTTPSPort)]
	_, hasAuto := srv.listeners[fmt.Sprintf("https:%d", backendPort+1)]
	srv.mu.Unlock()

	if !hasExplicit {
		t.Errorf("expected explicit rule listener on port %d", explicitHTTPSPort)
	}
	if hasAuto {
		t.Errorf("auto rule should NOT overwrite or duplicate explicit rule on port %d", backendPort+1)
	}
}

func TestProxy_GetMetricsSnapshot_And_Exclude(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		CertHost: "localhost",
		Relay: config.RelayCfg{
			Auto:    false,
			Exclude: []int{22, 53},
		},
		HTTPSExclude: []int{22, 53},
	}
	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	_ = cm.Refresh()
	lg := logger.New()
	srv := NewService(cfg, lg, cm)
	defer srv.Shutdown()

	// Verify isExcluded helper
	if !srv.isExcluded(22) {
		t.Errorf("expected port 22 to be excluded")
	}
	if srv.isExcluded(80) {
		t.Errorf("expected port 80 not to be excluded")
	}

	// Add dummy listenerState to verify GetMetricsSnapshot
	st := &listenerState{
		kind:      "https",
		name:      "demo-web",
		port:      8443,
		backend:   8080,
		startedAt: time.Now(),
	}
	st.activeConn.Store(3)
	st.totalConn.Store(10)
	st.bytesIn.Store(1024)
	st.bytesOut.Store(2048)

	srv.mu.Lock()
	srv.listeners["https:8443"] = st
	srv.mu.Unlock()

	metrics := srv.GetMetricsSnapshot()
	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}
	m := metrics[0]
	if m.Port != 8443 || m.Backend != 8080 || m.ActiveConn != 3 || m.TotalConn != 10 || m.BytesIn != 1024 || m.BytesOut != 2048 {
		t.Errorf("metrics mismatch: %+v", m)
	}

	// Verify ListenerMetrics
	lm := st.Metrics()
	if lm.Port != 8443 || lm.ActiveConn != 3 {
		t.Errorf("unexpected ListenerMetrics: %+v", lm)
	}

	if srv.addr(st) != "https :8443" {
		t.Errorf("expected 'https :8443', got %s", srv.addr(st))
	}
	if srv.addrOf("relay", 8080) != "[::]:8080" {
		t.Errorf("expected '[::]:8080', got %s", srv.addrOf("relay", 8080))
	}
}

func TestProxy_CountingConn_FullLifecycle(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeR.Close()
	defer pipeW.Close()

	var active atomic.Int64
	var bytesIn atomic.Uint64
	var bytesOut atomic.Uint64

	active.Store(1)
	cc := &countingConn{
		Conn:   pipeR,
		active: &active,
		in:     &bytesIn,
		out:    &bytesOut,
	}

	// UnderlyingConn
	if cc.UnderlyingConn() != pipeR {
		t.Error("UnderlyingConn did not match")
	}

	// Write from peer and Read from cc
	go func() {
		_, _ = pipeW.Write([]byte("ping"))
	}()

	buf := make([]byte, 10)
	n, err := cc.Read(buf)
	if err != nil || n != 4 {
		t.Fatalf("read failed: %v, n=%d", err, n)
	}
	if bytesIn.Load() != 4 {
		t.Errorf("expected bytesIn=4, got %d", bytesIn.Load())
	}

	// Write to peer from cc
	go func() {
		b := make([]byte, 10)
		_, _ = pipeW.Read(b)
	}()
	wn, err := cc.Write([]byte("pong"))
	if err != nil || wn != 4 {
		t.Fatalf("write failed: %v, wn=%d", err, wn)
	}
	if bytesOut.Load() != 4 {
		t.Errorf("expected bytesOut=4, got %d", bytesOut.Load())
	}

	// Optional interfaces fallback
	_ = cc.CloseRead()
	_ = cc.CloseWrite()
	_ = cc.SetKeepAlive(true)
	_ = cc.SetKeepAlivePeriod(time.Second)
	_, _ = cc.SyscallConn()

	// Close decrements active once
	_ = cc.Close()
	if active.Load() != 0 {
		t.Errorf("expected active=0 after close, got %d", active.Load())
	}
	// Idempotent close
	_ = cc.Close()
	if active.Load() != 0 {
		t.Errorf("expected active=0 after duplicate close, got %d", active.Load())
	}
}

func TestProxy_ActiveCountingConn(t *testing.T) {
	pipeR, pipeW := net.Pipe()
	defer pipeW.Close()

	var active atomic.Int64
	active.Store(1)

	zc := &activeCountingConn{
		Conn:   pipeR,
		active: &active,
	}

	if zc.UnderlyingConn() != pipeR {
		t.Errorf("UnderlyingConn did not match")
	}

	_ = zc.Close()
	if active.Load() != 0 {
		t.Errorf("expected active=0 after close, got %d", active.Load())
	}
	// Duplicate close should be idempotent
	_ = zc.Close()
	if active.Load() != 0 {
		t.Errorf("expected active=0 after duplicate close, got %d", active.Load())
	}
}

func TestProxy_LimitListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	limitLn := newLimitListener(ln, 1)

	// First client connects
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			defer c.Close()
			time.Sleep(50 * time.Millisecond)
		}
	}()

	conn1, err := limitLn.Accept()
	if err != nil {
		t.Fatalf("accept failed: %v", err)
	}
	_ = conn1.Close()
}

func TestProxy_HSTS_Header(t *testing.T) {
	tempDir := t.TempDir()
	log := logger.New()

	cfg := &config.Config{
		CertHost: "nas.local",
		HSTS: config.HSTSConfig{
			Enabled: true,
			MaxAge:  31536000,
		},
		HTTPSAuto: &[]bool{false}[0],
	}

	certs := cert.NewManager(cfg.CertConfigPath, cfg.CertHost, tempDir, true, false, "", "", "")
	_ = certs.Refresh()

	s := NewService(cfg, log, certs)

	// Backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port

	st := &listenerState{
		kind:      "https",
		name:      "hsts-test",
		port:      backendPort + 10,
		backend:   backendPort,
		stop:      make(chan struct{}),
		startedAt: time.Now(),
	}

	w := want{
		kind:    "https",
		name:    "hsts-test",
		port:    backendPort + 10,
		backend: backendPort,
		tls:     true,
	}

	s.startHTTPServer(st, w)
	defer func() {
		if st.httpServer != nil {
			_ = st.httpServer.Close()
		}
	}()

	// Test handler directly
	req := httptest.NewRequest("GET", "https://nas.example.com/", nil)
	rec := httptest.NewRecorder()

	st.httpServer.Handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("expected HSTS header for domain name, got %q", hsts)
	}

	// For IP address, HSTS MUST NOT be injected (RFC 6797)
	reqIP := httptest.NewRequest("GET", "https://192.168.1.100/", nil)
	recIP := httptest.NewRecorder()
	st.httpServer.Handler.ServeHTTP(recIP, reqIP)

	hstsIP := recIP.Header().Get("Strict-Transport-Security")
	if hstsIP != "" {
		t.Errorf("HSTS header must not be set for IP literal, got %q", hstsIP)
	}
}

func TestProxy_AllowLists_And_Handover(t *testing.T) {
	cfg := &config.Config{
		Relay: config.RelayCfg{
			Auto:  true,
			Allow: []int{8080},
		},
		HTTPSAllow: []int{9090},
	}
	s := &Service{cfg: cfg}

	if !s.isRelayAllowed(8080) {
		t.Error("expected 8080 allowed for relay")
	}
	if s.isRelayAllowed(8081) {
		t.Error("expected 8081 rejected by relay allow list")
	}
	if !s.isHTTPSAllowed(9090) {
		t.Error("expected 9090 allowed for https")
	}
	if s.isHTTPSAllowed(9091) {
		t.Error("expected 9091 rejected by https allow list")
	}

	// Test Mode = "whitelist" with empty allow list -> rejects everything
	cfgWhitelist := &config.Config{
		Relay: config.RelayCfg{
			Mode:  "whitelist",
			Allow: []int{},
		},
		HTTPSMode:  "whitelist",
		HTTPSAllow: []int{},
	}
	sW := &Service{cfg: cfgWhitelist}
	if sW.isRelayAllowed(8080) {
		t.Error("expected 8080 rejected in empty whitelist mode")
	}
	if sW.isHTTPSAllowed(9090) {
		t.Error("expected 9090 rejected in empty whitelist mode")
	}
}

func TestProxy_CountingReadCloser_And_ResponseWriter(t *testing.T) {
	var bytesIn atomic.Uint64
	var bytesOut atomic.Uint64

	// Test countingReadCloser
	rc := io.NopCloser(strings.NewReader("hello world"))
	crc := &countingReadCloser{ReadCloser: rc, read: &bytesIn}

	buf := make([]byte, 5)
	n, err := crc.Read(buf)
	if err != nil || n != 5 {
		t.Fatalf("read failed: %v, n=%d", err, n)
	}
	if bytesIn.Load() != 5 {
		t.Errorf("expected bytesIn=5, got %d", bytesIn.Load())
	}
	_ = crc.Close()

	// Test countingResponseWriter
	rec := httptest.NewRecorder()
	crw := &countingResponseWriter{ResponseWriter: rec, written: &bytesOut}

	wn, err := crw.Write([]byte("foobar"))
	if err != nil || wn != 6 {
		t.Fatalf("write failed: %v, wn=%d", err, wn)
	}
	if bytesOut.Load() != 6 {
		t.Errorf("expected bytesOut=6, got %d", bytesOut.Load())
	}
}


