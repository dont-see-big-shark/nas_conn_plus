package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

	// 1. Start a backend HTTP server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("auto-discovered HTTP!"))
	}))
	defer backend.Close()

	backendPort := backend.Listener.Addr().(*net.TCPAddr).Port
	targetHTTPSPort := backendPort + 1

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
