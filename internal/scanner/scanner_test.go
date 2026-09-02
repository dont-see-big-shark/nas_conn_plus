package scanner

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticReport(t *testing.T) {
	res := &Result{
		V4Wild:   map[int]bool{8080: true, 22: true},
		V6Any:    map[int]bool{22: true, 9090: true},
		V6Others: map[int]bool{22: true},
		PIDs:     map[int]int{8080: 1234, 22: 100},
		Names:    map[int]string{8080: "web", 22: "sshd"},
	}

	report := res.DiagnosticReport([]int{53})
	if !strings.Contains(report, "8080") {
		t.Errorf("expected report to contain port 8080, got:\n%s", report)
	}
	if !strings.Contains(report, "Will Relay") {
		t.Errorf("expected report to contain 'Will Relay', got:\n%s", report)
	}
	if !strings.Contains(report, "Native Dual-Stack") {
		t.Errorf("expected report to contain 'Native Dual-Stack', got:\n%s", report)
	}
}

func TestParseProcNetFile(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0                     
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0                     
   2: 00000000:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0                     
`
	tmpFile, err := os.CreateTemp("", "proc_net_tcp_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	res := &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}
	inodeMap := map[string]procInfo{
		"12345": {pid: 1000, name: "nginx"},
	}
	var missingInodes bool

	if err := parseProcNetFile(tmpFile.Name(), false, res, 9999, nil, inodeMap, &missingInodes); err != nil {
		t.Fatalf("parseProcNetFile failed: %v", err)
	}

	// 0x50 = 80
	if !res.V4Wild[80] {
		t.Errorf("expected port 80 in V4Wild")
	}
	if res.PIDs[80] != 1000 || res.Names[80] != "nginx" {
		t.Errorf("expected pid 1000 and name nginx for port 80, got %d %s", res.PIDs[80], res.Names[80])
	}
	// 0x16 = 22, bound to 127.0.0.1, not wildcard
	if res.V4Wild[22] {
		t.Errorf("expected port 22 not in V4Wild")
	}
	// missingInodes should be true because inode 67890 was not in inodeMap
	if !missingInodes {
		t.Errorf("expected missingInodes to be true for unmapped socket")
	}
}

func TestParseProcNetFile_IPv6_And_SelfInodes(t *testing.T) {
	content := `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000FFFF00000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0
`
	tmpFile, err := os.CreateTemp("", "proc_net_tcp6_*")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	_, _ = tmpFile.WriteString(content)
	tmpFile.Close()

	res := newResult()
	selfInodes := map[string]bool{
		"11111": true, // This socket is ours!
	}
	inodeMap := map[string]procInfo{
		"22222": {pid: 500, name: "java"},
		"33333": {pid: 600, name: "foreign-app"},
	}

	if err := parseProcNetFile(tmpFile.Name(), true, res, 1234, selfInodes, inodeMap, nil); err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// 0x1F90 = 8080: [::] socket, but in selfInodes, so V6Any=true, V6Others=false!
	if !res.V6Any[8080] {
		t.Errorf("expected 8080 in V6Any")
	}
	if res.V6Others[8080] {
		t.Errorf("our own socket 8080 must NEVER be marked V6Others (P1-2 regression)")
	}

	// 0x1F91 = 8081: ::ffff:0.0.0.0 (IPv4 mapped wildcard), so V4Wild=true
	if !res.V4Wild[8081] {
		t.Errorf("expected 8081 in V4Wild for ::ffff:0.0.0.0 (M4 regression)")
	}

	// 0x1F92 = 8082: [::] socket by foreign-app (pid 600 != 1234), so V6Others=true
	if !res.V6Others[8082] {
		t.Errorf("expected 8082 to be marked V6Others")
	}
}

func TestProber_TLSPreCheck_RejectsHTTPS(t *testing.T) {
	// Start real HTTPS server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https-content"))
	}))
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port

	// IsHTTPService must return FALSE because it's already an HTTPS service!
	if IsHTTPService(port, 1*time.Second) {
		t.Errorf("IsHTTPService must return false for existing TLS service on port %d (P0-1 regression)", port)
	}
}

func TestProber_RejectsPlaintextTLSErrorResponse(t *testing.T) {
	// Simulate Go net/http or nginx 400 Bad Request error response when plain HTTP hits HTTPS port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = conn.Read(buf)
			resp := "HTTP/1.0 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nClient sent an HTTP request to an HTTPS server.\n"
			_, _ = conn.Write([]byte(resp))
			_ = conn.Close()
		}
	}()

	if IsHTTPService(port, 1*time.Second) {
		t.Errorf("IsHTTPService must return false for 400 TLS error response (P0-1 regression)")
	}
}

func TestProber_AcceptsLegitHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello http"))
	}))
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port

	if !IsHTTPService(port, 1*time.Second) {
		t.Errorf("IsHTTPService should return true for normal HTTP server on port %d", port)
	}
}

func TestProber_CacheAndProbe(t *testing.T) {
	ResetProbeCache()
	defer ResetProbeCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("cached http test"))
	}))
	defer server.Close()

	port := server.Listener.Addr().(*net.TCPAddr).Port

	// First probe
	if !ProbeHTTP(port) {
		t.Errorf("expected ProbeHTTP to return true for live HTTP server")
	}

	// Second probe should hit cache
	if !ProbeHTTP(port) {
		t.Errorf("expected ProbeHTTP cache hit to return true")
	}

	// Clean cache
	CleanProbeCache(map[int]bool{port: false})
	probeMu.RLock()
	_, exists := probeCache[port]
	probeMu.RUnlock()
	if exists {
		t.Errorf("expected port %d to be pruned from probeCache", port)
	}
}

func TestDiagnosticReport_Excluded(t *testing.T) {
	res := &Result{
		V4Wild:   map[int]bool{22: true, 80: true},
		V6Any:    map[int]bool{},
		V6Others: map[int]bool{},
		PIDs:     map[int]int{22: 123},
		Names:    map[int]string{22: "sshd"},
	}

	// Exclude port 22
	report := res.DiagnosticReport([]int{22})
	if !strings.Contains(report, "Excluded") {
		t.Errorf("expected report to indicate port 22 is Excluded, got:\n%s", report)
	}
}

func TestScan_Basic(t *testing.T) {
	// Start a dummy listener so there's at least one active port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot open test listener")
	}
	defer ln.Close()

	res, err := Scan()
	if err != nil {
		// On some minimal CI or non-privileged environments, scanner command might return error
		t.Logf("Scan returned error (acceptable on restricted sandbox): %v", err)
		return
	}
	if res == nil {
		t.Fatal("expected non-nil Scan result")
	}
}

