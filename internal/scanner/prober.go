package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type probeEntry struct {
	isHTTP    bool
	updatedAt time.Time
}

var (
	probeMu    sync.RWMutex
	probeCache = make(map[int]probeEntry)
)

const negativeCacheTTL = 15 * time.Second

// IsHTTPService attempts a fast TCP handshake and sends an HTTP HEAD probe to 127.0.0.1:port.
// It returns true if the service is a plain HTTP service (and NOT already HTTPS/TLS).
func IsHTTPService(port int, timeout time.Duration) bool {
	// 1. Fast TLS pre-check: If the port successfully completes a TLS handshake,
	// it is ALREADY an HTTPS/TLS service. We must not upgrade or wrap it again!
	tlsDialer := &net.Dialer{Timeout: timeout / 2}
	tlsConn, err := tls.DialWithDialer(tlsDialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err == nil {
		_ = tlsConn.Close()
		return false
	}

	// 2. Plaintext HTTP probe
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send minimal HTTP HEAD request
	probeReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\nUser-Agent: nasconnplus-probe\r\n\r\n", port)
	if _, err := conn.Write([]byte(probeReq)); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return false
	}

	resp := string(buf[:n])
	if !strings.HasPrefix(resp, "HTTP/") {
		return false
	}

	// 3. Inspect status code and body:
	// Go net/http, nginx, Apache etc. return plaintext "400 Bad Request" if a plain HTTP request
	// is sent to an HTTPS listener (e.g. "Client sent an HTTP request to an HTTPS server" or "497").
	// We must not mistake these for valid plain HTTP backends!
	lines := strings.Split(resp, "\r\n")
	if len(lines) == 0 {
		return false
	}
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			if code == 400 || code == 497 {
				lower := strings.ToLower(resp)
				if strings.Contains(lower, "https") || strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") {
					return false
				}
			}
			// Status codes 200..499 are standard HTTP responses
			if code >= 200 && code <= 499 {
				return true
			}
		}
	}

	return true
}

// ProbeHTTP checks the cached detection result or executes a probe
func ProbeHTTP(port int) bool {
	probeMu.RLock()
	entry, ok := probeCache[port]
	probeMu.RUnlock()

	if ok {
		// Positive results are cached indefinitely until port closes.
		// Negative results are retried after TTL (allows slow-starting containers to be discovered).
		if entry.isHTTP || time.Since(entry.updatedAt) < negativeCacheTTL {
			return entry.isHTTP
		}
	}

	isHTTP := IsHTTPService(port, 400*time.Millisecond)

	probeMu.Lock()
	probeCache[port] = probeEntry{
		isHTTP:    isHTTP,
		updatedAt: time.Now(),
	}
	probeMu.Unlock()

	return isHTTP
}

// CleanProbeCache prunes ports that are no longer active
func CleanProbeCache(activePorts map[int]bool) {
	probeMu.Lock()
	defer probeMu.Unlock()

	for p := range probeCache {
		if !activePorts[p] {
			delete(probeCache, p)
		}
	}
}

// ResetProbeCache clears the entire probe cache (useful for testing)
func ResetProbeCache() {
	probeMu.Lock()
	defer probeMu.Unlock()
	probeCache = make(map[int]probeEntry)
}
