package scanner

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	probeMu    sync.RWMutex
	probeCache = make(map[int]bool)
)

// IsHTTPService attempts a fast TCP handshake and sends an HTTP HEAD probe to 127.0.0.1:port.
// It returns true if the service responds with standard HTTP protocol header (e.g. HTTP/1.x or HTTP/2).
func IsHTTPService(port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send minimal HTTP request probe
	probeReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\nUser-Agent: nasconnplus-probe\r\n\r\n", port)
	if _, err := conn.Write([]byte(probeReq)); err != nil {
		return false
	}

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil || n < 4 {
		return false
	}

	respHeader := string(buf[:n])
	// Valid HTTP responses start with "HTTP/"
	return strings.HasPrefix(respHeader, "HTTP/")
}

// ProbeHTTP checks the cached detection result or executes a fast probe
func ProbeHTTP(port int) bool {
	probeMu.RLock()
	cached, ok := probeCache[port]
	probeMu.RUnlock()
	if ok {
		return cached
	}

	isHTTP := IsHTTPService(port, 400*time.Millisecond)

	probeMu.Lock()
	probeCache[port] = isHTTP
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
