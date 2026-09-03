package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/metrics"
)

type probeEntry struct {
	isHTTP    bool
	updatedAt time.Time
}

var (
	probeMu    sync.RWMutex
	probeCache = make(map[int]probeEntry)
	// singleflight for thundering-herd suppression
	flightMu   sync.Mutex
	flightWait = make(map[int][]chan bool)
)

const (
	negativeCacheTTL = 15 * time.Second
	positiveCacheTTL = 5 * time.Minute
	maxProbeParallel = 16
)

// IsHTTPService attempts a fast TCP handshake and sends an HTTP HEAD probe.
// It tries 127.0.0.1 first and falls back to ::1 for v6-only services.
// It returns true if the service is a plain HTTP service (and NOT already HTTPS/TLS).
func IsHTTPService(port int, timeout time.Duration) bool {
	if isHTTPServiceOnHost("127.0.0.1", port, timeout) {
		return true
	}
	return isHTTPServiceOnHost("::1", port, timeout)
}

func isHTTPServiceOnHost(host string, port int, timeout time.Duration) bool {
	// 1. Fast TLS pre-check: If the port successfully completes a TLS handshake,
	// it is ALREADY an HTTPS/TLS service. We must not upgrade or wrap it again!
	tlsDialer := &net.Dialer{Timeout: timeout / 2}
	// #nosec G402 - probe must check local port regardless of certificate validity
	tlsConn, err := tls.DialWithDialer(tlsDialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err == nil {
		_ = tlsConn.Close()
		return false
	}

	// 2. Plaintext HTTP probe
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send minimal HTTP HEAD request
	probeReq := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\nUser-Agent: nasconnplus-probe\r\n\r\n", port)
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

// ProbeHTTP checks the cached detection result or executes a probe.
// It uses singleflight per port to suppress thundering herds and TTLs for
// both negative (15s) and positive (5m) results.
func ProbeHTTP(port int) bool {
	probeMu.RLock()
	entry, ok := probeCache[port]
	probeMu.RUnlock()
	if ok {
		ttl := negativeCacheTTL
		if entry.isHTTP {
			ttl = positiveCacheTTL
		}
		if time.Since(entry.updatedAt) < ttl {
			return entry.isHTTP
		}
	}

	// singleflight: if another goroutine is probing the same port, wait for it.
	// The owner always finishes within ~2x timeout (bounded dials), but wait
	// with a deadline anyway so a stuck owner can never park us forever.
	// The wait channel is buffered (cap 1), so a timed-out waiter never
	// blocks the owner's broadcast.
	flightMu.Lock()
	if chans, inFlight := flightWait[port]; inFlight {
		ch := make(chan bool, 1)
		flightWait[port] = append(chans, ch)
		flightMu.Unlock()
		select {
		case v := <-ch:
			return v
		case <-time.After(5 * time.Second):
			return IsHTTPService(port, 400*time.Millisecond)
		}
	}
	flightWait[port] = []chan bool{}
	flightMu.Unlock()

	isHTTP := IsHTTPService(port, 400*time.Millisecond)

	probeMu.Lock()
	probeCache[port] = probeEntry{isHTTP: isHTTP, updatedAt: time.Now()}
	probeMu.Unlock()
	metrics.ObserveProbe(isHTTP)

	flightMu.Lock()
	for _, ch := range flightWait[port] {
		ch <- isHTTP
	}
	delete(flightWait, port)
	flightMu.Unlock()

	return isHTTP
}

// ProbePorts probes multiple ports in parallel with bounded concurrency.
func ProbePorts(ports []int) map[int]bool {
	out := make(map[int]bool, len(ports))
	if len(ports) == 0 {
		return out
	}
	sem := make(chan struct{}, maxProbeParallel)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := ProbeHTTP(p)
			mu.Lock()
			out[p] = res
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return out
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

// ResetProbeCache clears the entire probe cache (useful for testing).
// It also drops pending singleflight waiters so no test can inherit a stale
// in-flight entry from a previous one.
func ResetProbeCache() {
	probeMu.Lock()
	probeCache = make(map[int]probeEntry)
	probeMu.Unlock()

	flightMu.Lock()
	flightWait = make(map[int][]chan bool)
	flightMu.Unlock()
}
