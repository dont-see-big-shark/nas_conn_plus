package ipc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Server struct {
	path      string
	ln        net.Listener
	provider  func() StatusReport
	stop      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// StartServer creates and serves a Unix domain socket with strict 0600 permissions
// It uses Lstat before Remove to avoid TOCTOU symlink attacks and ensures parent dir is 0700.
func StartServer(socketPath string, provider func() StatusReport) (*Server, error) {
	socketPath = filepath.Clean(socketPath)

	dir := filepath.Dir(socketPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create socket dir %s: %w", dir, err)
		}
	}

	// TOCTOU-safe cleanup: Lstat first to ensure we don't follow symlinks blindly
	if fi, err := os.Lstat(socketPath); err == nil {
		mode := fi.Mode()
		if mode&os.ModeSymlink != 0 {
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("remove stale symlink socket %s: %w", socketPath, err)
			}
		} else if mode&os.ModeSocket != 0 {
			if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
				return nil, fmt.Errorf("remove stale socket %s: %w", socketPath, err)
			}
		} else {
			return nil, fmt.Errorf("socket path %s exists and is not a socket (mode %v)", socketPath, mode)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("lstat socket %s: %w", socketPath, err)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(socketPath, 0o600)

	s := &Server{
		path:     socketPath,
		ln:       ln,
		provider: provider,
		stop:     make(chan struct{}),
	}

	s.wg.Add(1)
	go s.serve()

	return s, nil
}

func (s *Server) serve() {
	defer s.wg.Done()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}

			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			errStr := err.Error()
			if strings.Contains(errStr, "too many open files") ||
				strings.Contains(errStr, "too many") ||
				strings.Contains(errStr, "no buffer space") ||
				strings.Contains(errStr, "resource temporarily unavailable") ||
				strings.Contains(errStr, "temporary") {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if strings.Contains(errStr, "use of closed network connection") {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}

		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	report := s.provider()
	_ = json.NewEncoder(conn).Encode(report)
}

// Close gracefully stops the server and cleans up the socket file (idempotent)
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.stop)
		err = s.ln.Close()
		_ = os.Remove(s.path)
		s.wg.Wait()
	})
	return err
}
