package ipc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
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
func StartServer(socketPath string, provider func() StatusReport) (*Server, error) {
	_ = os.Remove(socketPath)

	dir := filepath.Dir(socketPath)
	if dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	// Restrict permissions to owner-only to prevent unauthorized IPC queries
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

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
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
