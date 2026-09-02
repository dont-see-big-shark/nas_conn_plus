package ipc

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

type Server struct {
	path     string
	ln       net.Listener
	provider func() StatusReport
	stop     chan struct{}
	wg       sync.WaitGroup
}

// StartServer creates and serves a Unix domain socket for IPC status queries
func StartServer(socketPath string, provider func() StatusReport) (*Server, error) {
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(socketPath, 0o666)

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
				return
			}
		}

		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	report := s.provider()
	_ = json.NewEncoder(conn).Encode(report)
}

// Close gracefully stops the server and cleans up the socket file
func (s *Server) Close() error {
	close(s.stop)
	err := s.ln.Close()
	_ = os.Remove(s.path)
	s.wg.Wait()
	return err
}
