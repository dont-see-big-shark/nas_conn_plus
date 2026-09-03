package proxy

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/cert"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/config"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/logger"
)

// P0-1 regression: when the semaphore is full, Accept must unblock on Close
// instead of hanging Shutdown forever.
func TestLimitListenerCloseUnblocksFullAccept(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	ln := newLimitListener(base, 1)

	// Occupy the single slot with a real connection.
	dialed, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialed.Close()
	held, err := ln.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	defer held.Close()

	// Second Accept blocks on the full semaphore; Close must release it.
	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		errCh <- err
	}()
	time.Sleep(100 * time.Millisecond) // let it block in acquire
	_ = ln.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected net.ErrClosed, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept stuck in acquire after Close: P0-1 deadlock")
	}
}

// P1: tryListen must surface the real errno so EADDRINUSE (retry helps) is
// distinguishable from EACCES (retry won't help).
func TestTryListenConflictError(t *testing.T) {
	occupant, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer occupant.Close()
	port := occupant.Addr().(*net.TCPAddr).Port

	tempDir := t.TempDir()
	trueVal := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &trueVal,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		Relay:        config.RelayCfg{Auto: false},
	}
	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	_ = cm.Refresh()
	srv := NewService(cfg, logger.New(), cm)
	defer srv.Shutdown()

	// HTTPS binds dual-stack ":port", which overlaps the 127.0.0.1 occupant
	// on most platforms; either way we must get a descriptive error, never a
	// silent nil listener.
	st, err := srv.tryListen(want{kind: "https", name: "conflict", port: port, backend: port})
	if err == nil {
		// Platform allowed coexistence (e.g. SO_REUSEADDR semantics);
		// close the extra listener and pass.
		if st != nil && st.ln != nil {
			_ = st.ln.Close()
		}
		t.Logf("platform permits overlapping bind on :%d, no conflict to report", port)
		return
	}
	for _, want := range []string{"https", "conflict"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("conflict error should name kind/port, got: %v", err)
		}
	}
}

// Privileged ports surface EACCES (not a silent nil) when unprivileged.
func TestTryListenPrivilegedPortError(t *testing.T) {
	tempDir := t.TempDir()
	trueVal := true
	cfg := &config.Config{
		PollSeconds:  1,
		GracePolls:   1,
		FallbackSelf: &trueVal,
		SelfDir:      tempDir,
		CertHost:     "localhost",
		Relay:        config.RelayCfg{Auto: false},
	}
	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	_ = cm.Refresh()
	srv := NewService(cfg, logger.New(), cm)
	defer srv.Shutdown()

	st, err := srv.tryListen(want{kind: "https", name: "priv", port: 1, backend: 1})
	if err == nil {
		// Running as root: bind succeeded, clean up.
		if st != nil && st.ln != nil {
			_ = st.ln.Close()
		}
		t.Log("running as root, privileged bind succeeded")
		return
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should identify the listener, got: %v", err)
	}
}
func TestLimitListenerAcceptReleaseCycle(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	ln := newLimitListener(base, 1)
	defer ln.Close()

	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", base.Addr().String())
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		srv, err := ln.Accept()
		if err != nil {
			c.Close()
			t.Fatalf("accept %d: %v", i, err)
		}
		_ = srv.Close()
		_ = c.Close()
	}
}
