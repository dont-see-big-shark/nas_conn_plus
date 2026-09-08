package app

import (
	"flag"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/cert"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/config"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/logger"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/proxy"
)

func TestApp_RunReconcile(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		CertHost: "localhost",
		Relay:    config.RelayCfg{Auto: false},
	}
	cm := cert.NewManager("", "localhost", tempDir, true, false, "", "", "")
	_ = cm.Refresh()
	lg := logger.New()
	srv := proxy.NewService(cfg, lg, cm)
	defer srv.Shutdown()

	// runReconcile should execute without panics
	runReconcile(lg, cm, srv)
}

func TestApp_Run_Version(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-v"}

	Run()
}

func TestApp_Run_Diagnostic(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-t"}

	Run()
}

func TestApp_Run_Status(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "status", "-socket", "/nonexistent/socket.sock"}

	Run()
}

func TestApp_Run_ConfigError(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-c", "/path/that/does/not/exist.json"}

	Run()
}

func TestApp_Run_FullCycle(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := tempDir + "/config.json"
	sockPath := tempDir + "/nasconn.sock"

	cfg := `{
		"cert_host": "localhost",
		"auto_trust_local_ca": false,
		"self_dir": "` + tempDir + `",
		"socket_path": "` + sockPath + `",
		"poll_seconds": 1,
		"relay": {"auto": false},
		"https_auto": false
	}`

	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-c", cfgPath}

	go func() {
		time.Sleep(100 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGINT)
		}
	}()

	Run()
}

func TestIsLoopbackDebugAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:6060", true},
		{"127.0.0.2:6060", true}, // whole 127/8 is loopback
		{"::1:6060", false},      // missing brackets: invalid SplitHostPort target
		{"[::1]:6060", true},
		{"[::ffff:127.0.0.1]:6060", true}, // v4-mapped loopback
		{"localhost:6060", true},
		{":6060", false}, // empty host = all interfaces: refuse
		{"0.0.0.0:6060", false},
		{"[::]:6060", false},
		{"192.168.1.1:6060", false},
		{"not-an-addr", false},
	}
	for _, c := range cases {
		if got := isLoopbackDebugAddr(c.addr); got != c.want {
			t.Errorf("isLoopbackDebugAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestApp_Run_DebugNonLoopbackRefused(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := tempDir + "/config.json"
	sockPath := tempDir + "/nasconn.sock"

	cfg := `{
		"cert_host": "localhost",
		"auto_trust_local_ca": false,
		"self_dir": "` + tempDir + `",
		"socket_path": "` + sockPath + `",
		"poll_seconds": 1,
		"relay": {"auto": false},
		"https_auto": false
	}`

	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-c", cfgPath, "-debug-addr", "0.0.0.0:6066"}

	go func() {
		time.Sleep(200 * time.Millisecond)
		// Refused: no listener may exist on the loopback alias of that port.
		if resp, err := http.Get("http://127.0.0.1:6066/metrics"); err == nil {
			resp.Body.Close()
			t.Error("non-loopback debug addr must not start a server")
		}
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGINT)
		}
	}()

	Run()
}

func TestApp_Run_OverrideWarn(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := tempDir + "/config.json"
	sockPath := tempDir + "/nasconn.sock"

	cfg := `{
		"cert_host": "localhost",
		"auto_trust_local_ca": false,
		"self_dir": "` + tempDir + `",
		"socket_path": "` + sockPath + `",
		"poll_seconds": 1,
		"override_default_excludes": true,
		"relay": {"auto": false},
		"https_auto": false
	}`

	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-c", cfgPath}

	go func() {
		time.Sleep(100 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGINT)
		}
	}()

	Run()
}

func TestApp_Run_DebugPprof(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := tempDir + "/config.json"
	sockPath := tempDir + "/nasconn.sock"

	cfg := `{
		"cert_host": "localhost",
		"auto_trust_local_ca": false,
		"self_dir": "` + tempDir + `",
		"socket_path": "` + sockPath + `",
		"poll_seconds": 1,
		"relay": {"auto": false},
		"https_auto": false
	}`

	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}

	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	flag.CommandLine = flag.NewFlagSet("nasconnplus", flag.ContinueOnError)
	os.Args = []string{"nasconnplus", "-c", cfgPath, "-debug-addr", "127.0.0.1:6065"}

	go func() {
		time.Sleep(150 * time.Millisecond)
		resp, err := http.Get("http://127.0.0.1:6065/debug/pprof/")
		if err != nil {
			t.Errorf("pprof endpoint error: %v", err)
		} else {
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected 200 OK for pprof, got %d", resp.StatusCode)
			}
		}

		respM, err := http.Get("http://127.0.0.1:6065/metrics")
		if err != nil {
			t.Errorf("metrics endpoint error: %v", err)
		} else {
			respM.Body.Close()
			if respM.StatusCode != http.StatusOK {
				t.Errorf("expected 200 OK for metrics, got %d", respM.StatusCode)
			}
		}

		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGINT)
		}
	}()

	Run()
}
