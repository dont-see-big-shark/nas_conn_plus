package app

import (
	"flag"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/cert"
	"github.com/jadenjoe/nasconnplus/internal/config"
	"github.com/jadenjoe/nasconnplus/internal/logger"
	"github.com/jadenjoe/nasconnplus/internal/proxy"
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

func TestApp_Run_DebugPprof(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := tempDir + "/config.json"
	sockPath := tempDir + "/nasconn.sock"

	cfg := `{
		"cert_host": "localhost",
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
		if err == nil {
			resp.Body.Close()
		}
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGINT)
		}
	}()

	Run()
}

