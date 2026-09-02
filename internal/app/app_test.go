package app

import (
	"flag"
	"os"
	"testing"

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
