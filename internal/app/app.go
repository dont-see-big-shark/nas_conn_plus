package app

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/jadenjoe/nasconnplus/internal/cert"
	"github.com/jadenjoe/nasconnplus/internal/config"
	"github.com/jadenjoe/nasconnplus/internal/ipc"
	"github.com/jadenjoe/nasconnplus/internal/logger"
	"github.com/jadenjoe/nasconnplus/internal/proxy"
	"github.com/jadenjoe/nasconnplus/internal/scanner"
)

var (
	Version   = "1.0.0"
	BuildDate = "2026-09-03"
)

func Run() {
	configPathFlag := flag.String("c", "", "Path to configuration file (default: ./config.json or /etc/nasconnplus/config.json)")
	flag.StringVar(configPathFlag, "config", "", "Path to configuration file (alias for -c)")

	testFlag := flag.Bool("t", false, "Diagnostic mode: scan open ports and print report, then exit")
	flag.BoolVar(testFlag, "test", false, "Diagnostic mode (alias for -t)")

	statusFlag := flag.Bool("s", false, "Status mode: query running nasconnplus daemon status and traffic metrics")
	flag.BoolVar(statusFlag, "status", false, "Status mode (alias for -s)")

	versionFlag := flag.Bool("v", false, "Show version and build info")
	flag.BoolVar(versionFlag, "version", false, "Show version and build info (alias for -v)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [command]\n\nCommands:\n  status       Query running daemon status\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	// Ergonomic subcommand support: `nasconnplus status`
	if len(os.Args) > 1 && os.Args[1] == "status" {
		*statusFlag = true
		if len(os.Args) > 2 {
			_ = flag.CommandLine.Parse(os.Args[2:])
		}
	} else {
		flag.Parse()
	}

	if *versionFlag {
		fmt.Printf("nasconn+ v%s (built %s, %s/%s)\n", Version, BuildDate, runtime.GOOS, runtime.GOARCH)
		return
	}

	log := logger.New()

	// Status query mode: connects to running daemon via IPC Unix socket
	if *statusFlag {
		report, err := ipc.QueryStatus(ipc.DefaultSocketPath())
		if err != nil {
			log.Warn("%v", err)
			os.Exit(1)
		}
		fmt.Println(ipc.RenderStatus(report))
		return
	}

	// Diagnostic mode: run scan once and print result table
	if *testFlag {
		log.Banner(Version)
		log.Info("Running network diagnostic scan...")
		res, err := scanner.Scan()
		if err != nil {
			log.Warn("Diagnostic scan failed: %v", err)
			os.Exit(1)
		}

		// Read exclusions from active config if available
		var excludes []int
		resolvedPath := config.ResolveConfigPath(*configPathFlag)
		if cfg, err := config.LoadConfig(resolvedPath); err == nil {
			seen := make(map[int]bool)
			for _, p := range cfg.Relay.Exclude {
				if !seen[p] {
					seen[p] = true
					excludes = append(excludes, p)
				}
			}
			for _, p := range cfg.HTTPSExclude {
				if !seen[p] {
					seen[p] = true
					excludes = append(excludes, p)
				}
			}
		}

		fmt.Println("\n" + res.DiagnosticReport(excludes))
		return
	}

	// Load Configuration
	resolvedPath := config.ResolveConfigPath(*configPathFlag)
	cfg, err := config.LoadConfig(resolvedPath)
	if err != nil {
		log.Warn("Configuration error: %v", err)
		os.Exit(1)
	}

	log.Banner(Version)
	log.Info("Starting service with config: %s", resolvedPath)
	log.Info("Settings: poll=%ds, grace_polls=%d, https_rules=%d, relay_auto=%v",
		cfg.PollSeconds, cfg.GracePolls, len(cfg.HTTPS), cfg.Relay.Auto)

	// Initialize Certificate Manager
	cm := cert.NewManager(
		cfg.CertConfigPath,
		cfg.CertHost,
		cfg.SelfDir,
		cfg.FallbackSelf != nil && *cfg.FallbackSelf,
		cfg.ACME.Enabled,
		cfg.ACME.Domain,
		cfg.ACME.Email,
		cfg.ACME.CacheDir,
	)
	if err := cm.Refresh(); err != nil {
		log.Warn("Certificate initialization: %v", err)
	} else {
		if cfg.ACME.Enabled {
			log.Info("TLS certificate ready (ACME enabled for %s)", cfg.ACME.Domain)
		} else {
			log.Info("TLS certificate loaded successfully (Host: %s)", cfg.CertHost)
		}
	}

	// Initialize Proxy Service
	srv := proxy.NewService(cfg, log, cm)
	startTime := time.Now()

	// Start IPC Status Server for `nasconnplus status` CLI ergonomics
	ipcServer, err := ipc.StartServer(ipc.DefaultSocketPath(), func() ipc.StatusReport {
		return ipc.StatusReport{
			Version:       Version,
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
			Timestamp:     time.Now(),
			Listeners:     srv.GetMetricsSnapshot(),
		}
	})
	if err != nil {
		log.Warn("IPC status server unavailable: %v", err)
	} else {
		defer ipcServer.Close()
	}

	// Graceful Shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		log.Info("Received termination signal, shutting down gracefully...")
		if ipcServer != nil {
			_ = ipcServer.Close()
		}
		srv.Shutdown()
		os.Exit(0)
	}()

	// Main Reconcile Loop
	ticker := time.NewTicker(time.Duration(cfg.PollSeconds) * time.Second)
	defer ticker.Stop()

	// Initial scan immediately
	runReconcile(log, cm, srv)

	for range ticker.C {
		runReconcile(log, cm, srv)
	}
}

func runReconcile(log *logger.Logger, cm *cert.Manager, srv *proxy.Service) {
	res, err := scanner.Scan()
	if err != nil {
		log.Warn("Port scan failed: %v (retaining current state)", err)
		return
	}

	if cerr := cm.Refresh(); cerr != nil {
		log.Warn("Certificate refresh check: %v", cerr)
	}

	srv.Reconcile(res)
}
