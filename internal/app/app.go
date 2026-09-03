package app

import (
	"context"
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
	// Handle `nasconnplus status`, `nasconnplus status -c x`, `nasconnplus -c x status`
	// Filter literal "status" token and parse remaining flags properly, respecting -c value
	args := os.Args[1:]
	var filtered []string
	statusFromArg := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "status" {
			isValue := false
			if i > 0 {
				prev := args[i-1]
				if prev == "-c" || prev == "-config" || prev == "--config" {
					isValue = true
				}
			}
			if !isValue {
				statusFromArg = true
				continue
			}
		}
		filtered = append(filtered, arg)
	}
	if statusFromArg {
		*statusFlag = true
	}
	_ = flag.CommandLine.Parse(filtered)

	if *versionFlag {
		fmt.Printf("nasconn+ v%s (built %s, %s/%s)\n", Version, BuildDate, runtime.GOOS, runtime.GOARCH)
		return
	}

	log := logger.New()

	if *statusFlag {
		report, err := ipc.QueryStatus(ipc.DefaultSocketPath())
		if err != nil {
			log.Warn("%v", err)
			return
		}
		fmt.Println(ipc.RenderStatus(report))
		return
	}

	if *testFlag {
		log.Banner(Version)
		log.Info("Running network diagnostic scan...")
		res, err := scanner.Scan()
		if err != nil {
			log.Warn("Diagnostic scan failed: %v", err)
			return
		}

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

	resolvedPath := config.ResolveConfigPath(*configPathFlag)
	cfg, err := config.LoadConfig(resolvedPath)
	if err != nil {
		log.Warn("Configuration error: %v", err)
		return
	}

	log.Banner(Version)
	log.Info("Starting service with config: %s", resolvedPath)
	log.Info("Settings: poll=%ds, grace_polls=%d, https_rules=%d, relay_auto=%v",
		cfg.PollSeconds, cfg.GracePolls, len(cfg.HTTPS), cfg.Relay.Auto)

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

	srv := proxy.NewService(cfg, log, cm)
	startTime := time.Now()

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	go func() {
		select {
		case <-sig:
			log.Info("Received termination signal, shutting down gracefully...")
			cancel()
		case <-ctx.Done():
		}
	}()

	ticker := time.NewTicker(time.Duration(cfg.PollSeconds) * time.Second)
	defer ticker.Stop()

	runReconcile(log, cm, srv)

	for {
		select {
		case <-ctx.Done():
			log.Info("Shutting down...")
			srv.Shutdown()
			return
		case <-ticker.C:
			runReconcile(log, cm, srv)
		}
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
