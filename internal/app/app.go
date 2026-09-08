package app

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof" // #nosec G108 - pprof endpoint is only bound when user explicitly provides --debug-addr
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/cert"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/config"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/ipc"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/logger"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/metrics"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/proxy"
	"github.com/dont-see-big-shark/nas_conn_plus/internal/scanner"
)

var (
	Version   = "1.1.0"
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

	socketFlag := flag.String("socket", "", "Path to IPC Unix domain socket (default: automatic)")
	debugAddrFlag := flag.String("debug-addr", "", "Enable pprof HTTP debug server on specified address (e.g. 127.0.0.1:6060, default disabled)")

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
				if prev == "-c" || prev == "-config" || prev == "--config" || prev == "-socket" {
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
		sockPath := *socketFlag
		if sockPath == "" {
			resolvedPath := config.ResolveConfigPath(*configPathFlag)
			// Pure read: a status query must never create config files.
			if cfg, err := config.LoadConfigFile(resolvedPath); err == nil && cfg.SocketPath != "" {
				sockPath = cfg.SocketPath
			} else {
				sockPath = ipc.DefaultSocketPath()
			}
		}
		report, err := ipc.QueryStatus(sockPath)
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

		diagnosticOpts := scanner.DiagnosticOptions{HTTPSAuto: true, HTTPSOffset: 1}
		var excludes []int
		resolvedPath := config.ResolveConfigPath(*configPathFlag)
		// Pure read: diagnostics must reflect the file, never create one.
		if cfg, err := config.LoadConfigFile(resolvedPath); err == nil {
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
			diagnosticOpts.HTTPSOffset = cfg.HTTPSOffset
			diagnosticOpts.HTTPSAuto = cfg.HTTPSAuto != nil && *cfg.HTTPSAuto
			diagnosticOpts.HTTPSMode = cfg.HTTPSMode
			diagnosticOpts.HTTPSAllow = cfg.HTTPSAllow
		}

		diagnosticOpts.ExcludedPorts = excludes
		fmt.Println("\n" + res.DiagnosticReport(diagnosticOpts))
		return
	}

	resolvedPath := config.ResolveConfigPath(*configPathFlag)
	// Split I/O: Ensure is the only writer, LoadFile is a pure reader.
	if _, err := config.EnsureDefaultConfig(resolvedPath); err != nil {
		log.Warn("Configuration error: %v", err)
		return
	}
	cfg, err := config.LoadConfigFile(resolvedPath)
	if err != nil {
		log.Warn("Configuration error: %v", err)
		return
	}
	if cfg.OverrideDefaultExcludes {
		log.Warn("override_default_excludes=true: built-in %d-port deny list DISABLED, only your explicit excludes apply", len(config.DefaultExcludePorts))
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
		if initErr := cm.ACMEInitError(); initErr != nil {
			log.Warn("ACME unavailable: %v", initErr)
		}
		if cm.ACMEReady() {
			log.Info("TLS certificate ready (ACME enabled for %s)", cfg.ACME.Domain)
		} else {
			log.Info("TLS certificate loaded successfully (Host: %s)", cfg.CertHost)
		}
	}

	srv := proxy.NewService(cfg, log, cm)
	startTime := time.Now()

	sockPath := *socketFlag
	if sockPath == "" {
		if cfg.SocketPath != "" {
			sockPath = cfg.SocketPath
		} else {
			sockPath = ipc.DefaultSocketPath()
		}
	}

	ipcServer, err := ipc.StartServer(sockPath, func() ipc.StatusReport {
		return ipc.StatusReport{
			Version:       Version,
			UptimeSeconds: int64(time.Since(startTime).Seconds()),
			Timestamp:     time.Now(),
			Listeners:     srv.GetMetricsSnapshot(),
		}
	})
	if err != nil {
		log.Warn("IPC status server unavailable at %s: %v", sockPath, err)
	} else {
		defer ipcServer.Close()
	}

	if *debugAddrFlag != "" {
		if !isLoopbackDebugAddr(*debugAddrFlag) {
			log.Warn("refusing to expose pprof/metrics on non-loopback %q; bind 127.0.0.1:6060 instead", *debugAddrFlag)
		} else {
			mux := http.NewServeMux()
			mux.Handle("/metrics", metrics.Handler())
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			debugSrv := &http.Server{
				Addr:              *debugAddrFlag,
				Handler:           mux,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    1 << 20,
			}
			go func() {
				log.Info("pprof debug server active on http://%s/debug/pprof/", *debugAddrFlag)
				if err := debugSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Warn("pprof debug server error: %v", err)
				}
			}()
			defer func() {
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer shutdownCancel()
				_ = debugSrv.Shutdown(shutdownCtx)
			}()
		}
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

func isLoopbackDebugAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		// Empty host (":6060") means all interfaces: refuse.
		// "localhost" resolves to loopback on all supported platforms.
		return host != ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func runReconcile(log *logger.Logger, cm *cert.Manager, srv *proxy.Service) {
	start := time.Now()
	res, err := scanner.Scan()
	if err != nil {
		metrics.ObserveReconcile(time.Since(start), err)
		log.Warn("Port scan failed: %v (retaining current state)", err)
		return
	}

	if cerr := cm.Refresh(); cerr != nil {
		log.Warn("Certificate refresh check: %v", cerr)
	}

	srv.Reconcile(res)
	metrics.ObserveReconcile(time.Since(start), nil)
}
