# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-03

This release closes the correctness and hardening backlog from the v1.0.x
security and QA reviews: two CRITICAL stability bugs, one remotely
exploitable header-injection flaw, IPC/config hardening, and a wave of
robustness fixes. No config file changes are required to upgrade.

### Highlights
- **No more listener cascade / port theft**: self-owned listener ports are
  excluded from auto-discovery, target occupancy is decided by real `bind`
  (`EADDRINUSE`) instead of wildcard tables, and conflicts retry on the next
  poll instead of stealing a neighbour's port.
- **Header injection fixed**: the L7 proxy moved from `Director` to `Rewrite`,
  so forged `X-Forwarded-For` / `Forwarded` and `Connection:`-driven header
  stripping no longer reach backends.
- **Certificates actually reload**: external and self-signed certificates are
  fingerprinted by content + mtime (was: file path / static string), so
  certbot-style in-place renewals take effect without a restart.
- **Safer defaults, honest docs**: the generated config now embeds the full
  19-port deny list, `override_default_excludes=true` logs a WARN, and the
  debug endpoint refuses non-loopback binds.

### Security fixes
- L7 `X-Forwarded-*` / `Forwarded` spoofing via `Director` + `Connection:`
  header stripping (remote, unauthenticated) — fixed with `Rewrite`.
- Unix socket created with umask-narrowed `0600`, `Lstat`-before-remove,
  client read deadline (5s) + 1MB cap, ANSI/control-char sanitizing and
  field truncation in status rendering.
- `--debug-addr` on a non-loopback address is now refused; debug uses an
  isolated `ServeMux` with full timeouts; loopback detection covers all of
  `127/8` and v4-mapped IPv6.
- `..` rejected in `socket_path`, `cert_config_path`, `selfsigned_dir` and
  `acme.cache_dir`; CWD trust check hardened (`/private/tmp`, `/dev/shm`,
  no false positive on `/tmpfoo`).
- CI: `govulncheck` is now a blocking gate (`gosec` / `golangci-lint` stay
  advisory until their baseline is clean).

### Behavior changes
- `status` and `-t` are pure reads and never create config files; only the
  daemon bootstraps a default config on first start.
- Self-signed fallback validity is 825 days (was 10 years).
- `MaxResponseHeaderBytes` 8K -> 32K (SSO-heavy backends such as DSM were
  getting 502s); `GracePolls` is clamped to 120.
- `tryListen` failures now log the real errno (`EADDRINUSE` vs `EACCES`).
- `ss` fallback parser handles both Netid-prefixed and bare `ss -tlnp`
  output; probe singleflight waiters have a 5s fallback deadline.

### Performance
- True kernel `splice(2)` zero-copy: relay connections unwrap to raw `*net.TCPConn` on both sides, enabling Go's Linux splice pipe optimization, 30s TCP keepalives, and half-close signaling without userspace memory copy; `relay.zero_copy` defaults to `true`.
- O(1) exclude/allow sets, per-inode `RLock` lookups, 10s inode-refresh
  debounce (test-injectable), singleflight + TTL probe cache (negative 15s /
  positive 5m), bounded `ProbePorts` parallelism (16), `Service.mu` ->
  `RWMutex`, zero-alloc buffer pool fix.

### Observability
- New dependency-free `internal/metrics` (`nasconn_reconciles_total`,
  `nasconn_reconcile_errors_total`, `nasconn_reconcile_last_duration_ms`,
  `nasconn_probes_total`, `nasconn_probes_http_total`) served at `/metrics`
  on the debug address.

### Tests
- Total statement coverage **83.4% -> 82.5%** (`go test -race
  -covermode=atomic`; delta is new defensive branches, per-package rows vary
  by OS — Linux CI is canonical).
- New: `tui` 100%, `metrics` 100%, config set/allow + Ensure/LoadFile tests, `formatBytes` MaxUint64 test, `bytePool` size-guard test, `FuzzParseSSOutput`, `BenchmarkBytePoolGetPut` (~43ns/op), `BenchmarkFormatBytes` (`~119ns/op`).
- This round: `TestLimitListenerCloseUnblocksFullAccept`, `TestLimitListenerAcceptReleaseCycle`, `TestTryListenConflictError`, `TestTryListenPrivilegedPortError`, `TestIsLoopbackDebugAddr`, `TestApp_Run_DebugNonLoopbackRefused`, `TestApp_Run_OverrideWarn`, `TestCertManager_SelfSignedRotation`, `TestCertManager_ACMEFailureSurfacesWithoutCert`, `TestParseSSOutputFormats`, `TestShouldRefreshInodesCooldown`, `TestDefaultConfigTextMatchesDenyList`, `TestUntrustedCWD`, `TestGracePollsClamped`, `TestTraversalPathsRejected`, `TestTruncateRunes`, `TestRenderStatusSanitizesUntrustedFields`.

## [1.0.1] - 2026-09-03

### Changed
- **Go Module Path Alignment**: Refactored module path from placeholder to canonical `github.com/dont-see-big-shark/nas_conn_plus` across all packages, imports, build scripts, Dockerfile, CI/CD release workflow, and documentation.
- **Go Ecosystem Distribution**: Enabled one-line worldwide installation via `go install github.com/dont-see-big-shark/nas_conn_plus/cmd/nasconnplus@latest` and indexing on `pkg.go.dev`.

---

## [1.0.0] - 2026-09-03

### Features & Capabilities
- **ProcFS Port Discovery**: Zero-dependency, high-speed `/proc/net/tcp` and `/proc/net/tcp6` kernel socket scanner with inode-to-PID mapping and caching.
- **Smart IPv6 Relay (L4)**: Automatic zero-copy relay using Google's `inetaf/tcpproxy` and Linux kernel `splice(2)` for high-throughput, low-latency forwarding.
- **HTTPS Auto-Upgrade (L7)**: Automated HTTP port sniffing and HTTPS reverse proxy on `Port + 1` with reverse proxy header injection (`X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`, `X-Forwarded-For`).
- **Native Dual-Stack Handover**: Automatically yields port if the backend service natively binds to IPv6 dual-stack (`[::]`), with zero service disruption.
- **Three-Tier TLS Management**:
  - Automatic Let's Encrypt certificates via ACME (`autocert`).
  - Hot-reloading external custom certificates with in-place SHA256 fingerprint deduplication.
  - Built-in 10-year ECDSA P-256 self-signed certificate generation as fallback.
- **Strict Security & Whitelist Mode**:
  - Built-in union protection for 17 high-risk ports (`22, 53, 67, 68, 123, 161, 445, 1883, 2375, 3306, 5432, 6379, 8086, 9000, 9200, 11211, 27017`).
  - Configurable `mode: "auto" | "whitelist"` for declarative access control.
  - RFC 6797 compliant HSTS header injection strictly gated to non-IP, non-self-signed domains.
  - Dropped `CAP_SYS_PTRACE`, `pid: host`, and `privileged: true` via `/proc/self/fd` socket inode matching.
- **IPC Status Dashboard**: Dedicated Unix domain socket IPC for querying real-time traffic statistics (`nasconnplus status`).
- **CLI Ergonomics & Diagnostic Mode**: Lipgloss-styled terminal diagnostics (`nasconnplus -t`) and rich status reporting.
- **Opt-in Performance Profiling**: `--debug-addr` CLI flag for on-demand CPU/heap pprof profiling with zero default exposure.
- **Robust Quality Assurance**: 82.1% statement test coverage with automated data race detection (`-race`) across all core packages.
- **Bilingual Documentation**: Complete documentation in both English (`README.md`) and Simplified Chinese (`README_zh.md`).
- **Deployment Artifacts**: Production Systemd service file and multi-architecture Docker Compose setup.
