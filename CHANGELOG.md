# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
