# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- GitHub Actions CI workflow with multi-version Go matrix and automated test coverage reporting.
- Standard community health documents (`CONTRIBUTING.md`, `SECURITY.md`, Issue & PR templates).
- Make targets for automated test coverage and HTML report generation (`make test-coverage`).

---

## [1.0.0] - 2026-09-03

### Added
- **ProcFS Port Discovery**: Zero-dependency, high-speed `/proc/net/tcp` and `/proc/net/tcp6` kernel socket scanner with inode-to-PID mapping and caching.
- **Smart IPv6 Relay (L4)**: Automatic zero-copy relay using Google's `inetaf/tcpproxy` and Linux kernel `splice(2)` for high-throughput, low-latency forwarding.
- **HTTPS Auto-Upgrade (L7)**: Automated HTTP port sniffing and HTTPS reverse proxy on `Port + 1` with reverse proxy header injection (`X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP`).
- **Native Dual-Stack Handover**: Automatically yields port if the backend service natively binds to IPv6 dual-stack (`[::]`).
- **Three-Tier TLS Management**:
  - Automatic Let's Encrypt certificates via ACME (`autocert`).
  - Hot-reloading external custom certificates.
  - Built-in 10-year ECDSA P-256 self-signed certificate generation as fallback.
- **IPC Status Dashboard**: Dedicated Unix domain socket IPC for querying real-time traffic statistics (`nasconnplus status`).
- **CLI Ergonomics**: Lipgloss-styled terminal diagnostics (`nasconnplus -t`) and rich status reporting.
- **Deployment Artifacts**: Production Systemd service file and multi-architecture Docker Compose setup.
