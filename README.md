<div align="center">

# 🚀 nasconn+

**Lightweight connection enhancement daemon engineered for NAS and self-hosted home labs**  
*Overcome IPv4 CGNAT · Automated IPv6 Relay · Port+1 Seamless HTTPS Upgrade*

[![CI](https://github.com/dont-see-big-shark/nas_conn_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/dont-see-big-shark/nas_conn_plus/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/Coverage-82.1%25-brightgreen.svg?logo=codecov)](https://github.com/dont-see-big-shark/nas_conn_plus)
[![Go Report Card](https://goreportcard.com/badge/github.com/dont-see-big-shark/nas_conn_plus)](https://goreportcard.com/report/github.com/dont-see-big-shark/nas_conn_plus)
[![Latest Release](https://img.shields.io/github/v/release/dont-see-big-shark/nas_conn_plus?logo=github&color=3388ff)](https://github.com/dont-see-big-shark/nas_conn_plus/releases)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.22-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20NAS%20%7C%20Docker-lightgrey)](https://github.com/dont-see-big-shark/nas_conn_plus)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](deploy/Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<p align="center">
  <b>Language / 语言:</b>
  <b>English</b> •
  <a href="README_zh.md">简体中文</a>
</p>

<p align="center">
  <a href="#-why-nasconn">Why nasconn+?</a> •
  <a href="#️-architecture--how-it-works">Architecture</a> •
  <a href="#-key-features">Key Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#️-configuration-guide-configjson">Configuration</a> •
  <a href="#-cli--ergonomics">CLI & Ergonomics</a> •
  <a href="#-testing--quality-assurance">Testing & Quality</a> •
  <a href="#️-build-from-source">Build from Source</a> •
  <a href="#-roadmap">Roadmap</a> •
  <a href="#-security-considerations">Security</a> •
  <a href="#-contributing">Contributing</a>
</p>

</div>

---

## 💡 Why nasconn+?

When deploying self-hosted applications on residential broadband or private NAS devices (Synology DSM, fnOS, UGREEN UGOS, ZimaOS, Unraid, TrueNAS, Proxmox VE), users consistently run into two frustrating bottlenecks:

1. **No Public IPv4 Address (Carrier-Grade NAT / CGNAT)**:
   - ISPs rarely assign public IPv4 addresses anymore, but **almost universally provide public IPv6 prefixes (`/64` or `/56`)**.
   - Many legacy services and Docker containers listen strictly on `0.0.0.0` (IPv4-only) by default, rendering them inaccessible from public IPv6 networks.
2. **Modern Browsers Enforcing Secure Contexts on Plain HTTP**:
   - Most self-hosted services (dashboards, cloud drives, photo managers, note-taking apps) expose plain HTTP out of the box.
   - When accessed remotely over non-`localhost` IPs or domains, browsers **disable critical Web APIs**: clipboard copy/paste, Progressive Web App (PWA) installation, camera/mic streaming, geolocation, and even credential autofill.
3. **Traditional Reverse Proxies (Nginx, Caddy, NPM, Traefik) Add Maintenance Burden**:
   - Setting up subdomains, SSL certificates, upstream directives, and DNS mappings for every single container or utility becomes cumbersome and error-prone.

**`nasconn+`** serves as a **zero-intrusion, invisible glue daemon**:
- **Automatic IPv6 Mirroring (Relay)**: Scans local TCP listeners bound strictly to `0.0.0.0`, and dynamically establishes transparent, same-port relaying on `[::]` (IPv6).
- **HTTP Port +1 HTTPS Upgrade**: Without touching existing container setups, `nasconn+` intercepts plain HTTP services and terminates TLS at `port + 1` automatically.

---

## 🛠️ Architecture & How It Works

```text
External Inbound Traffic (Public IPv6 / LAN)
    │
    ├───> [::]:8080 (IPv6) ───[ nasconn+ L4 Relay ]──────> 127.0.0.1:8080 (Local IPv4-Only Service)
    │
    └───> [::]:8081 (HTTPS) ──[ nasconn+ TLS Termination ]─> 127.0.0.1:8080 (Proxied with X-Forwarded headers)
```

### ✨ Key Features

- 🔄 **Adaptive Zero-Config Lifecycle**: Parses Linux kernel `/proc/net/tcp` directly with zero external tool dependencies. Automatically discovers newly started services in milliseconds and gracefully cleans up dead listeners with anti-flap debouncing.
- 🌐 **Intelligent L7 Reverse Proxy (Port + 1 Upgrade)**: Built on Go's standard `httputil.ReverseProxy`. Injects sanitized `X-Forwarded-Proto: https`, `X-Forwarded-Host`, `X-Forwarded-Port`, and `X-Real-IP` headers to **permanently eliminate 302 redirect loops and Mixed Content errors** in apps like 1Panel, Nextcloud, and WordPress. Supports WebSocket pass-through natively.
- 🚀 **High-Performance L4 Zero-Copy Relay**: Leverages Google's `inetaf/tcpproxy` engine. On Linux, transparently delegates socket bridging to kernel `splice(2)` zero-copy pipe operations, slashing CPU cycles and memory allocations under heavy traffic.
- 🤝 **Native Dual-Stack Polite Handover**: If a backend service later updates to natively bind `[::]:port`, `nasconn+` detects the external inode and immediately surrenders the port without downtime or conflicts.
- 🔐 **3-Tier Resilient Certificate Engine**:
  1. Automated Let's Encrypt issuance and renewal via ACME (`autocert`).
  2. Dynamic hot-reloading of custom external PEM certificates (SHA-256 fingerprint deduplication).
  3. Built-in ECDSA P-256 10-year self-signed certificate generation as a dependable fallback.
- 🎨 **Modern Geek Ergonomics**: Stylized CLI and ASCII banners powered by `charmbracelet/lipgloss`. Features a one-shot diagnostic mode (`-t`) that produces formatted terminal tables with color-coded status badges.
- 🛡️ **Defensive Security Baseline**: Hardened with union-merged exclusion lists protecting 17 high-risk infrastructure ports, optional explicit whitelists, connection limits, and RFC 6797-compliant HSTS policy enforcement.

---

## 🚦 Quick Start

### Option 1: Standalone Binary (Recommended for Linux / NAS Host)

1. Download the pre-built tarball for your CPU architecture (`amd64`, `arm64`, or `armv7`) from the [Releases page](https://github.com/dont-see-big-shark/nas_conn_plus/releases).
2. Extract the archive and install the binary:
   ```bash
   tar -zxvf nasconnplus-linux-amd64.tar.gz
   sudo mv nasconnplus /usr/local/bin/
   ```
3. Run a diagnostic check to inspect the host's current listening ports:
   ```bash
   sudo nasconnplus -t
   ```
4. Start the daemon (a default configuration file is automatically created on first launch):
   ```bash
   sudo nasconnplus -c /etc/nasconnplus/config.json
   ```

---

### Option 2: Systemd Daemon Service

To ensure `nasconn+` starts on boot and runs reliably in the background:

1. Create the configuration directory and copy the default config:
   ```bash
   sudo mkdir -p /etc/nasconnplus
   sudo cp config.example.json /etc/nasconnplus/config.json
   ```
2. Install and register the systemd unit:
   ```bash
   sudo cp deploy/nasconnplus.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```
3. Enable and start the service:
   ```bash
   sudo systemctl enable --now nasconnplus
   ```
4. Check service status and live logs:
   ```bash
   sudo systemctl status nasconnplus
   journalctl -u nasconnplus -f
   ```

---

### Option 3: Docker & Docker Compose

For containerized NAS platforms like Synology, fnOS, UGREEN UGOS, ZimaOS, and Unraid:

> [!IMPORTANT]
> #### ⚠️ 4 Crucial Docker Considerations
> `nasconn+` operates as low-level networking infrastructure. For optimal performance and safety:
> 
> 1. **Must use `network_mode: host`**:
>    Docker's default bridge network isolates containers inside a virtual subnet. This prevents `nasconn+` from seeing the host's `0.0.0.0` listeners or binding to the host's public IPv6 address.
> 2. **Least-Privilege Security (No Privileged Mode / No Host PID)**:
>    `nasconn+` inspects `/proc/self/fd` socket inodes natively, entirely eliminating the need for `pid: host`, `privileged: true`, or `CAP_SYS_PTRACE`. It only requires `CAP_NET_BIND_SERVICE` to bind privileged ports (< 1024, like 80/443).
> 3. **Mount Persistent Volumes**:
>    Always mount `./tls` and `./acme_cache`. Without persistent storage, certificates will be regenerated on every container restart, causing SSL certificate fingerprint mismatch warnings in browsers. Mount `/run/nasconnplus` for host CLI IPC communication.
> 4. **Router Inbound IPv6 Firewall Rules**:
>    If your router's firewall blocks unsolicited incoming IPv6 traffic by default, open the necessary inbound IPv6 ports directed to your NAS.

#### Production `docker-compose.yml`:

```yaml
version: '3.8'

services:
  nasconnplus:
    image: nasconnplus:latest
    build:
      context: .
      dockerfile: deploy/Dockerfile
    container_name: nasconnplus
    restart: unless-stopped

    # Essential: Must share the host network stack
    network_mode: host

    # Sandboxed least-privilege security
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp

    volumes:
      # Optional config override
      - ./config.json:/etc/nasconnplus/config.json
      # Mandatory persistent storage for TLS certificates & ACME state
      - ./tls:/etc/nasconnplus/tls
      - ./acme_cache:/etc/nasconnplus/acme_cache
      # Shared socket directory for host CLI queries (nasconnplus status)
      - /run/nasconnplus:/run/nasconnplus

    environment:
      - TZ=Asia/Shanghai
```

Run the container:
```bash
docker compose up -d
```

---

## ⚙️ Configuration Guide (`config.json`)

`nasconn+` is built on a **Zero-Config by Default** philosophy. Sane, production-tested defaults are pre-configured for polling intervals, debouncing counts, idle timeouts, and certificate storage.

### Minimal Recommended Configuration

```json
{
  // Domain or local hostname for TLS certificate SNI matching
  "cert_host": "nas.local",

  // Automatically mirror IPv4-only (0.0.0.0) listeners to IPv6 ([::])
  "relay": {
    "auto": true,
    "exclude": [22, 53]      // Ports to exclude from relay
  },

  // Automatically discover HTTP services and upgrade them to HTTPS on port + 1
  "https_auto": true,
  "https_exclude": [22, 53]  // Ports to exclude from HTTPS upgrade
}
```

### Full Configuration Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `https_offset` | Integer | `1` | Port offset for automatic HTTPS upgrade (e.g. `1` upgrades `8080 -> 8081`) |
| `https` | Array | `[]` | Explicit static HTTPS rules (takes precedence over `https_auto`), e.g. `[{"name": "WebDisk", "http": 8080, "https": 8443}]` |
| `relay.zero_copy` | Boolean | `false` | Enables Linux kernel `splice(2)` zero-copy relaying. Drastically reduces CPU and GC overhead under high throughput (active connections tracked; byte counting bypassed) |
| `relay.allow` | Array | `[]` | Whitelist for IPv6 relaying. If non-empty, only ports listed here are relayed (empty means fully automatic) |
| `https_allow` | Array | `[]` | Whitelist for auto HTTPS upgrade. If non-empty, only ports listed here receive HTTPS upgrades |
| `override_default_excludes` | Boolean | `false` | When `true`, disables the built-in 17 high-risk infrastructure exclusion ports |
| `max_conns_per_listener` | Integer | `2048` | Hard concurrent connection ceiling per listener to guard against file descriptor exhaustion |
| `hsts` | Object | Disabled | Strict-Transport-Security settings: `{"enabled": true, "max_age": 31536000, "include_subdomains": false}` (RFC 6797 compliant: automatically suppressed on IP literals and self-signed certificates) |
| `socket_path` | String | Auto | Path to the Unix Domain Socket for IPC (defaults to `$XDG_RUNTIME_DIR/nasconnplus.sock` or `/run/nasconnplus/nasconnplus.sock`) |
| `acme` | Object | Disabled | Automated Let's Encrypt certificate issuance: `{"enabled": true, "domain": "nas.example.com", "email": "admin@example.com"}` (requires public port 80 accessibility for HTTP-01 challenge) |
| `cert_config_path` | String | `""` | Path to an external JSON file defining custom TLS certificate pairs (supports live reload) |
| `poll_seconds` | Integer | `5` | Background socket scan interval in seconds |
| `grace_polls` | Integer | `2` | Anti-flap debounce threshold: number of consecutive scans a port must be missing before recycling its proxy |
| `idle_seconds` | Integer | `900` | Idle timeout in seconds before reaping inactive TCP connections |

---

## 🔍 CLI & Ergonomics

```text
Usage: nasconnplus [options] [command]

Commands:
  status
        Query live proxy metrics and listener status from the active daemon

Options:
  -c, -config string
        Configuration file path (searches ./config.json, then /etc/nasconnplus/config.json)
  -debug-addr string
        Enable pprof HTTP debug profiling server on specified address (e.g. 127.0.0.1:6060, default disabled)
  -s, -status
        Display running daemon status table (alias for `nasconnplus status`)
  -socket string
        Override the Unix domain socket path used for daemon communication
  -t, -test
        Diagnostic mode: perform a full host port probe and print report, then exit
  -v, -version
        Print version, commit, and runtime architecture
```

#### 📊 Live Status Dashboard (`nasconnplus status` or `nasconnplus -s`):
Query the background daemon from any terminal shell to view listener health, active connections, total processed requests, and bandwidth statistics:

```text
╭──────────┬────────────┬──────────────┬──────────────────┬────────┬────────┬───────┬─────────────────────────┬────────╮
│ SERVICE  │ TYPE       │ LISTEN ADDR  │ BACKEND          │ STATUS │ ACTIVE │ TOTAL │ TRAFFIC (RX / TX)       │ UPTIME │
├──────────┼────────────┼──────────────┼──────────────────┼────────┼────────┼───────┼─────────────────────────┼────────┤
│ 1panel   │ HTTPS (L7) │ https :18091 │ 127.0.0.1:18090  │ ● OK   │ 2      │ 154   │ ↓ 18.25 MB / ↑ 52.10 MB │ 1h 24m │
│ webdisk  │ HTTPS (L7) │ https :8081  │ 127.0.0.1:8080   │ ● OK   │ 1      │ 890   │ ↓ 120.4 MB / ↑ 1.48 GB  │ 1h 24m │
│ relay:22 │ Relay (L4) │ [::]:2222    │ 127.0.0.1:2222   │ ● OK   │ 0      │ 12    │ ↓ 45.00 KB / ↑ 82.30 KB │ 1h 24m │
╰──────────┴────────────┴──────────────┴──────────────────┴────────┴────────┴───────┴─────────────────────────┴────────╯

● Daemon: v1.0.0 | Uptime: 1h 24m | Active Conns: 3 | Total Traffic: 1.67 GB | Total Errors: 0
```

#### 🩺 One-Shot Diagnostic Mode (`nasconnplus -t`):
```text
╭───────┬────────────────┬─────────────┬──────┬───────────┬─────────────────────┬───────────────╮
│ PORT  │ IPv4 (0.0.0.0) │ IPv6 ([::]) │ PID  │ PROCESS   │ RELAY ACTION        │ HTTPS (+1)    │
├───────┼────────────────┼─────────────┼──────┼───────────┼─────────────────────┼───────────────┤
│ 22    │ YES            │ YES         │ 1024 │ sshd      │ ● Native Dual-Stack │ No HTTP       │
│ 3000  │ YES            │ No          │ 4182 │ node      │ ● Will Relay to IPv6│ ✓ https :3001 │
│ 8080  │ YES            │ No          │ 5219 │ java      │ ● Will Relay to IPv6│ ✓ https :8081 │
╰───────┴────────────────┴─────────────┴──────┴───────────┴─────────────────────┴───────────────╯
```

---

## 🔒 Security Considerations

> [!CAUTION]
> Once automated IPv6 relaying is active, if your router allows inbound IPv6 connections, local services previously isolated to private IPv4 **will become directly reachable from the public Internet via IPv6**.

1. **High-Risk Ports Protected by Default**: `nasconn+` maintains an automatic protection list (ports `22, 53, 67, 68, 123, 161, 445, 1883, 2375, 3306, 5432, 6379, 8086, 9000, 9200, 11211, 27017`). User-defined exclusions are merged via union; built-in protections are never wiped out unless explicitly requested via `override_default_excludes: true`.
2. **Router Firewall Hygiene**: We strongly recommend keeping the default drop policy for unsolicited inbound IPv6 traffic on your main gateway router, opening only the specific public ports you need.
3. **Whitelist Mode**: In sensitive environments, configure `"mode": "whitelist"` and populate `relay.allow` / `https_allow` arrays to adopt a strict whitelist approach.
4. **Strong Credentials & 2FA**: Ensure any backend service exposed to the public Internet is protected by strong passwords and Multi-Factor Authentication (MFA).
5. **ACME & HSTS Considerations**:
   - ACME HTTP-01 validation requires public port 80 to be reachable. If your ISP blocks port 80, deploy pre-generated certificates using `cert_config_path` or rely on the internal self-signed generator.
   - HSTS adheres strictly to RFC 6797: it is never injected for bare IP addresses or self-signed certificates, preventing irreversible browser lockouts.

---

## 🧪 Testing & Quality Assurance

All core business modules are verified with automated unit tests, end-to-end integration tests, and Go's race detector (`-race`), continuously audited by GitHub Actions CI. Total codebase statement coverage stands at **82.1%**:

| Package | Responsibility | Statement Coverage | Quality Focus |
| :--- | :--- | :---: | :--- |
| `internal/logger` | Structured terminal formatting & multi-channel logger | **100.0%** | Zero race conditions, graceful NO_COLOR fallback |
| `cmd/nasconnplus` | CLI entry point & binary launcher | **100.0%** | Argument forwarding & lifecycle execution |
| `internal/scanner` | Linux procfs socket sniffing, HTTP probing & diagnostics | **93.8%** | Zero-dependency procfs parsing, self-inode decoupling |
| `internal/config` | Config discovery, recursive parsing & boundary validation | **88.3%** | Whitelist modes, high-risk port union protection |
| `internal/app` | Daemon lifecycle, signal management & reconciliation loop | **85.5%** | Graceful termination, IPC integration, opt-in pprof |
| `internal/ipc` | Unix Domain Socket client/server IPC communication | **84.2%** | 0600 socket permissions, retry logic, status rendering |
| `internal/cert` | TLS certificate manager, ECDSA self-signing & ACME | **76.8%** | Live certificate reload, fingerprint caching, SNI fallback |
| `internal/proxy` | L4 zero-copy TCP relay & L7 HTTPS reverse proxy engine | **69.3%** | Splice zero-copy, connection limiter, HSTS, smooth handover |
| **Total Coverage** | **Entire Codebase Statements** | **`82.1%`** | **Automated CI Validation Across Go Versions** |

### Local Test Execution

```bash
# Run all unit tests
make test

# Run tests and output per-package coverage metrics
make coverage

# Run tests with race detector and generate visual HTML coverage report (coverage.html)
make test-coverage

# Run static analyzers and security linters
make lint
```

---

## 🛠️ Build from Source

Prerequisites: Go (>= 1.22) installed locally.

### Method A: One-line `go install`
```bash
go install github.com/dont-see-big-shark/nas_conn_plus/cmd/nasconnplus@latest
```

### Method B: Clone & Build
```bash
# Clone the repository
git clone https://github.com/dont-see-big-shark/nas_conn_plus.git
cd nas_conn_plus

# Build binary for current platform
make build

# Cross-compile for Linux (amd64 / arm64 / armv7), outputs to dist/
make release
```

---

## 🗺️ Roadmap

- [x] Native Linux `/proc/net/tcp` zero-dependency, millisecond port detection
- [x] L4 high-performance zero-copy IPv6 transparent relaying (`inetaf/tcpproxy` + Linux `splice(2)`)
- [x] L7 smart reverse proxy (auto HTTP sniffing with `port + 1` HTTPS upgrades)
- [x] Standard `X-Forwarded-*` header injection (resolves 1Panel / Nextcloud 302 redirect loops)
- [x] 3-tier certificate management (ACME Let's Encrypt, custom cert hot-reload, ECDSA 10-year self-signed fallback)
- [x] Local Unix Domain Socket live dashboard (`nasconnplus status`)
- [x] Terminal ergonomics & single-run diagnostic reporting (`-t` mode)
- [ ] 🔑 ACME DNS-01 challenge support for automated wildcard certificates behind blocked port 80/443
- [ ] 🌐 UDP port IPv6 mirroring and relaying support
- [ ] 🎯 SNI-based domain-level virtual host routing

---

## 🤝 Contributing

We warmly welcome community contributions! Whether submitting bug reports, suggesting features, improving documentation, or opening pull requests:

- 📜 **Contribution Guidelines**: See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and code standards.
- 🛡️ **Security Policy**: See [SECURITY.md](SECURITY.md) for responsible vulnerability disclosure.
- 📝 **Changelog**: See [CHANGELOG.md](CHANGELOG.md) for release history.
- 🐛 **Issues**:
  - [Report a Bug](https://github.com/dont-see-big-shark/nas_conn_plus/issues/new?template=bug_report.md)
  - [Request a Feature](https://github.com/dont-see-big-shark/nas_conn_plus/issues/new?template=feature_request.md)

---

## 💖 Acknowledgements

`nasconn+` stands on the shoulders of these outstanding open-source projects:

- [inetaf/tcpproxy](https://github.com/inetaf/tcpproxy) - Reliable, high-performance TCP proxying primitives
- [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) - Beautiful, expressive terminal styling and layout
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - Standard cryptographic building blocks and ACME client

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - free and open for both commercial and personal use.
