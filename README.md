<div align="center">

# 🚀 nasconn+

**Lightweight connection enhancement daemon engineered for NAS and self-hosted home labs**  
*Overcome IPv4 CGNAT · Automated IPv6 Relay · Port+1 Seamless HTTPS Upgrade*

[![CI](https://github.com/dont-see-big-shark/nas_conn_plus/actions/workflows/ci.yml/badge.svg)](https://github.com/dont-see-big-shark/nas_conn_plus/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/Coverage-82.5%25-brightgreen.svg?logo=codecov)](https://github.com/dont-see-big-shark/nas_conn_plus)
[![Go Report Card](https://goreportcard.com/badge/github.com/dont-see-big-shark/nas_conn_plus)](https://goreportcard.com/report/github.com/dont-see-big-shark/nas_conn_plus)
[![Latest Release](https://img.shields.io/github/v/release/dont-see-big-shark/nas_conn_plus?logo=github&color=3388ff)](https://github.com/dont-see-big-shark/nas_conn_plus/releases)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.25-00ADD8?logo=go)](https://golang.org)
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
  <a href="#why">Why nasconn+?</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#features">Key Features</a> •
  <a href="#quickstart">Quick Start</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#cli">CLI & Observability</a> •
  <a href="#security">Security</a> •
  <a href="#testing">Testing & Quality</a> •
  <a href="#build">Build from Source</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#contributing">Contributing</a>
</p>

</div>

---

<a id="why"></a>

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
- **HTTP Port +1 HTTPS Upgrade**: Without touching existing container setups, `nasconn+` probes plain HTTP services and terminates TLS at `port + https_offset` (default `+1`) automatically.

---

<a id="architecture"></a>

## 🛠️ Architecture & How It Works

```text
External Inbound Traffic (Public IPv6 / LAN)
    │
    ├───> [::]:8080 (IPv6) ───[ nasconn+ L4 Relay ]──────> 127.0.0.1:8080 (Local IPv4-Only Service)
    │
    └───> :8081 (HTTPS) ──[ nasconn+ TLS Termination ]─> 127.0.0.1:8080 (Proxied with X-Forwarded headers)
```

Every poll cycle the daemon scans local listeners (`/proc/net/tcp{,6}` on Linux, `ss` fallback, `lsof` on macOS), reconciles the desired relays and HTTPS frontends, and reaps dead listeners after `grace_polls` consecutive misses. Probing happens outside the service lock with bounded parallelism, so `nasconnplus status` never blocks behind slow backends.

<a id="features"></a>

### ✨ Key Features

- 🔄 **Adaptive Zero-Config Lifecycle**: Parses Linux kernel `/proc/net/tcp` directly with zero external tool dependencies. Automatically discovers newly started services and gracefully cleans up dead listeners with anti-flap debouncing. Self-owned listener ports are never re-discovered as new backends.
- 🌐 **Intelligent L7 Reverse Proxy (Port +1 Upgrade)**: Built on Go's standard `httputil.ReverseProxy` with the `Rewrite` hook. Injects server-controlled `X-Forwarded-Proto: https`, `X-Forwarded-Host`, `X-Forwarded-Port`, and `X-Real-IP` headers — client-forged `X-Forwarded-For` / `Forwarded` values never reach backends — eliminating 302 redirect loops and Mixed Content errors in apps like 1Panel, Nextcloud, and WordPress. Supports WebSocket pass-through natively.
- 🚀 **High-Performance L4 Relay**: Leverages `inetaf/tcpproxy`. By default on Linux (`relay.zero_copy: true`), socket bridging is delegated directly to kernel `splice(2)` pipe operations with zero userspace memory copying or GC overhead, while fully preserving TCP 30s keepalive and half-close signaling. Byte counters report 0 B in this mode (connection counts remain strictly accurate); set `relay.zero_copy: false` if byte traffic statistics are desired. Per-listener connection caps guard against file descriptor exhaustion.
- 🤝 **Native Dual-Stack Polite Handover**: If a backend service later updates to natively bind `[::]:port`, `nasconn+` detects the foreign listener and immediately surrenders the port without downtime or conflicts. Occupied target ports are never stolen: binds are decided by real `EADDRINUSE`, and conflicts back off and retry.
- 🔐 **3-Tier Resilient Certificate Engine**:
  1. Automated Let's Encrypt issuance via ACME (`autocert`, TLS-ALPN-01 — requires port 443 to reach the target listener).
  2. Dynamic reloading of custom external PEM certificates (SHA-256 content fingerprinting, so in-place renewals apply without restart).
  3. Built-in ECDSA P-256 825-day self-signed certificate generation as a dependable fallback (also reloaded when rotated on disk).
- 🎨 **Modern Geek Ergonomics**: Stylized CLI and ASCII banners powered by `charmbracelet/lipgloss`. A one-shot diagnostic mode (`-t`) prints formatted terminal tables with color-coded status badges, reflecting the actual loaded configuration.
- 🛡️ **Defensive Security Baseline**: Union-merged exclusion lists protecting 19 high-risk infrastructure ports (see [Security](#security)), optional explicit whitelists, per-listener connection limits, loopback-only debug endpoint, `0600` IPC socket, and RFC 6797-compliant HSTS policy enforcement.

---

<a id="quickstart"></a>

## 🚦 Quick Start & Installation

Choose your preferred installation method:

### Method 1: Homebrew (macOS & Linux)

```bash
# Add the official tap
brew tap dont-see-big-shark/tap

# Install nasconn+
brew install nasconnplus

# (Optional) Run automatically as a background daemon
brew services start nasconnplus
```

---

### Method 2: Docker / Docker Compose (NAS Platforms)

Pre-built multi-arch images (`linux/amd64`, `linux/arm64`, `linux/arm/v7`) are available on GitHub Container Registry:

#### One-line Docker Run:
```bash
docker run -d \
  --name nasconnplus \
  --network host \
  --restart unless-stopped \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  -v /etc/nasconnplus:/etc/nasconnplus \
  -v /run/nasconnplus:/run/nasconnplus \
  ghcr.io/dont-see-big-shark/nas_conn_plus:latest
```

#### Production `docker-compose.yml`:
```yaml
services:
  nasconnplus:
    image: ghcr.io/dont-see-big-shark/nas_conn_plus:latest
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
      # Optional config override (a default is generated on first start)
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

### Method 3: One-line `go install`

If Go (>= 1.25) is installed:
```bash
go install github.com/dont-see-big-shark/nas_conn_plus/cmd/nasconnplus@latest
```

---

### Method 4: Standalone Binary & Systemd Service

1. Download the pre-built tarball for your CPU architecture (`amd64`, `arm64`, or `armv7`) from the [Releases page](https://github.com/dont-see-big-shark/nas_conn_plus/releases).
2. Verify integrity and install the binary (the tarball contains a binary named `nasconnplus`):
   ```bash
   sha256sum -c nasconnplus-linux-amd64.tar.gz.sha256
   tar -zxvf nasconnplus-linux-amd64.tar.gz
   sudo mv nasconnplus /usr/local/bin/
   ```
3. Test your host's current listening ports:
   ```bash
   sudo nasconnplus -t
   ```
4. Enable and start as a systemd background daemon:
   ```bash
   sudo mkdir -p /etc/nasconnplus
   sudo cp config.example.json /etc/nasconnplus/config.json
   sudo cp deploy/nasconnplus.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now nasconnplus
   ```

---

<a id="configuration"></a>

## ⚙️ Configuration

`nasconn+` follows a **zero-config by default** philosophy: polling intervals, debounce counts, idle timeouts, and certificate storage all ship with production-tested defaults. The daemon resolves `./config.json` first (never from world-writable directories such as `/tmp`), then `/etc/nasconnplus/config.json`, and generates a default file on first start. `status` and `-t` are pure reads and never create files.

### Minimal Recommended Configuration

Valid JSON only — this project uses `_comment` keys for annotations because standard JSON has no comments (copy-paste the block below as-is, it parses):

```json
{
  "_comment": "TLS hostname for the self-signed fallback certificate",
  "cert_host": "nas.local",
  "_comment_relay": "Mirror IPv4-only (0.0.0.0) listeners to IPv6 ([::]). Omit exclude to enforce the built-in deny list.",
  "relay": {
    "auto": true,
    "exclude": [8080]
  },
  "_comment_https": "Auto-discover HTTP services and upgrade them to HTTPS on port + https_offset.",
  "https_auto": true,
  "https_exclude": [8080]
}
```

`relay.exclude` applies to **both** the L4 relay and the HTTPS auto-upgrade paths. Setting `override_default_excludes: true` disables the built-in deny list entirely (the daemon logs a WARN when you do).

### Full Configuration Reference

| Parameter | Type | Default | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- |
| `cert_host` | String | `"nas.local"` | — | Hostname for SNI matching and the self-signed fallback certificate |
| `relay.auto` | Boolean | `false` | — | Automatically mirror IPv4-only (`0.0.0.0`) listeners to IPv6 (`[::]`) |
| `relay.mode` | String | `"auto"` | `auto` / `whitelist` | `whitelist` relays only ports in `relay.allow` |
| `relay.zero_copy` | Boolean | `true` | — | Linux kernel `splice(2)` zero-copy relaying (enabled by default). Lower CPU and zero memory copying; byte counters report 0 B (active and total connection counts are tracked); set `false` to measure traffic bytes |
| `relay.exclude` | Array | built-in deny list | 1–65535 | Ports excluded from relaying (union-merged with the deny list) |
| `relay.allow` | Array | `[]` | 1–65535 | Whitelist for IPv6 relaying. If non-empty, only listed ports are relayed |
| `https_auto` | Boolean | `true` | — | Discover HTTP services and upgrade them to HTTPS on `port + https_offset` |
| `https_mode` | String | `"auto"` | `auto` / `whitelist` | `whitelist` upgrades only ports in `https_allow` |
| `https_offset` | Integer | `1` | 1–100 | Port offset for automatic HTTPS upgrade (e.g. `1` upgrades `8080 -> 8081`) |
| `https_exclude` | Array | built-in deny list | 1–65535 | Ports excluded from auto HTTPS upgrade (union-merged with the deny list) |
| `https_allow` | Array | `[]` | 1–65535 | Whitelist for auto HTTPS upgrade. If non-empty, only listed ports are upgraded |
| `https` | Array | `[]` | 1–65535, `http != https` | Explicit static HTTPS rules, take precedence over `https_auto`, e.g. `[{"name": "WebDisk", "http": 8080, "https": 8443}]` |
| `override_default_excludes` | Boolean | `false` | — | When `true`, disables the built-in high-risk exclusion list (logs a WARN) |
| `max_conns_per_listener` | Integer | `2048` | 1–4096 | Hard concurrent connection ceiling per listener against fd exhaustion |
| `poll_seconds` | Integer | `5` | 1–3600 | Background socket scan interval in seconds |
| `grace_polls` | Integer | `2` | 1–120 | Anti-flap debounce: consecutive missed scans before a listener is recycled |
| `idle_seconds` | Integer | `900` | 60–86400 | Idle timeout for HTTP keep-alive connections |
| `hsts` | Object | Disabled | — | `{"enabled": true, "max_age": 31536000, "include_subdomains": false}`. RFC 6797 compliant: never injected for IP literals or self-signed certificates |
| `socket_path` | String | Auto | no `..` | Unix Domain Socket path. Auto: `$XDG_RUNTIME_DIR/nasconnplus.sock`, else `/run/nasconnplus.sock` (root), else per-UID isolated dir |
| `acme` | Object | Disabled | — | `{"enabled": true, "domain": "nas.example.com", "email": "admin@example.com"}`. TLS-ALPN-01 only: port 443 must reach the target listener |
| `cert_config_path` | String | `""` | no `..` | External JSON file with custom TLS certificate pairs (content-hash reloaded) |
| `selfsigned_dir` | String | `/etc/nasconnplus/tls` | no `..` | Storage for the generated self-signed certificate |

---

<a id="cli"></a>

## 🔍 CLI & Observability

```text
Usage: nasconnplus [options] [command]

Commands:
  status
        Query live proxy metrics and listener status from the active daemon

Options:
  -c, -config string
        Configuration file path (tries ./config.json, then /etc/nasconnplus/config.json)
  -debug-addr string
        Loopback-only pprof + /metrics server (e.g. 127.0.0.1:6060, default disabled; non-loopback is refused)
  -s, -status
        Display running daemon status table (alias for `nasconnplus status`)
  -socket string
        Override the Unix domain socket path used for daemon communication
  -t, -test
        Diagnostic mode: perform a full host port probe and print report, then exit
  -v, -version
        Print version and runtime architecture
```

#### 📊 Live Status Dashboard (`nasconnplus status` or `nasconnplus -s`):
Query the background daemon from any terminal shell to view listener health, active connections, total processed requests, and bandwidth statistics:

```text
╭────────────┬────────────┬──────────────┬──────────────────┬────────┬────────┬───────┬─────────────────────────┬────────╮
│ SERVICE    │ TYPE       │ LISTEN ADDR  │ BACKEND          │ STATUS │ ACTIVE │ TOTAL │ TRAFFIC (RX / TX)       │ UPTIME │
├────────────┼────────────┼──────────────┼──────────────────┼────────┼────────┼───────┼─────────────────────────┼────────┤
│ 1panel     │ HTTPS (L7) │ https :18091 │ 127.0.0.1:18090  │ ● OK   │ 2      │ 154   │ ↓ 18.25 MB / ↑ 52.10 MB │ 1h 24m │
│ webdisk    │ HTTPS (L7) │ https :8081  │ 127.0.0.1:8080   │ ● OK   │ 1      │ 890   │ ↓ 120.4 MB / ↑ 1.48 GB  │ 1h 24m │
│ relay:3000 │ Relay (L4) │ [::]:3000    │ 127.0.0.1:3000   │ ● OK   │ 0      │ 12    │ ↓ 45.00 KB / ↑ 82.30 KB │ 1h 24m │
╰────────────┴────────────┴──────────────┴──────────────────┴────────┴────────┴───────┴─────────────────────────┴────────╯

● Daemon: v1.1.0 | Uptime: 1h 24m | Active Conns: 3 | Total Traffic: 1.67 GB | Total Errors: 0
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

#### 📈 Prometheus Metrics (`--debug-addr 127.0.0.1:6060`):
With the loopback-only debug server enabled, `GET /metrics` exposes dependency-free counters:

```text
nasconn_reconciles_total 128
nasconn_reconcile_errors_total 0
nasconn_reconcile_last_duration_ms 12
nasconn_probes_total 46
nasconn_probes_http_total 9
```

---

<a id="security"></a>

## 🔒 Security Considerations

> [!CAUTION]
> Once automated IPv6 relaying is active, if your router allows inbound IPv6 connections, local services previously isolated to private IPv4 **will become directly reachable from the public Internet via IPv6**. Additionally, all proxied traffic reaches backends from `127.0.0.1`, so backend "trust localhost" authentication bypasses treat remote users as local — secure your backends accordingly.

1. **High-Risk Ports Protected by Default**: `nasconn+` ships a built-in 19-port deny list covering remote-admin, database, file-sharing, and infrastructure ports — SSH (22), Telnet (23), DNS (53), rpcbind (111), MS-RPC (135), NetBIOS (137–139), SMB (445), NFS (2049), Docker APIs (2375–2376), MySQL (3306), RDP (3389), PostgreSQL (5432), Redis (6379), Elasticsearch (9200), Memcached (11211), MongoDB (27017). Your `exclude` entries are union-merged with it (source of truth: `DefaultExcludePorts` in `internal/config/config.go`); the built-ins are dropped only with `override_default_excludes: true`, which logs a WARN.
2. **Router Firewall Hygiene**: Keep the default drop policy for unsolicited inbound IPv6 traffic on your gateway router, opening only the specific public ports you need.
3. **Whitelist Mode**: In sensitive environments, set `"mode": "whitelist"` with `relay.allow` / `https_allow` to expose only evaluated services.
4. **Strong Credentials & 2FA**: Any backend reachable from the Internet must have strong passwords and multi-factor authentication — especially services that bypass authentication for localhost clients.
5. **ACME & HSTS Considerations**:
   - Only TLS-ALPN-01 is wired (via `GetCertificate`): port 443 must reach the target HTTPS listener, otherwise issuance never completes and the self-signed fallback keeps serving. There is no HTTP-01 handler, so opening port 80 alone changes nothing.
   - HSTS strictly follows RFC 6797: it is never injected for bare IP literals or self-signed certificates, preventing irreversible browser lockouts. Enable it only with a valid public-CA certificate on a real domain.
6. **Least Privilege**: The systemd unit runs as an unprivileged `nasconnplus` user with only `CAP_NET_BIND_SERVICE`; the container drops all capabilities except `NET_BIND_SERVICE`, runs read-only with `no-new-privileges`. The debug endpoint refuses non-loopback binds.

---

<a id="testing"></a>

## 🧪 Testing & Quality Assurance

All core business modules are verified with automated unit tests, end-to-end integration tests, and Go's race detector (`-race`), continuously audited by GitHub Actions CI (`vet`, `govulncheck` blocking, `gosec`/`golangci-lint` advisory, `-race` coverage). Total codebase statement coverage stands at **82.5%** (`go test -race -covermode=atomic ./...`; per-package numbers vary by OS — Linux CI is canonical):

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

<a id="build"></a>

## 🛠️ Build from Source

Prerequisites: Go (>= 1.25) installed locally.

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

# Build the container image
make docker-build
```

---

<a id="roadmap"></a>

## 🗺️ Roadmap

- [x] Native Linux `/proc/net/tcp` zero-dependency, millisecond port detection
- [x] L4 high-performance IPv6 transparent relaying (`inetaf/tcpproxy`, optional Linux `splice(2)` zero-copy)
- [x] L7 smart reverse proxy (auto HTTP sniffing with `port + offset` HTTPS upgrades)
- [x] Server-controlled `X-Forwarded-*` header injection (resolves 1Panel / Nextcloud 302 redirect loops)
- [x] 3-tier certificate management (ACME TLS-ALPN-01, custom cert hot-reload, ECDSA 825-day self-signed fallback)
- [x] Local Unix Domain Socket live dashboard (`nasconnplus status`, `0600`, sanitized rendering)
- [x] Terminal ergonomics & single-run diagnostic reporting (`-t` mode)
- [x] Hardened deployment defaults (unprivileged user, minimal capability set, read-only container, blocking `govulncheck`)
- [ ] 🔑 ACME DNS-01 challenge support for automated wildcard certificates behind blocked port 80/443
- [ ] 🌐 UDP port IPv6 mirroring and relaying support
- [ ] 🎯 SNI-based domain-level virtual host routing

---

<a id="contributing"></a>

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
