<div align="center">

# 🚀 nasconn+

**专为 NAS 与家庭自建服务打造的轻量级连接增强工具**  
*突破 IPv4 大内网限制 · 自动 IPv6 中继 · 端口 +1 无感升级 HTTPS*

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
  <b>语言 / Language:</b>
  <a href="README.md">English</a> •
  <b>简体中文</b>
</p>

<p align="center">
  <a href="#why">为什么需要</a> •
  <a href="#architecture">架构原理</a> •
  <a href="#features">核心特性</a> •
  <a href="#quickstart">快速开始</a> •
  <a href="#configuration">配置说明</a> •
  <a href="#cli">运维监控</a> •
  <a href="#security">安全建议</a> •
  <a href="#testing">测试与覆盖率</a> •
  <a href="#build">源码构建</a> •
  <a href="#roadmap">路线图</a> •
  <a href="#contributing">贡献指南</a>
</p>

</div>

---

<a id="why"></a>

## 💡 为什么需要 nasconn+ ？

在家庭宽带或私有 NAS（群晖 Synology、飞牛 fnOS、绿联 UGOS、极空间、Unraid、PVE）部署自建服务时，我们经常遇到两个极其头疼的问题：

1. **IPv4 没有公网 IP（大内网 / CGNAT）**：
   - 运营商不再提供公网 IPv4，但**几乎都分配了公网 IPv6**。
   - 很多 Docker 容器或旧服务默认**仅监听 `0.0.0.0` (IPv4-only)**，外网 IPv6 流量根本无法直接访问。
2. **现代浏览器对 HTTP 的严格封锁（Secure Context）**：
   - 绝大多数自建服务（如面板、网盘、相册、笔记）原生只提供 HTTP 协议。
   - 在非 `localhost` 的外网环境下访问 HTTP 时，浏览器的剪贴板读写、PWA 安装、摄像头、麦克风、地理位置甚至密码自动填充会被**直接禁用**。
3. **传统反向代理（Nginx / Caddy / NPM / Traefik）太繁琐**：
   - 每新增一个容器，就得手动写一次反代规则、解析子域名、申请绑定证书，对于轻量玩家和自建很多容器的玩家来说维护负担很重。

**`nasconn+`** 是一个**零侵入、隐形胶水层**守护进程：
- **自动 IPv6 镜像（Relay）**：自动检测所有只监听在 `0.0.0.0` 的 IPv4 TCP 端口，全自动在 `[::]`（IPv6）建立同端口中继！
- **HTTP 端口 +1 升级 HTTPS**：无需更改原本的 HTTP 服务，`nasconn+` 自动嗅探明文 HTTP 服务，在 `端口 + https_offset`（默认 `+1`）上开启 TLS 终结，直接提供 HTTPS 访问！

---

<a id="architecture"></a>

## 🛠️ 架构与工作原理

```text
外部访问 (公网 IPv6 / 局域网)
    │
    ├───> [::]:8080 (IPv6) ───[ nasconn+ Relay ]───> 127.0.0.1:8080 (本地 IPv4-Only 服务)
    │
    └───> :8081 (HTTPS) ──[ nasconn+ TLS终结 ]──> 127.0.0.1:8080 (解密转发给原 HTTP 服务)
```

守护进程每个轮询周期扫描本机监听端口（Linux 下读 `/proc/net/tcp{,6}`，兜底 `ss`，macOS 用 `lsof`），协调期望的中继与 HTTPS 前端，后端连续 `grace_polls` 次缺席后回收。探测在服务锁之外以有界并发执行，慢后端不会卡死 `nasconnplus status` 查询。

<a id="features"></a>

### ✨ 核心特性

- 🔄 **全自动生命周期自适应**：原生解析 Linux 内核 `/proc/net/tcp`，毫秒级快速扫描本地端口，后端服务启动即自动建立代理，后端关闭自动防抖回收，**不依赖外部 `ss` 命令**。自身监听端口永远不会被误判成新的后端。
- 🌐 **L7 智能反向代理（HTTPS 端口+1）**：基于 Go 标准库 `httputil.ReverseProxy` 的 `Rewrite` 钩子构建，只注入服务端可控的 `X-Forwarded-Proto: https`、`X-Forwarded-Host`、`X-Forwarded-Port`、`X-Real-IP` 请求头——客户端伪造的 `X-Forwarded-For` / `Forwarded` 到不了后端，**彻底根治 1Panel / Nextcloud / WordPress 等 Web 应用的 302 重定向循环与 Mixed Content 错误**，原生支持 WebSocket 穿透。
- 🚀 **高性能 L4 中继（IPv6 Relay）**：复用 `inetaf/tcpproxy`，Linux 下默认开启 `relay.zero_copy`，全链路委派至 Linux 内核 `splice(2)` 零拷贝管道直通，零用户态内存复制与 GC 负担；同时自动保障 TCP 30s KeepAlive 与半关闭（CloseRead/CloseWrite）正常传递。该模式下由于数据不经用户态，吞吐字节统计恒为 0（活跃连接数与总数依然精确统计）；如需观测吞吐字节数，可显式配置 `relay.zero_copy: false`。每个监听器有并发连接硬上限，防止文件句柄耗尽。
- 🤝 **原生双栈主动让位（Handover）**：若后端程序日后升级支持了原生 IPv6 双栈监听，`nasconn+` 检测到后会自动释放监听，绝不强占端口。目标端口被占用时以真实 `bind`（`EADDRINUSE`）为准判定，冲突退避重试，绝不抢走邻居端口。
- 🔐 **三级智能证书管理**：
  1. Let's Encrypt 自动申请（`autocert`，TLS-ALPN-01——需要 443 端口能到达目标监听器）。
  2. 自定义外部 PEM 证书动态重载（SHA-256 内容指纹，就地续签无需重启）。
  3. 内置 **ECDSA P-256** 保底证书：10 年本地 CA + 825 天服务证书（可按配置自动写入系统信任库；服务证书轮换无需重启）。
- 🎨 **现代极客终端体验**：由 `charmbracelet/lipgloss` 驱动的精美终端排版与 ASCII Logo，内置 `-t` 单次诊断模式，生成带圆角边框与状态 Badge 的网络报表，且诊断结论与实际加载的配置一致。
- 🛡️ **冲突自适应与优雅退出**：端口被临时占用时自动退避重试，支持 SIGINT / SIGTERM 优雅释放所有 Listener。Unix Socket `0600` 权限、状态渲染过滤注入字符、debug 端口仅限回环、HSTS 严格遵循 RFC 6797。

---

<a id="quickstart"></a>

## 🚦 快速安装与使用

提供多种灵活的安装部署方式：

### 方式 1：Homebrew 一键安装（macOS 与 Linux 推荐）

```bash
# 添加官方 Tap
brew tap dont-see-big-shark/tap

# 安装 nasconn+
brew install nasconnplus

# （可选）注册为系统后台自启常驻服务
brew services start nasconnplus
```

---

### 方式 2：Docker / Docker Compose 容器化部署（各大 NAS 系统推荐）

官方预编译多架构镜像（支持 `linux/amd64`、`linux/arm64`、`linux/arm/v7`）已自动发布至 GitHub Container Registry：

#### 一键 Docker 命令运行：
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

#### 生产级 `docker-compose.yml` 配置：
```yaml
services:
  nasconnplus:
    image: ghcr.io/dont-see-big-shark/nas_conn_plus:latest
    container_name: nasconnplus
    restart: unless-stopped

    # 核心：必须使用宿主机网络
    network_mode: host

    # 安全沙箱与权限收敛（无需特权模式）
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
      # 挂载配置文件（可选，首次启动会自动生成默认配置）
      - ./config.json:/etc/nasconnplus/config.json
      # 必须挂载：持久化存储 TLS 证书与 ACME 缓存，防止容器重建导致证书变更
      - ./tls:/etc/nasconnplus/tls
      - ./acme_cache:/etc/nasconnplus/acme_cache
      # 挂载 IPC 通信目录，供宿主机 nasconnplus status 访问
      - /run/nasconnplus:/run/nasconnplus

    environment:
      - TZ=Asia/Shanghai
```

启动容器：
```bash
docker compose up -d
```

---

### 方式 3：`go install` 一键全局安装

本地环境配置了 Go（>= 1.25）时，可直接通过 Go 官方工具链安装：
```bash
go install github.com/dont-see-big-shark/nas_conn_plus/cmd/nasconnplus@latest
```

---

### 方式 4：二进制直接运行与 Systemd 服务（Linux 宿主机）

1. 从 [Releases 页面](https://github.com/dont-see-big-shark/nas_conn_plus/releases) 下载预编译包（支持 `amd64` / `arm64` / `armv7`）。
2. 校验完整性并安装到系统路径（压缩包内二进制就叫 `nasconnplus`）：
   ```bash
   sha256sum -c nasconnplus-linux-amd64.tar.gz.sha256
   tar -zxvf nasconnplus-linux-amd64.tar.gz
   sudo mv nasconnplus /usr/local/bin/
   ```
3. 快速检测本地端口：
   ```bash
   sudo nasconnplus -t
   ```
4. 注册为 Systemd 开机自启常驻服务：
   ```bash
   sudo mkdir -p /etc/nasconnplus
   sudo cp config.example.json /etc/nasconnplus/config.json
   sudo cp deploy/nasconnplus.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now nasconnplus
   ```

---

<a id="configuration"></a>

## ⚙️ 配置说明

`nasconn+` 设计遵循 **开箱即用、零繁琐配置** 原则。所有底层引擎参数（轮询频率、防抖周期、空闲超时、自签名证书目录等）均内置了生产级默认值。守护进程按 `./config.json`（绝不从 `/tmp` 等全局可写目录加载相对路径配置）→ `/etc/nasconnplus/config.json` 的顺序解析，首次启动自动生成默认文件；`status` 与 `-t` 是纯读操作，永远不会创建文件。

### 核心推荐配置（日常使用仅需以下几行）

合法 JSON，注意本项目用 `_comment` 键写注释（标准 JSON 不支持 `//` 注释，下面这段可直接复制使用）：

```json
{
  "_comment": "自签兜底证书的主机名/域名",
  "cert_host": "nas.local",
  "_comment_relay": "把只监听 IPv4 (0.0.0.0) 的端口镜像到 IPv6 ([::])。不填 exclude 即启用内置拒绝清单",
  "relay": {
    "auto": true,
    "exclude": [8080]
  },
  "_comment_https": "自动嗅探 HTTP 服务并在 端口 + https_offset 上建 HTTPS 代理",
  "https_auto": true,
  "https_exclude": [8080]
}
```

`relay.exclude` 对 **L4 中继与 HTTPS 自动升级两条路径同时生效**。设置 `override_default_excludes: true` 会清空内置拒绝清单（启动时打 WARN）。

### 可选高级配置项（按需添加）

| 配置项 | 类型 | 默认值 | 约束 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `cert_host` | 字符串 | `"nas.local"` | — | SNI 匹配与自签兜底证书的主机名 |
| `relay.auto` | 布尔 | `false` | — | 自动把 IPv4-only（`0.0.0.0`）监听镜像到 IPv6（`[::]`） |
| `relay.mode` | 字符串 | `"auto"` | `auto` / `whitelist` | `whitelist` 下只中继 `relay.allow` 中的端口 |
| `relay.zero_copy` | 布尔 | `true` | — | 默认开启纯内核级 TCP `splice(2)` 零拷贝直通，显著降低 CPU 占用与内存复制；副作用：流量字节统计恒为 0（连接数、总连接与错误数仍精确监控），如需查看吞吐字节数请显式设为 `false` |
| `relay.exclude` | 数组 | 内置拒绝清单 | 1–65535 | 中继排除端口（与拒绝清单取并集） |
| `relay.allow` | 数组 | `[]` | 1–65535 | IPv6 中继显式白名单。若配置，仅中继此列表中的端口（留空表示全自动） |
| `https_auto` | 布尔 | `true` | — | 自动嗅探 HTTP 并在 `端口 + https_offset` 上升级 HTTPS |
| `https_mode` | 字符串 | `"auto"` | `auto` / `whitelist` | `whitelist` 下只升级 `https_allow` 中的端口 |
| `https_offset` | 整数 | `1` | 1–100 | 自动升级端口偏移量，例如 `1` 表示 `8080 -> 8081` |
| `https_exclude` | 数组 | 内置拒绝清单 | 1–65535 | HTTPS 自动升级排除端口（与拒绝清单取并集） |
| `https_allow` | 数组 | `[]` | 1–65535 | HTTPS 自动升级显式白名单。若配置，仅为列表中的端口开启 HTTPS |
| `https` | 数组 | `[]` | 1–65535 且 `http != https` | 手动固定映射（优先级高于 `https_auto`），例如：`[{"name": "网盘", "http": 8080, "https": 8443}]` |
| `override_default_excludes` | 布尔 | `false` | — | 是否清空内置高危端口拒绝清单（开启会在启动日志打 WARN） |
| `max_conns_per_listener` | 整数 | `2048` | 1–4096 | 每个监听器的最大并发连接数硬限制，防止慢速连接耗尽文件句柄 |
| `poll_seconds` | 整数 | `5` | 1–3600 | 监听端口扫描探测周期（秒） |
| `grace_polls` | 整数 | `2` | 1–120 | 后端服务离线防抖计数（连续 N 次扫描未发现时再回收端口） |
| `idle_seconds` | 整数 | `900` | 60–86400 | HTTP 保活连接空闲超时（秒） |
| `hsts` | 对象 | 禁用 | — | `{"enabled": true, "max_age": 31536000, "include_subdomains": false}`（RFC 6797 合规：IP 地址与自签证书自动抑制） |
| `socket_path` | 字符串 | 自动 | 禁止 `..` | 自定义 Unix Domain Socket 路径（默认 `$XDG_RUNTIME_DIR/nasconnplus.sock`，root 回退 `/run/nasconnplus.sock`，否则按 UID 隔离目录） |
| `acme` | 对象 | 禁用 | `enabled` 时必须填 `domain` | `{"enabled": true, "domain": "nas.xxx.com", "email": "admin@xxx.com"}`（仅 TLS-ALPN-01：443 端口必须能到达目标监听器） |
| `cert_config_path` | 字符串 | `""` | 禁止 `..` | 外部现有 TLS 证书清单文件路径（内容哈希动态重载） |
| `auto_trust_local_ca` | 布尔 | `true` | — | 自动把生成的本地 CA 写入 macOS 登录钥匙串或 Linux 系统 CA 库，兜底 HTTPS 无需手动导入。测试/沙箱环境可设为 `false` |
| `selfsigned_dir` | 字符串 | `/etc/nasconnplus/tls` | 禁止 `..` | 本地 CA 与兜底证书存储目录 |

---

<a id="cli"></a>

## 🔍 命令行与可观测性

```text
Usage: nasconnplus [options] [command]

Commands:
  status
        即时查询当前后台常驻守护进程的实时转发状态大盘与吞吐统计

Options:
  -c, -config string
        指定配置文件路径（默认先寻找 ./config.json，再寻找 /etc/nasconnplus/config.json）
  -debug-addr string
        仅限回环的 pprof + /metrics 服务（如 127.0.0.1:6060，默认关闭；非回环拒绝启动）
  -s, -status
        查询运行中的守护进程状态（等同于 nasconnplus status）
  -socket string
        指定 IPC Unix domain socket 路径（默认自动寻找系统运行目录）
  -t, -test
        诊断模式：执行一次全机网络与端口探测，输出综合诊断报表后退出
  -v, -version
        显示版本号与架构信息
```

#### 📊 实时状态大盘（`nasconnplus status` 或 `nasconnplus -s`）：
随时随地在任意终端执行一行命令，立即输出当前各代理端口的健康状态、活跃连接数、总处理量与吞吐流量统计：

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

#### 🩺 端口诊断模式（`nasconnplus -t`）：
```text
╭───────┬────────────────┬─────────────┬──────┬───────────┬─────────────────────┬───────────────╮
│ PORT  │ IPv4 (0.0.0.0) │ IPv6 ([::]) │ PID  │ PROCESS   │ RELAY ACTION        │ HTTPS (+1)    │
├───────┼────────────────┼─────────────┼──────┼───────────┼─────────────────────┼───────────────┤
│ 22    │ YES            │ YES         │ 1024 │ sshd      │ ● Native Dual-Stack │ No HTTP       │
│ 3000  │ YES            │ No          │ 4182 │ node      │ ● Will Relay to IPv6│ ✓ https :3001 │
│ 8080  │ YES            │ No          │ 5219 │ java      │ ● Will Relay to IPv6│ ✓ https :8081 │
╰───────┴────────────────┴─────────────┴──────┴───────────┴─────────────────────┴───────────────╯
```

#### 📈 Prometheus 指标（`--debug-addr 127.0.0.1:6060`）：
开启仅限回环的 debug 服务后，`GET /metrics` 输出无依赖计数器：

```text
nasconn_reconciles_total 128
nasconn_reconcile_errors_total 0
nasconn_reconcile_last_duration_ms 12
nasconn_probes_total 46
nasconn_probes_http_total 9
```

---

<a id="security"></a>

## 🔒 安全建议

> [!CAUTION]
> 开启自动 IPv6 中继后，若路由器放行了 IPv6 入站流量，原本仅局域网可见的 IPv4 服务将通过 IPv6 **直接暴露至公网**。并且所有转发流量在后端看来都来自 `127.0.0.1`，“信任本地回环免鉴权”的后端会把外网用户当成本地用户——请先加固后端。

1. **默认高危端口保护**：`nasconn+` 内置拒绝清单，覆盖 19 个远控、数据库、文件共享与基础设施端口——SSH（22）、Telnet（23）、DNS（53）、rpcbind（111）、MS-RPC（135）、NetBIOS（137–139）、SMB（445）、NFS（2049）、Docker API（2375–2376）、MySQL（3306）、RDP（3389）、PostgreSQL（5432）、Redis（6379）、Elasticsearch（9200）、Memcached（11211）、MongoDB（27017）。你的 `exclude` 配置与其取并集（唯一可信来源：`internal/config/config.go` 的 `DefaultExcludePorts`）；只有 `override_default_excludes: true` 会清空它，且会打 WARN。
2. **路由器防火墙**：建议在主路由上对非公开端口（如内网管理口、无密码测试服务）进行 IPv6 入站端口限制。
3. **白名单模式**：对安全性要求极高的环境，建议配置 `"mode": "whitelist"` 并填写 `relay.allow` / `https_allow` 显式白名单，仅放行经过评估的服务。
4. **安全凭据**：对于暴露在外网的服务，请务必开启强密码、多因素认证（2FA）或访问凭据，尤其是有“本地回环免鉴权”逻辑的服务。
5. **ACME 证书与 HSTS 考量**：
   - 只接了 TLS-ALPN-01（经 `GetCertificate`）：443 端口必须能到达目标 HTTPS 监听器，否则签发永远完成不了，自签兜底会一直服务。没有 HTTP-01 处理器，只放行 80 端口没有任何作用。
   - HSTS 遵守 RFC 6797 标准规范，仅在使用合规域名及有效证书时启用，禁止为 IP 地址或自签证书开启 HSTS，避免造成不可逆的浏览器证书死锁。
6. **最小权限**：systemd 单元以无特权 `nasconnplus` 用户运行，仅保留 `CAP_NET_BIND_SERVICE`；容器 drop 全部 capability 只加 `NET_BIND_SERVICE`，只读 + `no-new-privileges`；debug 端口拒绝非回环绑定。

---

<a id="testing"></a>

## 🧪 测试与质量保证 (Testing & Quality)

本项目核心业务模块均编写了自动化单元测试、集成测试与竞态检测（Race Detector），由 GitHub Actions CI 在多版本 Go 环境下自动守护（`vet` + 阻塞式 `govulncheck` + advisory 的 `gosec`/`golangci-lint` + `-race` 覆盖率）。整体语句覆盖率达到 **82.5%**（`go test -race -covermode=atomic ./...`；分包数字随操作系统漂移，以 Linux CI 为准）：

### 本地运行测试与覆盖率报告

```bash
# 运行全部单元测试
make test

# 运行测试并输出覆盖率统计
make coverage

# 开启竞态检测并生成 HTML 可视化覆盖率报表 (自动输出 coverage.html)
make test-coverage

# 执行代码风格与静态类型检查
make lint
```

---

<a id="build"></a>

## 🛠️ 源码编译与安装 (Build from Source)

如果你本地已配置 Go（>= 1.25）环境，可以通过以下方式直接从源码安装或构建：

### 方式 A：`go install` 一键全局安装
```bash
go install github.com/dont-see-big-shark/nas_conn_plus/cmd/nasconnplus@latest
```

### 方式 B：源码本地编译
```bash
# 克隆仓库代码
git clone https://github.com/dont-see-big-shark/nas_conn_plus.git
cd nas_conn_plus

# 编译当前平台二进制
make build

# 一键跨平台交叉编译 (Linux amd64 / arm64 / armv7)，产物输出至 dist/ 目录
make release

# 构建容器镜像
make docker-build
```

---

<a id="roadmap"></a>

## 🗺️ 开发路线图 (Roadmap)

`nasconn+` 持续演进中，欢迎社区共同参与建设：

- [x] 原生 Linux `/proc/net/tcp` 零依赖、毫秒级端口自动探测
- [x] L4 高性能 IPv6 同端口透明中继（基于 `inetaf/tcpproxy`，可选 Linux `splice(2)` 零拷贝）
- [x] L7 智能反向代理（自动嗅探 HTTP 并在 `端口 + offset` 开启 HTTPS 升级）
- [x] 服务端可控 X-Forwarded 报头注入（解决 1Panel/Nextcloud 302 重定向循环）
- [x] 三级证书安全管理（ACME TLS-ALPN-01、外部证书热重载、ECDSA 825 天自签证书兜底）
- [x] 本地 Unix Domain Socket 实时状态大盘（`nasconnplus status`，`0600` 权限 + 渲染清洗）
- [x] 终端人体工程学美化与单次诊断报表（`-t` 模式）
- [x] 部署加固默认值（无特权用户、最小 capability 集、只读容器、阻塞式 `govulncheck`）
- [ ] 🔑 ACME DNS-01 验证支持（针对家庭宽带封锁 80/443 端口场景自动申请泛域名证书）
- [ ] 🌐 UDP 端口 IPv6 镜像与中继转发支持
- [ ] 🎯 SNI 域名级智能多证书路由与虚拟主机支持

---

<a id="contributing"></a>

## 🤝 参与贡献与社区 (Contributing)

我们非常欢迎来自社区的任何贡献！无论是提出功能建议、汇报 Bug、改进文档，还是提交代码 PR。

- 📜 **贡献指南**：请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解开发规范与 PR 提交说明。
- 🛡️ **安全政策**：若发现潜在安全漏洞，请阅读 [SECURITY.md](SECURITY.md) 获取负责任披露指引。
- 📝 **版本记录**：查看 [CHANGELOG.md](CHANGELOG.md) 获取最新更新历史。
- 🐛 **提交反馈**：
  - [提交 Bug 报告](https://github.com/dont-see-big-shark/nas_conn_plus/issues/new?template=bug_report.md)
  - [提出新功能建议](https://github.com/dont-see-big-shark/nas_conn_plus/issues/new?template=feature_request.md)

---

## 💖 鸣谢 (Acknowledgements)

`nasconn+` 离不开开源社区优秀项目的基石力量：

- [inetaf/tcpproxy](https://github.com/inetaf/tcpproxy) - 提供强大的底层 TCP 代理能力
- [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) - 提供优雅的现代极客终端排版与配色
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - 提供 ACME 证书自动化能力

---

## 📄 开源许可证 (License)

本项目基于 [MIT 许可证](LICENSE) 开源，自由免费，允许商业与个人使用。
