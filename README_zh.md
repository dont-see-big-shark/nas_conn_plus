<div align="center">

# 🚀 nasconn+

**专为 NAS 与家庭自建服务打造的轻量级连接增强工具**  
*突破 IPv4 大内网限制 · 自动 IPv6 中继 · 端口 +1 无感升级 HTTPS*

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
  <b>语言 / Language:</b>
  <a href="README.md">English</a> •
  <b>简体中文</b>
</p>

<p align="center">
  <a href="#-为什么需要-nasconn-">为什么需要</a> •
  <a href="#️-架构与工作原理">架构原理</a> •
  <a href="#-核心特性">核心特性</a> •
  <a href="#-快速开始">快速开始</a> •
  <a href="#️-配置文件说明-configjson">配置说明</a> •
  <a href="#-命令行参数与人体工程学-cli--ergonomics">运维监控</a> •
  <a href="#-测试与质量保证-testing--quality">测试与覆盖率</a> •
  <a href="#️-源码编译与安装-build-from-source">源码构建</a> •
  <a href="#-开发路线图-roadmap">路线图</a> •
  <a href="#-安全建议">安全建议</a> •
  <a href="#-参与贡献与社区-contributing">贡献指南</a>
</p>

</div>

---

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
- **HTTP 端口 +1 升级 HTTPS**：无需更改原本的 HTTP 服务，配置中指定端口后，`nasconn+` 自动在 `端口 + 1` 开启 TLS 终结，直接提供 HTTPS 访问！

---

## 🛠️ 架构与工作原理

```text
外部访问 (公网 IPv6 / 局域网)
    │
    ├───> [::]:8080 (IPv6) ───[ nasconn+ Relay ]───> 127.0.0.1:8080 (本地 IPv4-Only 服务)
    │
    └───> [::]:8081 (HTTPS) ──[ nasconn+ TLS终结 ]──> 127.0.0.1:8080 (解密转发给原 HTTP 服务)
```

### ✨ 核心特性

- 🔄 **全自动生命周期自适应**：原生解析 Linux 内核 `/proc/net/tcp`，毫秒级快速扫描本地端口，后端服务启动即自动建立代理，后端关闭自动防抖回收，**不依赖外部 `ss` 命令**。
- 🌐 **L7 智能反向代理（HTTPS 端口+1）**：基于 Go 标准库 `httputil.ReverseProxy` 构建，自动注入 `X-Forwarded-Proto: https`、`X-Forwarded-Host`、`X-Real-IP` 请求头，**彻底根治 1Panel / Nextcloud / WordPress 等 Web 应用的 302 重定向循环与 Mixed Content 错误**，原生支持 WebSocket 穿透。
- 🚀 **高性能 L4 零拷贝中继（IPv6 Relay）**：复用 Google 团队维护的 `inetaf/tcpproxy`，Linux 下自动利用 `splice(2)` 零拷贝转发，高并发、低延迟、长连接保活。
- 🤝 **原生双栈主动让位（Handover）**：若后端程序日后升级支持了原生 IPv6 双栈监听，`nasconn+` 检测到后会自动释放监听，绝不强占端口。
- 🔐 **三级智能证书管理**：支持 **Let's Encrypt 自动申请与续签 (`autocert`)**、自定义证书热加载、以及自动生成 **ECDSA P-256** 10 年期自签证书保底。
- 🎨 **现代极客终端体验**：由 `charmbracelet/lipgloss` 驱动的精美终端排版与 ASCII Logo，内置 `-t` 单次诊断模式，生成带圆角边框与状态 Badge 的网络报表。
- 🛡️ **冲突自适应与优雅退出**：端口被临时占用时自动退避重试，支持 SIGINT / SIGTERM 优雅释放所有 Listener。

---

## 🚦 快速开始

### 方式 1：二进制直接运行（推荐 Linux / NAS 宿主机）

1. 从 [Releases 页面](https://github.com/dont-see-big-shark/nas_conn_plus/releases) 下载适合你架构的预编译包（支持 `amd64` / `arm64` / `armv7`）。
2. 解压并赋予执行权限：
   ```bash
   tar -zxvf nasconnplus-linux-amd64.tar.gz
   sudo mv nasconnplus /usr/local/bin/
   ```
3. 诊断测试（查看当前主机的端口分布情况）：
   ```bash
   sudo nasconnplus -t
   ```
4. 启动服务（首次运行会自动在当前目录或 `/etc/nasconnplus/` 生成默认配置文件）：
   ```bash
   sudo nasconnplus -c /etc/nasconnplus/config.json
   ```

---

### 方式 2：Systemd 后台常驻服务

为了让 `nasconn+` 在 NAS 或 Linux 服务器开机自启且在后台稳定常驻，推荐使用 Systemd：

1. 创建配置文件目录并放入配置：
   ```bash
   sudo mkdir -p /etc/nasconnplus
   sudo cp config.example.json /etc/nasconnplus/config.json
   ```
2. 安装服务单元：
   ```bash
   sudo cp deploy/nasconnplus.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```
3. 启动并设置开机自启：
   ```bash
   sudo systemctl enable --now nasconnplus
   ```
4. 查看运行状态与日志：
   ```bash
   sudo systemctl status nasconnplus
   journalctl -u nasconnplus -f
   ```

---

### 方式 3：Docker / Docker Compose 一键部署

对于极空间、飞牛私有云 (fnOS)、绿联 (UGOS)、群晖 (Synology)、Unraid 等 NAS 系统，推荐使用 Docker Compose 快速部署。

> [!IMPORTANT]
> #### ⚠️ Docker 部署 4 大核心注意事项（必读避坑指南）
> `nasconn+` 属于**底层网络基础设施**工具，需在宿主机嗅探端口并对外开放 IPv6/HTTPS 监听，容器配置建议遵循最小权限原则：
> 
> 1. **必须配置 `network_mode: host`**：
>    Docker 默认的 `bridge`（桥接）网络会将容器隔离在独立虚拟子网中，导致容器**无法感知宿主机的 0.0.0.0 端口**，也无法直接在宿主机的公网 IPv6 上开放中继。必须使用 Host 主机网络。
> 2. **无需特权模式与宿主机 PID 命名空间（最小权限）**：
>    `nasconn+` 创新性地采用 `/proc/self/fd` 套接字 inode 比对技术，完全消除了对 `pid: host`、`privileged: true` 及 `CAP_SYS_PTRACE` 的依赖。只需保留 `CAP_NET_BIND_SERVICE`（绑定 80/443 等 < 1024 特权端口）。
> 3. **必须挂载数据卷持久化存储**：
>    容器必须挂载持久化目录（如 `./tls` 和 `./acme_cache`）。如果不挂载，每次容器更新或重启都会重新生成证书，导致浏览器因 SSL 证书指纹变更而报错拦截。另外挂载 `/run/nasconnplus` 可供宿主机 CLI 快速通信。
> 4. **路由器 IPv6 防火墙放行（入站规则）**：
>    即使容器成功在中继了端口，若主路由器（光猫）默认拦截了入站流量，外网仍然无法连接。请在路由器设置中为 NAS 设备放行对应的 IPv6 入站端口。

#### `docker-compose.yml` 生产级配置：

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

    # 核心：必须使用宿主机网络
    network_mode: host

    # 安全沙箱与权限收敛（无需特权模式，非 root 运行）
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

运行容器：
```bash
docker compose up -d
```

---

## ⚙️ 配置文件说明 (`config.json`)

`nasconn+` 设计遵循 **开箱即用、零繁琐配置** 原则。所有底层引擎参数（轮询频率、防抖周期、空闲超时、自签名证书目录等）均内置了生产级默认值。

### 核心推荐配置（日常使用仅需以下几行）

```json
{
  // 证书绑定的本地主机名或域名（默认自动生成并热重载本地 ECDSA 自签名证书）
  "cert_host": "nas.local",

  // 自动将仅监听 IPv4 (0.0.0.0) 的端口镜像到 IPv6 ([::])
  "relay": {
    "auto": true,
    "exclude": [22, 53]      // 排除端口（如 SSH、DNS）
  },

  // 全自动 HTTP 服务嗅探与 HTTPS 升级（自动在 端口 + 1 上建立 HTTPS 代理）
  "https_auto": true,
  "https_exclude": [22, 53]  // 排除端口
}
```

### 可选高级配置项（按需添加）

| 配置项 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `https_offset` | 整数 | `1` | 自动升级端口偏移量，例如 `1` 表示 `8080 -> 8081` |
| `https` | 数组 | `[]` | 手动指定固定 HTTPS 映射（优先级高于 `https_auto`），例如：`[{"name": "网盘", "http": 8080, "https": 8443}]` |
| `relay.zero_copy` | 布尔 | `false` | 开启内核级 TCP `splice(2)` 零拷贝直通，显著降低大流量下的 CPU 占用与内存复制（开启后 active 连接数受监控，但无法统计吞吐字节） |
| `relay.allow` | 数组 | `[]` | IPv6 中继显式白名单端口。若配置，仅中继此列表中的端口（留空表示全自动） |
| `https_allow` | 数组 | `[]` | HTTPS 自动升级显式白名单端口。若配置，仅为列表中的端口开启 HTTPS（留空表示全自动） |
| `override_default_excludes` | 布尔 | `false` | 是否清空内置的 17 个高危基础设施端口（SSH/DNS/DHCP/NTP 等）排除清单 |
| `max_conns_per_listener` | 整数 | `2048` | 每个监听器的最大并发连接数硬限制，防止慢速连接耗尽文件句柄 |
| `hsts` | 对象 | 禁用 | HTTP 严格传输安全配置：`{"enabled": true, "max_age": 31536000, "include_subdomains": false}`（RFC 6797 合规：仅在有效 FQDN 域名与公共 CA 证书下注入，IP 地址与自签证书自动抑制） |
| `socket_path` | 字符串 | 自动 | 自定义 Unix Domain Socket 路径（默认自动隔离放置在 `$XDG_RUNTIME_DIR` 或 `/run`） |
| `acme` | 对象 | 禁用 | 自动向 Let's Encrypt 申请免费证书：`{"enabled": true, "domain": "nas.xxx.com", "email": "admin@xxx.com"}`（需宿主机公网开放 80 端口以响应 HTTP-01 质询） |
| `cert_config_path` | 字符串 | `""` | 外部现有 TLS 证书清单文件路径（支持动态重载） |
| `poll_seconds` | 整数 | `5` | 监听端口扫描探测周期（秒） |
| `grace_polls` | 整数 | `2` | 后端服务离线防抖计数（连续 N 次扫描未发现时再回收端口） |
| `idle_seconds` | 整数 | `900` | TCP 连接空闲超时释放时间（秒） |

---

## 🔍 命令行参数与人体工程学 (CLI & Ergonomics)

```text
Usage: nasconnplus [options] [command]

Commands:
  status
        即时查询当前后台常驻守护进程的实时转发状态大盘与吞吐统计

Options:
  -c, -config string
        指定配置文件路径（默认先寻找 ./config.json，再寻找 /etc/nasconnplus/config.json）
  -debug-addr string
        开启 pprof HTTP 性能分析服务并绑定指定地址（如 127.0.0.1:6060，默认关闭）
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
╭──────────┬────────────┬──────────────┬──────────────────┬────────┬────────┬───────┬─────────────────────────┬────────╮
│ SERVICE  │ TYPE       │ LISTEN ADDR  │ BACKEND          │ STATUS │ ACTIVE │ TOTAL │ TRAFFIC (RX / TX)       │ UPTIME │
├──────────┼────────────┼──────────────┼──────────────────┼────────┼────────┼───────┼─────────────────────────┼────────┤
│ 1panel   │ HTTPS (L7) │ https :18091 │ 127.0.0.1:18090  │ ● OK   │ 2      │ 154   │ ↓ 18.25 MB / ↑ 52.10 MB │ 1h 24m │
│ webdisk  │ HTTPS (L7) │ https :8081  │ 127.0.0.1:8080   │ ● OK   │ 1      │ 890   │ ↓ 120.4 MB / ↑ 1.48 GB  │ 1h 24m │
│ relay:22 │ Relay (L4) │ [::]:2222    │ 127.0.0.1:2222   │ ● OK   │ 0      │ 12    │ ↓ 45.00 KB / ↑ 82.30 KB │ 1h 24m │
╰──────────┴────────────┴──────────────┴──────────────────┴────────┴────────┴───────┴─────────────────────────┴────────╯

● Daemon: v1.0.0 | Uptime: 1h 24m | Active Conns: 3 | Total Traffic: 1.67 GB | Total Errors: 0
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

---

## 🔒 安全建议

> [!CAUTION]
> 开启自动 IPv6 中继后，若路由器放行了 IPv6 入站流量，原本仅局域网可见的 IPv4 服务将通过 IPv6 **直接暴露至公网**。

1. **默认高危端口保护**：`nasconn+` 内置保护清单（22, 53, 67, 68, 123, 161, 445, 1883, 2375, 3306, 5432, 6379, 8086, 9000, 9200, 11211, 27017）。用户的 `exclude` 配置会自动进行并集合并，无需担心用户手填端口遗漏核心安全防护。
2. **路由器防火墙**：建议在主路由上对非公开端口（如内网管理口、无密码测试服务）进行 IPv6 入站端口限制。
3. **白名单模式**：对安全性要求极高的环境，建议配置 `"mode": "whitelist"` 并填写 `relay.allow` / `https_allow` 显式白名单，仅放行经过评估的服务。
4. **安全凭据**：对于暴露在外网的服务，请务必开启强密码、多因素认证（2FA）或访问凭据。
5. **ACME 证书与 HSTS 考量**：
   - ACME HTTP-01 验证要求宿主机 80 端口能接收公网 Let's Encrypt 质询请求。若运营商封锁 80 端口，请使用外部申请的证书并配置 `cert_config_path` 或使用内置自签证书。
   - HSTS 遵守 RFC 6797 标准规范，仅在使用合规域名及有效证书时启用，禁止为 IP 地址或自签证书开启 HSTS，避免造成不可逆的浏览器证书死锁。

---

## 🧪 测试与质量保证 (Testing & Quality)

本项目核心业务模块均编写了自动化单元测试、集成测试与竞态检测（Race Detector），由 GitHub Actions CI 在多版本 Go 环境下自动守护。整体语句覆盖率达到 **82.1%**，核心子模块覆盖率明细如下：

| 模块 (Package) | 职责说明 | 覆盖率 (Coverage) | 质量保障重点 |
| :--- | :--- | :---: | :--- |
| `internal/logger` | 结构化终端排版与多通道着色日志记录器 | **100.0%** | 并发无竞态、NO_COLOR 终端无缝降级 |
| `cmd/nasconnplus` | 命令行入口点与二进制启动器 | **100.0%** | 参数透传与入口生命周期 |
| `internal/scanner` | Linux 内核 procfs 端口嗅探、HTTP 探测与报表 | **93.8%** | procfs 零依赖解析、自进程 /proc/self/fd 解耦、ss 解析测试 |
| `internal/config` | 配置文件查找、递归解析、高危端口并集防御与边界校验 | **88.3%** | 白名单模式、/tmp 敏感路径防提权、高危并集保护 |
| `internal/app` | 守护进程生命周期、CLI 参数解析与主事件循环协调器 | **85.5%** | 命令行解析、状态联动、优雅信号平滑终止、pprof 支持 |
| `internal/ipc` | Unix Domain Socket 客户端/服务端 IPC 通信与大盘渲染 | **84.2%** | 0600 权限隔离、优雅重试、健康状态报表 |
| `internal/cert` | TLS 证书管理器、ECDSA 自签与 Let's Encrypt 适配 | **76.8%** | 证书热重载、指纹防重复加载、多域名命中 |
| `internal/proxy` | L4 零拷贝 TCP Relay 中继与 L7 HTTPS 反向代理引擎 | **69.3%** | 零拷贝 splice、并发限制器、HSTS 注入、双栈平滑交接 |
| **综合覆盖率 (Total)** | **全项目业务代码总覆盖** | **`82.1%`** | **持续集成 CI 自动全链路守护** |

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

## 🛠️ 源码编译与安装 (Build from Source)

如果你本地已配置 Go（>= 1.22）环境，可以通过以下方式直接从源码安装或构建：

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
```

---

## 🗺️ 开发路线图 (Roadmap)

`nasconn+` 持续演进中，欢迎社区共同参与建设：

- [x] 原生 Linux `/proc/net/tcp` 零依赖、毫秒级端口自动探测
- [x] L4 高性能零拷贝 IPv6 同端口透明中继（基于 Google `inetaf/tcpproxy` + Linux `splice(2)`）
- [x] L7 智能反向代理（自动嗅探 HTTP 并在 `端口 + 1` 开启 HTTPS 升级）
- [x] 标准 X-Forwarded 报头注入（解决 1Panel/Nextcloud 302 重定向循环）
- [x] 三级证书安全管理（Let's Encrypt 自动续签、外部证书热重载、ECDSA 10年自签证书兜底）
- [x] 本地 Unix Domain Socket 实时状态大盘（`nasconnplus status`）
- [x] 终端人体工程学美化与单次诊断报表（`-t` 模式）
- [ ] 🔑 ACME DNS-01 验证支持（针对家庭宽带封锁 80/443 端口场景自动申请泛域名证书）
- [ ] 🌐 UDP 端口 IPv6 镜像与中继转发支持
- [ ] 🎯 SNI 域名级智能多证书路由与虚拟主机支持

---

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

- [inetaf/tcpproxy](https://github.com/inetaf/tcpproxy) - 提供强大的底层 TCP 零拷贝代理能力
- [charmbracelet/lipgloss](https://github.com/charmbracelet/lipgloss) - 提供优雅的现代极客终端排版与配色
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - 提供 Let's Encrypt ACME 证书全自动化能力

---

## 📄 开源许可证 (License)

本项目基于 [MIT 许可证](LICENSE) 开源，自由免费，允许商业与个人使用。
