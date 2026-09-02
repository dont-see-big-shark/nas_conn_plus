<div align="center">

# 🚀 nasconn+

**专为 NAS 与家庭自建服务打造的轻量级连接增强工具**  
*突破 IPv4 大内网限制 · 自动 IPv6 中继 · 端口 +1 无感升级 HTTPS*

[![Go Report Card](https://goreportcard.com/badge/github.com/jadenjoe/nasconnplus)](https://goreportcard.com/report/github.com/jadenjoe/nasconnplus)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-%3E%3D%201.22-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20NAS%20%7C%20Docker-lightgrey)](https://github.com/jadenjoe/nasconnplus)

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

1. 从 [Releases 页面](https://github.com/jadenjoe/nasconnplus/releases) 下载适合你架构的预编译包（支持 `amd64` / `arm64` / `armv7`）。
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
> #### ⚠️ Docker 部署 5 大核心注意事项（必读避坑指南）
> `nasconn+` 属于**底层网络基础设施**工具，需在宿主机嗅探端口并对外开放 IPv6/HTTPS 监听，因此容器配置有严格要求：
> 
> 1. **必须配置 `network_mode: host`**：
>    Docker 默认的 `bridge`（桥接）网络会将容器隔离在独立虚拟子网中，导致容器**无法感知宿主机的 0.0.0.0 端口**，也无法直接在宿主机的公网 IPv6 上开放中继。必须使用 Host 主机网络。
> 2. **必须配置 `pid: host`**：
>    用于扫描器访问宿主机的 `/proc` 获取端口属主（进程名与 PID）。若缺少此项，容器内将无法匹配宿主机上各进程的 PID。
> 3. **必须开启特权模式（`privileged: true`）**：
>    绑定特权端口（< 1024，如 80/443）及设置 `IPV6_V6ONLY` 底层套接字需要 Linux 网络管理能力。也可以精细化配置：
>    ```yaml
>    cap_add:
>      - NET_ADMIN
>      - NET_BIND_SERVICE
>    ```
> 4. **必须挂载数据卷持久化存储**：
>    容器必须挂载持久化目录（如 `./tls` 和 `./acme_cache`）。如果不挂载，每次容器更新或重启都会重新生成证书，导致浏览器因 SSL 证书指纹变更而报错拦截。
> 5. **路由器 IPv6 防火墙放行（入站规则）**：
>    即使容器成功在中继了端口，若主路由器（光猫）默认拦截了入站流量，外网仍然无法连接。请在路由器设置中为 NAS 设备放行对应的 IPv6 入站端口。

#### `docker-compose.yml` 完整配置：

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

    # 核心：必须使用宿主机网络和进程命名空间
    network_mode: host
    pid: host
    privileged: true

    volumes:
      # 挂载配置文件（可选，首次启动会自动生成默认配置）
      - ./config.json:/etc/nasconnplus/config.json
      # 必须挂载：持久化存储 TLS 证书与 ACME 缓存，防止容器重建导致证书变更
      - ./tls:/etc/nasconnplus/tls
      - ./acme_cache:/etc/nasconnplus/acme_cache

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
| `acme` | 对象 | 禁用 | 自动向 Let's Encrypt 申请免费证书：`{"enabled": true, "domain": "nas.xxx.com", "email": "admin@xxx.com"}` |
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
  -s, -status
        查询运行中的守护进程状态（等同于 nasconnplus status）
  -t, -test
        诊断模式：执行一次扫描，输出当前主机所有端口的分类报表后退出
  -v, -version
        显示版本号与架构信息
```

#### 📊 实时状态大盘（`nasconnplus status` 或 `nasconnplus -s`）：
随时随地在任意终端执行一行命令，立即输出当前各代理端口的活跃连接数、总处理量与吞吐流量统计：

```text
╭──────────┬────────────┬──────────────┬──────────────────┬────────┬───────┬─────────────────────────┬────────╮
│ SERVICE  │ TYPE       │ LISTEN ADDR  │ BACKEND          │ ACTIVE │ TOTAL │ TRAFFIC (RX / TX)       │ UPTIME │
├──────────┼────────────┼──────────────┼──────────────────┼────────┼───────┼─────────────────────────┼────────┤
│ 1panel   │ HTTPS (L7) │ https :18091 │ 127.0.0.1:18090  │ 2      │ 154   │ ↓ 18.25 MB / ↑ 52.10 MB │ 1h 24m │
│ webdisk  │ HTTPS (L7) │ https :8081  │ 127.0.0.1:8080   │ 1      │ 890   │ ↓ 120.4 MB / ↑ 1.48 GB  │ 1h 24m │
│ relay:22 │ Relay (L4) │ [::]:2222    │ 127.0.0.1:2222   │ 0      │ 12    │ ↓ 45.00 KB / ↑ 82.30 KB │ 1h 24m │
╰──────────┴────────────┴──────────────┴──────────────────┴────────┴───────┴─────────────────────────┴────────╯

● Daemon: v1.0.0 | Uptime: 1h 24m | Active Conns: 3 | Total Traffic: 1.67 GB
```

#### 🩺 端口诊断模式（`nasconnplus -t`）：
```text
╭───────┬────────────────┬─────────────┬──────┬───────────┬─────────────────────╮
│ PORT  │ IPv4 (0.0.0.0) │ IPv6 ([::]) │ PID  │ PROCESS   │ RELAY ACTION        │
├───────┼────────────────┼─────────────┼──────┼───────────┼─────────────────────┤
│ 22    │ YES            │ YES         │ 1024 │ sshd      │ ● Native Dual-Stack │
│ 3000  │ YES            │ No          │ 4182 │ node      │ ● Will Relay to IPv6│
│ 8080  │ YES            │ No          │ 5219 │ java      │ ● Will Relay to IPv6│
╰───────┴────────────────┴─────────────┴──────┴───────────┴─────────────────────╯
```

---

## 🔒 安全建议

> [!CAUTION]
> 开启自动 IPv6 中继后，若路由器放行了 IPv6 入站流量，原本仅局域网可见的 IPv4 服务将通过 IPv6 **直接暴露至公网**。

1. **路由器防火墙**：建议在主路由上对非公开端口（如内网管理口、无密码测试服务）进行 IPv6 入站端口限制。
2. **白名单排除**：对于 SSH (22)、内部数据库 (3306/5432) 等敏感服务，请在 `relay.exclude` 中明确排除。
3. **安全凭据**：对于暴露在外网的服务，请务必开启强密码、多因素认证（2FA）或访问凭据。

---

## 🤝 贡献与反馈

欢迎提交 Issue、功能建议或 Pull Request！
- 发现 Bug 请在 GitHub Issue 详细描述环境（NAS 型号、系统版本、复现步骤）。
- 新特性建议欢迎随时讨论交流。

---

## 📄 License

本项目基于 [MIT 许可证](LICENSE) 开源。
