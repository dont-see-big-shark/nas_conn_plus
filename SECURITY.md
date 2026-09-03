# Security Policy

## 支持的版本 (Supported Versions)

我们为以下版本的 `nasconn+` 提供安全修复与技术支持：

| 版本 | 是否支持安全更新 |
| :--- | :--- |
| `v1.x` | :white_check_mark: 支持 (Active) |
| `< v1.0` | :x: 不再维护 |

---

## 报告安全漏洞 (Reporting a Vulnerability)

如果您在 `nasconn+` 中发现了安全缺陷或潜在的漏洞，**请不要在公开的 GitHub Issue 中讨论**。

请通过以下方式私下与维护团队联系：

- **联系邮箱**：通过维护者 GitHub 个人主页查找安全联系方式。
- **GitHub 私密漏洞报告 (Private Vulnerability Reporting)**：直接在仓库页面的 `Security` -> `Advisories` -> `Report a vulnerability` 中创建私密报告 (已启用)。

### 报告时请包含以下信息：
1. 漏洞类型及受影响的模块（如 TLS 握手、HTTP 反代头注入、内核网络解析、IPC 通信）。
2. 复现步骤、POC 代码或最小复现配置。
3. 漏洞可能造成的影响评估（如信息泄露、未授权端口暴露、拒绝服务 DoS）。
4. 受影响版本与复现环境 (Go 版本、内核、容器/宿主机)。

我们承诺在收到报告后的 **48 小时内** 给出初步响应，并在确认漏洞后 **7 天内** 发布修复并在 `CHANGELOG.md` 中记录 CVE 编号。
我们遵循协调披露 (Coordinated Disclosure)，请给予至少 90 天的修复窗口期后再公开细节。

---

## 🛡️ 用户安全最佳实践

1. **IPv6 防火墙策略**：
   - 自动 IPv6 中继开启后，局域网内的 IPv4 服务将对外开放 IPv6 访问。建议在主路由器（或光猫）配置防火墙规则，仅放行明确需要外网访问的端口。
2. **敏感端口白名单排除**：
   - 强烈建议在 `config.json` 的 `relay.exclude` 与 `https_exclude` 中排除 SSH (22)、数据库 (3306, 5432, 6379) 等高危端口。
3. **IPC Unix Socket 安全**：
   - `nasconn+` 守护进程与 CLI 交互所使用的 Unix Socket 文件默认限制为 `0600` 权限，仅允许启动用户或 root 访问，杜绝本地多用户提权风险。
