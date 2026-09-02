# Contributing to nasconn+

首先，非常感谢您对 **nasconn+** 项目的关注与支持！我们欢迎所有形式的贡献，无论是报告 Bug、改进文档、编写测试用例，还是提交新功能代码。

## 📋 行为准则 (Code of Conduct)

为了构建一个友善、包容且高效的开源社区，请所有参与者相互尊重、理性沟通，共同维护积极和谐的协作氛围。

---

## 🛠️ 开发环境准备

在开始贡献代码前，请确保本地已安装以下工具：

- **Go**：>= 1.22（推荐使用最新稳定版）
- **Make**：用于执行构建与测试工作流
- **Docker**（可选）：用于测试容器化部署

### 克隆与编译

```bash
# 克隆仓库
git clone https://github.com/jadenjoe/nasconnplus.git
cd nasconnplus

# 验证依赖
go mod verify

# 本地编译二进制
make build

# 运行检查
make lint
```

---

## 🧪 测试与质量要求

`nasconn+` 作为底层网络连接与安全代理工具，对稳定性与安全性有严苛的要求。在提交 Pull Request 前，请务必保证：

1. **所有测试全部通过**：
   ```bash
   make test
   ```
2. **执行竞态检测并生成代码覆盖率**：
   ```bash
   make test-coverage
   ```
   - 核心业务逻辑必须包含单元测试。
   - 新增功能需提供相应的测试用例，避免拉低整体覆盖率。
   - 可以在浏览器打开 `coverage.html` 检查未覆盖的代码分支。
3. **静态代码检查**：
   ```bash
   make vet
   ```

---

## 🌿 分支与 Commit 规范

### 分支命名

- `feature/<name>`：新特性或功能增强
- `fix/<issue-id>-<description>`：Bug 修复
- `docs/<topic>`：文档补充与修订
- `refactor/<target>`：代码重构与性能优化

### Commit Message 规范

我们推荐遵循 [Conventional Commits](https://www.conventionalcommits.org/) 格式：

- `feat: add acme dns-01 challenge support`
- `fix: resolve race condition in listener cleanup`
- `test: add unit tests for counting conn interfaces`
- `docs: update docker compose guide for host networking`
- `refactor: optimize /proc/net/tcp parsing buffer reuse`

---

## 🚀 Pull Request 提交流程

1. Fork 本仓库至你的 GitHub 账号。
2. 从 `main` 分支切出新的特性分支。
3. 编写代码并添加对应的单元测试。
4. 运行 `make test-coverage` 和 `make lint` 确保所有检查通过。
5. 提交变更并推送到你的远程分支。
6. 发起 Pull Request，按照模板详细描述改动内容、影响范围及验证方式。
7. CI 机器人将自动运行多版本 Go 测试并上传覆盖率分析。

---

## 🐛 遇到问题或有新想法？

- 发现了 Bug？请在 [Issues](https://github.com/jadenjoe/nasconnplus/issues) 中提交并附带复现步骤与环境信息。
- 有关于架构或未来规划的想法？欢迎在 GitHub Discussions 或 Issue 中发起讨论。
