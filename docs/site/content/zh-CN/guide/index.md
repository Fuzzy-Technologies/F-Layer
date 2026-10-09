# 快速开始 {#quick-start}

先在本地试用 F-Layer，再选择服务检查或云部署。需要 **Python 3.11+ 和 Git**。
首次检查不需要云账号。

## 1. 安装稳定发行版 {#1-install-the-stable-release}

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git checkout v1.2.1
python -m venv .venv
```

在自己的终端中激活环境：

| 终端                    | 命令                         |
| ----------------------- | ---------------------------- |
| Linux/macOS bash 或 zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

```bash
python -m pip install .
```

环境问题请参阅[安装说明](installation.md)。

## 2. 运行首次检查 {#2-run-your-first-check}

```bash
python -m flayer --help
python -m flayer check --format json
```

预期结果为 `"command": "check"`、`"status": "ok"`，退出码 **0**。
这些检查确认 Python 和 F-Layer 可用，不会访问服务、认证云账号或创建服务器。

帮助中的 `{status,check,health,benchmark,lifecycle}` 表示**选择一个命令**，
无需输入花括号。例如，`python -m flayer check --help` 显示 `check` 的选项。

## 3. 选择实际场景 {#3-choose-a-real-scenario}

**检查 HTTP 服务。** 指定获准访问的端点：

```bash
python -m flayer health --endpoint https://example.com/ --timeout 3 --format json
```

将示例地址替换为自己的服务。这会发送 HTTP 请求；`"status": "ok"` 和退出码
`0` 表示检查通过。失败时返回非零退出码及结构化结果。
[CLI 指南](cli.md)介绍状态、限制和时间测量。

**在 Yandex Cloud 部署 SSH 网关。** 按照[首次部署](first-deployment.md)
准备配置和资源计划，再明确授权云变更。需要云账号及已认证的 `yc` 配置档；
云资源可能产生费用。网关通过 SSH 将流量转发到配置的目标，不是现成的 VPN 配置。

**集成到 Python 应用。** 从 [API 参考](../../en/api/index.md)和[配置指南](configuration.md)开始。

顶层 `status` 目前对云观测返回 `unsupported`，退出码 `4`。查看实际部署时，
请提供计划、状态文件和提供方配置档，使用 `lifecycle status`。
本地检查通过不代表云服务器已就绪。
