# 安装 {#install}

F-Layer 是 Python 软件包，需要 **Python 3.11 或更高版本**。安装发行版无需
Git 或 Docker。发行包名称为 `f-layer`，Python 模块和命令名称为 `flayer`。

## 安装发行包 {#install-the-release-package}

创建独立的 Python 环境：

```bash
python -m venv .venv
```

| 终端                    | 激活命令                     |
| ----------------------- | ---------------------------- |
| Linux/macOS bash 或 zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

从[发布文件](https://github.com/Fuzzy-Technologies/F-Layer/releases)下载
`f_layer-2.0.0-py3-none-any.whl` 和 `build-evidence.json`。
核对 wheel 的 SHA-256 与构建报告一致。在下载目录中安装带 `vpn` 可选依赖的
F-Layer 2.0：

```bash
python -m pip install "./f_layer-2.0.0-py3-none-any.whl[vpn]"
flayer --help
flayer check --format json
flayer project --help
flayer vpn --help
```

预期结果为 `"status": "ok"`，退出码为 `0`。`flayer` 和 `python -m flayer`
接受相同参数。然后阅读 [VPN 快速开始](index.md)，或使用
[SSH 网关指南](first-deployment.md)配置受限的 SSH 转发。

`vpn` 可选依赖提供用于在本地生成密钥的密码学库。发布文件还包括源码归档及
包含代码修订和产物哈希的构建报告。请将报告与安装包一起保存。

VPN 部署控制端应运行在 Linux 或用户管理的 WSL Linux 发行版中，并安装
OpenSSH 和 Yandex Cloud CLI。私有项目文件使用 POSIX 所有权和权限。
Windows 可以运行软件包诊断；部署时使用 WSL 环境。

## 开发环境 {#development-checkout}

只有开发者需要 Git。要使用集成分支：

```bash
git clone --branch develop https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
python -m pip install -e ".[dev]"
```

开发时运行与当前改动相关的测试。打开 pull request 后，CI 会执行完整检查。
测试和文档构建方法请参阅[开发指南](../development.md)。

## 安装问题 {#installation-issues}

| 现象                     | 处理方法                                                       |
| ------------------------ | -------------------------------------------------------------- |
| `No module named flayer` | 激活安装软件包时使用的环境，并在该环境中重新安装 wheel。       |
| `python` 不可用          | 统一使用 Python 3.11+ 启动命令，例如 `python3` 或 `py -3.11`。 |
| `flayer` 不可用          | 激活安装环境，或使用 `python -m flayer`。                      |
| Windows 激活受阻         | 直接使用 `.venv\Scripts\python.exe` 安装和运行。               |

凭据、生成的客户端配置和部署状态应保存在源码仓库之外。
