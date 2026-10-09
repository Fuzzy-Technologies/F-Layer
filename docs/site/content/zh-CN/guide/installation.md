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

安装 [v1.2.1 发行版](https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.2.1)的 wheel：

```bash
python -m pip install https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v1.2.1/f_layer-1.2.1-py3-none-any.whl
flayer --help
flayer check --format json
```

预期结果为 `"status": "ok"`，退出码为 `0`。`flayer` 和 `python -m flayer`
接受相同参数。此稳定版本的部署步骤请见 [SSH 网关指南](first-deployment.md)。

也可以从发行页下载 `f_layer-1.2.1-py3-none-any.whl`，将本地文件路径传给
`python -m pip install`。该发行页还提供源码压缩包和包含文件哈希的构建报告。
PyPI 发布是独立步骤；正式宣布 PyPI 发布之前，请使用上述 wheel。
即将推出的 2.0 功能尚未包含在稳定版 1.2.1 中。

部署指南需要 Linux 或 macOS，因为保存配置文件时会检查 POSIX 文件所有者和
访问权限。Windows 可以安装软件包并运行本地诊断；部署请使用 Linux 环境。

## 安装 2.0 预发布版本 {#install-the-20-candidate}

要使用 AmneziaWG 和 VLESS Reality，请在 Linux 或 WSL 中安装经过审核的
2.0 预发布 wheel，并启用 `vpn` 可选依赖。[快速开始](index.md)提供本地 wheel
安装命令、项目设置和部署步骤。应从已审核代码版本对应的
[CI 运行](https://github.com/Fuzzy-Technologies/F-Layer/actions)下载构建产物，
不要使用 v1.2.1 发行页上的 wheel。保留文件原始名称和版本。
预发布构建可能仍显示当前开发中的软件包版本；请核对代码版本，并确认存在
`flayer project` 和 `flayer vpn` 命令。本指南不表示软件包已在 PyPI 发布，
也不表示 2.0 稳定版已经发布。

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
