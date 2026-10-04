# 从源码安装 {#install-from-source}

F-Layer 需要 **Python 3.11 或更高版本**和 Git。`f-layer` 发行包包含 `flayer` Python 包。本文不假定已有 PyPI 发布版：安装当前检出的源码，使文档与行为一致。

## 克隆和安装 {#clone-and-install}

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git switch develop
python -m venv .venv
```

按控制台类型激活环境：

| 控制台                  | 激活命令                     |
| ----------------------- | ---------------------------- |
| Linux/macOS bash 或 zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

安装并检查当前包：

```bash
python -m pip install .
python -m flayer --help
python -m flayer check --format json
```

`check` 检查本地运行环境和包是否可用，不认证云账户、不推断文件夹、不创建基础设施，也不证明客户机就绪。成功的诊断以 `0` 退出。

模块命令 `python -m flayer` 可在基础包中使用。发行任务 #25 引入 `flayer` 控制台入口；包含该变更后，入口接受相同命令参数。

## 开发环境 {#development-checkout}

贡献者应以可编辑模式安装源码和固定版本的验证工具：

```bash
python -m pip install -e ".[dev]"
python tools/validate.py
```

规范验证工具执行编译、lint、类型检查和全部测试阶段，分别验证行覆盖率和分支覆盖率下限，并隔离安装 wheel。测试使用虚构资源，禁止未经请求的网络访问。文档构建见[开发流程](../development.md)。

## 安装问题 {#installation-issues}

| 现象                          | 下一步                                                                        |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `No module named flayer`      | 激活执行 `python -m pip install .` 时使用的同一环境，然后从检出目录重新安装。 |
| `python` 不可用               | 始终使用平台的 Python 3.11+ 启动器，例如 `python3` 或 `py -3.11`。            |
| `flayer` 不可用但模块命令可用 | 使用 `python -m flayer`；控制台入口需要当前版本包含任务 #25。                 |
| Windows 激活受阻              | 直接使用 `.venv\Scripts\python.exe` 执行安装和命令。                          |

切换分支后请重新安装，使安装包与源码版本一致。生成的环境、凭据和运行时状态不要进入版本控制。
