# 快速开始 {#quick-start}

创建一个私有 VPN 项目，将服务部署到 Yandex Cloud 服务器，再通过 **AmneziaWG**
或 **VLESS Reality** 连接设备。F-Layer 会创建云资源、安装两种服务，并为每台设备
分别导出客户端配置。

本教程需要包含 `flayer project` 和 `flayer vpn` 命令的 **2.0 开发候选版本**。
已发布的 **v1.2.1** 支持 [SSH 网关部署](first-deployment.md)，但不包含这些 VPN
命令。2.0 尚未发布为稳定版。

## 1. 安装候选版本 {#1-install-the-candidate}

如需委托能够访问终端的助手完成这些步骤，请复制 [AI 快速开始](ai-operator.md)
中的任务。该指南涵盖版本选择、助手应询问的问题、付费资源批准以及实际连接验证。
下方命令供手动执行。

使用 Linux 或 WSL，并准备 Python 3.11+、OpenSSH（`ssh` 和 `ssh-keygen`）以及
[官方 Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)。
从项目 CI 中下载已审查候选版本的 wheel 构建产物。按照[安装指南](installation.md)
创建并激活虚拟环境，然后安装该 wheel 及其 `vpn` 可选依赖。将下面的路径替换为
实际下载文件的路径，保留文件原有的版本号：

```bash
FLAYER_WHEEL=/absolute/path/to/downloaded-candidate.whl
python -m pip install "${FLAYER_WHEEL}[vpn]"
flayer project --help
flayer vpn --help
```

`vpn` 可选依赖提供用于在本地生成密钥的密码学库，无需 Git 或 Docker。
通过 v1.2.1 的发行版链接安装，得到的仍是 v1.2.1，而不是 2.0 候选版本；即使候选
构建暂时使用相同的软件包版本号，两者也不同。请选择经过审查的代码版本所对应的
构建产物。

## 2. 创建并配置项目 {#2-set-up-the-project}

按照官方说明初始化 `yc`，然后查看配置档并创建项目：

```bash
yc config profile list
flayer project init ~/flayer-vpn
```

打开 `~/flayer-vpn/project.toml`，在准备部署前填写以下设置：

| 设置                                     | 填写内容                                                                                       |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `identity.project`, `stack`, `owner_id`  | 用于标识项目、部署和所有者的名称。                                                             |
| `identity.scope_id`                      | 用于创建资源的 Yandex Cloud 文件夹 ID。                                                        |
| `cloud.yc_profile`                       | 已配置的 `yc` 配置档，需要有权在该文件夹中创建和删除计算及网络资源。                           |
| `cloud.zone_id`, `cloud.image_id`        | 目标可用区和 Ubuntu 24.04 **amd64** 镜像 ID。                                                  |
| `cloud.management_cidrs`                 | 管理员当前的公网 IPv4 地址，加上 `/32`；必须替换示例地址。                                     |
| `devices`                                | 设备名称及各自唯一的隧道地址；可以先使用示例中的 `laptop` 和 `10.66.0.2`。                     |
| `vless.target_host`, `vless.server_name` | 云服务器能够访问的 TLS 1.3 / HTTP/2 站点，其证书必须对指定服务器名称有效。预填主机名只是示例。 |

先保留示例路由设置，试用 IPv4 的 full 模式。连接前，请在 VPN 客户端设置中或设备
系统中关闭 IPv6，因为此版本不转发 IPv6。修改 TOML 中的 `ipv6_policy` 不会更改
设备的操作系统设置。

项目目录会保存 SSH 和 VPN 私钥。请将其放在 Git 仓库和共享目录之外，保留访问权限
限制，并妥善保存私有备份。在下一步之前，先确定需要哪些设备和路由。

## 3. 准备并部署 {#3-prepare-and-deploy}

```bash
flayer vpn prepare --project ~/flayer-vpn
flayer vpn deploy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
flayer vpn status --project ~/flayer-vpn
```

将 `YOUR_FOLDER_ID` 替换为与 `identity.scope_id` 完全相同的值。`prepare` 只创建
本地文件，不访问云。`deploy` 创建网络、子网、安全组、公网地址、启动磁盘和虚拟机，
然后安装两种 VPN 服务。资源存在期间，Yandex Cloud 会收取相应费用。

传输私有文件前，F-Layer 会通过 Yandex API 获取该项目所属虚拟机的 SSH 主机密钥，
并以此验证 SSH 连接。部署报告中的 `services-active` 表示服务器进程正在运行；
客户端连接仍需按下一节验证。

## 4. 连接设备 {#4-connect-a-device}

使用对应设备的文件。默认 `laptop` 设备的导入方法如下：

| 协议          | 导入内容                                                                 | 客户端设置                                                                                     |
| ------------- | ------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- |
| AmneziaWG     | `~/flayer-vpn/artifacts/device-laptop-amneziawg/amneziawg.conf`          | 导入支持 AmneziaWG 3.1 的客户端，再启用隧道。普通 WireGuard 客户端不支持新增的协议字段。       |
| VLESS Reality | `~/flayer-vpn/artifacts/device-laptop-vless-reality/import.txt` 中的 URI | 导入 v2rayN、v2rayNG 等兼容客户端。要接管整台设备的流量，需明确设置 DNS、路由和 VPN/TUN 模式。 |

VLESS 导入链接不包含完整的 DNS 和路由策略。对于原生 Xray 客户端，同一目录还提供
`client.json`，其中保留了应用代理策略，并在 `127.0.0.1:10808` 监听。应用需要使用
`socks5h://127.0.0.1:10808`；其他应用的流量不会自动经过该代理。
兼容客户端、分流路由和协议细节见 [AmneziaWG](../../../../architecture/amneziawg.md)
和 [VLESS Reality](../../../../architecture/vless-reality.md) 指南。

**每次只测试一种协议**。通过各自的客户端打开 HTTPS 网站，确认网站看到的公网
IPv4 地址是服务器地址，并检查 DNS 和 IPv6 的实际行为。导入成功或服务器服务
正在运行，都不能单独证明流量已通过隧道。

## 5. 恢复或删除部署 {#5-recover-or-remove-the-deployment}

如果创建云资源的过程被中断，请保留原项目文件并执行：

```bash
flayer vpn recover --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

重试前先阅读报告。如果服务器安装过程在中途被中断，可能需要检查并恢复已知的
私有文件；云资源恢复并不意味着可以覆盖服务器上无法确认归属的配置。

删除属于本项目的云资源：

```bash
flayer vpn destroy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

检查命令结果和云文件夹。本地密钥、客户端文件和状态仍保留在项目目录中，确认
清理完成前不要删除。

此版本不允许修改已准备项目的设置。如需添加设备或修改路由，请先使用原项目和
未修改的设置删除旧部署，再用所需设置初始化一个**新的私有项目目录**。CLI 尚不
支持在现有部署中直接添加设备、撤销访问权限或更换密钥。

## 后续步骤 {#next-steps}

目前实现的云提供方是 Yandex Cloud，其他云需要相应适配器。检查现有服务可使用
[CLI 诊断](cli.md)；要集成到 Python 应用，请阅读[配置指南](configuration.md)
和 [API 参考](../api/index.md)。发行版维护者按照
[VPN 发行验收流程](../../../../development/vpn-release-acceptance.md)记录真实云部署
和客户端检查的结果。

命令帮助中的花括号，例如 `{prepare,deploy,status,destroy,recover}`，表示
**选择一个命令**。不需要输入花括号。
