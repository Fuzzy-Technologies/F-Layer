# 快速入门 {#quick-start}

创建一个私有 VPN 项目，将服务部署到 Yandex Cloud 服务器，再通过 **AmneziaWG**
或 **VLESS Reality** 连接设备。F-Layer 会创建云资源、安装两种服务，并为每台设备
分别导出客户端配置。

## 1. 安装 F-Layer {#1-install-f-layer}

如需委托能够访问终端的助手完成这些步骤，请复制 [AI 快速入门](ai-operator.md)
中的任务。该指南涵盖安装、助手应询问的问题、付费资源批准以及实际连接验证。
下方命令供手动执行。

使用 Linux 或 WSL，并准备 Python 3.11+、OpenSSH（`ssh` 和 `ssh-keygen`）以及
[官方 Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)。
下载 F-Layer 2.0.0 wheel，并按[安装指南](installation.md)核对哈希。
创建并激活虚拟环境，然后安装 wheel 及其 `vpn` 可选依赖。
将下面的路径替换为实际下载文件的路径：

```bash
FLAYER_WHEEL=/absolute/path/to/f_layer-2.0.0-py3-none-any.whl
python -m pip install "${FLAYER_WHEEL}[vpn]"
flayer project --help
flayer vpn --help
```

`vpn` 可选依赖提供本地生成密钥所需的密码学库，以及离线生成二维码的 Segno。
无需 Git 或 Docker。

## 2. 创建并配置项目 {#2-set-up-the-project}

按照官方说明初始化 `yc`，查看 CLI 命名配置（profile），再创建项目：

```bash
yc config profile list
flayer project init ~/flayer-vpn
```

打开 `~/flayer-vpn/project.toml`，在准备部署前填写以下设置：

| 设置                                     | 填写内容                                                                                       |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `identity.project`, `stack`, `owner_id`  | 用于标识项目、部署和所有者的名称。                                                             |
| `identity.scope_id`                      | 用于创建资源的 Yandex Cloud 文件夹 ID。                                                        |
| `cloud.yc_profile`                       | 已配置的 `yc` 命名配置，需要有权在该文件夹中创建和删除计算及网络资源。                         |
| `cloud.zone_id`, `cloud.image_id`        | 目标可用区和 Ubuntu 24.04 **amd64** 镜像 ID。                                                  |
| `cloud.management_cidrs`                 | 管理员当前的公网 IPv4 地址，加上 `/32`；必须替换示例地址。                                     |
| `devices`                                | 设备名称及各自唯一的隧道地址；可以先使用示例中的 `laptop` 和 `10.66.0.2`。                     |
| `vless.target_host`, `vless.server_name` | 云服务器能够访问的 TLS 1.3 / HTTP/2 站点，其证书必须对指定服务器名称有效。预填主机名只是示例。 |

先保留示例路由设置，试用 IPv4 全隧道（`full`）模式。连接前，请在 VPN 客户端设置中或设备
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

在执行 `deploy`、`status`、`recover` 或 `destroy` 前，F-Layer 会检查
`cloud.yc_profile` 指定的配置能否读取 `identity.scope_id` 指定的文件夹。
预检失败时不会开始云资源生命周期操作，已有状态和日志保持不变。
出现 `authentication` 时，通过官方本地登录流程重新认证该配置；
出现 `permission_denied` 时，检查文件夹访问权限。仅有 `timeout` 不能证明
凭据已过期，也不能证明 API 服务中断。请将凭据保密，并按照
[AI 操作指南的排障步骤](ai-operator.md#5-deploy-and-observe)检查。
此预检不验证写权限，也不保证整个运行期间都能访问云服务。

## 4. 连接 Android 设备 {#4-connect-a-device}

参考客户端为 **Android 版 AmneziaVPN 5.0.3.0**。请使用对应设备的文件；
以下路径采用默认设备名 `laptop`。

1. 在 AmneziaVPN 中选择从文件添加连接，为 AmneziaWG 导入
   `artifacts/device-laptop-amneziawg/amneziawg.conf`。
   普通 WireGuard 客户端不支持 AmneziaWG 3.1 的附加字段。
2. 对于 VLESS，在另一块屏幕上本地打开
   `artifacts/device-laptop-vless-reality/amnezia-qr-01.svg`，
   使用 **AmneziaVPN 内置扫码器**扫描。若有多个编号二维码，须在同一次导入
   会话中依次扫描全部二维码。也可将 `amnezia.vpn` 作为连接文件导入，
   或粘贴其中的 `vpn://` 连接密钥。不要用此扫码器扫描由 `import.txt` 生成的二维码。
3. 启用 Android VPN 连接并授予系统请求的 VPN 权限。检查全设备 VPN/TUN 模式、
   指定的 DNS 服务器及应用或目标地址排除项。原生配置包含生成的 Xray DNS 和
   路由策略，但应用设置可能覆盖这些配置。请按前文说明在客户端或设备上禁用 IPv6；
   IPv4 测试成功并不能证明 IPv6 不会绕过连接。
4. **逐一测试**两种协议，先断开另一个配置。通过域名访问 HTTPS 网站，核对
   可见的公网 IPv4 是否为服务器地址，并验证实际流量、DNS、路由及 IPv6 行为。
   `services-active`、`connectivity=not-verified`、导入成功或客户端显示
   “已连接”，均不能单独证明互联网访问正常。

连接配置、二维码及连接密钥均可授予对应设备的访问权限，请妥善保密。
文件权限保持为 `0600`，配置包目录权限为 `0700`。
不要将其上传到在线二维码转换工具或公开的问题跟踪系统。

两种协议均可通过[本地设备导出](cli.md#export-an-existing-vpn-device)，从现有客户端文件生成 AmneziaVPN 原生连接文件和可选 QR 帧。应用单独出现问题时，使用 [Shorts/Telegram 对照诊断](cli.md#investigate-shorts-and-telegram-media)。

供 v2rayNG 等客户端使用的标准 VLESS URI 仍单独保存在 `import.txt` 中，
不携带完整 DNS 和路由策略。`client.json` 保留完整的 Xray 应用代理策略，
监听 `127.0.0.1:10808`。使用固定版本的 Xray 启动该配置，然后比较以下 HTTPS 检查：

```bash
curl --fail --show-error --max-time 20 --proxy socks5h://127.0.0.1:10808 https://example.com/
curl --fail --show-error --max-time 20 --ipv4 --proxy socks5://127.0.0.1:10808 https://example.com/
```

两项均须成功。第一项通过代理解析域名，第二项在本地解析为 IPv4。
另须使用操作人员选择的服务核对出口 IP。SOCKS 检查只覆盖使用该代理的应用，
不能代替 Android VPN/TUN 测试。目标的 TLS 1.3/HTTP2 预检同样不能证明
Reality 身份认证成功；更换目标或 Xray 版本后须重新验证真实客户端流量。
详见 [AmneziaWG](../../../../architecture/amneziawg.md) 和
[VLESS Reality](../../../../architecture/vless-reality.md) 指南。

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

目前已实现的云适配器支持 Yandex Cloud，其他云需要相应适配器。检查现有服务可使用
[CLI 诊断](cli.md)；要集成到 Python 应用，请阅读[配置指南](configuration.md)
和 [API 参考](../api/index.md)。发行版维护者按照
[VPN 发行验收流程](../../../../development/vpn-release-acceptance.md)记录真实云部署
和客户端检查的结果。

命令帮助中的花括号，例如 `{prepare,deploy,status,destroy,recover}`，表示
**选择一个命令**。不需要输入花括号。
