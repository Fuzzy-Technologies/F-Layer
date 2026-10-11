# CLI 和诊断结果 {#cli-and-diagnostic-results}

基础包支持通过 `python -m flayer` 调用命令行接口。所有帮助命令都可离线运行。`check` 是本地操作；HTTP 诊断需要明确的端点。

```bash
python -m flayer --help
python -m flayer check --format json
python -m flayer status --format text
python -m flayer health --help
python -m flayer benchmark --help
```

| 命令        | 观测                              | 网络                  |
| ----------- | --------------------------------- | --------------------- |
| `check`     | 本地 Python 和包可用性。          | 无。                  |
| `status`    | 本地检查和提供方观测支持。        | 基础 CLI 不访问网络。 |
| `health`    | 一个明确指定的 HTTP(S) 端点响应。 | 仅指定端点。          |
| `benchmark` | 有界 HTTP(S) 采样和传输计时。     | 仅指定端点。          |

在观测适配器接入之前，顶层 `status` 对提供方状态报告 `unsupported`，不会把缺少云端观测结果当作健康状态。任务 #20 引入的生命周期 `status` 是具有明确作用域的独立命令；参见[首次部署](first-deployment.md)。

## 明确端点的探测 {#explicit-endpoint-probes}

选择你已获授权访问的端点。以下示例使用保留域名 `example.com`；请替换成目标 HTTP(S) 端点：

```bash
python -m flayer health --endpoint https://example.com/ --timeout 3 --format json
python -m flayer benchmark --endpoint https://example.com/ --timeout 3 --count 3 --bytes 65536 --format json
```

端点 URL 不允许凭据、查询字符串和片段。TLS 证书验证保持开启，重定向和代理发现被禁用。报告省略端点、响应正文和原始异常内容。每次采样超时最多 30 秒，采样数最多 10，每次字节数最多 1 MiB。即使 DNS、TLS 或读取失败，总体执行时间和数据量仍受限制。结果描述从本机执行的此次探测，不代表提供方 SLA、VPN 吞吐量保证或部署成功。

## 退出状态 {#exit-status}

| 退出码 | 含义                      | 操作员行动                     |
| ------ | ------------------------- | ------------------------------ |
| `0`    | 所有请求的检查均为 `ok`。 | 使用已记录的观测。             |
| `1`    | 至少一项检查警告或失败。  | 查看结构化检查结果。           |
| `2`    | 命令输入或限制无效。      | 重试前修正参数。               |
| `3`    | 观测已过时。              | 获取新证据。                   |
| `4`    | 请求的观测不受支持。      | 提供端点或使用已实现的适配器。 |

JSON 报告包含 `schema_version`、`command`、汇总 `status` 和单项 `checks`。汇总状态不会掩盖任何失败的检查。自动化应检查进程退出码并解析结构化状态；不能因存在 JSON 报告就认定成功。

## 导出现有 VPN 设备 {#export-an-existing-vpn-device}

部署已生成设备文件后，可以导出一个已声明的设备：

```bash
flayer vpn export --project ~/flayer-vpn --device laptop --protocol amneziawg --output ~/flayer-export-awg --qr
flayer vpn export --project ~/flayer-vpn --device laptop --protocol vless-reality --output ~/flayer-export-vless --qr --format json
```

每个输出目录下会生成 `device-laptop-PROTOCOL/`，包含资源归属清单、原有协议文件、`amnezia.vpn`，以及指定 `--qr` 时生成的编号帧 `amnezia-qr-01.svg`。省略 `--qr` 即只导出文件。AWG 保留 `amneziawg.conf`；VLESS 保留 `client.json`、`import.txt` 和现有原生连接密钥。在 Android AmneziaVPN 中导入 `amnezia.vpn`、粘贴连接密钥，或在同一次导入中使用 **AmneziaVPN 自带扫描器扫描全部编号帧**。AWG 原生配置同时包含原始配置文本和 3.1 版结构化字段，包括 `HeaderProtectionKey`、填充参数和路由设置。普通 WireGuard 客户端不支持这些混淆字段。

导出是本地操作：不访问云端或服务器、不生成新凭据，也不检查服务器是否仍然存在。它先验证整个源文件组的归属和内容，再写入权限为 `0700` 的私有目录和 `0600` 的文件。可指定父目录已存在的新输出目录，或已有的私有目录。完全相同的导出可以重复执行；内容被修改、归属不同或文件选择不同的输出不会被覆盖。更改 QR 选项需使用另一输出目录。不能把源制品目录作为输出目录。AWG 原生导出支持一个或两个 DNS 服务器；更多服务器会被拒绝，因为原生连接外层只有两个 DNS 字段。失败时保留原始文件。

配置和 QR 图像允许以该设备身份连接，请保持私密。报告仅列出路径，不输出密钥或连接 URL。导出成功不等于连接成功；导入后需验证 DNS、路由、出口 IPv4 和客户端 IPv6 行为。原生结构和扫码帧格式依据 [AmneziaVPN 5.0.3.0 源码](https://github.com/amnezia-vpn/amnezia-client/tree/de93650a90739b87bb47a632872ea9d0adc9412f)。

## 排查 Shorts 和 Telegram 媒体问题 {#investigate-shorts-and-telegram-media}

握手、普通视频或 Speedtest 成功不能解释另一个应用失败的原因。服务内存占用低且没有 OOM 记录，不能支持内存不足的诊断。调整资源前，应收集同一事件的相关观测。

1. 记录 Android、AmneziaVPN、YouTube 和 Telegram 版本，网络（Wi-Fi 或移动网络）、DNS/私人 DNS 设置、VPN/TUN 模式和应用排除项。比较时关闭 Telegram 的独立代理，之后恢复原设置。在同一网络上测试同一个 Short 和同一个未缓存媒体文件：条件允许时直连，然后仅启用 AWG，再仅启用 VLESS。交替协议顺序重复三次，记录 UTC 开始时间、成功/错误和耗时。
2. 比较 YouTube 应用和浏览器中的同一个 Short。确认公网 IPv4 与服务器预期地址一致、DNS 使用预期解析器，且 IPv6 不会绕过隧道。分别测试 Wi-Fi 和移动网络，每次只改变一个设置。可重复的差异只缩小假设范围，不证明原因。
3. 每次尝试期间读取服务重启/退出状态、可用内存、近期 OOM、各 CPU 核心负载和网络错误/丢包。记录区间增量而非累计值。对分配部分 CPU 性能的虚拟机检查 steal time。Speedtest 和主观加载速度本身不能证明 CPU 不足。
4. 保存一次复现前后的短段 [AmneziaVPN 客户端日志](https://docs.amnezia.org/documentation/instructions/logging/)。F-Layer 默认关闭 Xray 访问和错误日志，因此生命周期日志不能诊断单个请求。必要时另行授权在测试环境中开展有时间上限的 [Xray 日志实验](https://xtls.github.io/en/config/log.html)，保留并恢复原文件和服务状态。目标地址、用户标识和原始日志保持私密；只导出脱敏的结果和耗时。不要静默修改已准备的文件或归属清单。
5. 若证据指向 DNS、UDP/QUIC 或路径 MTU，则在客户端/测试环境中单独验证该假设。[QUIC 使用 UDP](https://www.chromium.org/quic/)，这并不意味着 Shorts 失败由 QUIC 导致。不要假定 VLESS 和 AWG 的 UDP 传输行为相同。在客户端/浏览器支持时进行有界的 TCP 对照；其结果不能自动解释 Android 应用行为。AWG 配置已使用 MTU 1280，不应在缺乏路径证据时增大 MTU 或修改全局 MSS/防火墙策略。策略变更宜使用明确配置的新测试环境，并重复受影响的 DNS、路由和 IPv6 检查。

将每个假设记录为获得支持、被否定或尚未确定。本流程本身不授权修改生产 VPN 或延长付费测试环境的运行时间。
