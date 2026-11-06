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

## 可选 VLESS 传输导出（开发候选版本）

这些选项适用于面向 2.1 发布的 `develop` 候选构建，
已发布的 2.0.0 软件包不包含这些选项。普通导出保留现有行为、凭据和源文件。

- `--tls-fragment` 通过专用 Freedom 出站，对客户端到 VPN 的 Reality
  TLS 握手进行分片。固定策略使用 `tlshello`、100–200 字节分片和
  10–20 毫秒间隔，仅影响 VPN 传输。
- `--allow-quic` 在导出的客户端中选择 `xtls-rprx-vision-udp443`，
  允许内部 UDP 443 流量。普通 Vision flow 会拦截该流量，
  以便应用回退到 TCP。服务器现有 flow 保持不变。

两个选项可独立选择或组合使用，也可附加原生 QR 帧：

```bash
flayer vpn export --project ~/flayer-vpn --device laptop --protocol vless-reality --output ~/flayer-export-options --tls-fragment --allow-quic --qr
```

派生文件包包含 `client.json`、`amnezia.vpn` 和选定的 QR 帧。
请导入完整原生配置，或扫描其全部帧。不输出 `import.txt`，
因为普通 VLESS URI 无法保留完整导出策略。
修改任一选项且已有输出不同时，必须使用其他输出根目录。

导出器要求一个未配置代理链的 VLESS Reality TCP Vision 客户端。
遇到含糊的端点或用户、重复出站标签、既有代理链，
或已占用的 `tls-fragment` 标签时会拒绝操作。
这些选项不适用于 AWG。所有转换前均校验源清单，
不会执行云调用、来宾操作或生成凭据。

客户端必须支持选定的 Xray 功能。语法检查覆盖 Xray 26.9.30 和 26.10.31。
Freedom 分片形式为兼容性而保留，上游在 26.10.31 中已将其标记为弃用。
导出成功不能证明真实设备连通性或媒体播放成功。
VPN 服务器到目标的连接故障需要单独诊断。
契约与兼容性决策见 [ADR 0020](../../../../adr/0020-client-tls-fragment-export.md)。
