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
