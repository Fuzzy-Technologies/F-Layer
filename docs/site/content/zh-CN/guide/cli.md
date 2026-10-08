# CLI 和诊断结果 {#cli-and-diagnostic-results}

基础包提供模块 CLI。所有帮助命令都可离线运行。`check` 是本地操作；HTTP 诊断需要明确的端点。

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

在观测适配器接入之前，顶层 `status` 对提供方状态报告 `unsupported`，不会将空云视为健康。任务 #20 引入的生命周期 `status` 是具有明确作用域的独立命令；参见[首次部署](first-deployment.md)。

## 明确端点的探测 {#explicit-endpoint-probes}

选择你已获授权访问的端点。以下示例使用保留域名 `example.com`；请替换成目标 HTTP(S) 端点：

```bash
python -m flayer health --endpoint https://example.com/ --timeout 3 --format json
python -m flayer benchmark --endpoint https://example.com/ --timeout 3 --count 3 --bytes 65536 --format json
```

端点 URL 不允许凭据、查询字符串和片段。TLS 证书验证保持开启，重定向和代理发现被禁用。报告省略端点、响应正文和原始异常材料。每次采样超时最多 30 秒，采样数最多 10，每次字节数最多 1 MiB。即使 DNS、TLS 或读取失败，总工作量仍有限。结果描述从本机执行的此次探测，不代表提供方 SLA、VPN 吞吐量保证或部署成功。

## 退出状态 {#exit-status}

| 退出码 | 含义                      | 操作员行动                     |
| ------ | ------------------------- | ------------------------------ |
| `0`    | 所有请求的检查均为 `ok`。 | 使用已记录的观测。             |
| `1`    | 至少一项检查警告或失败。  | 查看结构化检查结果。           |
| `2`    | 命令输入或限制无效。      | 重试前修正参数。               |
| `3`    | 观测已过时。              | 获取新证据。                   |
| `4`    | 请求的观测不受支持。      | 提供端点或使用已实现的适配器。 |

JSON 报告包含 `schema_version`、`command`、汇总 `status` 和单项 `checks`。汇总严重程度不会隐藏失败观测。自动化应检查进程退出码并解析结构化状态；不能因存在 JSON 报告就认定成功。
