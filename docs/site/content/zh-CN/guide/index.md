# 快速开始 {#quick-start}

在 Yandex Cloud 中创建一台小型服务器，通过它建立连接，并在验证后删除资源。
稳定版 **v1.2.1** 使用 SSH 网关，只转发选定的连接。支持两种 VPN 协议的流程
正在为 2.0 准备，尚未包含在该稳定包中。

## 1. 检查安装 {#1-check-the-installation}

[安装发行包](installation.md)，然后运行：

```bash
flayer check --format json
```

预期结果为 `"status": "ok"`，退出码 `0`。这表示本地安装正常。下一步配置云访问。

## 2. 连接 Yandex Cloud 账号 {#2-connect-your-yandex-cloud-account}

本教程使用 Linux 或 macOS。安装并初始化
[官方 Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)，然后查看可用配置档：

```bash
yc --version
yc config profile list
```

记下配置档名称和要创建服务器的云文件夹 ID。在以下命令中，将 `example` 替换为
配置档名称，将 `example-folder` 替换为文件夹 ID。账号需要在该文件夹中创建和
删除计算、网络资源的权限。资源存在期间，Yandex Cloud 会收取相应费用。

## 3. 准备服务器配置 {#3-prepare-the-server-settings}

将[首次部署](first-deployment.md#prepare-a-secure-gateway-locally)中的 `gateway.toml`
示例复制到新的工作目录。填写云文件夹 ID、可用区、Ubuntu 24.04 镜像 ID、管理
访问的 IP 范围和自己的 SSH 公钥。示例会创建网络、子网、防火墙、公网地址、
启动磁盘和虚拟机。

运行该指南中的本地准备代码，生成服务器的 cloud-init 文件和
`generated-artifacts/plan.toml`。创建资源前检查这些文件。配置及生成的文件应保留
在同一工作目录中，后续命令也从该目录运行。

## 4. 创建并检查部署 {#4-create-and-inspect-the-deployment}

```bash
flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
```

第一条命令创建云资源，并将资源 ID 记录到 `stack.json`；第二条读取资源的当前
状态。请保留该状态文件，恢复和清理都需要它。若创建被中断，请按照
[恢复步骤](first-deployment.md#recovery-and-cleanup)处理。

cloud-init 完成后，按照[连接一台授权设备](first-deployment.md#connect-one-authorized-device)
创建客户端配置并启动 SSH 连接。使用示例设置时，访问 `127.0.0.1:8443` 会通过
服务器转发到 `example.org:443`。虚拟机处于运行状态并不代表这条连接已经可用。

## 5. 删除资源 {#5-remove-the-resources}

验证结束后，检查文件夹和项目名称，再运行：

```bash
flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

确认命令结果及云资源状态后，再删除状态文件。部署指南也说明了如何清理生成的
本地文件。

## 其他使用方式 {#other-ways-to-use-f-layer}

要检查现有 HTTP 服务，请将示例 URL 替换为服务地址：

```bash
flayer health --endpoint https://example.com/ --timeout 3 --format json
```

[CLI 指南](cli.md)介绍诊断和退出码。要集成到 Python 应用，请阅读
[配置指南](configuration.md)和 [API 参考](../api/index.md)。目前实现的云提供方是
Yandex Cloud；使用其他云需要相应的适配器。

帮助中的花括号，例如 `{create,status,destroy,recover}`，表示**选择一个命令**。
不需要输入花括号。
