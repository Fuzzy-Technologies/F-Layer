![Fuzzy Technologies 工程实验室中的 F-Layer 与 AIna](../en/assets/brand/FTech-card-F-Layer.png){ .fl-project-art }

# 部署并管理云服务器 {#deploy-and-operate-cloud-servers}

**F-Layer** 帮助工程师部署云服务器、管理服务使用的资源，并检查服务是否可访问。
可以通过命令行使用，也可以将其 Python API 集成到自己的应用中。

在配置文件中描述部署。F-Layer 生成资源计划，在获得明确许可后创建云资源，
并在本地保存资源标识。使用相同的计划和记录，可以查看部署状态、恢复中断的操作，
或者删除该部署所属的资源。

**F-Layer 2.0** 在 Yandex Cloud 部署运行 **AmneziaWG 3.1** 和
**VLESS Reality** 的企业 VPN，并为每台设备生成连接设置。此外还支持安全
SSH 网关和 HTTP 检查。其他云平台需要相应的适配器。
F-Layer 是开源软件；云资源费用由云服务商收取。

## 快速入门 {#quick-start}

从[安装](guide/installation.md)开始。
[快速入门](guide/index.md)介绍从安装 F-Layer 2.0 到创建私有项目、在 Yandex
Cloud 部署和连接客户端的完整步骤。安装后，以下命令无需云访问：

```bash
python -m flayer check --format json
```

预期结果为 `"status": "ok"`，退出码为 `0`。这只确认本地 Python 和软件包可用。
要创建服务器，请继续阅读部署指南。

## 下一步 {#choose-your-next-step}

<div class="grid cards" markdown>

- **通过自己的 VPN 服务器连接**

    [快速入门](guide/index.md)介绍两种 VPN 协议；
    [SSH 网关指南](guide/first-deployment.md)介绍受限的 SSH 转发。

- **检查运行中的服务**

    [CLI 指南](guide/cli.md)介绍 HTTP 检查、时间测量和 JSON 结果。

- **集成到自己的应用**

    查看 [Python API](api/index.md)及配置、状态和提供方的[架构](architecture.md)。

- **扩展或参与开发**

    [开发指南](development.md)介绍仓库流程和测试。

</div>

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) ·
[GitHub 仓库](https://github.com/Fuzzy-Technologies/F-Layer)
