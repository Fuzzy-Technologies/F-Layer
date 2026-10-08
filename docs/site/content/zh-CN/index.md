![Fuzzy Technologies 工程实验室中的 F-Layer 与 AIna](../en/assets/brand/FTech-card-F-Layer.png){ .fl-project-art }

# 部署并管理云服务器 {#deploy-and-operate-cloud-servers}

**F-Layer** 帮助工程师部署云服务器、管理服务使用的资源，并检查服务是否可访问。
可以通过命令行使用，也可以将其 Python API 集成到自己的应用中。

在配置文件中描述部署。F-Layer 生成资源计划，在获得明确许可后创建云资源，
并在本地保存资源标识。使用相同的计划和记录，可以查看部署状态、恢复中断的操作，
或者删除该部署所属的资源。

当前发行版支持 **Yandex Cloud**、带有独立设备连接设置的**安全 SSH 网关**，
以及 HTTP 可用性和响应、传输时间检查。它适用于自动化服务环境的团队，
以及为产品添加基础设施功能的开发者。其他云平台和 VPN 配置仍在规划中。
F-Layer 是开源软件；云资源费用由云提供方收取。

## 快速开始 {#quick-start}

[安装稳定发行版并运行首次检查](guide/index.md)。安装后，以下命令无需云访问：

```bash
python -m flayer check --format json
```

预期结果为 `"status": "ok"`，退出码为 `0`。这只确认本地 Python 和软件包可用。
要创建服务器，请继续阅读部署指南。

## 下一步 {#choose-your-next-step}

<div class="grid cards" markdown>

- **准备云服务器**

    阅读[首次部署](guide/first-deployment.md)，生成网关计划、检查资源并授权部署。

- **检查运行中的服务**

    [CLI 指南](guide/cli.md)介绍 HTTP 检查、时间测量和 JSON 结果。

- **集成到自己的应用**

    查看 [Python API](../en/api/index.md)及配置、状态和提供方的[架构](architecture.md)。

- **扩展或参与开发**

    [开发指南](development.md)介绍仓库流程和测试。

</div>

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) ·
[GitHub 仓库](https://github.com/Fuzzy-Technologies/F-Layer)
