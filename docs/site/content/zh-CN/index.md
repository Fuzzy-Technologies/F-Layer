![F-Layer by Fuzzy Technologies](../en/assets/brand/flayer-horizontal.svg){ .fl-brand-lockup }

# 具有明确契约的基础设施 {#infrastructure-with-explicit-contracts}

**F-Layer** 是用于部署、管理和集成安全云环境的模块化基础设施自动化平台。

其架构将配置、持久资源状态、提供方能力、部署配置档、生命周期操作和诊断证据分离。这些边界使单独的集成可以替换，操作可以复现。

!!! info "文档版本"
    GitHub Pages 对应 `master` 上的最新稳定发行版。本地构建描述已安装的源码版本；
    `develop` 可能包含后续里程碑已接受的变更。请通过相应 Git 标签的 changelog
    核对每个发行版包含的功能。

<div class="grid cards" markdown>

- **运行首次检查**

    从明确选定的源代码版本[安装并配置 F-Layer](guide/index.md)。

- **理解边界**

    阅读[架构](architecture.md)及其事实来源规则。

- **查看实际 API**

    浏览由已安装 wheel 生成的 [API 参考](../en/api/index.md)。

- **凭证据开发**

    遵循[开发流程](development.md)和确定性检查。

- **保持文档准确**

    查看[语言和发布规则](../en/documentation.md)。

</div>

## 设计原则 {#design-commitments}

- 核心独立于云提供方、网络协议和使用方应用。
- 凭据和私有基础设施标识符不进入版本控制的源文件。
- 配置、期望状态、观测状态和生成的制品相互分离。
- 本地验证使用确定性测试数据，不修改真实云资源。
- Python 类型注解和英文文档字符串是 API 的事实来源。

[用户指南](guide/index.md)介绍控制台使用方法；[项目标识](../en/brand.md)介绍 F-Layer 标志系列。

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) · [GitHub 仓库](https://github.com/Fuzzy-Technologies/F-Layer)
