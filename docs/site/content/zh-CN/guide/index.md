# 用户指南 {#user-guide}

从本地仓库和明确的提供方作用域开始。基础包可以验证配置、查看 Yandex Cloud 资源并运行有界只读诊断。生命周期和网关功能由第二轮实现引入；相关操作说明会在任何云操作之前指出所需模块。

1. [从源码安装](installation.md)，执行离线冒烟检查。
2. 使用已认证的 `yc` 配置档[配置提供方访问](configuration.md)。
3. [阅读 CLI 结果](cli.md)，包括不支持的观测和退出码。
4. 明确指定所有权和变更许可，[准备首次部署](first-deployment.md)。

F-Layer 在 `v1.0.0` 之前没有稳定 API。由已安装 wheel 生成的 [API 参考](../../en/api/index.md)描述此版本中实际存在的模块。
