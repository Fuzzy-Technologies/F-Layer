# 配置和提供方访问 {#configuration-and-provider-access}

配置文件指定项目、部署配置和需要创建的资源，并记录资源所属的部署，供后续管理使用。读取文件只会验证配置内容。Yandex Cloud 的访问权限需要通过下文的 `yc` 单独配置；不要把访问令牌或私钥写进配置文件。

## 明确项目和资源归属 {#explicit-identity}

`intent.toml` 等基础配置使用模式版本 `1`：

```toml
schema_version = 1
profile = "secure-gateway"

[identity]
project = "example-project"
stack = "example-stack"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"

[[resources]]
logical_id = "gateway"
kind = "instance"
name = "example-gateway"
```

这是一个示例。使用前，将 `scope_id` 替换为自己的 Yandex Cloud 文件夹 ID，并设置项目、部署和所有者名称。名称以字母开头，可包含小写英文字母、数字和连字符。云文件夹 ID 按单独规则验证。F-Layer 会拒绝未知字段、重复的 `logical_id` 和不支持的格式版本。

通过配置 API 在本地验证：

```python
from flayer.core.config import LoadConfig

config = LoadConfig("intent.toml")
print(config.identity.project, config.profile)
```

该基础模型记录资源的标识和归属。生命周期部署计划添加明确的依赖和提供方参数，由单独的加载器读取。网关配置档将安全设置编译到该计划中。完整操作步骤见[首次部署](first-deployment.md)。

## 现有 Yandex CLI 认证 {#existing-yandex-cli-authentication}

安装[官方 Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)，按厂商说明配置命名账户和配置档。请自行选择目标文件夹。F-Layer 不初始化配置档、不导出访问令牌，也不回退到配置档的默认文件夹。

```bash
yc --version
```

构造适配器是本地操作；读取操作会访问选定账户：

```python
from flayer.providers.contracts import ResourceKind
from flayer.providers.yandex import YandexCloudProvider, YandexCloudSettings

provider = YandexCloudProvider(
    YandexCloudSettings(folder_id="example-folder", profile="example")
)
status = provider.CheckAuthentication()

if status.authenticated:
    instances = provider.ListResources(ResourceKind.INSTANCE)
    print(len(instances))
```

对已获授权的账户使用实际作用域和配置档值。每条云命令显式提供文件夹和配置档；返回的作用域 ID 必须匹配。读取认证成功不证明拥有变更权限，也不证明可以访问所有资源类型。适配器不会将厂商的原始 stdout/stderr 包含在公开错误中。确切结果类型见[提供方契约](../architecture.md)和生成的 [API 参考](../api/index.md)。

## 凭据和持久状态 {#credentials-and-durable-state}

可选的基础凭据条目仅存储**引用**，从不存储内联值：

```toml
[[credentials]]
name = "provider-auth"
source = "env"
reference = "EXAMPLE_PROVIDER_AUTH"
```

配置加载器保存变量名称，不读取变量的值。当前 Yandex 适配器使用现有 `yc` 认证；该条目不会配置适配器，也不会将令牌注入命令。

运行时状态只保存必要的云资源 ID，以及项目、部署、作用域和所有者的标识。请放在操作员控制的目录中，不要提交。复用其他所有者的状态或修改这些标识以接管其他资源会被拒绝。
