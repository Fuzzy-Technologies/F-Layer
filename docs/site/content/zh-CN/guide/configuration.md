# 配置和提供方访问 {#configuration-and-provider-access}

配置文件指定项目、部署配置方案和需要创建的资源，并记录资源所属的部署，供后续管理使用。读取文件只会验证配置内容。Yandex Cloud 的访问权限需要通过下文的 `yc` 单独配置；不要把访问令牌或私钥写进配置文件。

## 明确项目和资源归属 {#explicit-identity}

`intent.toml` 等基础配置使用格式版本 `1`：

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

该基础模型记录资源的标识和归属。生命周期部署计划添加明确的依赖和提供方参数，由单独的加载器读取。网关配置方案将安全设置编译到该计划中。完整操作步骤见[首次部署](first-deployment.md)。

## 现有 Yandex CLI 认证 {#existing-yandex-cli-authentication}

安装[官方 Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)，按厂商说明设置账号和 CLI 命名配置（profile）。请明确选择目标云文件夹。F-Layer 不初始化 CLI 配置、不导出访问令牌，也不回退到该配置中的默认云文件夹。

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

对已获授权的账号，填写实际的作用域 ID 和 CLI 命名配置。每条云命令都显式指定云文件夹和命名配置；返回的作用域 ID 必须匹配。读取权限验证通过不代表拥有变更权限，也不证明可以访问所有资源类型。适配器不会将厂商的原始 stdout/stderr 包含在公开错误中。确切结果类型见[提供方契约](../architecture.md)和生成的 [API 参考](../api/index.md)。

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

## VPN 服务器资源

已安装的 CLI 从 `project.toml` 中可选的 `[resources]` 配置段读取新服务器的资源设置。
在运行 `flayer vpn prepare` 之前填写全部六个字段：

```toml
[resources]
platform_id = "standard-v3"
cores = 2
core_fraction = 50
memory_gib = 2
disk_size_gib = 10
disk_type = "network-hdd"
```

此配置请求 Intel Ice Lake、2 个保证性能为 50% 的 vCPU、2 GiB 内存及独立的
10 GiB HDD 启动磁盘。使用 SSD 时将类型设为 `network-ssd`。现有命令
`flayer vpn prepare --project DIRECTORY` 和
`flayer vpn deploy --project DIRECTORY --allow-mutation --scope-confirm FOLDER_ID`
会使用此配置段，无需额外的资源覆盖参数，也无需修改已安装的 Python 代码。

| 参数            | 支持的请求                                                                  |
| --------------- | --------------------------------------------------------------------------- |
| `platform_id`   | `standard-v1`、`standard-v2`、`standard-v3`；哈萨克斯坦须使用 `standard-v3` |
| `cores`         | 2–32 的整数，受平台及性能级别限制                                           |
| `core_fraction` | v1：5、20、100；v2：5、20、50、100；v3：20、50、100，单位为百分比           |
| `memory_gib`    | 1–128 GiB 的整数，受所选 vCPU 配置限制                                      |
| `disk_size_gib` | 10–1024 GiB 的整数，同时必须满足所选镜像的最小磁盘要求                      |
| `disk_type`     | `network-hdd` 或 `network-ssd`                                              |

性能低于 100% 时仅支持 2 或 4 个 vCPU。20%/50% 时每个 vCPU 的内存为
0.5–4 GiB，步长为 0.5 GiB；5% 时上限为每个 vCPU 2 GiB
（v2 还允许每个 vCPU 0.25 GiB，但总内存必须为整数 GiB）。
100% 时支持 2、4、6、8、10、12、14、16、20、24、28、32 个 vCPU；
每个 vCPU 的内存须为整数 GiB，v1 上限为 8，v2/v3 上限为 16，且总内存不超过
128 GiB。这是 F-Layer 支持的有限配置范围，并非 Yandex 的完整资源目录。
无效组合会在访问云之前被拒绝。仍须通过只读查询确认区域可用性、配额、镜像的
最小磁盘容量及当前价格。准备过程离线执行，不预留资源，也不估算费用。
请参阅官方[性能配置组合](https://yandex.cloud/en/docs/compute/concepts/performance-levels)。

为保持兼容性，完全省略此配置段会保留原有的 2 vCPU、2 GiB 内存和 20 GiB SSD
计划，平台及性能级别由 `yc` 选择。旧项目的指纹和资源归属保持不变。
空配置段或缺少字段均为错误。显式设置参与项目指纹及资源归属计算；准备之后
添加、删除或修改该配置段都会被拒绝。请保留原项目用于恢复或删除资源，
需要其他资源规格时创建新项目。此流程不调整现有虚拟机的资源大小。
