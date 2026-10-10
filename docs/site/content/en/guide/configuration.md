# Configuration and provider access

The configuration names your project, selects a deployment profile and lists
the resources to create. It also identifies which deployment owns those
resources, so F-Layer can manage them later. Reading this file only validates
its contents. To connect to Yandex Cloud, configure `yc` separately as shown
below; do not put access tokens or private keys in the configuration.

## Explicit identity

A foundation configuration such as `intent.toml` uses schema version `1`:

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

This is an example. Before using it, replace `scope_id` with your Yandex Cloud
folder ID and choose your own project, stack and owner names. Names start with
a letter and use lowercase letters, digits and hyphens. The cloud folder ID
has its own validation rules. F-Layer rejects unknown fields, duplicate
`logical_id` values and unsupported schema versions.

Validate locally through the configuration API:

```python
from flayer.core.config import LoadConfig

config = LoadConfig("intent.toml")
print(config.identity.project, config.profile)
```

This basic model describes resource identities. The lifecycle deployment plan
adds explicit dependencies and provider parameters; it is a separate loader.
A gateway profile compiles its security settings into that plan. See
[first deployment](first-deployment.md) for the complete process.

## Existing Yandex CLI authentication

Install the [official Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart)
and configure a named account/profile using the vendor's instructions. Select
the intended folder yourself. F-Layer does not initialize profiles, export
access tokens, or fall back to a profile's default folder.

```bash
yc --version
```

Constructing the adapter is local; its read operations access the chosen account:

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

Use actual scope/profile values for an authorized account. Each cloud command
supplies an explicit folder and profile; returned scope IDs must match.
Read authentication success does not establish mutation permissions or access
to every resource kind. The adapter never includes raw vendor stdout/stderr
in public errors. See the [provider contract](../architecture.md) and generated
[API reference](../api/index.md) for exact result types.

## Credentials and durable state

Optional foundation credential entries hold **references**, never inline values:

```toml
[[credentials]]
name = "provider-auth"
source = "env"
reference = "EXAMPLE_PROVIDER_AUTH"
```

The configuration loader saves the variable name without reading its value. The
current Yandex adapter uses existing `yc` authentication instead; this entry
does not configure that adapter or inject a token into its commands.

Runtime state stores the minimum external IDs and exact owned stack identity.
Keep it in an operator-controlled directory; do not commit it. Reusing another
owner's state or changing identity to adopt arbitrary resources is rejected.

## VPN server resources

The installed CLI reads initial server sizing from the optional `[resources]`
block in `project.toml`. Set all six fields before `flayer vpn prepare`:

```toml
[resources]
platform_id = "standard-v3"
cores = 2
core_fraction = 50
memory_gib = 2
disk_size_gib = 10
disk_type = "network-hdd"
```

This requests Intel Ice Lake, 2 vCPU with 50% guaranteed performance, 2 GiB RAM
and a separate 10 GiB HDD boot disk. Use `network-ssd` for SSD. The existing
`flayer vpn prepare --project DIRECTORY` and `flayer vpn deploy --project DIRECTORY
--allow-mutation --scope-confirm FOLDER_ID` commands consume this block; no
resource overrides or edits to installed Python code are needed.

| Setting         | Supported request                                                              |
| --------------- | ------------------------------------------------------------------------------ |
| `platform_id`   | `standard-v1`, `standard-v2`, `standard-v3`; Kazakhstan requires `standard-v3` |
| `cores`         | Integers 2–32, restricted by platform and performance level                    |
| `core_fraction` | v1: 5, 20, 100; v2: 5, 20, 50, 100; v3: 20, 50, 100 percent                    |
| `memory_gib`    | Whole GiB, 1–128, restricted by the selected vCPU combination                  |
| `disk_size_gib` | Whole GiB, 10–1024; must also fit the selected image                           |
| `disk_type`     | `network-hdd` or `network-ssd`                                                 |

Below 100%, only 2 or 4 vCPU are supported. At 20%/50%, RAM per vCPU is
0.5–4 GiB in 0.5 GiB steps; at 5%, the maximum is 2 GiB per vCPU
(v2 also permits 0.25 GiB per vCPU if total RAM is an integer).
At 100%, supported counts are 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32;
RAM must be a whole number of GiB per vCPU, up to 8 for v1 or 16 for v2/v3,
within the total 128 GiB limit. These are F-Layer's bounded supported shapes,
not the full Yandex catalogue. Invalid combinations fail before cloud access.
Regional availability, quotas, image minimum size and current prices still
need a read-only cloud check. Preparation is offline and is not a reservation
or cost estimate. See the official [performance combinations](https://yandex.cloud/en/docs/compute/concepts/performance-levels).

For compatibility, omitting the entire block preserves the previous 2 vCPU,
2 GiB RAM and 20 GiB SSD plan, with platform/performance selected by `yc`.
Old fingerprints and resource ownership remain unchanged. An empty or partial
block is an error. Explicit settings participate in the project fingerprint
and resource ownership. Adding, removing or changing the block after preparation
is rejected. Retain the original project for recovery/removal; use a new project
for different sizing. This workflow does not resize an existing VM.
