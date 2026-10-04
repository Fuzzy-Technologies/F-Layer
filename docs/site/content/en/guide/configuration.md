# Configuration and provider access

Configuration records intent and ownership. Authentication remains the
provider adapter's responsibility; configuration loading does not read a
credential file, resolve environment secrets, or contact a cloud account.

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

These are synthetic identifiers. Substitute your own intended folder and
ownership identity before provider calls. Core names use lowercase letters,
digits and hyphens, starting with a letter; the opaque scope ID is validated
separately. Unknown fields, duplicate logical IDs and unsupported schema
versions fail closed.

Validate locally through the configuration API:

```python
from flayer.core.config import LoadConfig

config = LoadConfig("intent.toml")
print(config.identity.project, config.profile)
```

This basic model describes resource identities. The lifecycle deployment plan
adds explicit dependencies and provider parameters; it is a separate loader.
A gateway profile compiles its security settings into that plan. See
[first deployment](first-deployment.md) for the second-wave path.

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

The foundation loader preserves that reference without resolving it. The
current Yandex adapter uses existing `yc` authentication instead; this entry
does not configure that adapter or inject a token into its commands.

Runtime state stores the minimum external IDs and exact owned stack identity.
Keep it in an operator-controlled directory; do not commit it. Reusing another
owner's state or changing identity to adopt arbitrary resources is rejected.
