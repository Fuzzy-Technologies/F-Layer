# Provider contract

F-Layer providers translate cloud-specific authentication and resource observations into an explicit, provider-neutral boundary. This interface supports **read-only Yandex Cloud discovery**. Creation, adoption, rollback and deletion use the separate [Yandex lifecycle adapter](yandex-lifecycle.md).

## Implemented interface

Import the generic boundary from `flayer.providers.contracts` and the first adapter from `flayer.providers.yandex`.

| Public API                   | Behavior                                                                        |
| ---------------------------- | ------------------------------------------------------------------------------- |
| `CloudProvider.Identity`     | Provider ID, explicit resource scope and non-secret authentication source       |
| `CloudProvider.Capabilities` | Implemented inventory and lookup operations, independent of account permissions |
| `CheckAvailability()`        | Local CLI execution probe; authentication remains unknown                       |
| `CheckAuthentication()`      | Read-access probe to the configured folder through existing CLI credentials     |
| `ListResources(kind)`        | Sorted, validated inventory for one supported resource kind                     |
| `GetResource(reference)`     | Lookup by resource ID with reference and returned-scope validation              |
| `DiscoverInventory()`        | Inventory across every supported kind, or a failure without partial results     |

A `ResourceReference` binds provider ID, scope ID, resource kind and resource ID. A `ProviderResource` contains that reference, name, vendor status, optional zone, immutable ownership labels and public IPv4 endpoints. Unknown state is explicitly `UNKNOWN`. Raw provider JSON, instance metadata and credentials never become resource fields.

Supported `ResourceKind` values are `INSTANCE`, `DISK`, `NETWORK`, `SUBNET`, `ADDRESS` and `SECURITY_GROUP`. Results are sorted by resource ID within each kind; full inventory follows enum order. Listing and lookup do not assert resource ownership. `HasLabels()` is a comparison helper requiring non-empty matching labels; mutation authorization follows the separate lifecycle adapter's complete ownership policy.

## Explicit authentication and scope

`YandexCloudSettings` requires a folder ID. There is no fallback to a profile's default folder. Settings also accept a profile name, CLI executable, bounded command timeout and inventory limit. They contain no token, key, credential file or local infrastructure assumption.

The adapter uses the CLI's existing authentication mechanism. It does not initialize profiles, read credential files, export tokens, call `iam create-token` or modify authentication settings. `CheckAuthentication()` verifies access to the selected folder; failure can indicate invalid credentials, insufficient permission or unavailable infrastructure. It does not claim that every resource-kind permission is granted.

Every cloud command specifies `--profile`, `--folder-id`, `--format json`, `--no-browser` and `--retry 0`. `SubprocessCommandRunner` uses an argument vector, `shell=False`, closed stdin and an explicit timeout. Construction, identity and capability inspection have no side effects. Availability executes only `yc --version`.

The CLI resolves IDs globally across accessible folders. The adapter therefore validates every returned resource's `folder_id` and rejects mismatched provider/scope references before executing lookup. A successful vendor command alone is insufficient scope evidence.

## Completeness and failure behavior

CLI list operations have a finite limit. The adapter requests an explicit limit, defaults to 10,000 resources per kind and rejects a response at or above that limit as `INCOMPLETE_INVENTORY`. This conservative rule can reject an exactly-full but complete response; increasing the configured limit within its bounded range resolves that ambiguity. Future pagination may replace this rule without changing callers' completeness requirement.

Malformed JSON, unexpected response structure, invalid resource IDs, duplicate IDs, malformed endpoints and unverified scope fail closed. One failed kind aborts `DiscoverInventory()` without returning a partial snapshot. Discovery is not an atomic cloud snapshot: resources may change between read operations.

`ProviderError` exposes a stable `ProviderErrorCode`, operation name and retry recommendation. Timeouts and throttling are retryable; automatic retry is not implemented. Known CLI markers map to authentication, permission, not-found, timeout, throttling and conflict categories; other nonzero exits become `COMMAND_FAILED`.

Vendor stdout/stderr are captured transiently to parse successful JSON or classify failures. They never appear in error messages. Subprocess and JSON exception chains are suppressed. `CommandResult` omits stdout/stderr from its representation. Returned names and labels are observed public resource fields; infrastructure owners must not place credentials in those fields.

## Example

```python
from flayer.providers.contracts import ResourceKind
from flayer.providers.yandex import YandexCloudProvider, YandexCloudSettings

provider = YandexCloudProvider(
    YandexCloudSettings(folder_id="example-folder", profile="example")
)

# These calls access the selected account; construction alone does not.
status = provider.CheckAuthentication()

if status.authenticated:
    instances = provider.ListResources(ResourceKind.INSTANCE)
```

For deterministic tests, inject a `CommandRunner` whose `Run(command, timeout)` returns `CommandResult`. Unit tests use synthetic resource IDs and documentation IP addresses. No tests invoke the CLI, read credentials or access real cloud resources.

## Design and validation

[ADR 0002](../adr/0002-read-only-provider-boundary.md) records the dependency and authorization decisions. The adapter adapts A-VPN's folder-scoped Compute/VPC discovery and label-based ownership comparison while separating them from deployment profiles and lifecycle mutation.

Official references:

- [Yandex CLI instance listing and global flags](https://yandex.cloud/en/docs/compute/cli-ref/instance/list)
- [Yandex CLI resource-ID lookup scope](https://yandex.cloud/en/docs/compute/operations/vm-info/get-info)
- [Yandex CLI disk listing](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/disk/list)
- [Yandex CLI security-group listing](https://yandex.cloud/en/docs/vpc/cli-ref/v0/security-group/list)
- [Yandex CLI address listing](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/v0/address/list)
