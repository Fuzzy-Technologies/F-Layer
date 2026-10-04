# Configuration and state

F-Layer core separates desired intent from the minimum inventory needed to
locate resources it owns. These contracts are implemented in `flayer.core`;
cloud provisioning, lifecycle orchestration, and deployment-specific settings
are separate work. See [ADR 0001](../adr/0001-config-state-contracts.md).

## Module boundaries

| Boundary                | Owns                                                                             | Excludes                                                                      |
| ----------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `flayer.core.contracts` | Schema validation, stack identity, ownership labels                              | Cloud authentication, cloud API behavior                                      |
| `flayer.core.config`    | Desired resources, profile identifier, credential references, TOML loading       | Credential resolution, regional defaults, provider-specific resource settings |
| `flayer.core.state`     | Owned resource locators, strict JSON loading, local atomic persistence           | Provider observations, authorization, cloud deletion, generated artifacts     |
| Provider adapters       | Provider settings, authentication, cloud API translation, ownership verification | Generic state storage policy                                                  |
| Deployment profiles     | Provider capability composition and profile-specific settings                    | Implicit core provider selection                                              |
| Diagnostics             | Observations and reports with explicit execution boundaries                      | Desired state or ownership authority                                          |

## Desired configuration

An explicit TOML file uses schema version `1`. The loader fails on a missing
file, invalid TOML, unknown fields, unsupported schema versions, and wrong
types; it never substitutes machine-specific settings or implicit cloud
defaults. Portable names use lowercase letters, digits, and hyphens, start
with a letter, and contain at most 63 characters. `scope_id` and provider
resource identifiers are opaque printable ASCII strings without whitespace,
limited to 256 characters.

```toml
schema_version = 1
profile = "secure-gateway"

[identity]
project = "example"
stack = "demo"
provider = "example-cloud"
scope_id = "example-scope"
owner_id = "example-owner"

[[resources]]
logical_id = "gateway"
kind = "instance"
name = "demo-gateway"

[[credentials]]
name = "cloud-auth"
source = "env"
reference = "EXAMPLE_AUTH"
```

`resources` and `credentials` may be omitted or empty. Logical resource IDs
and credential names are unique. Provider/profile adapters validate their
own detailed settings; version `1` does not accept arbitrary additional
settings in these core tables.

`SecretReference` accepts `env` with an uppercase environment variable name,
or `file` with a bounded nonempty path. No environment value or referenced
file is read while loading configuration. The authentication adapter owns
resolution and any relative-path policy. Configuration contains references,
never token values, passwords, or private-key bodies. The core cannot verify
the contents of an arbitrary reference; callers must protect credential files
and avoid committing private paths.

```python
from flayer.core.config import LoadConfig

config = LoadConfig("./stack.toml")
ownership_labels = config.identity.OwnershipLabels()
```

The resulting models are frozen dataclasses. Direct construction uses the
same field and uniqueness validation as decoding. Desired resources contain
logical names, without externally assigned resource IDs.

## Owned state

`StackState` records a complete `StackIdentity` and a tuple of
`ResourceState(logical_id, kind, resource_id)` values. The snapshot can hold
only the resources acquired so far in an interrupted deployment; no missing
locator is inferred. Provider locators must be unique within their kind,
and logical IDs must be unique across the inventory.

```python
from flayer.core.state import LoadState, ResourceState, SaveState, StackState

state = StackState(
    identity=config.identity,
    resources=(ResourceState("gateway", "instance", "example-instance"),),
)
SaveState("./runtime/state.json", state, expected_identity=config.identity)
loaded_state = LoadState("./runtime/state.json", expected_identity=config.identity)
```

The JSON schema has exactly `schema_version`, `identity`, and `resources`.
It does not persist credential references or values, full configuration,
provider response payloads, logs, health reports, generated files, or public
endpoints. An absent file returns `None`; a corrupt or foreign file raises
`StateError`. Duplicate JSON fields are rejected. Reads and writes have a 1 MiB
JSON limit. The opened descriptor must be a regular file; nonblocking open where
available prevents a post-validation FIFO substitution from hanging a reader.
Both the initial size and the bounded stream result are checked, so concurrent
file growth cannot bypass the limit. Oversized writes fail before replacement.

Every read, save, and removal requires an expected identity. All five
identity fields must match. `SaveState` also validates an existing snapshot
under the writer lock before replacing it. Ownership labels are
`managed-by=f-layer`, `flayer-project`, `flayer-stack`, and `flayer-owner`.
Before an actual cloud operation, a provider adapter must independently
check the provider scope and live resource labels. A state file alone never
authorizes modifying infrastructure.

`RemoveState(path, expected_identity)` removes only a matching local snapshot
and returns whether a file was removed. It is idempotent for an absent file
and does not delete any cloud resource. Lifecycle code must decide when
discarding a local inventory is safe after provider cleanup.

## Persistence and recovery

Use a trusted directory owned by the operating-system user. Avoid symlink
ancestors and `..` path components. All writers for a snapshot must use this
state API. The implementation rejects a symlink or nonregular target and
uses `O_NOFOLLOW` on platforms that support it, but cannot prevent a hostile
local user from racing directory changes in storage they control.

Writes acquire the sibling `.state.json.lock` exclusively, create a unique
temporary file in the same directory, flush and `fsync` it, and atomically
replace the target. Temporary files have owner-only POSIX permissions.
The parent directory is flushed on POSIX; Windows relies on `os.replace`
and the caller's directory ACLs. Existing corrupt or foreign snapshots block
save and removal and remain available for investigation.

Failure before replacement preserves the previous snapshot. Failure after
replacement may leave the new complete snapshot visible while directory
durability remains uncertain. Read and inspect state after such an error
before retrying lifecycle work. Atomic file replacement does not guarantee
durability on every remote filesystem and is not a cloud transaction.

A competing or stale writer lock causes an immediate `StateError`. A normal
operation removes its lock and pending temporary file. After a process crash,
confirm no writer is active, inspect the final state and any surviving
temporary snapshot, and then recover the local lock explicitly. The API does
not automatically steal locks, adopt foreign state, repair corruption, or
migrate unknown schema versions.

If the filesystem prevents temporary-file or lock removal, the API reports a
`StateError` for incomplete cleanup and preserves the underlying exception
chain. Pending artifacts then need the same explicit local recovery. A failure
to create a text stream closes its file descriptor before propagating the
error, so failed persistence does not leak an open descriptor.
