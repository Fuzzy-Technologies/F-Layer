# Extension contracts and discovery

`flayer.extensions` is an additive Python API for explicit provider and deployment
profile registration. The existing lifecycle core, CLI, configuration, ownership,
state, and artifact contracts remain unchanged. [ADR 0011](../adr/0011-explicit-extension-discovery.md)
records the discovery and loading boundary.

## Implemented contracts

| Contract                     | Responsibility                                                                    |
| ---------------------------- | --------------------------------------------------------------------------------- |
| `ExtensionDescriptor`        | Immutable kind, identifier, distribution, exact version, group, and factory.      |
| `ProviderExtension`          | Construct the existing read-only `CloudProvider` from `ProviderContext`.          |
| `LifecycleProviderExtension` | Optionally construct the separate existing `LifecycleProvider`.                   |
| `ProfileExtension`           | Compile a profile's strict configuration with exact `ProfileContext` ownership.   |
| `CompiledProfile`            | Expose identity, server bundle generation, and verified lifecycle TOML rendering. |
| `ExtensionRegistry`          | Register, select, and explicitly load exact validated descriptors.                |

`ProviderContext` contains only `scope_id`, an external CLI
`authentication_reference`, and bounded command timeout/inventory limits. It does
not resolve credentials, read credential files, accept credential bytes, select
executables, or carry an arbitrary options dictionary. An authentication reference
is an identifier naming an already configured external authentication source;
resolved tokens and key material must never be supplied as identifiers.
`ProfileContext` carries the existing validated `StackIdentity`. Configuration
values are validated by the selected profile schema, which rejects unknown fields
and keeps private credentials out of generated server configuration.

The extension object exposes its exact `Descriptor`. External entry points name
a zero-argument factory returning that object. The object must satisfy its group's
protocol and return the exact discovered descriptor, including its selected
metadata snapshot. A factory can obtain its descriptor by statically reading its
own explicitly located `.dist-info` directory through `DiscoverExtensions`.
Structural protocol validation checks required callable methods and identity;
the trusted implementation remains responsible for method semantics and outputs.

## Usable built-ins

| Kind     | Identifier         | Adapter                                                           |
| -------- | ------------------ | ----------------------------------------------------------------- |
| Provider | `yandex-read-only` | `YandexCloudProvider`; inventory and exact resource lookup.       |
| Provider | `yandex-lifecycle` | Separate read-only factory and `YandexLifecycleProvider` factory. |
| Profile  | `secure-gateway`   | Real strict gateway parser, compiler, server bundle, and plan.    |

All built-ins use the package's exact version. Listing descriptors and constructing
their adapters perform no provider operations. The read-only provider extension
does not implement the optional lifecycle factory. A caller must deliberately
select that separate factory before using existing mutation methods.

```python
"""Select a real scoped read-only adapter without performing cloud operations."""

from flayer.extensions import (
    ExtensionKind,
    ExtensionRegistry,
    ProviderContext,
    ProviderExtension,
)

registry = ExtensionRegistry()
descriptor = registry.Get(ExtensionKind.PROVIDER, "yandex-read-only")
extension = registry.Load(descriptor)
assert isinstance(extension, ProviderExtension)
provider = extension.CreateProvider(ProviderContext("example-folder", "external-profile"))
```

For a gateway, select `ExtensionKind.PROFILE` and `secure-gateway`, then call
`CompileProfile(configuration, ProfileContext(identity))`. The compiled adapter
rejects any configuration ownership mismatch. `BuildServerBundle()` produces the
existing owned artifact bundle in memory. Store it with `WriteArtifactBundle()`
before calling `RenderPlan(user_data_file=...)`; rendering verifies the exact
owned server bytes and manifest. It does not deploy the plan or prove guest or
transport readiness.

## Static metadata discovery

`DiscoverExtensions(metadata_directories)` accepts an explicit bounded sequence of
absolute, non-redirected `.dist-info` directories. It reads only `METADATA`,
`entry_points.txt`, and `RECORD` under each selected directory. It does not traverse
Python search paths, enumerate installed packages, invoke metadata finder hooks,
scan source modules, follow final symlinks, import plugin packages, query networks,
install packages, or inspect infrastructure. Directory and file counts, file
sizes, names, targets, and versions are bounded.

Supported entry-point groups are `flayer.providers.v1` and `flayer.profiles.v1`.
For example, an installed distribution's `entry_points.txt` can declare:

```ini
[flayer.providers.v1]
example = example_plugin.plugin:CreateExtension
```

Other ecosystems' groups are ignored. Unknown F-Layer groups, unsupported ABI
versions, malformed targets, extras, duplicate metadata fields, and duplicate
extension identities fail closed. Names are bounded lowercase identifiers.
Distribution names are normalized to lowercase hyphens, and only stable
three-component release versions are supported. External distributions cannot
claim `f-layer` or target the reserved `flayer` module namespace. Registration
rejects any duplicate `(kind, plugin_id)`, including built-in shadowing.

Descriptors contain a SHA-256 snapshot of the three metadata files. They provide
inspectable declared identity; they do not verify publisher identity, signatures,
installation provenance, or the authenticity of the package.

## Explicit loading and source ownership

Register discovered descriptors with `ExtensionRegistry(descriptors)`. Discovery
does not load them. `Load(descriptor, allowed=(exact_descriptor,))` is the separate
explicit trust decision for external code. The descriptor must match an exact
registry entry and an exact caller allowlist entry; the pin includes distribution,
version, group, target, selected location, and metadata digest. Application policy
must decide which inspected descriptors are trusted before populating the
allowlist. Built-ins are restricted to the exact known registry descriptors.

Before import, loading rechecks the metadata snapshot and verifies SHA-256/size
ownership in `RECORD` for the target module and every parent package. Each source
must be an exact regular non-linked file inside the selected installation root.
Source-only Python modules and ordinary packages are supported; namespace
packages, binary extensions, missing parent ownership, ambiguous package/module
targets, weak or missing hashes, and changed files fail closed.

Loading executes the verified immutable source bytes directly. A temporary import
hook serves only the already selected source chain so a parent's import of its
target uses those same bytes rather than stale bytecode or ambient source
resolution. The hook is removed after loading, including failures. Preloaded
same-name modules are rejected even when they report the correct file path,
unless this loader holds a receipt binding the exact module object, source path,
and executed source hash. Exact loader-owned source may be reused; changed code
in an already loaded module chain requires a fresh process. Registry repetition
returns the already validated extension without re-executing its factory.

External dependency imports and factory execution occur only after opt-in and are
part of trusting that package and environment. Loading is not a code sandbox,
dependency validator, or protection against an actively hostile process. A
failure removes only modules and receipts created by this loader attempt; it
cannot undo arbitrary plugin side effects or dependency imports. Runtime failures
are sanitized, and loaded descriptor/protocol mismatches fail closed.

## Validation evidence

Deterministic tests cover discovery without finder or module execution, malformed
metadata, ABI versions, duplicates and built-in shadowing, exact loading consent,
metadata/source drift, RECORD ownership, stale cached modules and bytecode,
sanitized failures, typed context bounds, real Yandex adapter construction, and a
complete local secure-gateway artifact-to-plan workflow. No tests use real cloud
operations or credentials.
