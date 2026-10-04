# ADR 0011: Static extension discovery and explicit loading

## Status

Accepted for [Task #29](https://github.com/Fuzzy-Technologies/F-Layer/issues/29).

## Context

The read-only Yandex adapter, its separate lifecycle adapter, and secure-gateway
profile are real extension consumers. Their contracts already separate resource
observation, owned mutation, and profile compilation. Requiring a generic mutation
interface from every provider would break this boundary.

Installed entry points are executable import targets. Discovering available
extensions must not import their modules, execute factories, query infrastructure,
or invoke installed metadata finder hooks. Searching arbitrary directories or
network locations would also create an implicit trust and scope expansion.

## Decision

Introduce `flayer.extensions` with immutable descriptors and an explicit registry.
Built-in descriptors name usable adapters for the existing implementations.
External discovery reads bounded `METADATA`, `entry_points.txt`, and `RECORD` only
from the exact `.dist-info` directories selected by the caller. It does not enumerate
installed distributions or search paths. Versioned groups are
`flayer.providers.v1` and `flayer.profiles.v1`. Plugin identifiers, distribution
identities, exact stable release versions, groups, and import targets are validated
before a descriptor enters the registry. Duplicates and unsupported F-Layer groups
fail closed.

External loading is a separate explicit operation. It requires the exact
registered descriptor and an exact descriptor allowlist, including its import
target. Metadata files are pinned by digest and rechecked before import so a
changed discovery snapshot cannot authorize loading. Exact `RECORD` hashes and
sizes bind the selected target and every parent package to regular source files
under the selected installation root. The reserved `flayer` namespace is excluded
from external targets. Loading executes verified in-memory source snapshots; a
temporary hook serves only selected-chain imports so parent imports cannot execute
stale bytecode. Cached modules require loader-owned object/path/source-hash receipts.
Loading checks the factory's extension protocol and exact declared identity. It is
an explicit code execution trust decision, not a sandbox or a package authenticity
check.

Provider factories return the existing `CloudProvider` protocol. A separate
`LifecycleProviderExtension` returns the existing `LifecycleProvider` protocol.
Profiles compile explicit configuration with an exact `StackIdentity` context and
return an adapter exposing server bundle generation and lifecycle plan rendering.
Bounded provider context contains a scope, an external authentication reference,
and execution limits; context never carries resolved credential bytes. Profile
configuration remains subject to the profile's own strict schema.

## Consequences

Importing the extension package and discovering metadata perform no plugin
execution. An operator can inspect a catalog before authorizing an exact external
factory. The existing CLI and lifecycle core remain unchanged. Constructing a
provider or compiling a built-in profile does not mutate infrastructure.

Only stable three-component release versions, source-only ordinary Python
packages, and entry points without extras are supported initially. Adding another
ABI requires a new group and explicit
compatibility decision. Operators supply selected metadata directories; automatic
installation, package resolution, credential management, dynamic module scanning,
and process isolation are outside this contract. Pins do not verify signatures,
publisher authenticity, or dependency ownership. The selected environment
and external package must be trusted before loading. External dependencies remain
part of the opted-in execution trust boundary. Cleanup cannot undo arbitrary
plugin side effects; only this attempt's created modules and receipts are removed.

## Alternatives

Automatic `importlib.metadata` finder traversal can invoke installed finder code
and expands discovery scope. Importing modules to inspect capabilities executes
unapproved code. A generic plugin framework, dependency resolver, or lifecycle
replacement adds speculative contracts without improving the current consumers.

## Compatibility and migration

Existing provider, lifecycle, profile, state, artifact, and CLI contracts remain
unchanged. Built-in extension adapters are additive. Existing consumers can keep
using the direct APIs; no configuration or persisted-state migration is required.

## References

- [Extension contracts](../architecture/extensions.md)
- [Read-only provider boundary](0002-read-only-provider-boundary.md)
- [Secure gateway profile](0007-secure-gateway-profile.md)
