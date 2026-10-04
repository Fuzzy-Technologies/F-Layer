# ADR 0001: Separate desired configuration from owned resource state

- Status: Accepted for implementation
- Date: 2026-10-04
- Related issues: #2, #18

## Context

F-Layer starts from a working application-specific automation baseline. That
baseline combines provider settings, gateway settings, regional defaults,
credential paths, and machine-specific artifact paths in one configuration.
Its resource-state file is useful, but lacks a versioned schema and an explicit
ownership check at the persistence boundary.

The reusable core needs stable identities before provider connectors and
deployment lifecycle operations can cooperate safely. Reading a missing or
malformed configuration must not implicitly select another environment.
Persisting a new snapshot must not replace an unrelated stack's inventory.

## Decision

Implement a standard-library core in `flayer.core` with three boundaries:

- `contracts` owns schema version validation, the immutable `StackIdentity`,
  and portable ownership labels.
- `config` owns strict TOML loading into immutable `DesiredConfig`,
  `DesiredResource`, and `SecretReference` models.
- `state` owns strict JSON loading into immutable `StackState` and
  `ResourceState` models, plus atomic local persistence.

Desired configuration and persisted state both declare schema version `1`.
Unknown versions, unknown fields, malformed types, and incomplete identities
are errors. There are no implicit provider, project, region, credential,
environment override, or storage-path defaults. Empty desired resource arrays
are valid and request no implicit infrastructure.

An identity contains `project`, `stack`, `provider`, `scope_id`, and `owner_id`.
All five fields must match an explicit caller expectation for state reads,
writes, and removal. Provider adapters attach and independently verify the
core's ownership labels when operating on actual resources. A local inventory
is a locator, not evidence of current cloud authorization or ownership.

Credential configuration contains only named `env` or `file` references.
The core never reads their values. Authentication adapters resolve those
references at their own boundary. State contains only its schema, identity,
and logical resource kinds and provider identifiers; configuration,
credentials, provider responses, endpoints, and generated artifacts are not
copied into it.

Persist state using an exclusive sibling lock, a unique sibling temporary
file, file flush and `fsync`, and atomic `os.replace`. On POSIX, flush the
directory after a committed replacement or removal. Reject symlink paths,
parent traversal, and nonregular targets. Refuse to overwrite or delete an
existing corrupt or foreign snapshot. Keep the previous snapshot if an error
occurs before replacement. Report that a replacement may already be visible
if a durability error occurs after its commit point.

## Consequences

- Core modules do not import a cloud SDK, run a CLI, initiate network traffic,
  or select a gateway implementation.
- Provider and deployment settings require their own typed contracts and
  translation into core identities; arbitrary dictionaries are deliberately
  absent from the initial core schema.
- Adding a field or migrating a schema is an explicit design and versioning
  decision. The loader does not guess how to migrate an application baseline.
- Successful state writes use owner-only POSIX permissions. Windows file
  confidentiality depends on the caller-owned directory's ACLs.
- A process crash may leave a writer lock. Recovery requires confirming that
  no writer is active and inspecting the surviving snapshot before removing
  that local lock; the implementation does not steal locks.
- Paths must be inside trusted caller-owned storage. These checks are not a
  security boundary against a local adversary who can mutate its directory
  entries concurrently. All writers must use the same state API.
- Atomic local replacement is not a distributed transaction or a cloud
  lifecycle implementation. Partial deployments can record the subset of
  acquired resource locators; lifecycle reconciliation and rollback remain
  separate work.

## Alternatives considered

1. **Copy the application configuration unchanged.** Rejected because it
   embeds one provider, gateway stack, regional defaults, and private storage
   assumptions in reusable core behavior.
2. **Accept arbitrary configuration and provider-response dictionaries.**
   Rejected because silent field typos and unrestricted payload persistence
   weaken ownership and secret-exclusion guarantees.
3. **Use one fixed temporary filename without a writer lock.** Rejected
   because overlapping writers can truncate or replace each other's pending
   snapshots and lose the ownership check's relationship to the commit.
4. **Introduce a database or cross-platform distributed locking dependency.**
   Deferred until a demonstrated multi-host state use case needs that contract.

## Validation

Deterministic tests cover strict schema/type validation, unknown and duplicate
fields, credential-reference isolation, immutable construction, each identity
dimension, partial/empty snapshots, idempotent local removal, corrupt-state
preservation, symlink/traversal rejection, held writer locks, permissions,
and failures before and after atomic replacement. No test resolves credentials
or mutates cloud resources. Failure-path tests also verify descriptor ownership
when stream creation fails and explicit reporting when artifact cleanup fails.

The implementation passes the repository's compile, Ruff, mypy, and pytest
gates before review.
