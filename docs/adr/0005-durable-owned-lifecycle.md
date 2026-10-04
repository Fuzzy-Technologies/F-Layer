# ADR 0005: Durable owned resource lifecycle

- Status: Accepted
- Related work: Task #20, Feature #6
- Date: 2026-10-04

## Context

A provider command and a local file replacement cannot be one atomic transaction.
An interrupted create can leave a resource without its local locator. An interrupted
delete can leave a locator for an already absent resource. Automatic retry of an
uncertain creation can produce duplicates, and rollback must preserve resources
that existed before the current operation.

## Decision

The generic core accepts an immutable `DeploymentPlan` and an injected
`LifecycleProvider`. A plan contains at most 128 unique logical resources, an exact
`StackIdentity`, immutable provider options, and an acyclic dependency graph.
Construction, topological ordering, and provider option validation are offline.
Core resource kinds use portable hyphenated names; `security-group` is explicitly
translated to the provider enum `security_group`.

Create, status, destroy, and recovery serialize through a cooperative operation
lock next to an explicit state path. The existing state writer lock independently
protects each atomic snapshot replacement. The operation lock does not coordinate
external programs that ignore this contract, and it is not a distributed lease.

The core persists a write-ahead journal before every mutation. The journal stores
only ownership, a SHA-256 plan fingerprint, a random operation ID, action, original
and newly created locators, and the pending logical resource. Snapshot state
remains schema version one and contains only ownership plus logical IDs, kinds, and provider IDs. Neither
file receives desired parameters, credentials, instance metadata, or command
output. Atomic replacement and directory synchronization reuse the owned-state
storage contract. Snapshot and journal reads use bounded regular-file descriptors
and nonblocking open where available to reject a post-validation FIFO substitution;
JSON reads and snapshot writes have a 1 MiB limit.

Create first discovers and validates preexisting exact-owned resources. A
preexisting resource whose dependency is absent blocks the operation before
mutation. Resource creation follows dependency order. Every confirmed creation is
journaled before its minimum locator enters the snapshot. A definite predispatch
failure rolls back only resources created by this operation, in reverse creation
order. Existing resources remain recorded and are preserved.

An uncertain provider failure leaves pending intent and returns a nonzero outcome.
Recovery observes the pending logical resource using complete ownership and stable
specification labels. When it becomes visible, recovery records it and either
resumes creation or performs an explicit rollback. The creation response and
recovered observation must carry this journal's `flayer-operation` nonce before
they enter the rollback-eligible set. Rollback rechecks that nonce at exact lookup
and the provider adapter repeats it immediately before deletion. A resource from
another operation cannot be treated as this operation's creation. A newly appeared
preexisting resource depending on a rollback resource blocks cleanup. An absent
resource after an uncertain submission remains uncertain: recovery never assumes submission failed
and never automatically repeats that creation.

Destroy operates only on recorded exact locators in reverse dependency order.
The engine and adapter both verify scope and complete ownership before deleting
by ID. Confirmed absence is idempotent success. Each confirmed removal is persisted
before proceeding. Partial destruction can resume, but cannot be rolled back by
recreating already removed infrastructure.

## CLI contract

`python -m flayer lifecycle` provides `create`, `status`, `destroy`, and `recover`.
Every command requires explicit plan, state, and preauthenticated `yc` profile
arguments. Mutation commands also require `--allow-mutation` and a
`--scope-confirm` value equal to the plan's exact folder ID. Recovery accepts
`--rollback` for interrupted create operations. Help and argument validation never
access infrastructure. API callers are responsible for authorizing their explicit
provider operations; the CLI flags are not a security policy or cloud IAM boundary.

## Recovery and limitations

A normal exception or cooperative interruption releases the operation lock while
leaving durable progress. A hard crash can leave an exclusive operation lock or
state writer lock. An operator must verify that the previous process is no longer
running before removing the corresponding local lock and invoking recovery.
Locks are never automatically expired or removed by a second process. Different
state paths are not mutually exclusive; use one authoritative state path per exact
stack ownership identity. Creation nonces prevent another operation's resources
from entering rollback eligibility, but do not provide a distributed cloud lock.

The provider must resolve an uncertain creation before the engine can safely
continue. The current journal does not store vendor operation IDs or automatically
abandon uncertain intent. Names alone never prove ownership. Resource presence is
an infrastructure observation; it does not establish guest readiness or successful
application deployment. No update or drift repair operation is implemented.

## Alternatives

- Retrying every failed create was rejected because timeout does not prove absence.
- Removing all matching resources on failure was rejected because it destroys
  preexisting infrastructure and treats discovered state as rollback eligibility.
- Keeping progress only in memory was rejected because accepted provider mutations
  must remain recoverable across local failures.
- Provider-specific orchestration in the core was rejected because cloud command
  syntax and supported resource parameters belong to an adapter.

## Compatibility and evidence

Existing configuration and snapshot schema contracts remain unchanged. Lifecycle
plans are a separate strict version-one TOML input with optional resource parameters
and dependencies. Deterministic fake-provider tests cover ordering, ownership,
idempotency, preexisting resource preservation, partial cleanup, accepted interrupted
create/delete, ambiguous absence, and snapshot failures. No real cloud operation is
part of these tests.
