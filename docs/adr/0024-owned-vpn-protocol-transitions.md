# ADR 0024: Owned VPN protocol transitions and immutable epochs

- Status: Proposed
- Date: 2026-11-07
- Tasks: [#128](https://github.com/Fuzzy-Technologies/F-Layer/issues/128), [#122](https://github.com/Fuzzy-Technologies/F-Layer/issues/122)
- Extends: [ADR 0023](0023-selectable-vpn-transports.md)

## Context and implementation boundary

The selected-project lifecycle retains an immutable six-resource creation plan.
WireGuard peer revisions now evolve one deployed transport without changing its
server key, other peers, runtime or cloud policy. Adding or disabling an entire
transport also changes host input policy and cloud ingress. It must preserve the
original resource identity while closing stale operation authority across both
peer and protocol changes.

This decision defines the next implementation boundary. The code accompanying
this ADR normalizes optional security-group rule labels and provides a pure
`IngressDelta` planner with complete expected-old/readback validation. It does not
dispatch a cloud command or implement the protocol CLI, migration, epoch store or
guest ingress transaction. Those workflows remain unavailable until integrated
and tested; ordinary deployment still refuses a changed protocol selection.

## Original creation identity and protocol epochs

Never replace the original six `ResourceSpec` values, creation labels, bootstrap
bytes/path/hash, VM attachments or serial-console trust fingerprint with a plan
compiled from new listeners. Generic cloud `state.json` remains unchanged. The
creation baseline is permanent; effective protocol state is a separate overlay.

Use immutable protocol epochs. Each new epoch binds the exact previous epoch,
the terminal pointer/digest of its WireGuard peer segment, configured protocol intent,
active protocol pins and retained confined material/server references, static selection fingerprint, active guest
receipts/histories, and complete cloud/host ingress receipts. Retain every closed
segment and its original files. No key bodies enter epoch or journal metadata.

Epoch zero is the existing creation baseline and original WireGuard peer layout.
A committed transition starts a separate peer segment whose genesis is the exact
new epoch digest. Peer records still bind the original creation digest. Subsequent
epochs close that segment before another begins. This ordering makes the graph
acyclic and prevents old peer plans from gaining authority after a protocol change.
Missing parents, segments, references or ownership proof fail closed; an orphan
artifact is not permission to infer a lost head.

Resolve active protocol pins through the verified epoch and its current peer
segment. A source reference may select original bytes, a closed peer request or a
protocol request only through an owned manifest and full digest. Do not regenerate
an installer to load historical state. Nonsecret traversal and whole-cloud cleanup
must work when client private files are lost; reading active credentials still
requires their complete private manifests.

Project schema 2 keeps a nonempty configured `protocols` declaration with retained
settings/material. An epoch records its active subset separately; that subset may
be empty. Disabling the final active transport preserves the VM, address, SSH and
retained profiles, and reports that no transport is active. Ordinary deploy must
not reactivate disabled protocols. Peer operations require an active target;
reenabling a protocol is explicit and names the retained members it will activate.

## Planning and coordinated mutation

The future public workflow has read-only `plan`/`status`, explicit `enable`/
`disable`, and `recover`. Bind a short-lived plan to desired intent, exact epoch/
peer head, current complete cloud policy/attachments, existing authenticated host
pin, all affected guest receipts/history and private request digests. Require
explicit mutation consent, exact scope and the expected baseline. Re-observe before
dispatch; expiry or drift cannot be repaired by editing only a CLI argument.

Use the existing project lock across every cooperating local entrypoint. A durable
protocol journal blocks ordinary deploy, runtime, export and peer mutation until
recovery completes. A guest reservation journal also rejects a second controller
with a copied project: a local advisory lock alone cannot serialize two machines.
Read-only status may report only verified old/new prefixes. Whole-cloud deletion
keeps its separate explicit scope and accepts only a complete known committed or
pending cloud-policy prefix, never arbitrary rules.

Guest ingress coordination precedes transport-specific locks in one fixed order.
Check expected authority under the lock that actually protects each mutation.
Persist reservation, intended hashes and operation nonce before allowing a cloud
write. Preserve that reservation while the cloud result is unknown. Completion or
cancellation consumes the old guest authority durably, so a delayed protocol-workflow SSH action
cannot activate after a reported rollback. Repeated recovery retains its exact
completion; it must not create a fresh authorization epoch on every retry.

## Exact cloud ingress deltas

Before planning, the controller must prove the complete original cloud graph and
effective policy against creation plus committed overlays. A self-supplied snapshot
is not proof that a live rule was previously authorized.

The pure `IngressDelta` binds the frozen security-group spec, full stack identity,
active resource, network, exact original rule IDs/metadata, one listener and an
operation ID. Preserve the original `flayer-spec` labels. A new allowance has a
description derived from the full owner hash, protocol and operation ID. It opens
exactly one TCP or UDP port with the complete declared IPv4 source list. It has no
real provider ID until a verified readback supplies one. A pre-existing broad or
narrow allowance on that port blocks a new enable plan.

Removal requires exactly all target-port allowance IDs from the verified receipt,
exact listener/source semantics and either original creation semantics or a full
owned operation tag. An untagged creation rule additionally requires a separately
attested `creationListener`, including the original protocol name, which must match
the target. The controller derives that binding from the original manifest-bound
protocol role or epoch before constructing the delta, never from port equality
or a caller's desired label. The generic creation spec alone has no transport
attribution. Refuse broad ranges, arbitrary descriptions, duplicate source
allowances, collateral IDs and TCP 22. Unrelated rules, descriptions and labels
must be byte-equivalent after normalization. Selected rules with labels cannot yet
be removed: the planned CLI writer cannot promise exact label restoration. This
does not discard labels from other rules or treat an unknown target as empty.

Optional rule labels follow the provider's bounded immutable map contract and
participate in complete policy comparison. Absent/empty labels normalize equally;
unknown fields and unsupported rule targets remain errors. The
[security-group response](https://yandex.cloud/en/docs/vpc/api-ref/SecurityGroup/get)
documents those labels and distinguishes active from updating policy.

The documented [update-rules API](https://yandex.cloud/en/docs/vpc/api-ref/SecurityGroup/updateRules)
accepts explicit deletion IDs/addition specs and returns a long-running operation.
Its request has no documented expected-generation precondition. Therefore the
implementation must treat before/readback checks as optimistic concurrency, not a
provider compare-and-swap guarantee. Use only proved IDs, never a whole-group
replacement that could erase another actor's entries.

The future [CLI writer](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/security-group/update-rules)
uses explicit group ID, scope, `--async` and `--retry 0`. The existing scoped adapter
already disables CLI retries. Persist the returned operation ID before polling and
verify its resource binding and terminal outcome before policy readback. A lost
result/operation ID remains recovery-required: an old-looking snapshot does not
prove that a queued mutation cannot still run. Never blindly resubmit or guess an
operation from timestamps. External drift stops reconciliation.

## Guest input policy and transport generations

Do not replay initial bootstrap or use `flush ruleset` to change a listener.
Verify the original boot file and exact committed overlays, then atomically replace
only the proved owned input table and persist its matching boot-file delta.
Preserve SSH and every unrelated transport. An accepting extra base chain cannot
override an existing dropping chain, so merely adding a second permissive chain
does not implement protocol activation.

Enable order: retain private credentials once; stage and verify runtime/configuration
with cloud and host ingress closed; activate the owned service; allow host input;
allow cloud input; verify all resulting receipts; commit the epoch. Disable order:
deny cloud input; deny host input; stop/remove only the owned service/interface and
its forwarding/NAT table; verify remaining transports; commit the epoch.

Retain verified private runtime/unit/configuration backups before removal. Rollback
uses the same pinned binary and keys without a download, rebuild or regeneration.
Never reset global forwarding while another tunnel uses it. A network operation
with an unknown result leaves its journal and cannot claim a completed rollback.

Disabling/re-enabling WireGuard is a new installation generation with a new owned
nonce, while server/client keys and declared addresses stay retained. Archive/reset
its old audit only through this explicit expected-receipt/history transaction;
ordinary installation of an absent root with retained audit remains refused.
Keep the retained fence while its root is absent; publish the replacement
generation and its new history under the existing WireGuard lock, without exposing
an absent root with initial history that could authorize an old installer.

A change to another protocol preserves active WireGuard keys/configuration/root
receipt but must consume its peer history under that same existing WireGuard lock
before the first protocol write. Use the existing valid equal-receipt cancellation
audit shape to publish a new chained history head. Already queued peer driver bytes
then observe a different expected history and refuse mutation; a reservation
understood only by new code is insufficient. Refuse a pending peer transaction
before this fence. Record the new history in the next epoch. If the protocol change
subsequently rolls back, publish a no-op epoch completion retaining the old active
pins/policy and recording the consumed history. Never restore the old history during
rollback. This requires an exact healthy active WireGuard receipt. If WireGuard is
inactive/absent, verify its separate complete namespace-absence and retained-history
proofs instead; never fabricate a running receipt merely to fence it.

## Explicit legacy project migration

Migration is a separate planned operation, never a prepare/deploy side effect.
Read verified schema-1 configuration, manifests, original bootstrap and observations
before capturing a creation baseline. Preserve all six actual specs and their old
bootstrap locator inside the project, original serial marker, host pin, filenames,
client exports and legacy fingerprints. Derive per-protocol material references
from existing combined credentials without issuing keys or changing server bytes.

Journal exact old/new public TOML snapshots and hashes, immutable metadata and the
publication boundary before atomically replacing `project.toml`. Recovery can
parse either recorded schema without reconstructing lost intent. Legacy and new
entrypoints must recognize pending/migrated state before creating keys or adapters.
An older package rejects schema 2 before mutation. Migration itself changes only
verified controller metadata, with read-only cloud/guest attestation; it does not
relabel resources, change ingress, reinstall services or create a paid resource.

## Consequences and validation

This requires extra bounded metadata and recovery paths, but keeps original
ownership independent from desired listeners and retains per-device continuity.
Rejecting ambiguous state is preferable to silently adopting rules or reviving a
revoked peer. Existing project and guest locks remain advisory for external cloud
administrators; no distributed atomicity or arbitrary-drift repair is promised.

Deterministic tests must cover full-rule identity/labels, retained SSH and unrelated
services, port/source collisions, stale plans, delayed commands, every publication
boundary, known/unknown provider outcomes, rollback without key rotation, missing
private keys during whole-cloud cleanup, and legacy migration from either TOML
snapshot. Use mocks and isolated Linux conformance, never the owner's desktop VPN.
Manual installed-client/live-cloud acceptance remains separately authorized work.

Rejected alternatives: recompile/relabel the original cloud plan; replace whole
security groups; replay bootstrap; infer success from an old-looking API snapshot;
store only the latest peer head without closing its parent segment; regenerate
credentials during migration; treat a second nftables accept chain as sufficient.
