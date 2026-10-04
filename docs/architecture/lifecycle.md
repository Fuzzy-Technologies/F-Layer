# Owned lifecycle orchestration

The core implements generic create, status, destroy, and explicit recovery through
`flayer.core.lifecycle.LifecycleEngine`. Cloud-specific commands are supplied by
`flayer.providers.lifecycle.LifecycleProvider`; the first implementation is the
Yandex Cloud adapter described in [the provider lifecycle contract](yandex-lifecycle.md).

## Plan and persistence boundaries

| Object            | Meaning                                               | Stored information                                    |
| ----------------- | ----------------------------------------------------- | ----------------------------------------------------- |
| `DeploymentPlan`  | Immutable desired resource graph, at most 128 entries | Explicit identity, immutable options and dependencies |
| `StackState`      | Minimum owned provider locators                       | Identity, logical ID, portable kind and provider ID   |
| Operation journal | Pending action and safe rollback eligibility          | Identity, plan digest, operation nonce and locators   |
| Provider result   | Bounded scoped observation                            | Normalized reference, status and ownership labels     |

The journal is `.<state filename>.operation.json`. Complete operations cooperate
through `.<state filename>.operation.lock`; snapshot writes use the existing state
writer lock. Both files are beside the caller-selected state path. Their names are
local recovery implementation details, not cloud identifiers.

A pending journal blocks a new create or destroy. A different plan fingerprint or
ownership identity blocks recovery. Desired parameters and credentials are never
copied into either persisted state file. Strict TOML resource kinds use hyphens:
`security-group` maps explicitly to `ResourceKind.SECURITY_GROUP`.

## Explicit CLI

All help surfaces are offline. Commands use an existing authenticated `yc` profile;
F-Layer does not read, print, or persist its credentials.

```bash
python -m flayer lifecycle create --config plan.toml --state stack.json \
  --yc-profile sandbox --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle status --config plan.toml --state stack.json \
  --yc-profile sandbox --format json
python -m flayer lifecycle destroy --config plan.toml --state stack.json \
  --yc-profile sandbox --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config plan.toml --state stack.json \
  --yc-profile sandbox --allow-mutation --scope-confirm example-folder --rollback
```

These are illustrative commands. Create, destroy and recover can mutate the chosen
cloud account; the example folder and profile are placeholders. Missing opt-in or a
scope confirmation that differs from `identity.scope_id` blocks the command before
provider execution. The top-level diagnostic `status` command retains its original
behavior; stack observations use `lifecycle status`.

## Generic lifecycle plan

Lifecycle plans are separate from the initial `DesiredConfig` model. Every field is
strictly checked; unknown fields and unsupported options fail before creation.
The optional `profile` is descriptive and does not implicitly load a profile.

```toml
schema_version = 1
profile = "generic"

[identity]
project = "example"
stack = "sandbox"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"

[[resources]]
logical_id = "network"
kind = "network"
name = "example-network"

[[resources]]
logical_id = "subnet"
kind = "subnet"
name = "example-subnet"
dependencies = ["network"]

[resources.parameters]
network_dependency = "network"
zone_id = "ru-central1-a"
ipv4_cidr = "10.23.0.0/24"
```

Only immutable scalar, array, and table values are allowed in resource parameters.
Adapter validation defines supported keys, bounds and relationships. Parameters
must contain non-secret deployment options. Secrets have no lifecycle plan field.

## Operation behavior

Create validates and adopts exact-owned existing resources before making changes.
A broken preexisting dependency graph blocks creation. New resources are created in
dependency order, journaled, then saved into the minimal snapshot. A definite failure
rolls back only newly created resources that retain its `flayer-operation` nonce;
preexisting resources survive. Both core and adapter verify this nonce before
rollback deletion. A preexisting resource depending on a rollback candidate blocks
cleanup. Use one authoritative state path for each exact stack identity; local
locks are not a distributed cloud lease.

An uncertain create stays pending even when inventory does not yet show its result.
Recovery can resume or roll back only after discovering the exact owned resource.
It never blindly retries an uncertain request. Partial destroy resumes from recorded
locators and treats confirmed absence as successful cleanup. A nonzero outcome and
`recovery_required` distinguish partial or uncertain progress from completion.

`lifecycle status` reports `present`, `missing`, or `not-recorded` for each planned
resource and includes its normalized `provider_status` when present. It does not
modify snapshot contents, discover unrelated infrastructure,
or assert guest readiness. A present resource does not establish SSH connectivity,
server hardening completion, or application health.

After a hard process crash, inspect the local operation or state writer lock and
verify the old process has stopped before removing that lock. Keep the journal and
snapshot intact, then run explicit recovery. An unresolved ambiguous creation needs
provider-side investigation; automatic intent abandonment is not implemented.

See [ADR 0005](../adr/0005-durable-owned-lifecycle.md) for failure ordering,
alternatives, and compatibility decisions.
