# ADR 0006: Scoped Yandex lifecycle mutations and explicit boot disk ownership

## Status

Accepted for the lifecycle implementation in Task #20.

## Context

The first provider adapter deliberately exposes only discovery. Lifecycle orchestration now needs bounded creation, exact owned deletion and a way to reconcile an interrupted mutation. A CLI timeout cannot prove that a remote operation was rejected. Retrying creation after an ambiguous failure can duplicate a resource and lose its cleanup locator.

The Yandex instance CLI can create a boot disk implicitly. That compound operation does not expose the same independently labeled disk request used by the lifecycle journal. Failure between disk allocation and instance creation can therefore leave an untracked disk.

Two processes using different local state paths can also target the same stack. Stack ownership alone cannot establish which operation created a resource for rollback.

## Decision

1. Keep `YandexCloudProvider` read-only. Add `YandexLifecycleProvider` as an explicit mutation adapter advertising create/delete capabilities. Both reuse scoped normalized observations.
2. Use immutable `ResourceSpec` requests and an explicit `LifecycleProvider` contract. Reject unsupported kinds, options, dependency bindings and malformed requests before mutation.
3. Support a narrow six-kind graph: network, subnet, security group, static IPv4 address, disk and instance. Bind dependencies using exact owned references rather than names or arbitrary CLI options.
4. Create the boot disk as a separate, labeled resource. Attach it using `--use-boot-disk` with `auto-delete=false`; the core journal owns reverse dependency cleanup. Do not use `--create-boot-disk`.
5. Attach complete stack ownership, the logical resource ID, a bounded desired-spec digest and the durable operation nonce. Stable discovery checks the desired digest; rollback additionally checks its operation nonce immediately before exact-ID deletion.
6. Treat every dispatched mutation failure as `MutationError(outcome_unknown=True)`. Preserve only sanitized stable error codes. Never retry a mutation automatically or assume that absence in one later inventory proves a failed create was never accepted.
7. Verify exact folder and ownership on observations and create responses. Delete only after a fresh exact-ID lookup, then confirm absence with one bounded lookup. Unconfirmed deletion remains uncertain.
8. Accept only a caller-declared nonsecret cloud-init JSON file paired with its SHA256 digest. Before any cloud access, reject unsafe files and digest drift. Pass a private temporary copy through `--metadata-from-file`, remove it after execution, and retain no file bytes in state or error messages.

## Consequences

Every explicit resource has discoverable labels and a journal-owned cleanup order. A lost create response can be reconciled to the exact operation without treating another operation's resource as a rollback candidate.

The adapter deliberately lacks update, import, automatic adoption of unlabeled assets, arbitrary metadata, credentials, service account attachment and arbitrary vendor command forwarding. Resource existence and provider status do not prove guest initialization, tunnel service readiness or end-to-end reachability.

Ownership labels are an application authorization boundary, not a provider-side transaction lock. The CLI has no conditional delete that atomically compares labels. Independent remote actors with permission to change labels remain outside the cooperative local locking model. Recovery is conservative when attribution or remote outcome is uncertain.

The implementation is validated with deterministic command fakes. No real account mutation or live CLI compatibility smoke test is included in this decision.

## Alternatives

- Implicit boot disk creation was rejected because its intermediate resource is not independently recorded or reconciled.
- Name-based deletion was rejected because names do not prove ownership or folder identity.
- Automatic retry after timeout was rejected because timeout is not evidence of non-submission.
- Treating every owned resource as created by the current operation was rejected because it makes concurrent adoption destructive during rollback.

## Compatibility

Existing read-only contracts and capabilities remain available. Mutation capabilities are additive. New creation calls require the durable operation ID. Delete supports an optional operation ID for rollback and complete stack ownership for explicitly requested destruction.

## References

- [Yandex lifecycle architecture](../architecture/yandex-lifecycle.md)
- [Yandex instance create CLI](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/instance/create)
- [Yandex disk create CLI](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/disk/create)
