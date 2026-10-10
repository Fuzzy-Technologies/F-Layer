# Yandex lifecycle adapter

`YandexLifecycleProvider` adds a deliberately bounded mutation boundary to the read-only Yandex adapter. Construction, capability discovery and `ValidateSpec` are offline. Mutation tests use deterministic command fakes; no real cloud operation is performed by the test suite.

## Request and capability contract

`ResourceSpec` contains an immutable logical ID, resource kind, portable name, named parameters and logical dependencies. Recursive values have bounded depth, size and signed 64-bit integers. Parameters are excluded from the request representation.

The mutation subclass advertises `create_resource` and `delete_resource` in addition to inventory and lookup. These describe implemented operations, not the current account's permissions. The original `YandexCloudProvider` still advertises only read operations.

| Kind           | Required parameters                                                                                                                                | Optional parameters                                  | Typed dependencies                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ---------------------------------------- |
| Network        | None                                                                                                                                               | None                                                 | None                                     |
| Subnet         | `zone_id`, `ipv4_cidr`, `network_dependency`                                                                                                       | None                                                 | Network                                  |
| Security group | `network_dependency`, `rules`                                                                                                                      | None                                                 | Network                                  |
| Address        | `zone_id`                                                                                                                                          | None                                                 | None                                     |
| Disk           | `zone_id`, `image_id`, `size_gib`                                                                                                                  | `type`: `network-ssd` or `network-hdd`               | None                                     |
| Instance       | `zone_id`, `cores`, `memory_gib`, `boot_disk_dependency`, `subnet_dependency`, `security_group_dependency`, `address_dependency`, `ssh_public_key` | `ssh_username`, `user_data_file`, `user_data_sha256` | Disk, subnet, security group and address |

`dependencies` must exactly match the distinct logical IDs used by typed dependency parameters. Before create, every dependency is refreshed by exact provider ID and checked for kind, folder, ownership and applicable zone. Address allocation must expose exactly one public IPv4 address before instance creation.

Numeric bounds are 2..32 cores, 1..128 GiB of memory and 10..1024 GiB of boot disk storage. Security groups accept 1..64 unique IPv4 rules with explicit ingress/egress direction, TCP/UDP/any protocol, strict CIDR notation and explicit valid TCP/UDP port ranges. Arbitrary descriptions, vendor options and IPv6 rules are unsupported in this version.

Public SSH keys must use structurally valid OpenSSH Ed25519 or RSA encoding; RSA modulus size is bounded to 2048..16384 bits. Optional comments are omitted from CLI metadata. Private key content is never an accepted option.

The portless `any` rule model translates to `from-port=0,to-port=65535` for `yc`,
which requires an explicit port selector even for that protocol. This CLI-only
translation preserves existing configuration, desired digests and ownership labels;
TCP/UDP retain their configured ranges. The original missing-port rejection and
the corrected parser path were reproduced with Yandex CLI 1.40.0 against a local
unreachable endpoint, without cloud access. This is parser evidence, not cloud acceptance.

## Ownership and recovery

The adapter attaches `managed-by`, `flayer-project`, `flayer-stack`, `flayer-owner`, `flayer-resource`, `flayer-spec` and `flayer-operation`. The stable desired digest is a SHA256-derived 40-character label. The operation ID is the core journal's 32-character lowercase hexadecimal nonce.

`FindResource` matches complete stack ownership and logical ID. Duplicate matches fail closed. A different desired digest, name or requested zone conflicts with creation; the adapter never silently updates or adopts drifted configuration. The operation nonce remains visible in normalized labels so the engine can distinguish a newly created resource from a preexisting or concurrently created one.

`CreateResource` executes at most one create command after validation and discovery. Every create command carries an explicit folder/profile, JSON output, disabled browser authentication and `--retry 0`, and executes without a shell under the configured deadline. Successful output must match scope, ownership, operation and requested name/zone.

Every dispatched failure is uncertain, including a timeout, malformed successful output or transport failure. A single inventory absence after timeout does not authorize another create. The core's durable journal controls explicit recovery and never blindly recreates an unresolved orphan.

Read-only preflight failures are explicitly classified as not submitted, so the core can roll back earlier creations safely. Uncertain mutation errors also override the inherited `retryable` recommendation to false; their timeout category does not permit a blind retry.

Upgrading the adapter does not clear an existing uncertain journal. Older journals
do not retain the original CLI rejection or an authoritative operation result.
Keep the project, snapshot and journal; inspect the pending resource and original
private CLI log before any further mutation. An empty inventory alone cannot
authorize resubmission, journal editing or a replacement project. The current
`recover` command can continue only when the exact pending owned resource is found;
automatic recovery from a recorded rejection is not implemented.

`DeleteResource` refreshes the exact persisted resource ID and checks complete stack ownership and logical ID. Rollback also supplies the expected operation nonce, which the adapter checks again immediately before deletion. Missing references are already deleted. After a dispatched delete, one lookup must confirm absence; otherwise cleanup remains uncertain. Names alone never authorize deletion.

The boot disk is an explicit resource. Instance creation uses an existing owned disk with `auto-delete=false`. The engine removes the VM first and the disk afterward, keeping partial allocation and interrupted cleanup discoverable.

## Nonsecret initialization artifact

`user_data_file` and `user_data_sha256` are paired options. The file must be a regular nonsymlink file with no parent symlinks, no traversal component, a matching SHA256 digest and at most 256 KiB. On POSIX it must belong to the invoking user and exclude group/other permissions. Nonregular files are rejected before opening so FIFOs cannot block preparation.

The accepted format is a JSON object, optionally prefixed by `#cloud-config` and a newline. Allowed top-level fields are `ssh_pwauth`, `disable_root`, `users`, `package_update`, `package_upgrade`, `packages`, `write_files` and `runcmd`. The deployment profile owns the generated content and its hardening policy. Callers must supply nonsecret content; this adapter is not a semantic detector for secrets hidden inside arbitrary script strings.

The adapter reads a bounded immutable snapshot, verifies its digest before cloud access and writes a private temporary copy for `--metadata-from-file user-data=...`. The CLI receives that copy; state, journals and sanitized exceptions receive no file bytes. Temporary preparation failure is definitely not submitted. Cleanup failure after submission preserves remote uncertainty.

## Observations and limits

Normalized observations retain only the existing public resource contract, including a finite known provider status and validated resource name. Static address zones are read from `external_ipv4_address.zone_id`.

Presence is not a readiness claim. An owned VM can exist while cloud-init is running or failed; its network service and end-to-end tunnel still require separate diagnostics. Live Yandex account permissions, current CLI behavior and guest initialization remain unverified until an explicitly authorized isolated cloud smoke test.

There is no remote atomic compare-and-delete for labels. Cooperative local locking and operation attribution reduce concurrent rollback risk; unrelated remote writers with label-changing privileges are outside that transaction model.

## Official CLI references

Command translations were checked against official Yandex documentation during implementation on 2026-10-04:

- [Network create](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/network/create) and [delete](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/network/delete)
- [Subnet create](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/subnet/create) and [delete](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/subnet/delete)
- [Security group create](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/security-group/create) and [delete](https://yandex.cloud/en/docs/vpc/cli-ref/security-group/delete)
- [Address create](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/address/create) and [delete](https://yandex.cloud/en/docs/cli/cli-ref/vpc/cli-ref/address/delete)
- [Disk create](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/disk/create) and [delete](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/disk/delete)
- [Instance create](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/instance/create) and [delete](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/instance/delete)

See [ADR 0006](../adr/0006-yandex-lifecycle.md) for the mutation and boot disk ownership decision.
