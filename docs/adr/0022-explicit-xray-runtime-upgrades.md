# ADR 0022: Explicit, recoverable Xray runtime upgrades

- Status: Proposed
- Date: 2026-11-05
- Related: [Task #118](https://github.com/Fuzzy-Technologies/F-Layer/issues/118), [Task #103](https://github.com/Fuzzy-Technologies/F-Layer/issues/103)

## Context

Xray 26.10.31 disables default MPTCP to reduce exposure to CVE-2026-98432.
Fresh installations must use checksum-pinned release assets. Existing projects
retain immutable private bundles, ownership receipts and device exports. Changing
a package constant cannot authorize replacement of a running executable, rotate
credentials or rewrite an old artifact manifest.

The Linux kernel needs independent vendor-specific assessment and maintenance.
Neither an Xray upgrade nor active services prove a patched kernel, working
client traffic, or successful YouTube playback.

## Decision

Add read-only `flayer vpn runtime-status` and explicit `upgrade`,
`rollback-upgrade`, and `recover-upgrade` operations. They reuse exact cloud
instance/address ownership and authenticated SSH trust, without creating,
updating or deleting cloud resources. Mutations require `--allow-mutation`, the
exact `--scope-confirm`, `--expected-version` and `--expected-receipt-sha256`.
The expected digest binds the complete previous remote receipt, including the
executable, private configuration and service hashes. An unexpected state fails
before any managed service or file changes.

The supported forward transition is 26.9.30 to 26.10.31. Archive bytes and SHA-256
are pinned independently for amd64 and arm64. Ordinary deployment never performs
an implicit runtime migration. Known legacy prepared installers are recognized
by exact normalized source hashes after their artifact manifests are verified;
their private bytes and manifests remain unchanged. A current trusted installer
is transferred in memory when operating on retained legacy bundles.

### Transaction and recovery

The operation stages and syntax-checks the new binary against the unchanged
configuration before stopping the one owned VLESS service. A complete private
transaction directory, containing both binaries and exact old/new receipts, is
atomically published before the executable is replaced. Its journal binds the
owner and all saved hashes. Configuration, systemd unit, device material, AWG,
cloud resources, firewall and local networking are outside the transaction.

After switching the binary and receipt, restart only that VLESS service and check
its target, syntax, activity and listener. A failure attempts an ownership-checked
rollback. A failed rollback or forced interruption leaves the verified journal
for explicit `recover-upgrade`, which restores the old runtime. Ordinary install
and removal refuse an interrupted transaction rather than guessing its outcome.

A committed transaction retains the previous runtime for explicit rollback.
Repeated upgrade with the original expected receipt is an idempotent check, not
another restart. Rollback requires the current new receipt; interrupted recovery
requires the original old receipt. Both verify every current and saved managed
file before writing. Normal removal also verifies and removes a committed
transaction's exact owned files. Unknown files, symlinks, hardlinks, unsupported
versions, changed configuration or service content block these operations.

Directory entries and atomic file replacements are synchronized for durability.
A process killed before publication may leave an inert staging directory; it is
not treated as an owned deployment and is not deleted by guessing its ownership.

### Observation and compatibility

Runtime status reports bounded nonsecret versions/hashes, transaction state,
running kernel release and its installed package version when available. Kernel
patch status stays `not-assessed`; upstream version comparison cannot detect
distribution backports. No package upgrade, reboot or firewall mitigation occurs
implicitly. Any such work needs its own bounded maintenance procedure under #103.

Native `.vpn`/QR contents, VLESS TCP Reality/Vision policy, DNS/routes and AWG MTU
stay unchanged. Contract tests follow the versioned AmneziaVPN 5.1.0.6 import
model; actual Android/desktop import and playback remain live acceptance in #73.
The existing POSIX controller/private-storage contract remains in force. Windows
checks use isolated fixtures; no command starts WSL or a local VPN client.

## Validation

Deterministic tests cover clean installation, legacy project retries, explicit
consent, exact receipt checks, idempotency, failed health, interrupted writes,
rollback/recovery, tampered journals and private output suppression. Supported
Linux CI validates real pinned runtime configuration and installed-package CLI
composition without production infrastructure. Canonical full, documentation
and reproducible artifact gates apply to the exact PR head.

## Consequences and alternatives

Runtime maintenance becomes a separate authenticated operation rather than a
side effect of deployment. It requires a short VLESS interruption and temporary
space for two verified executables. A kernel reboot would interrupt both VPN
protocols and is deliberately separate.

Recreating the VM, rotating credentials, following a moving latest release,
editing receipts manually, accepting arbitrary old installer programs, or copying
Amnezia's Docker/firewall update scripts would violate these boundaries. A
public F-Layer release is unnecessary for an internally verified candidate wheel.
