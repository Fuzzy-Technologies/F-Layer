# Standard WireGuard implementation boundaries

The release-2.1 development candidate adds low-level standard WireGuard intent,
private material codecs and configuration renderers. These APIs are not part of
the published 2.0.0 package. Their architecture follows
[ADR 0023](../adr/0023-selectable-vpn-transports.md).

## Implemented foundation

`flayer.vpn_selection.VpnProtocolSelection` binds a protocol to an explicit
subset of declared device IDs. Additional IP tunnels use an exact private
device/address map; AWG keeps its existing device address field and VLESS has
no tunnel addresses. Ordering is canonical, without allocating addresses or
renaming devices. `Project()` produces a profile containing only the selected
protocol's devices and listener, plus the shared identity and route policy.
Unrelated device/address/listener changes do not affect that projection.
`ParseProtocolSelections()` validates membership, not a complete project file.

`flayer.profiles.wireguard` provides validated `WireGuardSettings`,
`WireGuardPeer` and `WireGuardMaterial`, explicit material generation and
bounded exact JSON codecs. Standard WireGuard uses separate X25519 keys and
per-device preshared keys. Repeated preparation must decode retained material;
calling the generator again intentionally creates different credentials.
Private fields are excluded from representations and invalid input is not echoed.

The server renderer emits only its private key and selected peers' public and
preshared keys. A client renderer emits only that device's private key, the
server public key, its preshared key, explicit address, endpoint, MTU, routes,
DNS and keepalive. Neither configuration contains AWG obfuscation parameters.
Validate tunnel membership and addresses before generating material. Reject
shared Curve25519 identities, private-scalar aliases or public/reused preshared keys, invalid subnets,
TCP listeners and mismatched client endpoint ports.

These public APIs prepare bytes in memory. Credential bytes require a verified
private owned store before persistence or transfer; do not put them in logs or cloud metadata.
The stable service name derives from complete stack identity and does not change
when peer membership changes.

## Owned guest implementation

`PrepareWireGuard()` creates a sensitive server bundle containing `server.conf`,
`deployment.json` and a standalone `install.py`, plus one standard `wireguard.conf`
per selected device. Preparation is offline and retains the supplied material.
The descriptor binds the complete stack owner, tools source pin, exact program
and configuration hashes, public peer identities, addresses and route policy.
It contains no client private keys. Native AmneziaVPN exports remain Task #129.

The guest program implements fresh install, exact repeat verification, read-only
check/status, systemd start/stop, receipt-bound removal and interrupted-install
recovery. Fresh schema-2 project deployment invokes it through the host-pinned
SSH receiver. Existing schema-1 installations require the separate migration/
ingress workflow; do not run the program manually on a production guest to bypass it.

The initial platform is Ubuntu 24.04 amd64 with its GA 6.8 kernel. Before building
tools or publishing managed configuration, first-install admission reads the fixed
[Ubuntu CVE-2026-98432 JSON](https://ubuntu.com/security/cves/CVE-2026-98432.json).
It requires exactly the `linux` package's `noble` entry to be `released` and the
running image package to meet that entry's fixed version. A `pending` description,
unavailable response, another kernel family or ambiguous evidence blocks activation.
At implementation time Ubuntu lists the noble fix as pending; its target version
is not proof of a released fix. The installer never upgrades/reboots the kernel or
applies a host-wide mitigation. Such maintenance requires a separate plan.

Installed receipts cache that named-CVE evidence, the complete executing Ubuntu
`/proc/version_signature`, installed image/modules revision, available module's
source checksum and disk-artifact hash. A loaded module must expose the same
source checksum; after interface creation this loaded identity is mandatory
before link-up. Missing or mismatched build/source identities fail closed.
These are executing-build/source facts and a separate disk hash, not hashes of
the running image or loaded memory. See [Ubuntu kernel identity](https://ubuntu.com/kernel)
and the [kernel module ABI](https://docs.kernel.org/admin-guide/abi-stable.html).
Ordinary status, repeat and boot checks compare current kernel facts against the
receipt without downloading metadata or reinstalling tools. A changed kernel
requires explicit policy maintenance. This assesses one named baseline, not all
kernel security. No status claims end-to-end traffic or media playback.

Tools are built privately from the checksum-pinned upstream
`wireguard-tools 1.0.20260223` archive. Bounded extraction never creates links and rejects unsafe
paths; it skips only the pinned archive's unused, exactly identified wg-quick link.
The built executable must report the pinned version and Linux amd64
format. The private service directory retains the source license. No package
installation, system binary replacement or userspace fallback is attempted.
Build prerequisites (`make`, compiler, libc headers), `ip`, `ss`, `nft`, `unshare`,
`modinfo`, `dpkg-query`, Python and systemd must already be available on the guest.
The receipt records compiler/make executable hashes and versions, target, libc/kernel
headers package versions and exact fixed upstream build options. The toolchain
must remain unchanged during the build; ordinary status does not rebuild tools.

The full owner digest determines the private directory; the stable service,
interface and nft table use a short owner prefix plus full operation markers.
Private directories/files require exact ownership and modes. Checks reject
symlinks, hard links, extra files, changed configuration/binary/unit bytes,
unknown peers/addresses, occupied UDP ports and overlapping existing guest routes.
A private operation lock serializes controller mutations. Systemd callbacks are
bound to the exact installed program and unit and verify their receipts.

Forwarding/NAT rules use only the selected interface, explicit peer sources and
declared destination routes. Their exact JSON policy is compiled first in an
ephemeral network namespace and then compared with observed guest rules.
The program never flushes the host ruleset, edits global input policy, restarts
shared networking or resets IPv4 forwarding used by other tunnels. Guest IPv6
must already be disabled. Existing-guest cloud and input-ingress transitions are separate integration
work; running a service alone does not prove that its UDP listener is reachable.

A complete private journal and staged files are published together before any
service/interface activation. Files and directory boundaries are fsynced before
activation and before retiring cleanup evidence. Installation failure removes only proved owned
objects. Removal/recovery require explicit mutation consent and the exact old
receipt SHA256. The journal retains nonsecret file hashes outside the tree being
deleted so interrupted partial cleanup can resume. Foreign or drifted state is
retained for diagnosis. A committed healthy service survives journal-finalization
failure. Replacement, peer changes and key rotation are refused by ordinary
installation; they need explicit transitions rather than implicit regeneration.

## Explicit project selection and offline preparation

The development candidate accepts schema-2 private projects through the public
loader and offline preparation CLI. An explicit repeated option opts into this
format; omitting it retains the exact schema-1 AWG/VLESS template and fingerprints:

```bash
flayer project init ~/flayer-wireguard --protocol wireguard
# Edit the cloud placement and administration address in project.toml first.
flayer vpn prepare --project ~/flayer-wireguard
```

Repeat `--protocol` to select any nonempty combination of `amneziawg`,
`vless-reality` and `wireguard`. OpenVPN remains unavailable until its separate
implementation. An empty, repeated or unknown selection is an error, never an
implicit fallback to the old pair. The whole document is validated before keys
are generated: inactive/unknown settings, duplicate UDP listeners, TCP 22,
overlapping networks, invalid MTU, extra device-address keys or more than two DNS
servers are refused.

Each selected protocol table requires explicit `device_ids`. WG uses its own
`[wireguard.device_addresses]` map; top-level `devices.ipv4_address` belongs only
to AWG members and VLESS has no tunnel address. IDs and assigned addresses are
retained while declaration order is canonicalized. No addresses are allocated by
enumeration and no protocol enrolls all devices implicitly.

`SelectedVpnProject` keeps a full public project fingerprint separately from
`TransportFingerprint()`. Each transport's fingerprint includes its selected
members, listener/settings, identity and shared route policy. It excludes other
protocols' devices/listeners/settings and cloud placement. An unselected device
can be declared without changing any retained transport bytes.

Preparation creates separate owned `server-<stack>-<protocol>-credentials`
bundles containing private `material.json` and its `intent.sha256` proof, plus
that protocol's server bundle. Exact matching material is decoded, not regenerated.
All existing bundle manifests/file sets are verified before publishing new bundles.
Changed own membership/settings or drift fails closed without rewriting other
protocols. If a later local bundle write fails, already committed credentials
remain available for an unchanged retry. Existing filesystem ownership and 0700/
0600 private-storage requirements still apply.

Preparation also snapshots an owned nonsecret `server-<stack>-creation` bundle:
`creation.json` stores the exact ordered six-resource specs, creation labels,
original project/plan fingerprints and independent protocol bundle digests;
`cloud-init.json` retains the exact original bootstrap bytes. Compilation reads
this snapshot rather than rebuilding instance labels or bootstrap from current
settings. Fresh WG bootstrap includes build tools, kmod, iproute2 and util-linux;
it never upgrades or reboots the kernel. Preparation creates no cloud state or
placeholder client exports. Existing snapshots are verified without regenerating
their installer programs, credentials or bootstrap.

Editing an old project to schema 2 is not migration. Retained generic cloud state or a pending operation journal,
legacy combined credentials, bootstrap/trust bundles or device exports block this
preparation. Keep the original schema-1 configuration, keys, manifests and cleanup
references until an explicit migration/ingress workflow can prove the old baseline.

## Fresh project lifecycle

Fresh schema-2 `deploy`, `status`, `recover` and `destroy` use the original
six-resource plan. Mutations require explicit consent and exact scope before
preparation, authentication or vendor downloads. Before submitting a fresh WG VM,
the controller additionally requires released noble/linux evidence; the guest
still verifies the executing build. Unavailable or pending evidence blocks
creation before billing resources. Healthy retries/status use the cached guest
baseline; cleanup and destroy recovery never depend on that download.

Every cloud observation verifies exact scope, kind, name, zone and original
creation labels. Security-group observation additionally checks network attachment
and the complete effective IPv4 rule multiset, including descriptions and
multiplicity. Documented numeric JSON encodings are normalized; IPv6, indirect
targets and unknown policy are refused. Rule IDs remain available in the bounded
snapshot. All surviving original resources are checked before each deletion, so
a drifted firewall stops cleanup before the first VM is deleted. Cleanup never
adopts an unrecorded or replaced resource. No cloud rule update is implemented by
this slice and no existing resource is relabeled.

The VM's actual sole IPv4 interface must also reference the exact owned subnet
and only the original security group, with the reserved public NAT address and
an internal address in that subnet. IPv6, extra interfaces and unknown attachment
fields are refused. Its exact owned boot disk must remain writable and excluded
from automatic deletion; extra disks, filesystems or local disks are refused.
The final ID-bound instance deletion repeats the complete attachment read and
compares its pinned snapshot. This prevents a changed VM attachment from bypassing
ingress checks or deleting an unrelated auto-delete disk. See the provider's
[instance attachment schema](https://yandex.cloud/en/docs/compute/api-ref/Instance/get).

The SSH receiver accepts at most three selected transports. WG install runs first
so an interrupted WG transaction cannot trigger another transport's installer;
only installation carries mutation consent and its following check is read-only.
Server programs are read from their pinned original bundles. Actual client files
are published only after the owned reserved IP matches the instance and all
selected services are verified active. The IAM serial-key marker uses the
original project fingerprint, even if an unrelated device or local auth-profile
alias changes. That does not rotate keys or recreate resources. Changing selected
membership, listeners, routes, sizing or placement requires an explicit transition.

Cloud recovery retains the generic durable journal and original operation IDs.
With no cloud journal, explicit guest recovery accepts only the observed WG
receipt or a separate complete-absence proof for empty leftover metadata. It
does not remove a healthy service or enroll peers. Ordinary deploy does not repair
an interrupted guest transaction. Status accepts no mutation options and reports
service health separately from client connectivity. The authorized boot callback
recreates the private volatile coordination file after reboot; status remains
read-only. If reboot interrupted installation/removal before a service can restore
that file, status may read without creating it and discards the result if a
mutator creates any lock path during observation. Recovery still locks exclusively
and rechecks its exact current proof. All mutating service callbacks establish
the coordination file before effects. Whole-project destroy uses the frozen nonsecret cloud snapshot even
when private client or SSH keys have been lost. Local artifacts are retained;
old trust or client exports block another deployment after cleanup.

## Owned peer runtime transaction

The private `_wireguard_peer.py` implements a guest transaction for one explicit
enrollment or revocation. Its controller packer emits a stdlib-only driver and a
checksum-bound maintenance helper. Standalone loading accepts only the exact
private root-owned regular helper file with no links or symbolic ancestry;
the approved bytes are verified before execution. The helper is transient: the
original installed program, tools binary, license, unit, owner, nonce and cached
kernel/build evidence stay unchanged. Device private keys never reach the guest.

Before activation, verify the exact previous canonical receipt, complete active
runtime and one-device delta. Changing another peer's key/address, server key,
listener, subnet, route policy or runtime pin is an error. Stage a complete private
candidate and a schema-2 nonsecret metadata journal in the existing transaction namespace.
Probe atomic directory-exchange support on that same filesystem before live
changes. No peer action downloads tools, generates credentials, upgrades a kernel,
changes cloud ingress, recreates an interface or restarts a service.

Use upstream [`wg syncconf`](https://raw.githubusercontent.com/WireGuard/wireguard-tools/v1.0.20260223/src/man/wg.8)
to change only differences while preserving unchanged sessions. Enrollment changes
the kernel peer before admitting its address through nftables; revocation denies
that source before removing its kernel peer. Replace only the proved owned table
with one delete-and-create nft batch; never flush the host ruleset. Accept only
the recorded old/new prefixes in that order. Unexplained combinations or unrelated
interface, kernel or firewall drift stop before the next mutation. Endpoint roaming,
handshake times and traffic counters remain outside managed configuration.

Publish the complete candidate through Linux
[`RENAME_EXCHANGE`](https://man7.org/linux/man-pages/man2/renameat2.2.html), so boot
never sees missing or mixed configuration files. The complete active root receipt
decides whether commit occurred: recovery restores only the selected old peer/
policy prefix before publication, and preserves a healthy desired root afterward,
including a failed post-publication fsync. Persist the commit proof and directory
boundaries before retiring backups or the journal. Partial backup deletion and an
empty final journal are recoverable without rolling back an already committed peer.
Recovery requires the current receipt, original previous receipt hash and original
observed history head. Explicitly persist both exchange-parent directories before
erasing any backup, including a resumed commit after fsync failure.

A separate nonsecret `peer-<owner>.json` records the last exact action/device,
old/new receipt/deployment digests and its previous history hash. Its canonical
digest forms a chained history head. Apply and recovery require the original
observed head; an identical completed retry must match that latest commit's parent.
Returning to identical configuration bytes after enrollment/revocation cannot
replay a stale request, including longer repeated cycles. Status reports both
current and transaction-original heads. These hashes are operation preconditions,
not client connection keys. Canonical metadata bytes, unknown files, wrong old
proofs or changed commit history fail closed. Status exposes bounded facts only.

An unapplied recovery also consumes its original history authority. Before
acknowledging cancellation or erasing recovery backups, durably publish a version 1
audit record with equal previous/current receipt hashes, the actual unchanged
deployment digest and the original history parent. Its hash fences an apply RPC
that was delayed before acquiring the exclusive guest lock: that old request can
no longer activate after recovery returned `not-applied`. Exact recovery retries
retain the same fence; a later attempt requires a newly observed history head.
A published fence is a valid rollback-cleanup prefix after a crash, including an
empty final journal. It never proves a committed enrollment or revocation.

The entrypoint requires explicit mutation consent and the shared exclusive lock;
read-only status creates no coordination file and discards an observation if a
lock appears while reading after reboot. Temporary private request staging does
not change the managed installation.

Deterministic POSIX tests simulate independent kernel/table state and interrupt
each activation/publication/cleanup boundary while using actual private files,
directory exchange and fsync calls. These model tests do not attest a live kernel
or nft policy. Separate isolated Linux CI checks real pinned-tool peer updates,
interface identity, nft echo/live equivalence, rejected-batch atomicity and
unrelated-table preservation. No desktop network or production guest is exercised.

## Peer SSH boundary

`SshGuestProvisioner.WireGuardPeerOperation()` now exposes the guest transaction
through the existing independently host-pinned SSH channel. It accepts a retained
private server bundle, one named enrollment/revocation, and `status`, `apply` or
`recover`. Mutation requires exact scope confirmation, explicit consent, current
receipt and original chained history; recovery also requires the original receipt.
Status rejects mutation options. Validate these before SSH, bind the exact server
role/name and descriptor owner to the full stack identity, and verify its retained
configuration/program hashes. Service maintenance uses the same strengthened
owner check. No suffix-only bundle can authorize a different stack's guest root.

Only the driver/helper and server configuration/descriptor travel through private
SSH stdin; the descriptor keeps the original installed-program pin. The root
receiver independently validates the exact four-file envelope, target and consent
before private temporary staging, then invokes a bounded argument vector. It
forwards no raw stderr. The controller rejects duplicate fields, extra output,
wrong targets/descriptor hashes, inconsistent history facts or arbitrary results.
Mutation acknowledgments distinguish `committed` and recovery `not-applied`;
they do not replace a following healthy-service observation. Portable tests use
in-memory runner/staging boundaries and execute no SSH or guest program.

A bounded read-only `history-status` observes the owner-bound audit even when
the installed root/unit are absent. It validates managed ancestry and audit
ownership without creating a directory or coordination file. Ordinary deployment
requires this history proof before any installer: removing the service cannot
hide retained revocation history or permit old controller files to reactivate keys.
An absent installed root with retained audit is refused by the guest install guard
even when the caller supplies that audit's current digest. Recreating such a root
requires an explicit protocol recovery contract, not ordinary installation.

Installation also carries the exact expected history through private stdin.
The packed driver rechecks it under the same exclusive guest lock as installation,
closing the gap between the observation RPC and mutation. Verify the retained
`original.py` bytes against the original descriptor pin before loading the approved
installer as a module and calling its unchanged installation/check functions.
This avoids nesting its CLI lock and preserves the original installed program,
runtime and startup callbacks. A read-only check verifies that same history before
the receiver continues to another transport; the WG guard always runs first even
if the input batch listed another protocol first.
Transient input copies use exclusive private files in the request stage itself;
they require no existing managed root and make no cross-filesystem rename assumption.

This low-level API does not persist controller intent or issue fresh device keys.
The project workflow below supplies its durable journal and retains complete
old/new bundles and original proofs.

## Private controller revision store

The private `_vpn_revisions.py` provides persistence for the project peer
controller and effective lifecycle resolution. Each attempt
first writes an owner-bound metadata journal, then an immutable private bundle of
new material/configuration and the retained installer, then the bundle's exact
digest before remote activation. Reuse complete staging after an interrupted digest
publication; never regenerate partially retained credentials. Before each rename,
fsync the exact private temporary inode, including reuse after an earlier file-sync
failure. An incomplete private
stage fails closed for inspection before any remote operation.

After a verified active guest result, persist a separate immutable nonsecret commit
record before advancing an atomic private head pointer and retiring the journal.
Bind each record to its exact parent, creation baseline, old/new transport pins and
guest receipt/history. A recovered unapplied attempt retains its prepared bytes
for audit and advances the guest cancellation history while keeping its active
receipt, keys and configuration unchanged. New completion records use schema
version 2: a submitted unapplied attempt must prove that exact guest fence. An
unstaged attempt that could never submit an apply RPC advances only local evidence
and retains the guest history. Historical version 1 records remain readable with
their original immutable semantics. Publication retries reconcile exact existing
record/pointer bytes.
An interrupted version 1 committed completion can retire its remaining journal
without rewriting that immutable record. A submitted version 1 unapplied completion
whose head was already published but whose journal remains is ambiguous: reject
that upgrade state before any provider/guest operation and retain it for explicit
inspection. Its old unfenced evidence is never silently reinterpreted as version 2.
Already retired version 1 cancellations are not retroactively protected against
delayed legacy requests; only a subsequent verified commit or cancellation
advances their guest authority.
Unknown, missing, linked or mismatched ownership metadata is never adopted.

The loader checks the complete bounded chain (at most 4096 records), independently
of private client key availability. Validate completion digest types/formats before
any publication and preflight the same capacity bound before staging or advancing
a new head; exact completed retries remain possible at capacity.
Only reading active material/server bytes
requires their complete pinned request manifest. This lets whole-cloud
cleanup retain its original nonsecret ownership proof even if client keys are lost.
Original creation resources/bootstrap and unrelated protocol bundles stay unchanged.
A persistent private advisory lock covers complete cooperating project workflows;
read-only absence fallback creates no file and discards a raced observation.
Selected prepare/deploy/status/recovery and peer operations share this lock;
whole-stack destroy validates nonsecret revisions and retains private artifacts.
Unsupported selected runtime/export commands still refuse before mutation.
Tests use synthetic projects and actual POSIX private
files/locks, with no cloud, SSH or desktop network operation.

## Project peer workflow

`PrepareWireGuardPeerEnrollment()` and `PrepareWireGuardPeerRevocation()` now
prepare deterministic in-memory profile/material changes for one named peer.
Enrollment requires the caller's already retained new device credentials and
explicit unused address; these functions never generate keys. The server key,
all unrelated peer credentials/addresses and their rendered client bytes remain
unchanged. Invalid identities, address/key reuse, an over-capacity enrollment or
revocation of the final peer are refused. The original private material remains
available for audit. Removing the final peer requires protocol deactivation.
These preparation APIs do not contact the guest, disconnect a peer, persist a
revision or update project state. `RunVpnPeer()` now composes them with retained
controller revisions and the owned SSH transaction.

For a deployed schema-2 WireGuard project, edit `project.toml` to describe exactly
one named enrollment/revocation. Declare a new device and explicit unused tunnel
address for enrollment; keep every old peer/address and other protocol unchanged.
Revocation removes only that protocol membership/address, retaining shared device
declarations needed by other protocols. Removing the final peer requires protocol
deactivation. Read-only plan validates this delta before external access, observes
the complete original cloud graph, effective ingress/attachments, existing IAM host
pin and active guest receipt/history, then reports `baseline_sha256` and
`plan_expires_at`. No key is generated during plan.

```console
flayer vpn peer plan --project PROJECT --protocol wireguard --device phone --change enroll --format json
flayer vpn peer enroll --project PROJECT --protocol wireguard --device phone --allow-mutation --scope-confirm FOLDER_ID --expected-baseline-sha256 BASELINE --plan-expires-at EXPIRES_AT
flayer vpn peer status --project PROJECT --protocol wireguard --device phone --change enroll --format json
flayer vpn peer recover --project PROJECT --protocol wireguard --device phone --change enroll --allow-mutation --scope-confirm FOLDER_ID --expected-baseline-sha256 JOURNAL_BASELINE
```

Replace the uppercase placeholders with the project, exact scope and reported
proofs. Apply must echo the plan within 600 seconds. Generate and retain only one
new device key/PSK after matching consent and baseline, persist the journal/request,
then re-observe cloud/trust and guest proofs immediately before remote apply.
Preserve the original installed-program bytes/pin. Verify a healthy desired guest
result and its computed chained history before advancing the local head.
An identical latest completed retry verifies health without key generation or
guest mutation, even when its original plan has expired.

An unknown SSH outcome leaves the journal intact. Peer status reports a separate
journal baseline and nonzero exit status while recovery is required. Explicit
recovery echoes that baseline, target, scope and consent; it uses retained original
proofs and files without key generation, finalizing a published root or rolling
back only an uncommitted prefix. A complete rolled-back candidate is reused on
the next identical fresh plan. Missing pre-activation staging can be archived as
unapplied; incomplete private bytes require inspection and are never replaced.
Recovery also recomputes the original plan binding using current cloud locators,
endpoint and IAM host pin plus the stored original head/receipt/history and expiry.
A valid same-owner replacement graph or changed host pin cannot receive recovery
writes under the old plan. Expiry itself does not prevent explicit recovery.
Ordinary prepare/deploy/status/recover refuse a pending peer journal. Full-project
destroy remains a separately consented whole-cloud cleanup and never needs client
or administration private keys.

After commit, ordinary lifecycle uses effective protocol pins and the original
six-resource creation plan/bootstrap/SSH marker. It checks peer history before
unrelated installers, so restoring old controller files cannot adopt a repeated
guest configuration. Other services, resources, addresses and existing client
files remain unchanged. Client delivery remains Task #129; peer completion alone
does not export native profiles or establish Internet/media acceptance.

## Remaining integration

Adding/removing a protocol on an existing guest, schema-1 migration, explicit
cloud/guest ingress overlays remain Task
#128. Schema-2 Xray runtime maintenance and the separate device-export command
still refuse before provider/output mutation. Existing schema-1 AWG/VLESS
loading, bootstrap bytes, resource labels and fingerprint algorithms are unchanged.

Native AmneziaVPN `.vpn` and QR exports remain Task #129. Runtime pins record the
chosen upstream tools revision and verified source archive SHA256. No new protocol is advertised
as deployed or available through the existing export CLI by these APIs alone.

Deterministic tests cover actual Curve25519 public derivation, private-material
round trips, per-device secret boundaries, exact full/split client settings,
malformed/private input refusal and independence from unrelated devices/listeners.
POSIX filesystem tests use a synthetic kernel/service model for crash, rollback,
foreign state and cleanup cases. Linux CI additionally builds the real pinned
tool and checks kernel `wg` output and nft JSON in an ephemeral network namespace;
it does not alter desktop or production networking. Installed phone/desktop traffic
acceptance remains a separate gate. A rendered configuration establishes no
connectivity or media playback result and performs no cloud, guest or local network operation.
