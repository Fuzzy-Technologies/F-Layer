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
without rewriting that immutable record, including a record published before its
head pointer. Inspect the exact manifest-owned pending completion before remote
access. A submitted version 1 unapplied completion whose immutable record exists
but whose journal remains is ambiguous: reject that upgrade state before any
provider/guest operation and retain it for explicit inspection, whether its head
was published or not. Its old unfenced evidence is never silently reinterpreted
as version 2.
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

## Immutable protocol source references

The private `_vpn_protocol_sources.py` now names an exact source independently
from its active/disabled state. An owner-bound `ProtocolSource` contains only the
canonical protocol pin and a fixed original, peer-request or protocol-request
reference. It contains no configuration or key body. Closed source/identity/pin
models reject unsupported extensions before nonsecret serialization. Current peer
lifecycle reads use this resolver; original bundle names, manifests, installer bytes and client
files remain unchanged. A source reference alone neither commits an epoch nor
activates a service.

Protocol-request preparation copies retained material/server roles in memory and
records their original pin, operation nonce and preceding-state digest. It does
not generate credentials, render a new installer or publish files. A future epoch
controller must journal before publication or remote mutation. Full owned request
manifests, exact file sets, role names and digests are checked before reconstructing
the canonical virtual bundles. Reject foreign owners, redirected paths,
noncanonical or contradictory request metadata. Nonsecret epoch traversal and
cloud cleanup must not call this private-byte reader; missing client keys are not
permission to regenerate a projection. Epoch publication/selection remains open.

## Peer segments for protocol epochs

The private revision store can now read and publish a separate WireGuard peer
segment from an explicit `PeerSegment` context. Its genesis is the complete epoch
digest; immutable peer records still bind the permanent creation digest. Metadata
heads and journals live in the fixed private `protocol-epochs/<digest>` directory,
while original creation files and all immutable request/completion bundles keep
their existing locations. The starting projection uses retained protocol sources,
including the preceding segment's last committed peer request, without rewriting
an installer, credential or closed head.

Each segment validates its exact starting pin, guest receipt/history, parent chain
and pending journal, and returns every referenced peer artifact name. The future
epoch graph reader must verify all closed segments and compare their combined
artifact names with the global store; a single segment is not the whole graph.
Inactive WireGuard permits no peer record or pending operation. Configured sources
may be retained with an empty active subset. Metadata traversal needs no private
client payload; resolving a retained projection still requires its exact bytes.

This component does not publish a protocol epoch or authorize remote work.
Ordinary lifecycle/peer entrypoints refuse protocol heads, journals, interrupted
publication files or segment directories until the protocol coordinator is
integrated. They cannot silently fall back to the original peer head. Existing
epoch-zero projects retain their metadata bytes and behavior. Isolated POSIX tests
exercise both segments, stale copied heads, ownership/path checks and interrupted
completion publication; no desktop VPN, SSH or cloud command is executed.

## Scoped asynchronous cloud ingress SDK

The concrete `VpnYandexProvider` now supplies `BeginIngressChange()` and
`ReadIngressChange()` for the exact listener delta defined in
[ADR 0024](../adr/0024-owned-vpn-protocol-transitions.md). This is a provider
primitive, not the protocol CLI or its durable project/guest coordinator.
The caller must prove the original cloud graph, committed effective policy and
original listener attribution, and persist intent before calling Begin. It must
not call Begin again while a submitted outcome is pending or unknown.

Begin requires explicit mutation consent, exact scope and the expected complete
before-policy digest. It reads the complete group again, then submits one scoped
ID-bound `update-rules --async --print-metadata` with CLI retries disabled. Only
proved deletion IDs or one tagged addition are sent; reject comma, option-like
and oversized deletion IDs before any I/O. Return only the minimal operation ID,
resource ID and full request fingerprint. Persist that reference before polling,
even if the provider completed immediately. No post-submission read is hidden in
Begin, and a lost/malformed response never becomes `not-applied` or an automatic
resubmission.

Read accepts only the retained reference bound to that exact plan. Require the
documented `UpdateSecurityGroupMetadata` type, target group and allocated rule IDs.
Pending and terminal failure are bounded facts, not healthy policy or proof of
rollback. Successful completion requires both the typed operation response and a
fresh complete active-policy observation to match the full delta, including
unchanged unrelated rules/resource metadata and the actual allocated IDs. Raw
provider messages are discarded. A later read may retry observation; it never
repeats the mutation.

Operation JSON and direct security-group policy reads share a 1 MiB byte bound,
reject duplicate keys at every depth and reject nonstandard JSON numbers. The
strict group reader also protects ordinary selected-project observation/deletion.
The upstream [operation metadata contract](https://github.com/yandex-cloud/cloudapi/blob/master/yandex/cloud/vpc/v1/security_group_service.proto)
and [CLI operation reader](https://yandex.cloud/en/docs/cli/cli-ref/operation/cli-ref/get)
define the wire boundary. Tests use the real scoped adapter with an in-memory
runner; they invoke no CLI executable or network. Durable epoch publication,
guest reservation/fencing, rollback and protocol CLI integration remain Task #128.

## Durable ingress intent and dispatch uncertainty

The private ingress-plan codec retains the complete versioned `IngressDelta`,
including the original creation spec, scoped resource, rule IDs, descriptions and
labels, source CIDRs, listener attribution and operation nonce. Its canonical byte
hash equals the existing plan fingerprint. Decoding reruns the full delta contract
and requires exact canonical bytes; unknown fields, duplicates, nonstandard JSON,
unsupported model extensions and metadata above 1 MiB are refused. This does not
recompile a plan from current desired settings.

The project ingress journal binds that exact plan to the original creation digest,
preceding-state digest and short-lived expiry. Under the common project lock,
publish `protocol-ingress-pending.json` before the immutable owned intent bundle.
Before one separately authorized SDK submission, durably advance `prepared` to
`dispatching`. This phase means the cloud outcome is uncertain. Retain the exact
returned operation/resource/plan reference as `recorded` before polling. Neither a
timeout, expiry nor an old-looking policy permits resetting dispatch or resubmitting
the plan. Reserve space for the maximum operation reference before publishing any
intent. A late known acknowledgment may still be recorded after expiry.

Recognize only an exact interrupted forward publication from a verified temporary
file. Reconciliation finishes that same publication and consumes no new authority.
Conflicting intent, skipped/backward phases, missing immutable bytes or a different
known operation stop recovery. All original credentials and configuration bundles
remain unchanged. Retained intent without its journal, or an additional unrecorded
intent, cannot be adopted. Reusing a complete visible bundle and granting dispatch
both re-sync its verified files, manifest, bundle directory and artifact parent
through pinned handles. A failed barrier leaves dispatch ungranted; an existing
unknown publication lock is preserved. Read-only journal observation does not
perform these writes. Supported complete policy can exceed 64 KiB; only this fixed
journal path uses the explicit 1 MiB metadata bound. Peer metadata keeps its existing
bound and path contract.

These are local storage primitives, with no cloud or guest dispatch and no public
protocol command yet. The preceding-state digest does not attest a live epoch by
itself. The future coordinator must verify the epoch graph and full original cloud
attachments/policy, hold the guest reservation/fences, and satisfy the SDK consent
and expected-old checks. Copied controllers are not serialized by a local file
lock. There is no journal reset/removal API here: verified epoch completion and
scoped rollback remain integration work. Existing lifecycle/peer entrypoints refuse
this pending journal or its interrupted publication before provider operations.

## Owned host input policy planning

The private `InputPolicy` binds original SSH source networks and protocol listeners
to the frozen creation bundle and exact original `/etc/nftables.conf` bytes. It
checks protocol order against the original pins, preserving transport attribution
independently from a coincident UDP port. It neither recompiles the cloud creation
plan nor generates credentials. Closed public models reject hidden extensions,
source/port collisions, TCP 22/UDP 68 listeners and ambiguous declarations. UDP 68
is reserved for the unconditional DHCP-client exception. Every target scalar is
validated before equality/filtering, including the listener removed by disable.

`InputTransition` changes exactly one listener. Its live program replaces only the
proved existing `inet flayer_bootstrap` table in a single `nft -f` batch. SSH, DHCP,
loopback, ICMP limits, established traffic and all unrelated listener declarations
remain intact. An empty active subset keeps administration access. Its boot overlay
uses scoped `destroy table` plus the complete table, making fresh boot/reload
idempotent without `flush ruleset`. Ubuntu 24.04's documented
[`destroy` semantics](https://manpages.ubuntu.com/manpages/noble/man8/nftables.8.html#tables)
support this boundary; capability preflight remains the guest coordinator's job.
Rollback restores old listener semantics with the operation's new marker, rather
than reinstating an earlier generation token.

The native fingerprint accepts only one owned input table and dropping input
chain, strips kernel handles/metainfo, and retains every ordered rule expression.
It must be compared with the expected program compiled in an ephemeral namespace,
following the existing WireGuard guest pattern. A hash by itself does not establish
correct rules or connectivity. The
[atomic replacement contract](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement)
applies to the complete batch; adding another accepting base chain would still
encounter the [existing dropping chain](https://wiki.netfilter.org/wiki-nftables/index.php/Configuring_chains).

Pure tests preserve the original bootstrap and reject drift without creating files.
Real parser/kernel conformance runs only in explicitly isolated Linux CI namespaces:
rejected batches retain the old table, live replacement and repeated/fresh boot
agree with isolated compilation, rollback keeps a new marker, and an unrelated
table/counter remains byte-equivalent. This component executes no command. Guest
locks/reservations, receipt/history checks, durable boot-file publication and recovery
must be integrated before exposing a public protocol mutation command.

## Guest protocol reservation and peer-history fence

The stdlib-only private reservation backend accepts one closed hash-only intent
bound to the full owner, permanent creation, preceding common authority/state,
plan nonce/expiry and actual active-WG receipt or complete namespace-absence proof.
It acquires common ingress coordination before the existing WG lock. A persistent
private preparation journal precedes the history fence, and a copied controller
cannot substitute another intent through its own local project lock.
Recovered writes re-sync the owned namespace and every publication ancestor through
pinned directory handles before fencing or dispatch authority, even when all
directories were already visible after a crash. Completed operation nonces cannot
be reused with a new parent/history.

For active WG, use the existing valid v1 equal-receipt cancellation audit under the
WG lock. The running root receipt, credentials, configuration, binary, interfaces
and service stay unchanged; the chained peer history advances. Already queued peer
drivers recognize the changed history and refuse their old expected authority.
Pending peer/install transactions block reservation. Absent WG requires actual
root/unit/interface/NAT/enablement absence and retained peer history; no running
receipt or installation is fabricated to fence it.

`Reserve` durably publishes `preparing` then `reserved`, reusing its own exact
history fence after an interruption. `Expose` consumes the single external-dispatch
grant before a later write. Repeated calls and expired plans cannot issue another
grant; a complete interrupted exposed temporary record is already uncertain.
`Cancel` accepts only unexposed intent, retains any consumed WG history and publishes
one immutable cancelled completion plus a new common head before retiring pending
metadata. Exact retries reuse that completion. Bounded complete parent traversal
rejects orphan records, lost heads, unknown files and unsupported metadata; it never
infers a new initial authority from a missing mutable pointer.

Normal peer/install and current standalone WG-maintenance entrypoints check the
pending common journal under WG coordination. History observation remains available.
Existing service callbacks retain their separate already-owned boot/start/stop
contract. Frozen original server bundles are still retained; introducing current
maintenance guards does not rewrite an existing private bundle or install it on a
server implicitly.

This is a private backend with no RPC/public protocol command yet. It does not
attest cloud/input policy from a preceding-state hash alone, apply nft policy,
publish a boot file, change a service or resolve a submitted cloud outcome.
Completion after exposure and known rollback prefixes require the full coordinator.
Tests use real private POSIX fixture files and locks with modeled guest networking,
cover old queued peer refusal, copied intents, actual absence, publication/retry,
expiry/capacity, unknown exposure and retention of original runtime/key bytes.

## Reserved host input transaction

The private stdlib input backend now consumes an exact exposed reservation. Its
composite public plan binds a cloud-plan digest and one complete host input delta
to the reservation hash; a hash of preceding state alone is not live attestation.
The controller facade and guest share the same closed policy renderer and native
normalizer. Compile expected tables in disposable guest network namespaces and
compare their complete expressions with the running owned table before writing.

Persist the exact public recovery request before replacing the boot file, then
atomically replace only `inet flayer_bootstrap`. Preserve SSH, all unrelated
listeners/tables and WG runtime/key bytes. Only the documented boot-first prefixes
are accepted, including a reboot or complete interrupted temporary publication.
Re-sync an already-visible target boot file and its parent before proceeding.
The native writer inherits both coordination descriptors so it cannot outlive
its SSH parent and race recovery after losing the protecting locks.

Rollback restores the preceding listener semantics with the new operation marker;
it never restores the old guest history. Complete/partial foreign files and native
drift refuse recovery. Repeated terminal calls verify their exact result; a rolled
back operation cannot be applied again. Read-only status performs no persistent
repair. Its intermediate phases do not claim a terminal boot/native fingerprint.

This is an input backend, with no public protocol CLI or SSH RPC yet. It neither
changes cloud rules nor orders transport service activation/removal. The exposed
reservation remains pending until the full protocol coordinator records all cloud,
service and input receipts in an epoch; no input result alone retires it. Tests
use simulated networking plus real nftables/stdlib backends exclusively inside
the isolated Linux CI namespace. No desktop or deployed server is changed.

## Nonsecret retained source traversal

Source metadata traversal now verifies the complete manifest owner, file roles,
sizes, sensitivity and full externally pinned bundle digest without opening any
private payload. Original, peer and protocol sources retain the same canonical
material/server role digests even after private files are lost. Required public
intent/request files still need their exact payload hashes and closed decoders;
an owned manifest alone cannot override contradictory request metadata.

The reader pins directory/manifest/public-file identity and rejects unknown
members, unsafe links/permissions, changed membership and detectable snapshot
drift. Missing declared private files are distinct from foreign entries. A declared
private hash is a retained reference, never proof that an unopened payload is
present or healthy. Full private use/export and artifact deletion retain their
existing complete-content checks; this traversal grants neither authority.

This supplies nonsecret references for the upcoming epoch graph and whole-cloud
cleanup after client-key loss. It does not activate protocol transitions or bypass
complete cloud ownership/pending-operation checks. No epoch head is inferred from
orphan artifacts, and ordinary entrypoints still refuse unintegrated epoch metadata.

## Committed protocol graph reader

The private committed graph reader now verifies immutable epoch bundles, exact
closure of every preceding WG peer segment, retained source-role pins and complete
cloud/input/service evidence references. It rejects missing parents/segments,
orphan peer/protocol/ingress artifacts, pending journals, stale authority and
operation/byte limits. The final epoch bundle digest starts the next separate peer
segment; every old segment and creation spec stays unchanged.

Cloud evidence distinguishes known terminal changes, never-dispatched cancellation
and completed exact inverse operations. Restored provider IDs/descriptions remain
the actual readback, with original and compensating intent artifacts retained.
Input receipts bind applied, unchanged or restored policy bytes. Service references
are closed and source-bound; their hashes alone do not attest a live service.
The authorizing intent binds all evidence hashes, then the exact guest completion
enters the final bundle, avoiding a circular digest. See ADR 0024 for publication
ordering and the schema-1 unexposed cancellation boundary.

Configured sources remain nonempty while the active subset may become empty.
History checks use deployment hashes from retained public manifests, retaining the
old-driver-compatible fence without opening private bodies. All metadata traversal
continues after client/private source-file loss; ordinary use still needs complete
private content. Capacity helpers must run before consuming guest/cloud authority.

Epoch intent schema 2 additionally binds the full generation-record3, exact native
terminal-journal digest and reconstructed generation-bearing composite plan.
The generation source digest selects the exact configured WG source; graph traversal
checks all three source-file pins against retained public server metadata. A disable
restoration records both the original-root fence and the fresh installed-root fence
in order, retaining keys and addresses under the replacement receipt. An attempted
enable rolled back to absence still records its fresh generation fence. Unstarted
not-applied intent claims no native mutation or replacement receipt. Native rollback
requires restored input; genuine unfenced schema-1 cancellations remain distinct.
Schema-1 intent loading is unchanged, and these checks need no private source bodies.
Native epochs also preserve each unrelated protocol's preceding complete service
receipt or absence proof; unchanged source selection alone cannot replace that proof.

This reader has no publication workflow, guest schema-2 finalizer or public
protocol CLI yet. Existing ordinary entrypoints still reject epoch metadata until
the coordinator, transport-generation handling, authenticated live attestation and
recovery are integrated. The reader performs no guest, cloud or desktop operation
and never infers actual runtime health from a locally authored proof record.

## Nonce-bound WireGuard generation candidates

Explicit generation candidates retain the original installer, deployment,
server/peer credentials, verified binary and license byte-for-byte. A schema-2
root adds one separately pinned lifecycle helper and binds both systemd callbacks
to a fresh nonce. Complete file and cached executing-kernel checks precede reuse;
there is no download, rebuild or key generation. Default first-time preparation
continues producing schema 1 and its unchanged unit format/vendor gate.

The callback re-reads root metadata under the existing WG lock and rejects stale
or absent nonce, wrong executable, drift and lock contention before runtime
mutation. Its native children inherit that descriptor. Peer transactions preserve
all eight schema-2 file pins, including the helper, without admitting helper/unit
replacement. Unknown files and schema aliases remain errors.

Schema-2 unit filenames include the nonce as well as the owner prefix. Root and
peer transaction paths stay stable; legacy schema-1 filenames stay unchanged.
This keeps a delayed command for an old unit from selecting a new generation's
loaded callback. Bounded receipt-based path selection alone does not establish
health. Full checks require the exact unit path and reject other-generation or
unknown owner names and broken enablement links. Complete absence and fresh
installation also refuse those retained entries without deleting/adopting them.
Status, peer operations and reservation observations target the verified unit.

The cache preparer writes only a complete unpublished private candidate outside
managed runtime/unit paths; it neither activates it nor grants authority. Schema-2
callbacks reject pending reservations unless the exact sealed native context binds
their current generation, request/head and consumed history. Ordinary remove/recover
refuse these generations before publishing a legacy cleanup intent. The private
native backend below implements scoped generation transitions; normal epoch/public
protocol admission remains blocked pending the complete controller coordinator.
POSIX tests exercise real private files and locks with simulated networking only.

## Reserved generation cache journal

`PrepareFresh` first builds a complete private staged schema-1 baseline, then uses
the same cached-generation path to derive a staged schema-2 candidate. Explicit
consent, the three retained source-file pins, the approved current receiver/helper
pin, canonical distinct empty private directories and actual namespace/collision
checks precede the original vendor-CVE/executing-kernel/build gate. Both snapshots
stay outside managed runtime, authority and unit directories. The binary/configuration
build is shared with direct installation, which preserves its original wire format.

Source bytes and executing-kernel facts are rechecked before acknowledgment. Each
snapshot receipt is written last after exclusive complete file writes; interrupted
prefixes remain unpublished and are refused on retry. Neither preparation creates
keys, a legacy install transaction, a root/unit, reservation, history fence or live
network state. A private snapshot is not attestation or protocol mutation authority;
the coordinator must still bind it into the exact reserved generation/cache request.

The private cache backend now binds complete cached/candidate WG receipts and
source-role pins beside the cloud-plan hash and exact input delta in a schema-2
composite request. It requires the exact exposed common reservation and retained
WG fence under common then WG locks. Journal preparation before writing any private
cache bytes; never infer protocol authority from a cache or its receipt alone.

Cache paths use the full owner and complete receipt digest. Verify all private
runtime/configuration bytes and cached executing-kernel facts; retain the original
installer as data. Preserve active root, service, key/configuration bytes and
consumed peer history. No download, build, key generation, interface, input or
cloud mutation occurs. Source/candidate bodies remain private and diagnostics are
bounded hashes/phases. Cache preparation is limited to 12 MiB per retained root.

Persist each exact file inode and every cache-directory boundary, publishing its
receipt last. With its exact preparing journal and complete verified source bytes,
retry may append only a matching truncated suffix or fill recorded missing entries
after interrupted directory publication. Unknown/differing prefixes refuse. A
missing journal grants no torn-file recovery. Prepared cache drift/missing private
bodies also refuses; completed retries verify/resync the retained cache without
the original transient sources. Read-only status performs no repair and never
reports a prepared cache as an active generation.

Generation-record schema 2 binds a fresh schema-2 candidate for both enable and
disable. On disable the candidate is reserved for restoration, retaining the exact
cached configuration/keys, runtime and kernel facts under a new operation nonce and
unit identity. An uncertain old stop must never target a restored old unit name.
Schema-1 generation records remain readable for cache recovery but cannot gain
host-input authority or an unplanned candidate beneath an existing exposed hash.

The input backend accepts this versioned composite only after the exact generation
journal is prepared and both complete recovery caches verify. Common then WG locks
still protect the original actual runtime/history observation. Cache preparation
does not itself authorize input: the trusted cache backend must keep the exact file
and ancestor descriptors pinned and synchronized across boot/live changes and
recheck them before a terminal input journal is published. Missing/unfinished caches,
copied journal intent/history, changed bytes or replaced inodes refuse further writes.
Read-only input status verifies recovery readiness without repairing/resynchronizing
the cache. Legacy schema-1 input composites retain their existing private behavior.

## Sealed native WG transitions

The private native backend implements generation enable/disable and rollback while
the common reservation stays exposed. Native admission requires generation-record
schema 3 and its explicit callback ABI. Its candidate helper must match the approved
current private receiver source before any original disarm; records 1/2 stay readable
without acquiring this capability. Persist the admitted helper pin, allowing a later
approved receiver for the same ABI to recover the sealed operation without replacing
its immutable candidate. Kernel/runtime/configuration/key pins remain unchanged.
Schema-3 input opening requires the matching healthy native record even when no
runtime journal exists yet; preparation and closing keep their pre-native paths.

The original root is disarmed under common then WG locks before any WG unlock.
The parent keeps common while systemctl callbacks take only WG; native children
inherit the applicable descriptors. Reconcile the exact loaded file-backed unit,
then verify no queued job, main/control process or populated cgroup-v2 subtree
before retiring a unit or acknowledging activation. Job observation uses explicit
empty properties; no job is Job=, not Job=0. The unique retired unit can safely be
stopped again after death between intent and dispatch. Never reuse its name for
restoration. Shared forwarding and unrelated transports remain intact.

Publication/recovery retains exact caches and verifies both original and fresh
generation history. A disable rollback uses the preplanned fresh unit and a second
consumed history link, preserving all keys and addresses. Installed roots require
strict peer/address state even during interrupted removal; only staged roots admit
known partial activation. Torn candidate bytes may match only the pinned source
prefix; cleanup uses validated bounded member sets and preserves unexpected files.

Pin and resync the actual root payload, unit, link and directory inodes across final
barriers and acknowledgment. Stage/installed receipt replacement has separate pinned
scopes. Same-byte replacements are detected or explicitly resynchronized before a
later acknowledgment. Every starting retry reconciles PID1's loaded definition.
A quiescent cached parse error is recognized before reload; strict loaded identity
is required afterward, so known torn publication does not strand recovery.
After reboot, a complete terminal journal temp can be reconciled before restarting
only an exact installed candidate with complete kernel absence and a drained unit.
Read-only status reports recovery required without repairing the journal or claiming
activation. Installed partial peer/address drift is not a reboot-recovery prefix.

The trusted `Origin` observer additionally handles an original unit that stops
after exact Reserve/Expose but before first native admission, or in `ready` or
`unchanged`. Only generation-record3 gains this recovery path. Validate complete
original receipt/source/unit files, current kernel and consumed history before
recognizing full owned kernel absence plus an inactive drained unit and empty
cgroup. Partial kernel state, foreign files/units, jobs/PIDs and stale history refuse
before cache, input or runtime mutation. Quiescence is not active health or proof
that a reboot occurred; initial reservation/exposure still require their original
healthy proof. Cache/input callers select the trusted observer as a code dependency,
never a JSON option. Recovery permanently retires the old unit, restoring the fresh
planned identity on rollback with the same credentials/runtime and a new history
link. Read-only native status reports recovery required. A stopped `unchanged`
rollback cannot open input until restored; previously restored input stays unchanged.

Cloud ordering, common completion, generation-bearing epoch publication, fresh-build
orchestration and public protocol CLI admission remain integration work.
No live server/client or traffic acceptance is implied by these private primitives.

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
