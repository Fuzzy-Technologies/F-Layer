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
recovery. This is a low-level implementation; the public project CLI and existing
SSH receiver do not yet select or invoke it. Do not run the program manually on
an existing production guest to bypass the pending project/ingress workflow.

The initial platform is Ubuntu 24.04 amd64 with its GA 6.8 kernel. Before building
tools or publishing managed configuration, first-install admission reads the fixed
[Ubuntu CVE-2026-98432 JSON](https://ubuntu.com/security/cves/CVE-2026-98432.json).
It requires exactly the `linux` package's `noble` entry to be `released` and the
running image package to meet that entry's fixed version. A `pending` description,
unavailable response, another kernel family or ambiguous evidence blocks activation.
At implementation time Ubuntu lists the noble fix as pending; its target version
is not proof of a released fix. The installer never upgrades/reboots the kernel or
applies a host-wide mitigation. Such maintenance requires a separate plan.

Installed receipts cache that named-CVE evidence and exact image/module hashes.
Ordinary status, repeat and boot checks compare current kernel facts against the
receipt without downloading metadata or reinstalling tools. A changed kernel
requires explicit policy maintenance. This assesses one named baseline, not all
kernel security. No status claims end-to-end traffic or media playback.

Tools are built privately from the checksum-pinned upstream
`wireguard-tools 1.0.20260223` archive. Bounded extraction rejects links and unsafe
paths, and the built executable must report the pinned version and Linux amd64
format. The private service directory retains the source license. No package
installation, system binary replacement or userspace fallback is attempted.
Build prerequisites (`make`, compiler, libc headers), `ip`, `ss`, `nft`, `unshare`,
`modinfo`, `dpkg-query`, Python and systemd must already be available on the guest.

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
must already be disabled. Cloud and guest input ingress are separate integration
work; running a service alone does not prove that its UDP listener is reachable.

A complete private journal and staged files are published together before any
service/interface activation. Installation failure removes only proved owned
objects. Removal/recovery require explicit mutation consent and the exact old
receipt SHA256. The journal retains nonsecret file hashes outside the tree being
deleted so interrupted partial cleanup can resume. Foreign or drifted state is
retained for diagnosis. A committed healthy service survives journal-finalization
failure. Replacement, peer changes and key rotation are refused by ordinary
installation; they need explicit transitions rather than implicit regeneration.

## Remaining integration

Project schema 2, selection through the public project CLI, SSH receiver integration,
cloud/guest ingress transitions and scoped enrollment/revocation remain Task #128.
Connecting the guest receipts/recovery/removal to the full project lifecycle is
also pending. Existing schema-1
AWG/VLESS loading and fingerprint algorithms are unchanged by this foundation.

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
