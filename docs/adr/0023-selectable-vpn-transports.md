# ADR 0023: Selectable VPN transports and isolated coexistence

- Status: Proposed
- Date: 2026-11-06
- Tasks: [#127](https://github.com/Fuzzy-Technologies/F-Layer/issues/127), [#121](https://github.com/Fuzzy-Technologies/F-Layer/issues/121)

## Context and delivery status

Existing private projects provision AmneziaWG and VLESS Reality together. Adding
standard WireGuard and OpenVPN requires explicit selection, separate credentials
and networks, and safe evolution of already prepared projects. Ordinary deployment
currently refuses changed prepared intent. Preserve that refusal until a dedicated
transition workflow can prove ownership and recover interrupted changes.

This ADR defines the implementation contract for release 2.1. The new schema,
commands and protocols below are planned; merging this decision does not implement
or deploy them. Server/export implementation, automated gates, documentation and
installed-client acceptance remain separate Tasks under Features #120 and #119.

## Selection and compatibility

Keep project schema 1, its implicit AWG/VLESS pair, fingerprints, filenames,
credentials, manifests, host trust and cloud state byte-compatible. Ordinary
preparation, deployment and export must not migrate a legacy project implicitly.

Project schema 2 adds an explicit, nonempty `protocols` array. Allowed identifiers
are `amneziawg`, `vless-reality`, `wireguard` and `openvpn`. Reject unknown or
duplicate identifiers; normalize selection to this fixed order for fingerprints.
Require settings for selected protocols and reject inactive protocol tables.
Schema 2 is rejected by older packages before mutation; it is an intentional
forward-compatibility boundary, not permission to recreate the VM.

Identity, cloud placement, route policy and named devices retain their existing
meaning. `devices.ipv4_address` remains AWG-only. Each additional IP tunnel has a
`device_addresses` table mapping the exact declared device IDs to explicit private
IPv4 addresses. No device is renamed and no address is allocated by enumeration.
VLESS has no tunnel-address allocation. New protocol material never reuses an
AWG key, VLESS UUID or another protocol's certificate.

The following fragment illustrates future schema-2 fields; it is not a complete
project or a configuration accepted by the current package:

```toml
schema_version = 2
protocols = ["amneziawg", "vless-reality", "wireguard", "openvpn"]

[wireguard]
port = 51821
tunnel_cidr = "10.67.0.0/24"
mtu = 1280

[wireguard.device_addresses]
laptop = "10.67.0.2"
phone = "10.67.0.3"

[openvpn]
port = 1194
protocol = "udp"
tunnel_cidr = "10.68.0.0/24"
mtu = 1280

[openvpn.device_addresses]
laptop = "10.68.0.2"
phone = "10.68.0.3"
```

Validate all selected settings before generating material or constructing a cloud
adapter. Require unique transport/port pairs, reserve TCP 22 for administration,
and reject overlapping cloud/tunnel networks, server/network/broadcast addresses,
duplicate peer addresses and insufficient subnet capacity. Reserve the first host
address of each tunnel for its server. Validate bounded MTU values; 1280 is the
initial default. DNS and full/split IPv4 routes use the existing strict contract.
Native exports support at most two DNS servers and must reject truncation.
IPv6 remains explicitly disabled on the guest; compatible client precautions and
leak checks are mandatory acceptance evidence, not inferred from a running service.

## Ownership and transition lifecycle

Generic `state.json` remains schema 1 and stores the same six cloud-resource
locators. New owned transport descriptors and operation journals are separate
private versioned files. Bind them to the exact stack identity, original project
fingerprint, desired per-transport fingerprint, material/artifact manifest hashes
and observed guest receipt. They contain no keys, certificates or configuration
bodies. Retain schema-1 artifacts and host pins unchanged during explicit migration.

The future `flayer vpn protocol` workflow has read-only `plan`, explicit `enable`
and `disable`, and `recover` operations. Mutation requires the existing
`--allow-mutation` and exact `--scope-confirm`, plus the plan's expected baseline
digest. Bind the baseline to current owned cloud ingress, guest receipts and local
material. Re-observe before the first write; reject foreign ownership, changed
host trust, drift, expired plans, unresolved journals or an unexpected old digest.
Adding or removing a protocol is never an ordinary `deploy` side effect.

Stage and validate private material, rendered configuration and verified runtime
before activation. Journal the intended old/new hashes before each remote change.
Preserve the existing SSH ingress and all other selected protocols. Cloud ingress
updates use an ownership-checked exact old rule set and provider readback; an
uncertain API result requires recovery, not a repeated guessed mutation. Update
only the proved owned guest input chain atomically: an earlier accepting nftables
base chain does not override a later dropping base chain. Never use `flush ruleset`.

Each new protocol owns its service, interface, runtime directory, ingress entries
and interface-scoped forwarding/NAT table. Names derive from the complete stack
identity: `flayer-wg-<12hex>` / `fwg<12hex>` and
`flayer-ovpn-<12hex>` / `fov<12hex>`; interfaces stay within Linux's 15-byte limit.
Accept only declared peer sources and destinations, established return traffic,
and owned-interface masquerading. Reject tunnel-to-tunnel forwarding. Unrelated
tables, services, host routes, DNS and network adapters are outside the operation.
Do not reset global forwarding when another tunnel may still depend on it.

An identical operation verifies and reuses the installed receipt without downloads,
package installation, credential generation or service restart. Failure before
activation leaves existing services intact. Failure after a bounded change rolls
back only that change from verified private backups. A crash or ambiguous result
leaves a durable recovery-required state. Recovery reconciles exact observed old
or new state; unknown state fails closed. Deactivation removes only proved owned
service/interface/files and ingress/NAT entries; it retains private controller
material for audit and requires separate explicit erasure. It cannot delete a VM,
disk, reserved address, shared network or another protocol's resources.

## WireGuard runtime and peer material

Use Ubuntu 24.04 amd64's kernel WireGuard implementation. Upstream recommends the
kernel implementation on Linux; avoid a second Go runtime and implicit userspace
fallback. Verify guest platform, kernel capability and the supported patched-kernel
policy before installation. Record the exact running kernel/package versions;
kernel security updates and reboot authorization belong to #103, not protocol
activation. A missing or unapproved kernel fails before mutation.

Build private `wg` tools from upstream `v1.0.20260223`, commit
`49ce333da02056ae7b22ee2aeb6afe8aaed79b19`. The implementation must pin and verify
the source archive SHA256, preserve upstream notices, and record build/toolchain
and installed-binary hashes in its ownership receipt. Do not install a floating
WireGuard package or modify system `wg-quick` services. Runtime updates require
an explicit expected-receipt operation with staged validation and rollback.

Generate a distinct X25519 server key, one X25519 key pair and random preshared
key per device locally. Private directories use `0700`, regular files `0600`,
and existing path/link/manifest guards apply. Only the server private key and peer
public/preshared keys reach the guest; client private keys remain on the controller
and in that device's private export. Persist once and verify exact device/address
ownership on reuse. Standard WireGuard contains no AWG obfuscation fields.

Enrollment stages the one new peer while retaining all old keys and addresses.
Revocation atomically removes that peer from owned configuration and the running
interface; deleting an export alone is not revocation. Explicit rotation binds
the expected previous material and receipt and identifies which profiles require
reimport. Server-key rotation affects every WireGuard profile and must say so.

## OpenVPN runtime and credential lifecycle

Build upstream OpenVPN `2.7.9`, commit
`7b60c2aa34992639691e3a2d651fe27301e2e9d5`, on Ubuntu 24.04 amd64 with OpenSSL 3.
Pin and verify the release-source SHA256, preserve notices, and record compiler,
authenticated distribution build dependencies and binary hashes in the receipt.
Do not replace the system OpenVPN binary or service. Disable DCO initially so
kernel-module changes are outside this feature. Runtime maintenance follows the
same staged, expected-old, recoverable contract as WireGuard.

Support one explicitly selected UDP or TCP listener; default to UDP 1194. TCP is
an operator-selected fallback with separate matching client settings, not an
automatic second listener. Use `topology subnet`, certificate-bound static CCD
addresses, `ccd-exclusive`, and distinct server/client certificate roles. Do not
enable duplicate common names or password-only authentication.

Generate a private ECDSA P-256 CA, server key/certificate and one key/certificate
per device locally using the VPN cryptography dependency. CA basic constraints
and signing usage, leaf key usage, server/client EKUs, random positive serials,
issuer signatures and exact public/private key pairing are checked on reuse.
Stable server and device certificate names derive from stack/device identity.
The CA private key and device private keys never reach the guest. The guest gets
only the CA certificate, its server key/certificate, CRL, static control-channel
key and minimal CCD entries. Ordinary state and diagnostics contain none of them.

Use TLS 1.2 or newer, mutual certificate verification, exact expected server-name
verification, AEAD data ciphers `AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305`, and
`tls-crypt` with a locally generated 256-byte static key. Reject compression,
legacy cipher fallback, arbitrary scripts/plugins and unbounded pushed policy.
The control key is shared by this OpenVPN service; it does not replace per-device
certificate authentication. Rotating it requires reimporting all OpenVPN profiles.
Per-client `tls-crypt-v2` is a possible later extension, not an implicit promise.

CA validity is 3650 days; server and device certificates are valid for 365 days,
bounded by their issuer's expiry. Allow five minutes of not-before clock skew.
Check UTC validity on prepare, plan and status. An expired or invalid material set
fails closed and never silently regenerates. Report renewal due within 30 days.
CRLs have a 30-day next-update interval; report renewal due within seven days.
Renewal is explicit, retains identities/keys unless rotation is separately selected,
and installs only a verified replacement. CA rotation is a separate all-client
migration with explicit impact and rollback; never perform it during deployment.

Revocation records the exact device serial, publishes a CA-signed CRL and excludes
its CCD entry. Restart only the selected OpenVPN service after installing the CRL
so existing sessions are terminated as well as future handshakes refused. Explain
that this bounded operation interrupts other OpenVPN sessions; AWG, WireGuard and
VLESS must remain unchanged. An expired CRL is not accepted as healthy. Retain
revocation history across renewal and retries, with no serial reuse.

## Client artifacts and acceptance

Keep owned bundle names `device-<deviceId>-<protocol>` and safe repeated-export
behavior. A standard WireGuard bundle contains `wireguard.conf` and native
`amnezia.vpn`; OpenVPN contains self-contained `client.ovpn` and native
`amnezia.vpn`. Include only the selected device's credentials, endpoint, exact
route/DNS policy and required public CA/server identity. Never export CA signing
keys, server private keys, administration credentials or another device's material.

Use the existing `--qr` option only for complete Amnezia native scanner frames,
with the established qCompress/QDataStream framing and frame-count limit. Standard
WireGuard QR is a different importer contract and requires an explicit future
format selector; never label native frames as universally compatible. OpenVPN
QR likewise has no universal plain-profile contract. Default file-only exports
do not import the optional QR renderer.

Target AmneziaVPN 5.1.0.6 on Android and Windows for both new native profiles.
Match its pinned source schema: `amnezia-wireguard` / `wireguard` and
`amnezia-openvpn` / `openvpn`, with third-party `last_config` containing the
protocol's structured JSON and exact native `config`, not raw text in place of
the structured object. Keep device IDs, peer fields, CA/name verification,
transport, routes and DNS consistent across both representations.

Standard WireGuard clients on Android/Windows consume `.conf`; OpenVPN 2.6/2.7
community clients and OpenVPN Connect clients must be tested with the selected
AEAD/TLS profile. These are target matrices, not completed compatibility claims.
Record exact client versions and importer behavior during #132/#126 acceptance.
Configuration syntax, a round trip or an active service cannot establish DNS,
IPv6 precautions, roaming, reconnect behavior, Internet access or media playback.

Implementation gates cover schema-1 golden fingerprints/artifacts, subset
selection, collisions, isolated kernel/tool/OpenVPN conformance, native file/QR
round trips, redaction, ownership and interrupted rollback/recovery. Installed-wheel
tests use mocks or isolated resources. Any live deployment, paid resource creation,
host reboot or desktop VPN switch needs separate bounded owner authorization.
Existing phone/desktop profiles remain valid throughout unrelated protocol work.

## References

- [Existing project lifecycle, ADR 0019](0019-private-vpn-project-workflow.md)
- [WireGuard Linux implementation guidance](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/README.md)
- [Pinned WireGuard tools](https://github.com/WireGuard/wireguard-tools/tree/49ce333da02056ae7b22ee2aeb6afe8aaed79b19)
- [Pinned OpenVPN release](https://github.com/OpenVPN/openvpn/tree/7b60c2aa34992639691e3a2d651fe27301e2e9d5)
- [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html)
- [Amnezia 5.1.0.6 WireGuard model](https://github.com/amnezia-vpn/amnezia-client/blob/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02/client/core/models/protocols/wireGuardProtocolConfig.cpp)
- [Amnezia 5.1.0.6 OpenVPN model](https://github.com/amnezia-vpn/amnezia-client/blob/ac175c8a8147cfe56f98c8372ec17ea2ba00bb02/client/core/models/protocols/openVpnProtocolConfig.cpp)
