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

These are memory-only APIs. Credential bytes require a verified private owned
store before persistence or transfer; do not put them in logs or cloud metadata.
The stable service name derives from complete stack identity and does not change
when peer membership changes.

## Remaining integration

Project schema 2, selection through the public project CLI, owned kernel service
provisioning, cloud/guest ingress transitions, receipts, enrollment/revocation,
recovery and cleanup remain integration work in Task #128. Existing schema-1
AWG/VLESS loading and fingerprint algorithms are unchanged by this foundation.

Native AmneziaVPN `.vpn` and QR exports remain Task #129. Runtime pins in the
module record the chosen upstream tools revision and verified source archive
SHA256; they do not install or execute that runtime. No new protocol is advertised
as deployed or available through the existing export CLI by these APIs alone.

Deterministic tests cover actual Curve25519 public derivation, private-material
round trips, per-device secret boundaries, exact full/split client settings,
malformed/private input refusal and independence from unrelated devices/listeners.
Kernel/runtime conformance and installed phone/desktop traffic acceptance remain
separate gates. A rendered configuration establishes no connectivity or media
playback result and performs no cloud, guest or local network operation.
