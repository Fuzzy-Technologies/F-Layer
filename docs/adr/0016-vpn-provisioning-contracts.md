# ADR 0016: Transport-neutral VPN provisioning and private artifacts

- Status: Proposed
- Date: 2026-10-09
- Related: [Task #56](https://github.com/Fuzzy-Technologies/F-Layer/issues/56), [Feature #55](https://github.com/Fuzzy-Technologies/F-Layer/issues/55)

## Context

The SSH gateway in ADR 0007 forwards selected TCP connections. A VPN deployment
also needs device credentials, routing intent, server installation, client
configuration, and credential revocation. Those concerns must remain separate
from generic cloud resource creation and persisted provider identifiers.

AmneziaWG and VLESS Reality need the same ownership and artifact boundaries but
have different traffic models. An IP tunnel can carry operating-system traffic;
a local application proxy carries only traffic explicitly sent to that proxy.
Exporting a client file does not prove that a server is deployed, that a client
has imported it, or that packets can cross the tunnel.

## Decision

Add `flayer.profiles.vpn` as a public, transport-neutral profile contract. Its
schema contains a `StackIdentity`, declared devices, IPv4 routes, DNS addresses,
and named TCP/UDP listeners. It neither imports concrete transport implementations
nor calls a cloud provider. Existing configuration, lifecycle, state, artifact,
and diagnostics interfaces remain compatible.

`ParseVpnProfile()` accepts only these public fields. Unknown fields, including
inline credentials, fail with value-free errors. `LoadVpnProfile()` reads at
most 64 KiB of explicit TOML and does not resolve environment variables, credentials,
DNS names, or provider accounts. Dataclasses validate direct construction as
strictly as decoded input.

| Contract               | Meaning                                                         |
| ---------------------- | --------------------------------------------------------------- |
| `VpnDevice`            | Stable device name and optional private IPv4 tunnel address.    |
| `VpnRoutes`            | Full or split IPv4 routes, explicit DNS, and IPv6 prerequisite. |
| `VpnEndpoint`          | IPv4 address or lowercase DNS name plus an explicit port.       |
| `VpnListener`          | One named transport, TCP/UDP port, and source CIDR allowlist.   |
| `VpnCapabilities`      | Supported route modes and IP-tunnel/application-proxy scope.    |
| `VpnProfile`           | Public intent bound to one exact project, stack, scope, owner.  |
| `PreparedVpnTransport` | Private server/client artifacts with exact ownership checks.    |

A profile allows at most 16 devices and eight transport listeners. Device names,
assigned tunnel addresses, transport names, and protocol/port pairs must be
unique. Each IP tunnel device needs an explicit RFC1918 IPv4 address by preparation
time. A concrete adapter owns tunnel subnet membership, server-address collision
checks, public-key formats, UUIDs, and other protocol-specific settings.

### Routing and address-family semantics

`full` requires exactly `0.0.0.0/0`; `split` requires canonical non-overlapping
CIDRs which do not collectively cover the complete IPv4 address space. DNS
addresses must be IPv4 unicast destinations included in the declared routes.
No implicit direct DNS fallback is part of this contract.

Route scope and traffic scope are distinct. For `network_mode="ip-tunnel"`, full
routing describes the IPv4 traffic assigned to the tunnel. For
`network_mode="application-proxy"`, full routing means all IPv4 destinations for
applications using that proxy. It does not configure the operating system's
route table or capture other applications. Adapters, descriptors, CLI output,
and guides must preserve this distinction.

The initial schema supports only IPv4. It rejects IPv6 destinations and any
capability claiming IPv6 reachability. `ipv6_policy="disabled"` records an explicit
client prerequisite: the operator must disable client IPv6 or use a separately
verified client policy that prevents bypass. This value is not evidence that
F-Layer changed a host setting, installed a kill switch, or proved leak protection.
The schema intentionally rejects a claimed `block` policy because generic
contracts cannot establish operating-system enforcement. DNS endpoint names
still need concrete adapter-side IPv4 resolution and reachability checks.

### Secrets and lifecycle composition

Private keys and client credentials belong to concrete transport material
objects and generated `Artifact` payloads. They never become profile fields,
generic `ResourceState`, CLI diagnostics, or exception text. Concrete secret
objects hide material in `repr`; callers must not serialize them with generic
object serializers or log their contents. Python memory is not a secure enclave.

`BuildVpnServerBundle()` and `BuildVpnDeviceBundle()` require every opaque
transport payload to be marked sensitive. Server bundles use
`{stack}-{transport}` and device bundles use `{device_id}-{transport}`. These
names prevent two protocols from colliding for the same stack or device. The
existing owned artifact store supplies private POSIX permissions, exclusive
creation, complete manifests, content digests, and verified local cleanup.

`PreparedVpnTransport` requires exactly one sensitive server bundle and one
sensitive bundle for every declared device. All bundles must have the exact
profile ownership and transport names. No readiness or successful authentication
status is created merely by preparing them.

Cloud initialization remains nonsecret as required by ADR 0007. A lifecycle plan
may create the network, reserved address, disk, instance, and public bootstrap.
A separate guest provisioner transfers the sensitive server bundle over an
explicitly authenticated channel after checking host trust and ownership. It
must not embed those private files in provider metadata or cloud-init. A cloud
instance reported as running is not evidence of a working VPN service.

Diagnostics must report separate observations for provider resources, guest
installation, service state, client export, and end-to-end reachability. This
contract does not create successful health evidence for unexecuted checks.

### Replacement, revocation, and cleanup

`VpnProfile.Fingerprint()` hashes public intent. A prepared transport fingerprint
also includes concrete capabilities and exact file digests; it exposes no file
content. `ValidateVpnReplacement()` requires the caller's expected previous
fingerprint and preserves the complete stack identity and transport name.
It accepts explicitly changed device membership or settings after validating
both complete prepared sets. This is a pure precondition check, not a write,
remote revocation, or permission to overwrite an existing artifact directory.

The guest provisioner must verify the expected current deployment before
changing remote credentials. Removing a device requires updating the server
configuration and validating the resulting service state. Deleting a local
client file or omitting it from a new bundle does not revoke access remotely.
The old client material remains sensitive until server-side revocation succeeds.
A failed or interrupted guest update must retain enough nonsecret evidence for
explicit recovery and must not report completion.

Local bundle replacement continues to use the existing exclusive publication
and cleanup rules. Unknown files, changed bytes, foreign owners, and incomplete
manifests prevent automatic removal. Explicitly approved old artifacts are
removed only after verifying their complete stored manifest; fresh artifacts
are then published under the expected ownership. These are separate filesystem
operations, not an atomic multi-bundle or guest transaction. A crash may require
operator recovery. Cloud destruction remains the lifecycle's separately
controlled operation and never follows from local artifact cleanup.

## Validation

Targeted deterministic tests exercise full/split routes, DNS reachability,
unsupported IPv6, invalid types, duplicate device/listener identities, private
payload requirements, two-transport artifact namespaces, complete bundle sets,
expected-old replacement checks, and existing artifact-store cleanup refusal
for foreign or modified files. They also verify that generic infrastructure
state refuses transport credentials and that invalid input is not echoed.

These tests create only temporary local fixture files. They do not prove real
cloud deployment, guest installation, protocol interoperability, client import,
revocation on a running guest, or end-to-end connectivity. Those checks belong
to the concrete implementations and explicitly authorized deployment acceptance.

## Consequences

Two concrete transports can share public intent and safe local artifact storage
without introducing transport-specific resource kinds or extending generic state
with private material. New implementations must declare their real traffic scope
and cannot silently widen routes or promise unavailable IPv6 support.

The first contract requires explicit client IPv6 precautions and has no generic
kill-switch implementation. Artifact storage remains POSIX-only until a separate
Windows ACL-aware implementation exists. Concrete adapters must still implement
and test their own credential issuance, configuration validation, installation,
service checks, rollback, and revocation behavior.

## Alternatives

Embedding private credentials in cloud-init would contradict the existing
metadata boundary. Storing credentials in generic provider state would widen
read access and couple resource cleanup to transport secrets. Treating application
proxy output as an OS-wide VPN would misrepresent what the client actually does.
Reusing device-only bundle names would collide when both protocols are enabled.

## Compatibility

This adds a version-one VPN schema and new module. It does not alter the existing
SSH gateway profile, static-site profile, provider parameters, persisted resource
state, or artifact store format. Existing public imports remain unchanged.
