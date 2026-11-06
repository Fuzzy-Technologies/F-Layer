# ADR 0020: Opt-in VLESS client transport exports

- Status: Proposed
- Date: 2026-11-06
- Task: [#114](https://github.com/Fuzzy-Technologies/F-Layer/issues/114)

## Context

An installed VPN service does not prove that a particular client network passes
its handshake or application traffic. Existing private projects must support
explicit client transport choices while retaining credentials, server identity,
prepared manifests and ordinary export behavior.

## Decision

Extend offline `flayer vpn export` with independent `--tls-fragment` and
`--allow-quic` options for VLESS Reality TCP Vision clients. Python callers use
`tlsFragment` and `allowQuic`; both default to false. Existing CLI flags, file
formats, device identities and byte-preserving default exports remain compatible.

Verify all original device files against their ownership manifest before deriving
any output. Require exactly one VLESS outbound, endpoint and user. Reject
unsupported transports/flows, duplicate outbound tags and existing selected
`proxySettings` or `sockopt.dialerProxy` chains. Keep parser diagnostics private.

TLS fragmentation adds a reserved `tls-fragment` Freedom outbound and points
only the VLESS transport's `sockopt.dialerProxy` at it. Use `packets = tlshello`,
`length = 100-200` and `interval = 10-20`. Preserve existing socket options and
other outbound, authentication, Reality, DNS and route policy. Refuse a helper-tag
collision rather than replacing another outbound.

QUIC selection changes only the selected client's Vision flow to
`xtls-rprx-vision-udp443`. The suffix permits UDP 443 at the client; it is removed
before the Vision request reaches the server. The server's existing flow and
credentials remain valid. Compose this choice with fragmentation without changing
ordinary Vision's UDP 443 interception by default.

Derived exports contain the exact client JSON and a complete native AmneziaVPN
`.vpn`, plus numbered native QR frames when requested. Omit the plain VLESS URI
for either option, so every supported import preserves the complete derived policy.
Require separate output when selected bytes or files differ; never overwrite or
prune an existing export. No cloud call, guest operation, source write, key
generation or device-connectivity claim is introduced.

## Compatibility and validation

Retain the Freedom fragmentation form used by supported existing clients.
Xray 26.10.31 still implements it but marks it deprecated in favor of FinalMask.
Migrating existing clients to another representation is outside this export change.
Pinned Xray 26.9.30 and 26.10.31 parser tests cover default, independent and combined
options. Native envelopes carry the exact derived JSON; scanner frames reconstruct
the same Qt-compressed bytes.

Deterministic tests cover malformed/ambiguous inputs, proxy-chain refusal, flag
validation, full/split routes, source immutability, private permissions, repeated
exports, output conflicts, native round trips and public CLI wiring. Tests use
synthetic identities; real-device acceptance is recorded separately.

## Consequences

Operators can select a transport policy while keeping existing project/server
ownership and credentials. Clients must support the chosen Xray features and
import the complete profile. Fragmentation affects the client-to-VPN handshake;
server-to-destination reachability remains a separate concern. Neither option
guarantees application or media availability.

## References

- [Pinned Freedom configuration](https://github.com/XTLS/Xray-core/blob/v26.10.31/infra/conf/freedom.go)
- [Pinned Freedom fragmentation implementation](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/freedom/freedom.go)
- [Pinned Vision client flow handling](https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/vless/outbound/outbound.go)
- [ADR 0019](0019-private-vpn-project-workflow.md)
