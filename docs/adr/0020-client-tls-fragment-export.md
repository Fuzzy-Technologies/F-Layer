# ADR 0020: Optional TLS fragmentation for existing Reality clients

- Status: Proposed
- Date: 2026-10-16

## Context

A running Reality service and valid credentials do not prove that a client's
network passes the authenticated TLS handshake. A client can work through a
separate encrypted transport while the same direct connection fails. Replacing
the server or rotating credentials does not address this condition.

## Decision

Add the opt-in `flayer vpn export --tls-fragment` option for VLESS Reality TCP.
Verify the complete existing device bundle before transforming its client JSON.
Chain only the VPN transport through a named Freedom outbound that fragments
TLS ClientHello records into 100–200 byte pieces with 10–20 ms intervals.
Retain device credentials, endpoints, DNS, routing, and the other outbounds.
Reject existing proxy chains instead of replacing them implicitly.

Also expose the independent opt-in `--allow-quic` option for existing Vision
clients. Vision's default client flow intercepts UDP 443; this can prevent
applications that require QUIC from loading media even when HTTPS checks pass.
Select the documented `xtls-rprx-vision-udp443` client flow without changing the
server's Vision setting. Preserve the default export behavior and all other
authentication, routing, DNS, and transport fields. Allow composition with TLS
fragmentation and reject unsupported transports or ambiguous client selections.

The native AmneziaVPN envelope contains the exact transformed JSON. Omit the
plain VLESS URI because it cannot carry the fragmentation policy. Normal
exports remain byte-preserving. Changing export options requires separate
output when the existing owned output differs. No server operation, source
write, credential generation, or implicit connectivity claim is introduced.

## Validation

Tests cover native-envelope round trips, unchanged authentication and routing,
source immutability, unsafe composition, protocol restrictions, QR selection,
repeated exports, and refusal to overwrite differently selected outputs.
QUIC tests verify exact flow-only changes, independent and combined options,
CLI exposure, input validation, and unchanged source credentials and policy.
Network acceptance remains an explicit operator action outside the test gate.

## Consequences

Clients must support Xray Freedom fragmentation and import the complete native
profile or client JSON. Fragmentation is an optional network compatibility
setting and cannot fix unavailable destinations on the server's outbound path.

## References

- [Project X Freedom fragmentation](https://xtls.github.io/en/config/outbounds/freedom.html)
- [Project X Vision UDP 443 client flow](https://xtls.github.io/en/config/outbounds/vless.html)
- [ADR 0019](0019-private-vpn-project-workflow.md)
