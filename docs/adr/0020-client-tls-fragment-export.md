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
clients. Vision's default client flow intercepts UDP 443; application fallback
and QUIC media transport can behave differently even when HTTPS checks pass.
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

## Intermediate playback checkpoint

Task: [#114](https://github.com/Fuzzy-Technologies/F-Layer/issues/114).
On 2026-11-03, an operator-reported Android browser check found that ordinary
YouTube videos played after selecting a derived client with the following policy:

- Reality over TCP with the `xtls-rprx-vision` client flow; UDP 443 remains intercepted.
- The `tls-fragment` Freedom chain uses `packets = tlshello`, `length = 100-200`,
  and `interval = 10-20`.
- IPv4-only client routing and DNS through `1.1.1.1`, with `queryStrategy = UseIPv4`.
- Existing credentials, endpoint, Reality parameters, routes and client log policy retained.
- The existing server continued using Vision, IPv4 DNS and Freedom egress,
  with access and error logging disabled; no server change accompanied the test.

Shorts still failed. The preceding QUIC-enabled client had intermittently played
ordinary videos before losing playback, so this observation does not establish
QUIC as the sole cause or demonstrate sustained reliability. It provides a
reproducible client policy for the next acceptance checks, not Windows acceptance
or a completed YouTube fix. The ADR remains proposed.

Reproduce the client policy from an original prepared Vision bundle using
`flayer vpn export --tls-fragment --qr`, with the project's declared device and
a separate private output directory. Do not add `--allow-quic` for this baseline.
Keep previously exported profiles for comparison. Native-envelope and QR tests
pin the TCP fallback and fragmentation parameters using synthetic credentials;
they cannot establish live playback.

## Consequences

Clients must support Xray Freedom fragmentation and import the complete native
profile or client JSON. Fragmentation is an optional network compatibility
setting and cannot fix unavailable destinations on the server's outbound path.

## References

- [Project X Freedom fragmentation](https://xtls.github.io/en/config/outbounds/freedom.html)
- [Project X Vision UDP 443 client flow](https://xtls.github.io/en/config/outbounds/vless.html)
- [ADR 0019](0019-private-vpn-project-workflow.md)
