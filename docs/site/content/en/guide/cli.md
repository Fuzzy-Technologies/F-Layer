# CLI and diagnostic results

The module CLI is available in the foundation package. All help commands are
offline. `check` is local; HTTP diagnostics require an explicit endpoint.

```bash
python -m flayer --help
python -m flayer check --format json
python -m flayer status --format text
python -m flayer health --help
python -m flayer benchmark --help
```

| Command     | Observation                                           | Network                     |
| ----------- | ----------------------------------------------------- | --------------------------- |
| `check`     | Local Python and package availability.                | None.                       |
| `status`    | Local checks plus provider observation support.       | None in the foundation CLI. |
| `health`    | One explicit HTTP(S) endpoint response.               | Only the supplied endpoint. |
| `benchmark` | Bounded HTTP(S) samples and measured transfer timing. | Only the supplied endpoint. |

The top-level `status` reports `unsupported` for provider state until an
observation adapter is wired into that command. It does not report an empty
cloud as healthy. Lifecycle `status` is a separate, scoped command introduced
by task #20; see [first deployment](first-deployment.md).

## Explicit endpoint probes

Choose an endpoint you are authorized to access. These documentation examples
use reserved `example.com`; replace it with your intended HTTP(S) endpoint:

```bash
python -m flayer health --endpoint https://example.com/ --timeout 3 --format json
python -m flayer benchmark --endpoint https://example.com/ --timeout 3 --count 3 --bytes 65536 --format json
```

Credentials, query strings and fragments are rejected in endpoint URLs. TLS
certificate verification remains enabled; redirects and proxy discovery are
disabled. Endpoint/body/raw exception material is omitted from reports.
Timeouts are bounded at 30 seconds per sample, counts at 10, and bytes at
1 MiB per sample. The overall work remains finite, including DNS/TLS/read
failures. Results describe this probe from this machine, not a provider SLA,
VPN throughput guarantee, or a successful deployment.

## Exit status

| Exit code | Meaning                               | Operator action                                   |
| --------- | ------------------------------------- | ------------------------------------------------- |
| `0`       | Every requested check is `ok`.        | Use the recorded observations.                    |
| `1`       | At least one check warns or fails.    | Inspect structured check results.                 |
| `2`       | Invalid command input or limits.      | Correct arguments before retrying.                |
| `3`       | Observation is stale.                 | Obtain fresh evidence.                            |
| `4`       | Requested observation is unsupported. | Supply an endpoint or use an implemented adapter. |

JSON reports include `schema_version`, `command`, aggregate `status`, and
individual `checks`. Aggregate severity never hides a failed observation.
For automation, check the process exit code and parse structured statuses;
do not infer success from the presence of a JSON report.

## Export an existing VPN device

After deployment has created the device artifacts, export one declared device:

```bash
flayer vpn export --project ~/flayer-vpn --device laptop --protocol amneziawg --output ~/flayer-export-awg --qr
flayer vpn export --project ~/flayer-vpn --device laptop --protocol vless-reality --output ~/flayer-export-vless --qr --format json
```

Each output root contains `device-laptop-PROTOCOL/` with an ownership manifest,
the exact existing protocol files, `amnezia.vpn` and, with `--qr`, numbered
`amnezia-qr-01.svg` frames. Omit `--qr` for files only. AWG retains `amneziawg.conf`;
VLESS retains `client.json`, `import.txt` and its existing native connection key.
In Android AmneziaVPN, import `amnezia.vpn`, paste its connection key, or scan
**all numbered frames with AmneziaVPN's own scanner** in the same import session.
The native AWG profile carries the structured 3.1 fields as well as the original
configuration, including `HeaderProtectionKey`, padding and route settings.
Ordinary WireGuard clients cannot use these obfuscation fields.

Export is local: it makes no cloud or guest calls, generates no new credentials,
and does not check whether the server still exists. It verifies complete source
ownership and content, then writes private `0700` directories and `0600` files.
Use a new output root whose parent exists, or an existing private root. An identical
export can be repeated; changed, foreign or differently selected output is never
overwritten. Changing the QR option requires a separate output root. The source
artifact store cannot be used as output. Native AWG export supports one or two
DNS servers; more are rejected because the native connection envelope has two
DNS slots. The original source files remain intact on failure.

Profiles and QR images grant device access: keep them private. The report lists
paths, never keys or connection URLs. Export success is not connectivity evidence;
verify DNS, routes, exit IPv4 and client IPv6 behavior after import. Native schema
and scanner framing follow [AmneziaVPN 5.0.3.0 source](https://github.com/amnezia-vpn/amnezia-client/tree/de93650a90739b87bb47a632872ea9d0adc9412f).

## Optional VLESS transport exports (development candidate)

These options are available in `develop` candidates for release 2.1. They are
not included in the published 2.0.0 package. Ordinary exports retain their
existing behavior, credentials and source files.

- `--tls-fragment` fragments the client-to-VPN Reality TLS handshake through
  a dedicated Freedom outbound. The fixed policy uses `tlshello`, 100–200 byte
  fragments and 10–20 ms intervals. It affects only the VPN transport.
- `--allow-quic` selects `xtls-rprx-vision-udp443` in the exported client.
  This permits inner UDP 443 traffic. The ordinary Vision flow intercepts that
  traffic so applications can fall back to TCP. The server keeps its existing flow.

Select either option independently or combine them, with optional native QR frames:

```bash
flayer vpn export --project ~/flayer-vpn --device laptop --protocol vless-reality --output ~/flayer-export-options --tls-fragment --allow-quic --qr
```

The derived bundle contains `client.json`, `amnezia.vpn` and the selected QR
frames. Import the complete native profile or scan all its frames. It omits
`import.txt`, since a plain VLESS URI does not preserve the complete export policy.
Changing either option requires a separate output root when existing output differs.

The exporter requires one unchained VLESS Reality TCP Vision client. It refuses
ambiguous endpoints or users, duplicate outbound tags, existing proxy chains,
and a conflicting `tls-fragment` tag. These options are rejected for AWG.
Source manifests are verified before any transformation; no cloud/guest operation
or credential generation takes place.

Use a client supporting the selected Xray features. Syntax checks cover Xray
26.9.30 and 26.10.31. The Freedom fragmentation form is retained for compatibility;
upstream marks it deprecated in 26.10.31. Export success does not establish actual
device connectivity or media playback. Failures between the VPN server and a
destination need separate diagnosis. See [ADR 0020](../../../../adr/0020-client-tls-fragment-export.md)
for the contract and compatibility decision.
