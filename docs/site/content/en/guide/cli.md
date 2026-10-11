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

## Investigate Shorts and Telegram media

A working handshake, ordinary video or Speedtest does not identify why another
application fails. Low service memory and no OOM records do not prove a memory
problem; collect correlated observations before changing server capacity.

1. Record Android/AmneziaVPN/YouTube/Telegram versions, network (Wi-Fi or mobile),
   DNS/private-DNS settings, VPN/TUN mode and app exclusions. Disable Telegram's
   separate proxy for the comparison, then restore its prior setting afterwards.
   Test the same Short and the same uncached media file on the same network:
   direct connection where possible, AWG only, then VLESS only. Repeat three times,
   alternating protocol order, and record UTC start, success/error and duration.
2. Compare the YouTube app with the same Short in a browser. Verify the public
   IPv4 equals the server's expected address, DNS uses the intended resolvers, and
   IPv6 cannot bypass the tunnel. Test Wi-Fi and mobile separately; change only
   one setting at a time. A repeated difference narrows the hypothesis, not the cause.
3. During each attempt, read service restart/exit state, available memory, recent
   OOM events, per-core CPU usage and network errors/drops. Record interval deltas,
   not cumulative counters. In a VM with fractional CPU, inspect steal time.
   Speedtest and subjective loading differences alone do not establish CPU limits.
4. Save a short [AmneziaVPN client log](https://docs.amnezia.org/documentation/instructions/logging/)
   around one reproduction. F-Layer's Xray access/error logs are disabled by
   default, so lifecycle journals cannot diagnose an individual request. If needed,
   separately authorize a bounded temporary [Xray logging](https://xtls.github.io/en/config/log.html)
   experiment on the test stand, preserving and restoring the original files and
   service state. Keep destinations, user identifiers and raw logs private; export
   only sanitized outcome/timing. Do not silently edit a prepared bundle or its manifest.
5. If evidence points to DNS, UDP/QUIC or path MTU, test that hypothesis separately
   on the client/test stand. [QUIC uses UDP](https://www.chromium.org/quic/); this
   does not mean a Shorts failure is caused by QUIC. Do not assume the VLESS path
   and AWG carry UDP identically. Use a bounded client/browser TCP comparison where
   available; its result does not automatically explain the Android app. The AWG
   profile already uses MTU 1280, so do not increase it or change global MSS/firewall
   policy without path evidence. Prefer a new explicitly configured test profile
   for policy changes and repeat affected DNS/routing/IPv6 checks.

Record each hypothesis as supported, rejected or unresolved. Do not change a
production VPN or extend a paid stand's lifetime based on this procedure alone.
