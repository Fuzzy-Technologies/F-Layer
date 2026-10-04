# Diagnostics, Health, and Benchmarks

F-Layer exposes read-only diagnostics through `flayer.diagnostics` and the module CLI.
The implementation adapts the A-VPN baseline's structured check results, report freshness,
and bounded download measurements. It does not embed a provider, guest operating system,
transport profile, service catalog, or private infrastructure configuration.

## Implemented CLI

```bash
python -m flayer --help
python -m flayer check --format json
python -m flayer status --format text
python -m flayer health --endpoint https://your-controlled-endpoint.example/health --timeout 3
python -m flayer benchmark --endpoint https://your-controlled-endpoint.example/sample \
  --timeout 3 --count 3 --bytes 65536 --format json
```

Use an endpoint you have authorized for the requested traffic. `--endpoint` is mandatory
for network work. No command contacts a default service, discovers cloud resources,
reads credentials, runs SSH, or mutates infrastructure.

| Command | Current observation | Offline behavior |
| --- | --- | --- |
| `check` | Local Python runtime compatibility | Reports local execution only |
| `status` | Runtime plus generic provider observation boundary | Provider observation is unsupported until an adapter supplies it |
| `health` | An explicit endpoint returns HTTP 2xx | Missing endpoint is unsupported |
| `benchmark` | Repeated limited HTTP downloads | Missing endpoint is unsupported |

`health` measures endpoint reachability. It does not establish cloud lifecycle state,
guest hardening, tunnel handshakes, or application correctness. `benchmark` records the
application payload downloaded and elapsed HTTP request time. Its throughput includes
DNS/connect/TLS/response overhead and is not an upload or maximum link capacity estimate.

## Results and Exit Codes

JSON output has `schema_version: 1`, `command`, aggregate `status`, and an ordered `checks`
array. Each check has `name`, `status`, `message`, and a `details` object. JSON keys are
sorted; no response body or raw exception text is included. Text output uses the same
sanitized observations, with one line per check.

| Status | Exit code | Meaning |
| --- | --- | --- |
| `ok` | 0 | All requested observations succeeded |
| `warning` | 1 | A supplied observation reports degraded or pending state |
| `failed` | 1 | A check failed or structured evidence was invalid |
| `stale` | 3 | Health evidence expired or has a future timestamp |
| `unsupported` | 4 | No adapter/evidence/endpoint was supplied, or its schema is unsupported |
| Invalid CLI input | 2 | Command arguments, endpoint, or bounds are invalid |

Aggregation precedence is `failed`, `stale`, `unsupported`, `warning`, `ok`.
An empty report is unsupported. A local runtime success cannot mask absent remote evidence.

## Adapter Boundary

`RunChecks()` accepts read-only `HealthProbe` callables returning `CheckResult` objects.
Adapters own their authorization and timeout enforcement. The collector converts exceptions
or invalid return values to failed checks without copying exception messages.

`ProviderStatus()` accepts a generic observation mapping with `state` equal to `ready`,
`pending`, `failed`, or `absent`; only this allowlisted state is reported. It never invokes
a provider SDK. Adapters translate their native resource states at this boundary.

`EvaluateHealthReport()` accepts already collected evidence with integer `schema_version: 1`,
a finite numeric Unix `timestamp`, and `status` equal to `ok`, `warning`, or `failed`.
It rejects malformed fields and marks evidence outside `[now - max_age_seconds, now]` stale.
It does not parse raw serial console output or load guest files.

`EndpointTransport` is injectable for offline tests and future adapters. The default
`MeasureEndpoint()` uses the standard library HTTP client inside a spawned worker. A
parent deadline covers process startup, DNS, connect, TLS, and response reads. On expiry
the worker is terminated; cleanup waits are bounded to one second each for terminate/kill.

## Traffic and Output Bounds

- HTTP(S) endpoints must be explicit and contain no user information, query, or fragment.
- Each request has a finite timeout from greater than zero through 30 seconds.
- A benchmark contains 1 through 10 requests, with 1 through 1,048,576 application payload
  bytes read per request. Defaults are 3 requests, 3 seconds, and 65,536 bytes.
- Requests use `GET` and a `Range` header. The read cap remains enforced if a server ignores
  the header. The cap describes payload consumed by the client, not transport framing or
  server transmission before the connection closes.
- Redirects are failures and are never followed. Environment proxy settings are not read.
  HTTPS uses the standard library's certificate verification defaults.
- Public output omits endpoint addresses, response bodies, headers, and raw error strings.
  Serialization recursively redacts credential-like keys, bearer/private-key text, URLs,
  and IPv4 text. Arbitrary objects and binary data are replaced instead of stringified.
  Unsafe mapping keys are sanitized with deterministic suffixes for collisions, and nested
  data is capped at 16 levels so cyclic adapter data cannot break rendering.

Redaction is an additional boundary, not a general detector of every possible secret.
Adapters must return allowlisted diagnostic facts and omit unrelated private data. Do not
attach raw provider responses, serial console output, or credential values as ordinary fields.
Injected transports must obey their timeout and byte-limit contract; the collector validates
metrics but cannot cancel arbitrary code supplied by a caller.

## Validation and Next Integration

Unit tests exercise status aggregation, freshness, recursive redaction, malformed adapter
data, CLI input privacy, payload caps, redirect failures, deadlines, termination, and cleanup
without external network traffic. CLI help and local checks are safe for install/import smoke.

Provider-backed CLI status and deployment-specific guest checks remain adapter integration
work. The provider/configuration tasks can compose these contracts after their own interfaces
stabilize. See [ADR 0003](../adr/0003-safe-diagnostics.md).
