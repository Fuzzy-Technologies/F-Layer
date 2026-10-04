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
