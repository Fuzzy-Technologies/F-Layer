# ADR 0003: Safe Diagnostics with Explicit Observation Boundaries

- Status: Accepted
- Date: 2026-10-04
- Related task: #23

## Context

The A-VPN baseline combines cloud discovery, guest self-audit, SSH, service targets,
and transfer measurements. F-Layer needs reusable diagnostics before its configuration,
provider, and lifecycle interfaces stabilize. Copying that composition would embed VPN
and private infrastructure assumptions and could trigger unintended traffic or expose
raw provider or command output.

## Decision

Introduce `flayer.diagnostics` with structured, versioned `CheckResult` and
`DiagnosticReport` contracts. Outcomes distinguish successful, warning, failed, stale,
and unsupported evidence. Missing evidence is unsupported, not successful.

Collect read-only health probes and generic provider observations through injected
interfaces. Validate supplied health report schema and timestamps separately from health
outcomes. Do not discover or authorize infrastructure from inside diagnostics.

Provide `python -m flayer status/check/health/benchmark` as the concrete initial CLI.
Local runtime checks work offline. Remote health and benchmarks require an explicit HTTP(S)
endpoint and bounded time/count/payload options. Default HTTP transport uses an isolated
spawned worker so the parent can terminate stalled DNS, connection, TLS, or read work at
the deadline. Redirects and proxy discovery are disabled; TLS verification remains enabled.

Expose only safe measurement facts. Response content, endpoint identifiers, credentials,
and raw exception strings never enter reports. Recursively sanitize structured output and
suppress raw invalid CLI argument values. Adapter authors must supply allowlisted facts;
redaction alone cannot establish that arbitrary external text is safe.

## Consequences

- Diagnostics can be implemented and tested independently of provider and lifecycle tasks.
- Exit codes reflect incomplete or failed evidence; offline `status` currently exits 4.
- HTTP throughput is a limited end-to-end measurement, not claimed tunnel/link capacity.
- Worker startup adds overhead; reported HTTP duration excludes worker startup, while the
  hard parent deadline includes it. Process cleanup may add up to two bounded seconds.
- Injected custom probes/transports retain responsibility for enforcing their own bounds.
- Provider CLI integration and deployment-specific guest checks are later compositions.

## Alternatives

Copying A-VPN's cloud/SSH composition would couple diagnostics to an unstabilized provider
and a specific deployment. A socket timeout alone would leave DNS or slow streamed reads
outside a hard total deadline. Thread-only cancellation could leave network work running
after the caller returned. An isolated process provides a bounded cancellation owner.

## Compatibility and Migration

This is an additive contract for the bootstrap package. There are no deployed lifecycle
interfaces to replace. A-VPN private configuration and generated artifacts are not migrated.
Public JSON carries schema version 1 so later changes can be explicit.

## Validation

Deterministic unit tests cover result validation, status aggregation, freshness, redaction,
CLI input privacy, HTTP payload/redirect bounds, deadline cancellation, and cleanup using
injected probes/transports/processes. The canonical compile, Ruff, mypy, and pytest gates
must pass before review. Tests do not contact live infrastructure or external services.
