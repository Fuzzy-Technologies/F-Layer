# Ecosystem Integration

`flayer.integrations` implements a consumer-neutral version-one observation
contract for 1337, Fuzzy ecosystem tools, and other clients. This is the F-Layer
side of an integration boundary. Synthetic fixtures and an offline reference
workflow demonstrate this package's behavior; no live 1337 or MCP integration
has been verified.

The architectural principle is: models reason; the durable core governs
execution, state, ownership, and evidence. AI and MCP applications are clients.
No model, parsed envelope, capability advertisement, or adapter grants hidden
authorization. The decision is recorded in
[ADR 0012](../adr/0012-consumer-neutral-evidence-contracts.md).

## Envelopes and ownership

Both envelopes contain exactly these metadata fields. A result additionally
contains `evidence`; requests have no parameters or evidence payload.

| Field            | Contract                                                                |
| ---------------- | ----------------------------------------------------------------------- |
| `schema_version` | Integer `1`; booleans and unknown versions are rejected                 |
| `envelope`       | `request` or `result`, matching the parser invoked                      |
| `identity`       | Complete exact `StackIdentity`; no omitted/defaulted fields             |
| `request_id`     | 1..64 ASCII letters, digits, dots, underscores, or dashes; starts alnum |
| `operation`      | One of the five read-only observation operations below                  |
| `evidence`       | Result only; the operation selects its strict evidence schema           |

`identity` contains `project`, `stack`, `provider`, `scope_id`, and `owner_id`.
All five must match independently held caller expectations. State projection
checks the identity retained by `StackState`. Diagnostic and lifecycle reports
have no identity field, so their adapters require an explicit `observed_identity`
from the host that selected the source. This checks contract binding; it is not
remote attestation and cannot verify source provenance.

`ParseRequest(payload, expected_identity)` returns validated intent.
`ParseResult(payload, expected_request)` additionally requires identical
operation, request identifier, version, scope, and ownership. Result correlation
does not authenticate the sender, establish freshness, prevent replay, or prove
guest readiness. Parsed requests and result payloads remain untrusted
representations. Hosts must authenticate their transports and independently
authorize access to their evidence sources.

Identity and request identifiers are non-secret routing metadata, not free-form
payload fields. Keep credentials and private content out of these fields. The
contract must preserve exact identity rather than redact it into an ambiguous
ownership boundary. The examples use only synthetic identities.

## Supported observations

| Operation          | Adapter            | Evidence                                                           |
| ------------------ | ------------------ | ------------------------------------------------------------------ |
| `status`           | `AdaptDiagnostics` | Aggregate diagnostic severity and ordered check outcomes           |
| `health`           | `AdaptDiagnostics` | Aggregate diagnostic severity and ordered check outcomes           |
| `benchmark`        | `AdaptDiagnostics` | Diagnostic outcomes and allowlisted numeric measurements           |
| `state`            | `AdaptState`       | Count of recorded owned resources                                  |
| `lifecycle-report` | `AdaptLifecycle`   | Existing action/outcome, recovery flag, and resource-status counts |

Diagnostic report command names must exactly match the request operation.
Check outcomes retain the existing `ok`, `warning`, `failed`, `stale`, and
`unsupported` meanings and severity order. Empty checks are `unsupported`.
The parser rejects an aggregate status inconsistent with the check outcomes.
Each check contains only `status` and a `metrics` object. Check order is retained;
metric keys are canonicalized, and diagnostic names and messages are omitted.

Metrics are optional. Unknown details are omitted by adapters; unknown wire
metric fields and invalid values for known metrics are rejected. No strings,
booleans, credential bytes, response content, or unstructured errors are metrics.

| Metric             | Permitted value                                         |
| ------------------ | ------------------------------------------------------- |
| `duration_seconds` | Finite number from 0 through 30                         |
| `received_bytes`   | Integer from 0 through 1,048,576                        |
| `byte_limit`       | Integer from 1 through 1,048,576                        |
| `http_status`      | Integer from 100 through 599, or `null`                 |
| `throughput_mbps`  | Finite number from 0 through 1,000,000,000,000, or null |

State evidence's `resource_count` describes a local ownership snapshot. It does
not assert that those resources still exist remotely or that a deployment is
healthy. Lifecycle evidence contains `action`, `status`, `recovery_required`,
and a `resources` array of `{status, count}` categories. Supported actions are
`status`, `create`, `destroy`, and `recover`; supported outcomes are `complete`,
`incomplete`, `uncertain`, `rolled-back`, and `rollback-incomplete`. Resource
categories are `recorded`, `present`, `missing`, and `not-recorded`. Counts are
unique by category and total at most 4,096.

A lifecycle report can describe a previously performed mutation. Summarizing
that report does not request, approve, retry, or execute the mutation. Operations
such as `create`, `destroy`, `recover`, `apply`, and `execute` are rejected as
request operations. Any future mutation-facing integration needs a separately
reviewed authorization and durable execution contract.

## Bounds and serialization

- UTF-8 input and serialized output are limited to 65,536 bytes.
- Decoded nesting is limited to eight levels and 4,096 values.
- Diagnostics contain at most 128 checks, with at most five unique metrics each.
- State and lifecycle resource totals are limited to 4,096.
- JSON duplicate keys, nonstandard numeric constants, unknown fields, invalid
  types, and unknown versions are rejected without echoing raw input.
- `SerializeRequest` and `SerializeResult` emit deterministic standard JSON.

These bounds constrain in-process parsing and evidence conversion. They do not
create a network timeout, authorize an endpoint, or bound an arbitrary host
callback. There are no dispatch callbacks in this package. Existing diagnostics
APIs own their explicit probe and benchmark limits, and the durable lifecycle
core owns its operation state and recovery semantics.

## Offline reference workflow

1. An authorized host selects one exact stack identity and a trusted evidence
   source. A client prepares an observation request with a correlation identifier.
2. The host parses the request against independently selected identity context.
   Parsing performs no provider work, credential lookup, or state write.
3. The host independently obtains observations through existing F-Layer APIs.
   For example, `LifecycleEngine.Status()` reads owned remote existence; health
   probes and benchmark transports must be explicitly chosen and bounded.
4. The corresponding adapter projects only allowed evidence. Adapters perform
   no provider calls, execute no lifecycle methods, and write no state.
5. The consumer parses the result against its original request and interprets it
   with authenticated source provenance and any host-owned freshness policy.

```python
from flayer.core.contracts import StackIdentity
from flayer.core.state import StackState
from flayer.integrations import (
    AdaptState, IntegrationOperation, IntegrationRequest, ParseRequest,
    ParseResult, SerializeRequest, SerializeResult,
)

identity = StackIdentity("example", "sandbox", "fake", "scope-example", "example-owner")
request = IntegrationRequest(identity, "example-001", IntegrationOperation.STATE)
parsed = ParseRequest(SerializeRequest(request), identity)
result = AdaptState(parsed, StackState(identity))
observed = ParseResult(SerializeResult(result), request)
```

See the [synthetic wire examples](https://github.com/Fuzzy-Technologies/F-Layer/tree/develop/examples/integrations) and the
[offline functional reference test](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/tests/functional/test_ecosystem_reference.py).
The reference test uses existing status, health, benchmark, persisted-state, and
lifecycle-status APIs with local fixtures and a fake provider. It checks that
parsing and adapters never dispatch provider calls and that owned state content
is unchanged. Contract tests exercise every operation's wire examples, foreign
ownership, incorrect correlation, malformed and bounded input, privacy omission,
and mutation-name rejection. This evidence proves the F-Layer-side boundary;
it does not prove an external consumer implementation is compatible.

## Extension boundary

Transport hosting, MCP tool registration, consumer authentication, replay and
freshness policies, and external-client conformance are outside this package.
There is no consumer name in the core contracts and no speculative orchestration,
scheduler, or agent execution layer. Version 1 rejects schema expansion rather
than silently discarding it. New incompatible fields or operations require an
explicit version and compatibility decision.
