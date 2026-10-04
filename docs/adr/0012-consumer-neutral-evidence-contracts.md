# ADR 0012: Consumer-neutral Integration Evidence Contracts

- Status: Accepted
- Date: 2026-10-04
- Related task: #30

## Context

1337 and other Fuzzy ecosystem clients need a bounded way to request and consume
F-Layer observations. Models reason; the durable F-Layer core governs execution,
state, ownership, and evidence. An AI or MCP client must not gain infrastructure
authorization from parsing a message, discovering a capability, or naming a stack.

The existing diagnostic, state, and lifecycle models are useful evidence sources,
but their full contents are unsuitable for an external wire boundary. Resource
locators, arbitrary diagnostic details, and provider status text can disclose
infrastructure data. There is no verified live 1337 integration in this repository.

## Decision

Add an independent `flayer.integrations` package with version-one request and
result envelopes. Bind every message to an exact `StackIdentity`, a bounded
request correlation identifier, and an explicit read-only operation. Parsing
requires independently supplied identity expectations; result parsing also
requires the originating request. Reject unsupported versions, duplicate or
unknown fields, unbounded input, and all mutation operation names.

Adapt already obtained diagnostic reports, owned state snapshots, and lifecycle
reports into allowlisted evidence. Preserve diagnostic outcomes and bounded
numeric measurements, local recorded-resource counts, and lifecycle action,
outcome, recovery requirement, and resource-status counts. Omit resource and
logical identifiers, diagnostic names/messages, endpoints, provider strings,
raw errors, configuration, credentials, and arbitrary payloads.

Only identity routing metadata and the correlation identifier contain caller
strings. They are required non-secret metadata for an authorized transport;
validation is not authentication or a general secret detector. Callers must not
put secrets into those fields. Examples use wholly synthetic metadata.

These envelopes do not dispatch operations. Hosts independently authorize reads,
select trusted evidence sources, and obtain any explicit endpoint/transport limits
through existing APIs. Lifecycle mutation results may be summarized as historical
evidence; this does not provide a mutation request, approval, or execution path.

## Consequences

- F-Layer has one transport- and consumer-neutral evidence contract.
- Ownership correlation is mandatory, but source provenance and transport
  authentication remain explicit host responsibilities.
- Parsing and adapters perform no provider calls, filesystem writes, or dispatch.
- Aggregate evidence intentionally omits detailed resource troubleshooting data.
- State counts describe recorded ownership, not remote existence or health.
- Snapshots carry no freshness assertion, replay protection, or authorization.
- Requests for new operations require an explicit contract change and review.

## Alternatives

Embedding 1337 orchestration in the core would couple F-Layer to a consumer and
create speculative scheduler behavior. Reusing full model serialization would
expose locators and arbitrary prose. Accepting mutation requests as generic
payloads would obscure authorization boundaries. Redaction alone cannot prove
that external strings are safe; a narrow allowlist is the chosen boundary.

## Compatibility and Migration

This is an additive F-Layer-side contract. It does not claim live 1337 or MCP
compatibility. Version 1 uses strict schemas; incompatible extensions require a
new version. Existing CLI, core, provider, and secure-gateway contracts are unchanged.

## Validation

Deterministic fixtures exercise bounded wire round trips, exact ownership and
request correlation, unknown fields and versions, malformed and duplicate JSON,
secret-bearing evidence omission, and rejection of mutation request names.
Reference workflows compose existing local evidence sources with adapters.
The canonical full gate and strict documentation builder are required before review.
