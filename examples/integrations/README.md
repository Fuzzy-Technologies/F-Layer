# Synthetic Integration Wire Examples

These examples describe the implemented F-Layer-side version-one contract from
[Ecosystem Integration](../../docs/architecture/ecosystem-integration.md).
All identities and evidence are synthetic. They do not represent real cloud
resources, private infrastructure, live 1337 compatibility, authorization,
attestation, or verified guest readiness.

| Observation        | Request                                                        | Result                                                       |
| ------------------ | -------------------------------------------------------------- | ------------------------------------------------------------ |
| Status             | [status-request.json](status-request.json)                     | [status-result.json](status-result.json)                     |
| Health             | [health-request.json](health-request.json)                     | [health-result.json](health-result.json)                     |
| Benchmark          | [benchmark-request.json](benchmark-request.json)               | [benchmark-result.json](benchmark-result.json)               |
| Owned state        | [state-request.json](state-request.json)                       | [state-result.json](state-result.json)                       |
| Lifecycle evidence | [lifecycle-report-request.json](lifecycle-report-request.json) | [lifecycle-report-result.json](lifecycle-report-result.json) |

Each pair shares exact identity, operation, schema version, and request identifier.
The status example is unsupported when no provider observation is available.
The health and benchmark values are fabricated successful observations. The state
count represents recorded ownership only. The lifecycle example reports missing
resources and required recovery rather than masking incomplete evidence.

`ParseRequest` and `ParseResult` validate representations; neither dispatches
work or grants permission. Mutation request names are unsupported. The fixtures
are round-tripped by `tests/contract/test_integration_contracts.py`.
