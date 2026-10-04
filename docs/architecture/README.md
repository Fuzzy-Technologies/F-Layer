# Architecture

Start with the [implemented architecture reference](reference.md), including
composition, lifecycle ownership, and documentation/distribution diagrams.
The exact installed public surface is generated from the wheel, while
[coverage rules](../development/documentation-coverage.md) account for every
tracked repository file.

| Boundary                               | Stable reference                                  |
| -------------------------------------- | ------------------------------------------------- |
| Configuration and owned state          | [Configuration and state](configuration-state.md) |
| Read-only provider interfaces          | [Provider contract](provider-contract.md)         |
| Durable orchestration and recovery     | [Lifecycle](lifecycle.md)                         |
| Scoped Yandex mutation adapter         | [Yandex lifecycle](yandex-lifecycle.md)           |
| Deployment profile and owned artifacts | [Secure gateway](secure-gateway.md)               |
| Redacted health and benchmark evidence | [Diagnostics](diagnostics.md)                     |

These documents describe implemented contracts. Roadmap direction must be labeled
separately. Significant choices, alternatives, and compatibility consequences
belong in the [Architecture Decision Records](../adr/README.md).
