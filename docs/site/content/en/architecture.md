# Architecture

F-Layer is organized around explicit boundaries. The documentation platform
reads current modules from the installed wheel; the [API reference](api/index.md)
shows the contracts actually present in this revision.

| Boundary | Responsibility |
|---|---|
| Configuration | Validate user intent without embedding credentials or local machine paths. |
| State | Preserve the minimum resource identity and lifecycle evidence needed for management. |
| Provider | Own cloud API translation, authentication adapters, and capability discovery. |
| Deployment profile | Compose capabilities into a concrete infrastructure outcome. |
| Lifecycle | Coordinate create, observe, cleanup, rollback, and interrupted operations. |
| Diagnostics | Produce bounded health and benchmark evidence without changing infrastructure. |
| Generated artifacts | Expose clear ownership, provenance, and disposal rules. |

These are architecture responsibilities, not a claim that every boundary has
completed implementation. Provider-specific behavior belongs behind contracts;
AI clients, future CLIs, and external integrations consume those contracts.

## Source of truth

- Accepted decisions live in [Architecture Decision Records](https://github.com/Fuzzy-Technologies/F-Layer/tree/develop/docs/adr).
- Detailed designs live in [architecture sources](https://github.com/Fuzzy-Technologies/F-Layer/tree/develop/docs/architecture).
- Public source contracts live in the installed Python package.
- Runtime credentials and real resource state never become documentation fixtures.

The first implementation wave establishes governance, configuration/state,
provider boundaries, diagnostics, and validation. Lifecycle orchestration follows
the stabilization of those contracts.
