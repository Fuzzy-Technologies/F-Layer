# Architecture Decision Records

F-Layer uses Architecture Decision Records for decisions that materially affect architecture, public contracts, compatibility, security boundaries, persistence, provider interfaces, or extension design.

## Naming

```text
0000-template.md
0001-short-decision-name.md
0002-another-decision.md
```

ADR numbers are stable once assigned.

## Lifecycle

1. Record the context and decision before or together with implementation.
2. Link the implementation Feature/Task and relevant PRs.
3. Describe consequences and rejected alternatives.
4. Do not silently rewrite an accepted ADR to represent a different decision; supersede it with a new ADR when necessary.

Use [0000-template.md](0000-template.md) as the starting point.

## Accepted decisions

| ADR                                                 | Decision                                                            |
| --------------------------------------------------- | ------------------------------------------------------------------- |
| [ADR 0001](0001-config-state-contracts.md)          | Separate desired configuration from owned resource state            |
| [ADR 0002](0002-read-only-provider-boundary.md)     | Establish a read-only provider boundary using explicit folder scope |
| [ADR 0003](0003-safe-diagnostics.md)                | Safe Diagnostics with Explicit Observation Boundaries               |
| [ADR 0004](0004-documentation-platform.md)          | Static installed-package documentation platform                     |
| [ADR 0005](0005-durable-owned-lifecycle.md)         | Durable owned resource lifecycle                                    |
| [ADR 0006](0006-yandex-lifecycle.md)                | Scoped Yandex lifecycle mutations and explicit boot disk ownership  |
| [ADR 0007](0007-secure-gateway-profile.md)          | Explicit secure gateway profile and owned artifacts                 |
| [ADR 0008](0008-reproducible-release-automation.md) | Reproducible distributions and explicit owner publication           |
| [ADR 0009](0009-distribution-version-source.md)     | One source for distribution and runtime versions                    |
| [ADR 0010](0010-documentation-completeness.md)      | Explicit repository documentation completeness                      |
| [ADR 0014](0014-scoped-releases-and-changelog.md)   | Milestone-scoped releases and human-readable changelogs             |

Release history and the human-readable changelog follow
[ADR 0014](0014-scoped-releases-and-changelog.md).
