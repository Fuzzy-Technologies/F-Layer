![F-Layer by Fuzzy Technologies](assets/brand/flayer-horizontal.svg){ .fl-brand-lockup }

# Infrastructure with explicit contracts

**F-Layer** is a modular infrastructure automation platform for deploying,
managing, and integrating secure cloud environments.

Its architecture separates configuration, durable resource state, provider
capabilities, deployment profiles, lifecycle operations, and diagnostic
evidence. Those boundaries make individual integrations replaceable and
operations reproducible.

!!! info "Foundation stage"
    F-Layer is in early development. This documentation describes the current
    installed package and accepted architecture. There is no stable public API
    or compatibility guarantee before `v1.0.0`. Architecture direction does
    not imply that every lifecycle or deployment feature is implemented.

<div class="grid cards" markdown>

- **Understand the boundaries**

    Read the [architecture](architecture.md) and its source-of-truth rules.

- **Inspect the actual API**

    Browse the [API reference](api/index.md), generated from the installed wheel.

- **Build with evidence**

    Follow the [development workflow](development.md) and deterministic gates.

- **Keep documentation honest**

    Review [language and publication contracts](documentation.md).

</div>

## Design commitments

- The core is independent from a cloud provider, network protocol, and consumer.
- Credentials and private infrastructure identifiers stay outside tracked source.
- Configuration, desired state, observed state, and generated artifacts remain separate.
- Local validation uses deterministic fixtures and never mutates real cloud resources.
- Python annotations and English docstrings are the API source of truth.

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) ·
[GitHub repository](https://github.com/Fuzzy-Technologies/F-Layer)
