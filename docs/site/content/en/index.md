![F-Layer by Fuzzy Technologies](assets/brand/flayer-horizontal.svg){ .fl-brand-lockup }

# Infrastructure with explicit contracts

**F-Layer** is a modular infrastructure automation platform for deploying,
managing, and integrating secure cloud environments.

Its architecture separates configuration, durable resource state, provider
capabilities, deployment profiles, lifecycle operations, and diagnostic
evidence. Those boundaries make individual integrations replaceable and
operations reproducible.

!!! info "Versioned documentation"
    GitHub Pages follows the latest stable `master` release. A local build
    describes its installed source revision; `develop` can include accepted work
    for later milestones. Use the tagged changelog to check each release's scope.

<div class="grid cards" markdown>

- **Run the first checks**

    [Install and configure F-Layer](guide/index.md) from an explicit source revision.

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

See the [user guide](guide/index.md) for console usage and the
[project identity](brand.md) for the F-Layer logo family.

[Fuzzy Technologies](https://fuzzy-technologies.github.io/) ·
[GitHub repository](https://github.com/Fuzzy-Technologies/F-Layer)
