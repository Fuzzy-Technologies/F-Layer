# F-Layer

![F-Layer](docs/site/content/en/assets/brand/flayer-horizontal.svg)

Release history: [Changelog](CHANGELOG.md) · [GitHub Releases](https://github.com/Fuzzy-Technologies/F-Layer/releases).

F-Layer is a modular infrastructure automation platform by Fuzzy Technologies
for deploying, managing, and integrating secure cloud environments.

Reusable configuration, state, provider, lifecycle, deployment, and diagnostics
contracts keep the core independent from one cloud, protocol, or consumer.
Stable releases are tagged on `master`; `develop` integrates accepted work for
later milestones. See the changelog for the scope of each released version.

[Documentation](https://fuzzy-technologies.github.io/F-Layer/) ·
[User guide](docs/site/content/en/guide/index.md) ·
[Architecture](docs/architecture/README.md) ·
[Development protocol](DEVELOPMENT_PROTOCOL.md) ·
[Release workflow](docs/RELEASE_WORKFLOW.md)

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git checkout v1.2.0
python -m pip install .
python -m flayer check --format json
```

Build the static, installed-wheel API documentation with
`python tools/build_api_reference.py`; see [documentation setup](docs/site/README.md).
Read [AGENTS.md](AGENTS.md) before contributing.

Apache License 2.0. See [LICENSE](LICENSE).
