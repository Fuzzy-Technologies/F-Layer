# F-Layer

Release history: [Changelog](CHANGELOG.md) · [GitHub Releases](https://github.com/Fuzzy-Technologies/F-Layer/releases).

F-Layer is a modular infrastructure automation platform by Fuzzy Technologies
for deploying, managing, and integrating secure cloud environments.

Reusable configuration, state, provider, lifecycle, deployment, and diagnostics
contracts keep the core independent from one cloud, protocol, or consumer.
F-Layer is in early foundation development; no stable public API is promised
before `v1.0.0`.

[Documentation](https://fuzzy-technologies.github.io/F-Layer/) ·
[Architecture](docs/architecture/README.md) ·
[Development protocol](DEVELOPMENT_PROTOCOL.md) ·
[Release workflow](docs/RELEASE_WORKFLOW.md)

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

Build the static, installed-wheel API documentation with
`python tools/build_api_reference.py`; see [documentation setup](docs/site/README.md).
Read [AGENTS.md](AGENTS.md) before contributing.

Apache License 2.0. See [LICENSE](LICENSE).
