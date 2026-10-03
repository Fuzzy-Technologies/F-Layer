# F-Layer

F-Layer is a modular infrastructure automation platform by Fuzzy Technologies for deploying, managing, and integrating secure cloud environments.

The platform is designed around reusable lifecycle, provider, configuration, state, and diagnostics contracts. The first implementation focuses on repeatable cloud gateway deployment and configuration generation while keeping the core independent from any single provider, protocol, or consumer.

## Status

F-Layer is in early foundation development. The repository is not yet a stable public API and no compatibility guarantee is implied before the first `v1.0.0` release.

## Repository layout

```text
src/flayer/        Python package foundation
tests/             Deterministic test layers
tools/             Repository automation helpers
docs/              Architecture, ADR, development, and future user docs
.github/            Pull request, issue, and CI automation
```

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

Python distribution name: `f-layer`  
Python import package: `flayer`

## Development workflow

Normal development uses:

```text
master
  ↑
develop
  ↑
feature/* or fix/*
```

Read [AGENTS.md](AGENTS.md) and [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md) before making changes.

## License

Apache License 2.0. See [LICENSE](LICENSE).
