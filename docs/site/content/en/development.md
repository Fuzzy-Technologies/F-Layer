# Development

F-Layer uses `master` for stable publication, `develop` for integration, and
scoped `feature/*` or `fix/*` branches for implementation. Pull requests target
`develop` and require human review.

Read [AGENTS.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/AGENTS.md)
and the [development protocol](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/DEVELOPMENT_PROTOCOL.md)
before making changes.

## Python validation

```bash
python -m pip install -e ".[dev]"
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

Source, comments, docstrings, tests, and canonical documentation are English.
The [Python style contract](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/development/PYTHON_CODE_STYLE.md)
is authoritative.

## Infrastructure safety

Local tests use mocks, fixtures, and deterministic data. They do not create,
update, or delete real cloud resources. Documentation discovery does not import
the F-Layer runtime package.

## Build this reference

```bash
python tools/build_api_reference.py
```

The command builds a wheel and installs it with the fully pinned documentation
toolchain in an isolated environment. It generates strict MkDocs output,
checks exact rendered anchors and local links, validates language metadata,
and records wheel provenance under `_build/api-reference/`.

Markdown tables are padded to each column's widest cell so raw source stays
readable. Check all tracked Markdown with `python -m tools.markdown_tables`;
apply a requested whitespace-only alignment with
`python -m tools.markdown_tables --write`. Fenced examples remain unchanged.
The documentation build rejects table drift alongside broken links/anchors.

```bash
python tools/build_api_reference.py --serve
```

The preview uses the same verified installed-package output on
`127.0.0.1:8000`. See [documentation contracts](documentation.md) for publication
and localization details.
