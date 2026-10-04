# Documentation platform

F-Layer follows the Fuzzy Technologies MkDocs Material documentation blueprint.
English source lives in `content/en/`; localization hashes, missing states, and
glossaries live in `../i18n/`. Python API contracts remain in package docstrings.

```bash
python tools/build_api_reference.py
python tools/build_api_reference.py --serve
python -m tools.locale_documentation validate --output _build/documentation-gates/locales.json
```

The clean builder installs a wheel and the exact documentation lock in an
isolated environment, prevents runtime imports, generates module pages from
installed source, validates strict links/anchors and localization, and writes
`_build/api-reference/build-evidence.json`. A preprovisioned virtual environment
can be selected with `--environment-python PATH` for offline/reproducible CI
runners; its documentation versions must match the lock exactly.

Generated API symbols use the same blueprint source-hash scheme in a disposable
registry, with `missing` RU/ZH states. They never receive synthetic reviews.
The copied validator retains the upstream hash, schema keys, and review semantics; internal identifiers follow house style.

PRs and `develop` upload preview artifacts. Only an approved `master` push
can deploy Pages. Routes: `/F-Layer/en/`, `/F-Layer/ru/`, `/F-Layer/zh-CN/`.
Dependencies are separate from runtime metadata in `../requirements-api.txt`.
