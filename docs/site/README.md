# Documentation platform

F-Layer follows the Fuzzy Technologies MkDocs Material documentation blueprint.
English source lives in `content/en/`; localization hashes, review states, and
glossaries live in `../i18n/`. Python API contracts remain in package docstrings.

```bash
python tools/build_api_reference.py
python tools/build_locale_sites.py
python tools/build_api_reference.py --serve
python -m tools.locale_documentation validate --output _build/documentation-gates/locales.json
```

The clean builder installs a wheel and the exact documentation lock in an
isolated environment, prevents runtime imports, generates module pages from
installed source, validates strict links/anchors and localization, and writes
`_build/api-reference/build-evidence.json`. A preprovisioned virtual environment
can be selected with `--environment-python PATH` for offline/reproducible CI
runners; its documentation versions must match the lock exactly.
Place that environment outside `_build/api-reference/`, which the builder
recreates. If environment creation restores stale generated output into the
owned build root, the build fails before publishing and requests an external
verified environment.

Generated API symbols use the same blueprint source-hash scheme in a disposable
registry. Actual translations and review records determine their locale states;
generating a registry never creates a translation or a review.
The copied validator retains the upstream hash, schema keys, and review semantics; internal identifiers follow house style.

The multilingual wrapper renders approved RU/ZH pages without draft notices
and uses current English fallbacks for missing or outdated translations. It preserves the
installed-wheel import guard and strict links/anchors, adds per-route reachability
evidence, and never creates human approvals. Translation basis hashes prevent a
canonical registry refresh from hiding outdated translations. See [the rollout contract](../i18n/README.md).

PRs and `develop` upload preview artifacts. Only an approved `master` push
can deploy Pages. Routes: `/F-Layer/en/`, `/F-Layer/ru/`, `/F-Layer/zh-CN/`.
Dependencies are separate from runtime metadata in `../requirements-api.txt`.

## Completeness evidence

The [coverage contract](../development/documentation-coverage.md) distinguishes
rendered Markdown, generated public API, and explicitly justified source-only
files. `_build/api-reference/repository-coverage.json` inventories every tracked
file and defined package symbol. Unknown or overlapping file categories, source
files omitted from the wheel, extra or changed package files, missing API
anchors, and existing but unreachable Markdown pages fail the build.

The generated coverage page links every file or rendered page. All canonical
repository Markdown is included, including ADR templates, governance/release
guides, and GitHub's PR template. The [architecture reference](../architecture/reference.md)
connects implemented boundaries and diagrams to the current source contracts.

The wheel is installed into a fresh owned build target, independently of the
selected documentation-tool environment. An ambient or previously installed
F-Layer cannot influence API discovery, and the environment is not mutated by
the package install. Strict English output is assembled into a fresh publication
tree before locale fallbacks are created; restored sibling routes are discarded.
