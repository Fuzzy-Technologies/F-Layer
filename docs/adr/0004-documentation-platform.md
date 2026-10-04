# ADR 0004: Static installed-package documentation platform

- Status: Accepted
- Date: 2026-10-04
- Task: [#33](https://github.com/Fuzzy-Technologies/F-Layer/issues/33)
- Related rollout: [#27](https://github.com/Fuzzy-Technologies/F-Layer/issues/27)

## Context

F-Layer needs documentation from its first implementation wave. FuzzyRoutines
already provides a Fuzzy Technologies blueprint for canonical API generation,
corporate styling, multilingual source identity, honest review state, and safe
publication. A second documentation stack would add avoidable maintenance.

## Decision

Adopt MkDocs Material, mkdocstrings-python, and Griffe. Build from a clean
installed wheel with runtime imports disabled and independently guarded.
Keep dependencies in a fully pinned, transitive documentation lock. Keep
English Google-style source docstrings canonical; use original F-Layer SVG
branding and supported CSS/theme configuration for the corporate dark,
violet/green presentation.

Generate module pages and public-symbol inventories from the installed wheel,
so the independent documentation PR remains valid against the bootstrap and
automatically includes later integrated modules. Authored English units retain
tracked review metadata. Disposable generated API units use the blueprint's
`fuzzy-doc-unit-v1` hashes and stable IDs, with explicitly `missing` RU/ZH
states; no generated registry claims approved translations.

Reuse the blueprint locale validator with house-style identifier names while preserving its hash and review semantics.
English is canonical, with Russian and Simplified Chinese fallback routes until
human review satisfies the same source-hash and accountable-role requirements.
The review and hash scheme must not be weakened by automation.

Only an event of type `push` with `github.ref == refs/heads/master` deploys Pages.
The workflow does not claim or enforce repository branch protection. Pull requests and `develop` build
strict, disposable artifacts with read-only repository permissions. Package
publication remains a separate workflow.

## Consequences

API output tracks the installed package rather than duplicated prose. Source,
local links, exact anchors, generated-output policy, source hashes, and wheel
provenance are deterministic gates. Documentation and API inventories remain
available as downloadable CI evidence. Locale fallbacks make missing work
visible without misrepresenting English text as reviewed translations.

Generated API translation review is intentionally not implemented in this wave;
future reviewed overlays must use tracked metadata and the same validator.
A typed stub describes the ported locale validator boundary without altering
its validation semantics. New project tools follow the Python style contract.

## Alternatives

A separate pdoc or Sphinx implementation would duplicate an established stack.
Runtime introspection could execute provider code or require credentials.
Manually authored API pages could drift as independent implementation PRs merge.
Generated HTML committed to Git would mix source and disposable artifacts.

## Compatibility and migration

This establishes new documentation routes without changing public Python APIs.
The moving reference carries the early-development status. Stable-version
routes will be added only when stable release artifacts exist.
