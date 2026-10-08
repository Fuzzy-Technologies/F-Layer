# Documentation contracts

F-Layer adopts the [Fuzzy Technologies documentation blueprint](https://github.com/Fuzzy-Technologies/FuzzyRoutines/tree/develop/docs/documentation-blueprint):
MkDocs Material, mkdocstrings-python, and Griffe with static discovery from an
installed wheel. The theme is extended through tracked configuration, CSS,
and SVG assets. Generated HTML remains disposable and untracked.

## API discovery

Every nonprivate Python module in the installed `flayer` package receives a
generated API page; `flayer.__main__` is an explicit supported exception to the
underscored-path rule. Private modules and helpers remain source-only and are
recorded with reasons. Discovery reads syntax and never imports runtime code.
An import guard makes attempted package execution fail the build. The entire
installed package must match source inventory and bytes, excluding bytecode.
Public definitions and callable protocols require exact generated HTML anchors;
each API page links to its corresponding `develop` source.

Every tracked file must match exactly one explicit coverage rule. All canonical
Markdown, including policy, release guides, ADRs and templates, and repository
entry points, is rendered and must be reachable from the English entry page.
Tests, tools, workflows, examples, assets, and configuration have accountable
dispositions rather than fabricated API documentation. Locale overlays are
rendered by the locale wrapper with explicit review state.
The [coverage contract](../../../development/documentation-coverage.md) defines
the boundary and machine-readable evidence.

Every tracked Markdown table uses content-aligned column padding. The source
gate checks raw readability before publishing; it preserves escaped pipes,
inline code cells, alignment markers and literal fenced examples.

Authored English pages use the tracked locale unit registry. Dynamically
generated API units use a disposable inventory with the same stable symbol
IDs and versioned source hashes. Their target-language states are explicitly
`missing`; this generated inventory cannot manufacture a translation or review.

## Language and review

English is canonical. The authored Russian and Simplified Chinese pages have
been checked against their English sources by AIna-Dev, as requested by the
project owner. Reviewed pages open directly without a draft notice. Missing
or outdated translations display the current English text with a fallback notice.
Generated API pages and untranslated engineering references remain in English.

Each translation records its stable unit ID, English source hash and path.
Approval requires named editorial and technical reviews with UTC timestamps
and the current source hash. F-Layer explicitly permits AI reviews under
[ADR 0015](../../../adr/0015-accountable-ai-translation-review.md); those records
identify the reviewer as AI and also bind the reviewed translation's text hash.
They do not represent human review. Changing either text requires a new review;
refreshing the English registry alone cannot restore approval.

Terminology uses aligned locale glossaries. Review provenance remains available
in the tracked registry and generated build evidence.

## Publication

Pull requests and `develop` produce downloadable preview and evidence artifacts.
Only a `push` event for the `master` branch may deploy the verified Pages
artifact. Documentation publishing is separate from package publication.

The public routes are `/F-Layer/en/`, `/F-Layer/ru/`, and `/F-Layer/zh-CN/`.
The root opens the English reference. No immutable release documentation is
claimed before a stable release exists.

[ADR 0004](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/adr/0004-documentation-platform.md)
records the accepted generator, review, source-hash, fallback, and publication
boundaries.
