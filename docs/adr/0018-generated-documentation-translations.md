# ADR 0018: Reviewed translations for generated documentation

## Status

Proposed. Related: [Task #75](https://github.com/Fuzzy-Technologies/F-Layer/issues/75).

## Context

The authored guides have translations, but generated API pages, repository guides,
and the coverage inventory still display English. Translating navigation labels
alone does not translate their content. The release 2.0 documentation must cover
all human-facing prose while keeping callable names, commands, paths, and original
source listings exact.

## Decision

- Discover every rendered repository Markdown document, public module docstring,
  public definition, and constructor docstring included by the API renderer.
- Store translations in `docs/i18n/generated/<locale>/` TOML catalogs. Bind each
  review to the existing `fuzzy-doc-unit-v1` canonical hash and the exact translated
  text hash. Require editorial and technical review, reviewer identity and type,
  a timezone-aware date, and the project authority from ADR 0015.
- Preserve all Markdown headings, their canonical anchors, executable code fences,
  and source link destinations. Mermaid node labels, state aliases, and transition
  captions are translated while identifiers, connections, and direction stay exact.
  Translated documents retain their existing locale routes.
- Use a static Griffe extension to replace documentation objects only. The wheel,
  Python identifiers, signatures, original source listings, and import guard remain
  unchanged. A module is translated only when all its rendered prose is reviewed.
- Render inventory descriptions from reviewed locale messages using the actual
  tracked-file and definition inventory. Source-only code is classified explicitly;
  its bytes are not treated as prose awaiting translation.
- Missing or changed content remains visibly missing or stale. Record actual
  states in build evidence. The documentation builder rejects incomplete
  translations for package versions 2.0 and later; the same check can be requested
  explicitly with `--require-complete-translations` during stabilization.

## Consequences

Adding documentation or changing API descriptions requires corresponding locale
review before a 2.0 publication. AI review remains attributable AI review and never
becomes a claim of human approval. Strict rendering, exact links, static discovery,
repository coverage, and installed-wheel parity remain required independently.

## Alternatives

Copying English into locale files would conceal untranslated content. Translating
source files would alter the code being documented. Both are rejected.
