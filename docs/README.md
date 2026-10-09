# F-Layer documentation

- [`site/`](site/README.md) — branded MkDocs Material documentation generated from an installed wheel;
- [`architecture/`](architecture/) — accepted architecture boundaries and source contracts;
- [`adr/`](adr/) — Architecture Decision Records;
- [`development/`](development/) — engineering conventions and Python style;
- [`RELEASE_WORKFLOW.md`](RELEASE_WORKFLOW.md) — branch, release, and tag workflow;
- [`i18n/`](i18n/project.toml) — stable English units, aligned terminology, and translation state.

English is canonical. Reviewed Russian and Simplified Chinese pages are
published alongside it. Missing or outdated translations display the current
English source with a notice. Reviews identify their reviewer and bind both
source and translation hashes; the project permits accountable AI review under
[ADR 0015](adr/0015-accountable-ai-translation-review.md).
The builder reads current architecture and ADR sources into the generated site
and discovers public API modules statically from the installed package.
Generated HTML stays disposable and untracked under `_build/`.
