# F-Layer documentation

- [`site/`](site/README.md) — branded MkDocs Material documentation generated from an installed wheel;
- [`architecture/`](architecture/) — accepted architecture boundaries and source contracts;
- [`adr/`](adr/) — Architecture Decision Records;
- [`development/`](development/) — engineering conventions and Python style;
- [`RELEASE_WORKFLOW.md`](RELEASE_WORKFLOW.md) — branch, release, and tag workflow;
- [`i18n/`](i18n/project.toml) — stable English units, aligned terminology, and translation state.

English is canonical. Russian and Simplified Chinese have explicit missing-translation
fallback routes until accountable human reviews approve translated content.
The builder reads current architecture and ADR sources into the generated site
and discovers public API modules statically from the installed package.
Generated HTML stays disposable and untracked under `_build/`.
