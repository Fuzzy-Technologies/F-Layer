# Localization review contract

English remains canonical. Russian (`ru`) and Simplified Chinese (`zh-CN`)
translations require editorial and technical review. The owner authorized AIna-Dev
to record attributable AI reviews under [ADR 0015](../adr/0015-accountable-ai-translation-review.md).
Reviewed pages open without a visible review notice. Missing or stale translations
show the current English source and their actual status. Approval and successful
publication are separate checks.

```bash
python -m tools.locale_documentation validate
python -m tools.build_locale_sites
```

The wrapper builds strict installed-wheel English and locale sites with the same
import guard and pinned toolchain. It verifies provenance attributes, links,
anchors and route reachability. Disposable `build-evidence.json` distinguishes
`authoredTranslationReviewComplete`, `translationReviewComplete`, and
`humanReviewComplete`. Generated-unit states are also recorded individually.
AI reviews never count as human reviews, and untranslated pages remain missing.

## Unit identity and state

Stable IDs and canonical `sourceHash` retain the `fuzzy-doc-unit-v1` payload.
Each existing translation records its path and `basedOnSourceHash`. Updating
canonical metadata alone cannot make an outdated translation current.

| Metadata state | Rendered text                | Review meaning                                |
| -------------- | ---------------------------- | --------------------------------------------- |
| `missing`      | Current English fallback.    | No translation or review is claimed.          |
| `draft`        | Localized draft.             | Required review is incomplete.                |
| `review`       | Localized text under review. | Required review is incomplete.                |
| `stale`        | Current English fallback.    | Source or reviewed translation has changed.   |
| `approved`     | Reviewed localized text.     | Authorized roles reviewed the current source. |

Approval requires the roles selected by `reviewClass`, a named reviewer, a UTC
`reviewedAt` and current `reviewedSourceHash`. `reviewerType` defaults to `human`.
AI approval requires explicit project opt-in and `reviewerType = "ai"` on every
AI record. It additionally requires `reviewedTranslationHash`: SHA-256 of the
UTF-8 translation with normalized newlines. Missing roles, unauthorized reviewer
types, changed sources and changed reviewed translations fail validation.
An AI's actual review may be recorded; a human identity must never be invented.

## Updating a translation

1. Inspect the English change and refresh its canonical hash.
2. Mark affected translations `stale`, preserving previous review provenance.
3. Reconcile meaning, terminology, ownership/consent instructions, commands,
   code, paths and explicit heading anchors against the current source.
4. Set the current `basedOnSourceHash` and obtain actual authorized reviews.
5. Record the actual reviewer type, identity, role, UTC timestamp and matching
   source hash; AI records also bind the reviewed translation text hash.
6. Approve only the reviewed text, run affected checks and let CI build the site.

Paths must remain inside the intended locale; unregistered overlays fail.
Glossary concept IDs and notes remain English while preferred terms are localized.
Source links to absent translations resolve to the locale's English fallback.

## Generated reference catalogs

[ADR 0018](../adr/0018-generated-documentation-translations.md) extends source-bound
review to repository guides, API descriptions, and inventory prose. A repository
translation lives in `docs/i18n/generated/<locale>/repository/<source-path>.toml`.
API and inventory catalogs contain `[[units]]` records under the same locale.

Each record contains `sourcePath`, `sourceHash`, translated `body`,
`reviewedTranslationHash`, `reviewer`, `reviewerType`, a timezone-aware `reviewedAt`,
and `reviewRoles = ["editorial", "technical"]`. Repository IDs are
`repository:<source-path>`; API IDs retain `symbol:<qualified-name>` and add
`module:<qualified-name>` for module introductions. The existing versioned
canonical hash includes the callable signature, so signature changes also require
review. Catalog files must be tracked, and duplicate or unknown IDs fail validation.

Repository translations retain all headings, their canonical anchors, and exact
executable code fences. Mermaid labels are translated without changing node IDs,
connections, or direction. The static API extension translates documentation objects while
preserving original source listings, signatures, and installed-wheel bytes.
A module uses translated prose only when all its rendered descriptions are reviewed.
Inventory descriptions are translated from the actual file and symbol inventory;
source paths, code, and machine identifiers retain their original spelling.

## Publication evidence

The [review snapshot](review-snapshot.md) records authored-guide review evidence.
The build artifacts contain the complete discovered inventory and actual review
states for the exact commit. Review alone does not imply deployment: publication
requires a successful Pages deployment of the promoted master commit.
The stable release gate also requires a closed milestone with zero open items.

For release 2.0 and later, the documentation builder rejects any rendered narrative
page without current complete review in both languages. Earlier stabilization
branches can request the same check explicitly:

```bash
python -m tools.build_locale_sites --require-complete-translations
```
