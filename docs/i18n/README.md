# Localization review contract

English remains canonical. The nine authored pages in Russian (`ru`) and
Simplified Chinese (`zh-CN`) have editorial and technical review by AIna-Dev,
requested by the owner and recorded as AI review under [ADR 0015](../adr/0015-accountable-ai-translation-review.md).
Generated API and other untranslated units display current English with explicit
fallback notices. Reviewed guides open directly without a visible review notice.
Actual master Pages publication remains a separate Task #27 acceptance step.

```bash
python -m tools.locale_documentation validate
python -m tools.build_locale_sites
```

The wrapper builds strict installed-wheel English and locale sites with the same
import guard and pinned toolchain. It verifies provenance attributes, links,
anchors and route reachability. Disposable `build-evidence.json` distinguishes
`authoredTranslationReviewComplete` from `humanReviewComplete`; AI reviews never
count as human reviews, and untranslated pages remain missing.

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

## Release-1.2 evidence

The [review snapshot](review-snapshot.md) lists all 18 reviewed translations and
current hashes. Review does not imply deployment. Task #27 also requires a
successful Pages deployment from the exact promoted master commit. Feature #8
and release-1.2 can close only after all their acceptance criteria are met.
The stable release gate still requires a closed milestone with zero open items.
