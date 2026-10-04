# Localization rollout contract

English remains canonical. Russian (`ru`) and Simplified Chinese (`zh-CN`)
authored pages are draft translations until accountable human review is recorded.
The user guide, overview, architecture, and development pages have localized
assets. Generated API, repository reference, and other missing units display the
current English text with an explicit fallback banner. Pages publication and
translation review are separate outstanding rollout steps; preparation does not
complete task #27.

```bash
python -m tools.locale_documentation validate
python -m tools.build_locale_sites
```

The wrapper first runs the strict installed-wheel English builder, then builds
each locale with the same import guard and exact dependency lock. It verifies
rendered state banners, exact links and anchors, and reachability of every
localized or fallback route. Evidence lives in the disposable
`_build/api-reference/build-evidence.json` under `renderedLocales`.

## Unit identity and state

Every authored page has a stable ID and canonical `sourceHash` using the unchanged
`fuzzy-doc-unit-v1` payload. Each nonmissing translation records its locale path
and `basedOnSourceHash`: the English source actually used for that translation.
Refreshing the canonical registry alone cannot make an old translation current.

| Metadata state | Rendered text                | Review meaning                                       |
| -------------- | ---------------------------- | ---------------------------------------------------- |
| `missing`      | Current English fallback.    | No translation file or review is claimed.            |
| `draft`        | Localized draft.             | Human editorial and technical review is incomplete.  |
| `review`       | Localized text under review. | Required human review is incomplete.                 |
| `stale`        | Current English fallback.    | Translation must be reconciled with current English. |
| `approved`     | Reviewed localized text.     | Required roles reviewed the current canonical hash.  |

The validator rejects unregistered locale pages, paths outside the intended
locale, missing source basis hashes, and a stale basis presented as current.
Explicit `stale` entries are allowed so the build can render an honest fallback.
Existing approval checks still require the review roles defined by `reviewClass`,
a named reviewer, a UTC timestamp, and a matching `reviewedSourceHash`.
Automation never fills those human review fields.

## Updating a translation

1. Inspect the canonical change and update its registered `sourceHash`.
2. Mark affected translations `stale`; keep their previous `basedOnSourceHash`.
3. Reconcile prose with the current English page. Preserve commands, code,
   identifiers, and explicit canonical heading anchors.
4. Set `basedOnSourceHash` to the current English hash and set state to `draft`.
5. Request the required accountable human reviews before setting `approved`.
6. Run locale validation and the strict multilingual wrapper before review.

Translated source links point to an existing English source when a translation
is absent. The renderer adapts those links to the locale's generated English
fallback route without weakening tracked-source link validation.

Glossary keys, notes, and reference metadata remain English; preferred terms and
navigation/banner labels are target-language localization assets. Draft glossary
terms remain subject to human terminology review.
