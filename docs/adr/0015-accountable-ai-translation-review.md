# ADR 0015: Explicit, source-bound AI translation review

- Status: Proposed for owner review
- Date: 2026-10-09
- Related: [Task #27](https://github.com/Fuzzy-Technologies/F-Layer/issues/27), [Feature #8](https://github.com/Fuzzy-Technologies/F-Layer/issues/8)

## Context

ADR 0004 adopted human-only translation approval. The owner subsequently asked
AIna to reverify the Russian and Chinese documentation and remove the notices
describing those pages as translation drafts. That direction authorizes an
actual AI review, not an invented human approval. Build success alone remains
insufficient evidence of translation quality.

## Decision

F-Layer explicitly selects `reviewerTypes = ["human", "ai"]` in its tracked
project manifest. Projects without that opt-in retain the human-only default.
An AI review identifies `reviewerType = "ai"`, the actual reviewer, editorial
or technical role, UTC timestamp and current `reviewedSourceHash`. It additionally
requires `reviewedTranslationHash`, SHA-256 of UTF-8 text with normalized newlines.
Both source and translation changes invalidate AI approval. Existing role and
source-basis requirements and the `fuzzy-doc-unit-v1` scheme stay intact.

AIna-Dev checks all nine authored English pages against both localized versions:
meaning, terminology, ownership and consent constraints, commands, code, paths,
anchors and navigation. Only those 18 actually reviewed translations receive approval records.
Generated API and untranslated repository references remain explicit English
fallbacks. Approved pages retain machine-readable provenance without a visible
review notice. Draft, missing and stale pages retain their accurate notices.
Build evidence distinguishes authored review completion from human review.

This supplements the review-authority decision in ADR 0004. It does not waive
human PR review or the stable-release milestone gate. Task #27 still requires
successful publication from the exact promoted master commit; the milestone
must be completed, closed and empty before stable publication.

## Consequences

The user-facing guides can be published without misleading draft labels, while
their AI provenance remains auditable. AI review is fallible and is not described
as independent human certification. Later text edits require a new actual review,
not a mechanical hash refresh. The candidate becomes v1.2.1; v1.2.0 stays immutable.

## Alternatives

Hiding notices while keeping draft metadata misrepresents the published state.
Adding fictitious human identities fabricates evidence. Waiting for unrelated
human reviewers does not carry out the owner's requested AIna verification.

## Compatibility

Runtime and CLI behavior remain compatible. Existing human records default to
`reviewerType = "human"`. The opt-in extends only documentation review authority.
No cloud resources, package-index uploads or repository access rules change.
