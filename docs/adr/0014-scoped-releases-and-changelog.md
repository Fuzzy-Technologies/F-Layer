# ADR 0014: Milestone-scoped releases and human-readable changelogs

## Status

Accepted for the owner-authorized 1.0.0 and 1.1.0 releases.

## Context

Accepted `develop` contains completed 1.0 and 1.1 work together with 1.2/2.0 work.
Promoting its whole tip would silently ship later milestones in the earlier
releases. Each requested release needs a precise code boundary, an immutable tag,
rebuildable artifacts, and an understandable explanation for users.

The 1337 reference defines its changelog hierarchy in its development protocol,
and its release-card template in its release workflow. No separate changelog ADR
was found in that reference's accepted ADR directory. F-Layer records the adapted
decision explicitly here.

## Decision

For this staged publication, create `release/1.0.0` from the released `master`
baseline and select the accepted release-1.0 commits. Create `release/1.1.0` from
the resulting released master state and select the accepted release-1.1 commits.
Record source PRs/commit identities and bounded release-only adjustments. Do not
select later product features merely because they already exist in `develop`.

Use PRs to promote both candidates in order. Run focused changed-file checks
locally; CI runs the complete regression, documentation, and applicable artifact
gates. Every stable version has an explicit literal source version, matching
package metadata, an annotated immutable `vX.Y.Z` tag on its exact master commit,
and a GitHub Release with audited assets. Publish 1.0.0 before advancing master to
1.1.0. Propagate release-only metadata and decisions back to develop through a PR.
Temporary administrative workflows remain on isolated branches and are removed.
GitHub Releases do not authorize PyPI publication or real infrastructure changes.

Stable publication requires completed acceptance and a closed native `release-X.Y`
milestone with no open items. Passing implementation CI or an instruction to finish
a release does not waive its acceptance criteria. The owner verifies those criteria
before closure; automation checks native milestone evidence without closing it.

Use the Fuzzy Technologies changelog hierarchy:

```text
# F-Layer Changelog
# Major N
## Minor N.M
### Patch P — vN.M.P — YYYY-MM-DD
#### Digest
#### Added
#### Fixed
#### Changed
#### Removed
#### Security
```

Omit irrelevant sections while preserving that order. Newest majors, minors, and
patches appear first within their level. Published entries remain historical;
correct a proven factual error only with owner authorization. Do not add a
free-form Unreleased section. A Digest states the user-visible result briefly;
the detailed sections explain concrete behavior rather than commit chronology.

GitHub release titles use `F-Layer vX.Y.Z — <short user-facing digest>`.
Cards start with `## Digest`, followed by `## What's Changed`,
`## Validation`, `## Breaking Changes`, `## Try it from source`, and `## Notes`
when relevant. State None explicitly for an empty breaking-change section.
Distinguish shipped behavior, actual test evidence, and outstanding operational
validation. Preserve commands for checking out the exact tag; link the detailed
changelog and source provenance without turning the digest into a commit dump.

## Release-1.2 scope addendum — 2026-10-08

Apply the same milestone selection to the owner-requested 1.2.0 publication:
start at released 1.1.0 and select accepted PRs #46, #48, #59, and #60.
Include bounded stabilization for locale-source links, versioned installation
examples, source hashes, and release metadata. Plugin discovery, ecosystem
integration contracts, and the static-site profile stay in later milestone work.

Publish actual draft/fallback states without human approval records in candidate
documentation. Task #27, Feature #8 and release-1.2 must be completed, including
genuine human-review criteria and actual master/Pages evidence, before stable
release publication. Return release-only changes to develop through a PR,
preserving all accepted later milestone work.

The earlier addendum incorrectly allowed stable publication before milestone
completion. That exception was not owner-authorized and is withdrawn. On
2026-10-08 the premature v1.2.0 release was reclassified as Pre-release, its title
was corrected to include `v`, and its immutable tag and assets were preserved.

## Consequences

- Releases reflect their milestone scope even when integration is ahead.
- Tags, source/package versions, notes, and asset hashes can be checked together.
- CI owns full regressions; local development avoids repeating those suites.
- Changelog text is included in source distributions and generated documentation.
- The staged baseline requires explicit back-merges; history is not rewritten.
- A stable tag does not claim live cloud, guest readiness, translation approval,
  or successful PyPI publication.

## References

- [1337 changelog](https://github.com/Fuzzy-Technologies/1337/blob/develop/CHANGELOG.md)
- [1337 changelog contract](https://github.com/Fuzzy-Technologies/1337/blob/develop/DEVELOPMENT_PROTOCOL.md#8-changelog-contract)
- [1337 release-card format](https://github.com/Fuzzy-Technologies/1337/blob/develop/docs/RELEASE_WORKFLOW.md#published-release-notes)
- [F-Layer release workflow](../RELEASE_WORKFLOW.md)
- [F-Layer changelog](../../CHANGELOG.md)
