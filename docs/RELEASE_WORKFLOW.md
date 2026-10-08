# Branch and Release Workflow

This document defines the branch, merge, release, and tag workflow for F-Layer.

It complements `DEVELOPMENT_PROTOCOL.md`. If these documents conflict, stop and resolve the conflict before continuing release work.

## Branch roles

| Branch pattern      | Purpose                                         | Normal source              | Normal destination |
| ------------------- | ----------------------------------------------- | -------------------------- | ------------------ |
| `master`            | Stable released/public state                    | release/hotfix/publication | tag/publication    |
| `develop`           | Integration branch for the next release         | `feature/*`, `fix/*`       | `release/*`        |
| `feature/<name>`    | Product, architecture, governance, or task work | `develop`                  | `develop`          |
| `fix/<name>`        | Non-release correction                          | `develop`                  | `develop`          |
| `release/<version>` | Release stabilization                           | `develop`                  | `master`           |
| `hotfix/<name>`     | Urgent released-state correction                | `master`                   | `master`           |

## Protected branches

`master` and `develop` are expected to be protected. Normal changes arrive through pull requests; review conversations are resolved before merge; protected branches cannot be deleted or force-pushed; stable CI checks become required once their contexts exist; owner/admin bypass is reserved for recovery.

## Normal development

```text
Task
  ↓
feature/* or fix/* from develop
  ↓
PR → develop
  ↓
CI + human review
  ↓
merge
```

Squash merge is the default for ordinary PRs into `develop`.

## Release flow

F-Layer uses Semantic Versioning without build numbers:

```text
v1.0.0
v1.0.1
v1.1.0
v1.1.1
v2.0.0
```

A release is cut from accepted `develop`:

```text
develop
  ↓
release/X.Y.Z
  ↓
validation + version/release metadata
  ↓ PR
master
  ↓
annotated tag vX.Y.Z
  ↓
back-merge to develop
```

Release tags are immutable. The tag, package version, release notes, and distributed artifact version must agree.

## Hotfix flow

```text
master
  ↓
hotfix/<name>
  ↓ PR
master → next patch tag
  ↓
back-merge to develop
```

Never fix only `master` and leave `develop` divergent.

## Issue completion

The owner-authorized staged 1.0.0/1.1.0 publication selects accepted commits by
milestone instead of promoting the whole advanced develop tip. See
[ADR 0014](adr/0014-scoped-releases-and-changelog.md) and the
[changelog](../CHANGELOG.md) for scope, history, and release-card rules. Each
release is finalized and tagged on master before the next candidate is promoted;
release-only changes return to develop through a PR. The 1.2.0 scope addendum
selects accepted documentation/security PRs #46, #48, #59, and #60 on released
1.1.0. The premature stable classification of its artifact was withdrawn;
RU/ZH-CN human-review acceptance remains required before stable publication.
Later milestone runtime features stay in develop.
Full regression gates run
in CI, while local development checks the affected files.

Tasks remain open during implementation and review. A merged PR may complete explicitly linked native Task issues through repository automation. Features close only when required child Tasks and feature-level acceptance criteria are satisfied. Passing CI does not replace milestone acceptance.

## Stable publication requires a completed milestone

Before publishing a stable GitHub Release or uploading to PyPI, the owner must
verify all Task, Feature and milestone acceptance criteria and close the native
`release-X.Y` milestone. Its `open_issues` count must be zero. An instruction to
finish a release does not waive unfinished acceptance criteria. Automation must
not close planning items or invent human approvals to make publication pass.

Use GitHub CLI with read access to the canonical repository for the preflight:

```bash
python tools/release_validation.py --check-milestone 3
```

This example checks release-1.2 against the checked-out package version. Replace
the native milestone number for another release. The check reads GitHub's native
state, validates repository/number/minor-version identity, and fails for open,
incomplete, unavailable or malformed evidence. It does not build, publish or change
planning state. Run it immediately before stable GitHub publication, alongside
the exact-master CI and tag/artifact checks. Direct GitHub UI publication remains
an owner-controlled action; the preflight is not a GitHub UI permission restriction.
The PyPI workflow performs this check before full validation and repeats it when
creating publication evidence.

Release titles use `F-Layer vX.Y.Z — <short user-facing digest>`; annotated tags use
`vX.Y.Z`, and package versions use `X.Y.Z`. Release-card section order follows
ADR 0014. A candidate may have draft/fallback Pages and a GitHub **Pre-release**
label, but it must not be advertised as the latest stable release.

On 2026-10-08, v1.2.0 was incorrectly classified as stable while Task #27,
Feature #8 and release-1.2 remained open. Its title was corrected and its release
classification changed to Pre-release. The existing tag, commit and audited assets
remain immutable. After acceptance is completed, changed release code requires a
new patch version and tag; never move v1.2.0 onto a different commit.

## Implemented validation and release evidence

`Release artifact validation` runs without write or OIDC permissions on pull requests,
`develop`/`master` pushes, and `v*` tag pushes. It never publishes. CI uploads a wheel,
a source distribution, and `build-evidence.json` containing source commit, version,
fixed build timestamp, exact backend version, artifact sizes, SHA256 digests, and
reproducibility/rebuild results.

Run the same artifact validation from a clean committed checkout:

```bash
python -m pip install -e '.[dev]'
python tools/release_validation.py
```

Generated files appear only in `_build/release`. The tool refuses an existing output
directory; remove that generated directory before an intentional rerun. Ignored and
untracked files never enter its build snapshot. Distribution members must match
owned tracked source, with only expected packaging metadata generated by Hatchling.
The audit rejects traversal, duplicate members, links, private/generated paths,
recognizable private keys or token formats, excessive expanded sizes, mismatched
metadata, and invalid wheel `RECORD` hashes. This is an ownership and packaging
check; it cannot identify every possible secret inside an otherwise approved source
file. Review of tracked source remains necessary.

Two builds use the exact pinned Hatchling backend and the commit's
`SOURCE_DATE_EPOCH`. Their wheel and source-distribution bytes must match. A further
wheel build from the audited source distribution must contain identical members.
The source distribution therefore carries the complete authored documentation,
tests, validation tools, workflows, license, and package metadata needed to rebuild.

Bootstrap metadata (`0.0.0`, without `flayer.__version__`) may pass a pull-request
artifact preview. Tagged release and publication checks require a non-bootstrap
literal `flayer.__version__`. Static project versions must agree with that value;
dynamic Hatch metadata must read `src/flayer/__init__.py` directly.

For a real release, validate the existing tag after fetching master and tags:

```bash
git fetch origin master --tags
python tools/validate.py
python tools/release_validation.py --tag vX.Y.Z
```

The tag must be annotated, use stable `vX.Y.Z` without leading zeroes, prerelease
suffixes or build numbers, match all package versions, and resolve to both the exact
checkout commit and `origin/master`. A tag on `develop`, an old master commit, a
lightweight tag, or an absent source version fails closed. Tags do not create GitHub
Releases or complete Features/Milestones.

## Owner-controlled PyPI publication

Publication is disabled until the owner configures the intended PyPI project and
GitHub repository variables. No account, secret, environment, tag, GitHub Release,
or package publication is created by the implementation PR.

| Configuration                 | Required value                                                      |
| ----------------------------- | ------------------------------------------------------------------- |
| PyPI project                  | `f-layer`; confirm name availability and ownership before enabling  |
| Trusted Publisher owner       | `Fuzzy-Technologies`                                                |
| Trusted Publisher repository  | `F-Layer`                                                           |
| Trusted Publisher workflow    | `release-publish.yml`                                               |
| Trusted Publisher environment | Empty; the workflow does not require a GitHub environment           |
| `FLAYER_RELEASE_OWNER`        | Exact GitHub login of the authorized release owner                  |
| `FLAYER_PYPI_ENABLED`         | `true`, set only after the intended Trusted Publisher is configured |
| Workflow revision             | `master`, containing the reviewed release implementation            |
| Dispatch tag                  | Existing annotated `vX.Y.Z`, matching current master and versions   |
| Dispatch milestone            | Native `release-X.Y` number; closed with no open items              |
| `confirm_publication`         | Explicitly checked for that manual dispatch                         |

The owner must configure a normal Trusted Publisher for an owned existing PyPI
project, or a pending publisher if the name is available. Use the production PyPI
endpoint; this workflow cannot redirect uploads to an arbitrary index and does not
accept a token/password. Official setup instructions:

- [Creating a project through Trusted Publishing](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [Adding a publisher to an existing project](https://docs.pypi.org/trusted-publishers/adding-a-publisher/)
- [Publishing with a Trusted Publisher](https://docs.pypi.org/trusted-publishers/using-a-publisher/)

After review and tag validation, the configured owner selects `master` in **Actions
→ Publish an owner-approved PyPI release**, enters the exact existing tag, and checks
`confirm_publication`. The dispatch also requires the native release milestone
number. Any open/incomplete milestone, missing opt-in, wrong owner, wrong branch/repository,
invalid tag, bootstrap version, failed full validation or failed artifact audit
blocks publication. Successful validation transfers only this run's audited
artifacts to a separate job. That job has OIDC permission and runs the pinned PyPA
publisher without checking out or executing project build code. PyPI independently
verifies the configured repository/workflow identity. Package name availability,
Trusted Publisher account configuration, and an actual upload are not validated by
local tests. The action produces PyPI attestations for successful trusted uploads.

A pushed tag does not publish. Manual dispatch confirmation is the publication
intent for that run. Re-running a publication uses the same immutable tag; an
existing PyPI version fails rather than silently skipping uploads. Disabling
`FLAYER_PYPI_ENABLED` blocks future publication jobs. Repository administrators
remain responsible for authorizing who can modify workflows and release variables.

## Completion and housekeeping

Existing post-merge automation verifies a merged PR and native Task type before
closing explicit linked Tasks and deleting eligible merged implementation branches.
The release workflows do not weaken that contract and do not close Features or
Milestones. Their acceptance criteria must be checked separately by the owner.
