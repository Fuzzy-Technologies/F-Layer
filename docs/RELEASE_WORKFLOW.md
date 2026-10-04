# Branch and Release Workflow

This document defines the branch, merge, release, and tag workflow for F-Layer.

It complements `DEVELOPMENT_PROTOCOL.md`. If these documents conflict, stop and resolve the conflict before continuing release work.

## Branch roles

| Branch pattern | Purpose | Normal source | Normal destination |
| --- | --- | --- | --- |
| `master` | Stable released/public state | release/hotfix/publication | tag/publication |
| `develop` | Integration branch for the next release | `feature/*`, `fix/*` | `release/*` |
| `feature/<name>` | Product, architecture, governance, or task work | `develop` | `develop` |
| `fix/<name>` | Non-release correction | `develop` | `develop` |
| `release/<version>` | Release stabilization | `develop` | `master` |
| `hotfix/<name>` | Urgent released-state correction | `master` | `master` |

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

Tasks remain open during implementation and review. A merged PR may complete explicitly linked native Task issues through repository automation. Features close only when required child Tasks and feature-level acceptance criteria are satisfied. Milestone completion is planning state, not implementation evidence.
