# Multilingual review handoff

[Task #27](https://github.com/Fuzzy-Technologies/F-Layer/issues/27) and
[Feature #8](https://github.com/Fuzzy-Technologies/F-Layer/issues/8) track the
reviewed EN/RU/ZH-CN rollout for release-1.2. This snapshot follows the 1.2.0 release back-merge and the documentation
entry-point refresh. Landing pages, Quick Start and first-deployment drafts
match their current English sources. Installation commands select the stable
1.2.0 tag. These edits preserve draft status without adding human reviews.

## Current review scope

All 18 authored translations are current-source **drafts**. No human approval
records have been added. Canonical units without translations continue to use
explicit English fallback. Read the current `docs/i18n/units.toml` before
reviewing: a later English edit can invalidate the source hashes below.

The links open the canonical English page and both localized source files.
Every row requires editorial and technical review for each locale.

| Canonical unit                                                              | RU draft                                           | ZH-CN draft                                              | Required roles        | Canonical source hash                                                     |
| --------------------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------- |
| [page:architecture](../site/content/en/architecture.md)                     | [RU](../site/content/ru/architecture.md)           | [ZH-CN](../site/content/zh-CN/architecture.md)           | editorial + technical | `sha256:ec88468bbf2a50a96f2365f47035ffbf747d6be85bbedaa558eaf04364a19df7` |
| [page:development](../site/content/en/development.md)                       | [RU](../site/content/ru/development.md)            | [ZH-CN](../site/content/zh-CN/development.md)            | editorial + technical | `sha256:3e13b58ec7a14f97c5d4f774a4727fe67aeaf9ba91a4720972768bd8154450a2` |
| [page:documentation](../site/content/en/documentation.md)                   | [RU](../site/content/ru/documentation.md)          | [ZH-CN](../site/content/zh-CN/documentation.md)          | editorial + technical | `sha256:aea7a3de31f6432c0f66d3be012e12572fd881a0178452fd35cf4850e23f3352` |
| [page:guide](../site/content/en/guide/index.md)                             | [RU](../site/content/ru/guide/index.md)            | [ZH-CN](../site/content/zh-CN/guide/index.md)            | editorial + technical | `sha256:847717324cc0748455fa4307c33922f08c83fad7c9033f8ab13e55016deb3bee` |
| [page:guide.cli](../site/content/en/guide/cli.md)                           | [RU](../site/content/ru/guide/cli.md)              | [ZH-CN](../site/content/zh-CN/guide/cli.md)              | editorial + technical | `sha256:5fb769af7ee418e6969f064600c5249fdbf489c2cf663a0a2851c07447c69fbc` |
| [page:guide.configuration](../site/content/en/guide/configuration.md)       | [RU](../site/content/ru/guide/configuration.md)    | [ZH-CN](../site/content/zh-CN/guide/configuration.md)    | editorial + technical | `sha256:072347586a80864d7df609f36662c002da9a27380ffc0884595c045fcdc0f6c9` |
| [page:guide.first-deployment](../site/content/en/guide/first-deployment.md) | [RU](../site/content/ru/guide/first-deployment.md) | [ZH-CN](../site/content/zh-CN/guide/first-deployment.md) | editorial + technical | `sha256:6d25dab7598389367b6d943f45d9c60ff77f4d5bb2b5dcd8646d18faa6f50798` |
| [page:guide.installation](../site/content/en/guide/installation.md)         | [RU](../site/content/ru/guide/installation.md)     | [ZH-CN](../site/content/zh-CN/guide/installation.md)     | editorial + technical | `sha256:b9a10d56c86ab6cbd255310727c044f9e3112e06dba8a966c4442697ec32950f` |
| [page:index](../site/content/en/index.md)                                   | [RU](../site/content/ru/index.md)                  | [ZH-CN](../site/content/zh-CN/index.md)                  | editorial + technical | `sha256:d976cde3058d4243de5ff36e9cc77fdf352abac825af9d4839e298f8a9d5ae1f` |

## Reviewing and recording evidence

1. Review each locale against the linked current English source. Check prose,
   terminology, ownership/consent instructions, commands, paths and heading anchors.
2. Use the PR's `flayer-documentation-preview` artifact to inspect the generated
   `ru/` and `zh-CN/` routes. Each page must show its actual draft/fallback state;
   source-only or generated API material remains explicitly English where missing.
3. Leave accountable editorial and technical decisions in the PR discussion.
   A source-hash refresh or machine-generated translation is not human review.
4. After genuine review, record the actual reviewer login, actual UTC review
   timestamp, role and matching canonical hash in the existing translation's
   `reviews` entries. Update only that reviewed translation to `approved`.
5. Run locale validation, submit the evidence through a reviewed PR, and let CI
   build the strict multilingual site. Preserve earlier provenance when content
   becomes stale; obtain new review evidence before reapproving it.

The following is a schema illustration, not an approval record. Replace the
placeholders with actual human evidence only after both reviews occurred:

```toml
[units.translations.ru]
state = "approved"
path = "docs/site/content/ru/guide/cli.md"
basedOnSourceHash = "<current canonical sourceHash>"

[[units.translations.ru.reviews]]
role = "editorial"
reviewer = "<actual reviewer login>"
reviewedAt = "<actual UTC review timestamp>"
reviewedSourceHash = "<current canonical sourceHash>"

[[units.translations.ru.reviews]]
role = "technical"
reviewer = "<actual reviewer login>"
reviewedAt = "<actual UTC review timestamp>"
reviewedSourceHash = "<current canonical sourceHash>"
```

Use the corresponding `zh-CN` translation table for Chinese reviews. The registry
and existing validator define required roles; this handoff does not change them.

## Publication and completion

Human-approved translations and the dependency correction enter `develop` via
reviewed PRs. Prepare the release candidate according to the release scope and
[release workflow](../RELEASE_WORKFLOW.md); a develop preview does not update
GitHub Pages. The multilingual builder and Pages deployment must pass on the
exact promoted `master` commit, with reachable `/F-Layer/en/`, `/F-Layer/ru/`
and `/F-Layer/zh-CN/` routes and matching build evidence.

Record the released source commit, successful Pages workflow/deployment URL,
reviewed locale states and evidence in Task #27 before completing it. Feature #8
also requires its native child Tasks and feature acceptance criteria to be met.
This preparation PR must use `Related: #27`, so merge alone cannot auto-close the
reviewed-publication Task.
