# Multilingual review evidence

AIna-Dev reviewed all nine authored English pages against both Russian and
Simplified Chinese translations, as requested by the project owner. These are
18 reviewed translations with editorial and technical AI records (36 role
records), recorded at `2026-10-08T23:30:06Z`. No human approvals are claimed.
[ADR 0015](../adr/0015-accountable-ai-translation-review.md) explains the authority.

## Reviewed scope

The review checked meaning, glossary terms, cloud mutation consent, ownership,
recovery and cleanup instructions, command/code parity, paths, anchors and links.
Corrections clarify Russian device-artifact ownership and Chinese virtual-machine
terminology; examples consistently select v1.2.1. The registry binds each record
to its English source hash and reviewed translated text hash. Later edits require
fresh actual review. Generated APIs and other absent translations remain English.

| Canonical unit                                                              | Russian                                            | Simplified Chinese                                       | Reviewed canonical hash                                                   |
| --------------------------------------------------------------------------- | -------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------- |
| [page:architecture](../site/content/en/architecture.md)                     | [RU](../site/content/ru/architecture.md)           | [ZH-CN](../site/content/zh-CN/architecture.md)           | `sha256:ec88468bbf2a50a96f2365f47035ffbf747d6be85bbedaa558eaf04364a19df7` |
| [page:development](../site/content/en/development.md)                       | [RU](../site/content/ru/development.md)            | [ZH-CN](../site/content/zh-CN/development.md)            | `sha256:3e13b58ec7a14f97c5d4f774a4727fe67aeaf9ba91a4720972768bd8154450a2` |
| [page:documentation](../site/content/en/documentation.md)                   | [RU](../site/content/ru/documentation.md)          | [ZH-CN](../site/content/zh-CN/documentation.md)          | `sha256:5fedb80b0a5fcde074364bb7a85ec394267dfcdbd6b6b1fda57a1b9f38edc0f6` |
| [page:guide](../site/content/en/guide/index.md)                             | [RU](../site/content/ru/guide/index.md)            | [ZH-CN](../site/content/zh-CN/guide/index.md)            | `sha256:02548935927c0f08f5635b47561943471bd1358758b81d1107a3da7628c2a368` |
| [page:guide.cli](../site/content/en/guide/cli.md)                           | [RU](../site/content/ru/guide/cli.md)              | [ZH-CN](../site/content/zh-CN/guide/cli.md)              | `sha256:5fb769af7ee418e6969f064600c5249fdbf489c2cf663a0a2851c07447c69fbc` |
| [page:guide.configuration](../site/content/en/guide/configuration.md)       | [RU](../site/content/ru/guide/configuration.md)    | [ZH-CN](../site/content/zh-CN/guide/configuration.md)    | `sha256:072347586a80864d7df609f36662c002da9a27380ffc0884595c045fcdc0f6c9` |
| [page:guide.first-deployment](../site/content/en/guide/first-deployment.md) | [RU](../site/content/ru/guide/first-deployment.md) | [ZH-CN](../site/content/zh-CN/guide/first-deployment.md) | `sha256:6d25dab7598389367b6d943f45d9c60ff77f4d5bb2b5dcd8646d18faa6f50798` |
| [page:guide.installation](../site/content/en/guide/installation.md)         | [RU](../site/content/ru/guide/installation.md)     | [ZH-CN](../site/content/zh-CN/guide/installation.md)     | `sha256:f8d72455e17cc9fd8a93b9463cf078041bf8f826fb064f8530d1d9a1712b698d` |
| [page:index](../site/content/en/index.md)                                   | [RU](../site/content/ru/index.md)                  | [ZH-CN](../site/content/zh-CN/index.md)                  | `sha256:d976cde3058d4243de5ff36e9cc77fdf352abac825af9d4839e298f8a9d5ae1f` |

`docs/i18n/units.toml` contains the exact localized hashes, reviewer type, identity,
roles and timestamps. The project manifest explicitly opts into AI review;
projects without this setting remain human-only. This is translation review,
not independent human certification.

## Publication acceptance still required

Task #27 and Feature #8 remain open until the exact promoted master commit passes
strict multilingual CI and Pages deployment. Check reachable `/F-Layer/en/`,
`/F-Layer/ru/` and `/F-Layer/zh-CN/` routes against that run's build evidence.
Record the source commit, workflow/deployment URL and reviewed locale states in
Task #27 before completing it. Related implementation PRs must not auto-close
publication acceptance on merge alone.

Close Feature #8 only after its required child Tasks and feature acceptance
criteria are met. Close release-1.2 with zero open items before publishing a
stable v1.2.1 release and immutable annotated tag. Preserve preliminary v1.2.0.
