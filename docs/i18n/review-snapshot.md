# Multilingual review evidence

## Current authored-page review

AIna-Dev reviewed all **12 authored English pages** against their Russian and
Simplified Chinese translations on 2026-10-09. Subsequent page edits have their
own exact review timestamps in the registry. This covers 24 translations
and 48 editorial/technical AI review records. No human approvals are claimed.
The authority and source/translation hash contract are recorded in
[ADR 0015](../adr/0015-accountable-ai-translation-review.md).

The review checks meaning, natural engineering terminology, command and code
parity, cloud mutation consent, ownership and cleanup, headings, links and
actual release availability. Russian prose now explains concrete settings and
actions; Linux and Yandex Cloud directories use «каталог». The Russian Yandex
CLI link opens the vendor's Russian instructions. Install precedes Quick Start,
which leads with a concrete Yandex Cloud walkthrough. Installation uses the F-Layer 2.0.0 wheel with the `vpn` extra and its
build evidence; the operator records the exact package and source identity.

The API landing page and project identity page are now translated as well.
The brand-image paths were subsequently corrected to the canonical asset
location and re-reviewed; their exact later timestamps are in the registry.
The API landing no longer repeats the obsolete pre-1.0 compatibility notice.
Localized links stay in their language's API and engineering-reference routes.
The Quick Start covers package installation, private project settings,
authenticated guest provisioning, both client imports, DNS and routing checks,
and cleanup. Independent AI reviewers checked Russian and Chinese terminology
and protocol details. Generated API and engineering-reference translations use
separate source-bound catalogs; this authored review does not approve content
absent from those catalogs.

The AI operator guide, README prompt and Quick Start entry points received
editorial and technical self-review by AIna-Dev. This review checks version and
provider honesty, bounded paid-resource consent, retained authorization,
prerequisite handling, private state, real-client verification and cleanup.
The owner-requested 2.0 preparation was re-reviewed across README, landing,
installation, Quick Start, AI guidance and maintainer examples: old-version
comparisons are removed, installation uses the 2.0.0 artifact, and the runtime
version matches. These follow-up checks are AI self-reviews.
The owner-requested 2.0 preparation was re-reviewed across README, landing,
installation, Quick Start, AI guidance and maintainer examples: old-version
comparisons are removed, installation uses the 2.0.0 artifact, and the runtime
version matches. These follow-up checks are AI self-reviews.
It is not an independent-agent live deployment; that evidence remains part of
the release acceptance procedure.

| Canonical unit                | Reviewed canonical hash                                                   |
| ----------------------------- | ------------------------------------------------------------------------- |
| `page:api`                    | `sha256:5d6a97e054991df75bd7d964df247aa0e77b3fa70251866f4f8ec19f1cd24728` |
| `page:architecture`           | `sha256:ec88468bbf2a50a96f2365f47035ffbf747d6be85bbedaa558eaf04364a19df7` |
| `page:brand`                  | `sha256:7dc4a34669dc538db351ce211014c64ea31d79c00d540badb364bce3c4d620aa` |
| `page:development`            | `sha256:3e13b58ec7a14f97c5d4f774a4727fe67aeaf9ba91a4720972768bd8154450a2` |
| `page:documentation`          | `sha256:b4d1f228b3280cba13b0dbf9900b3a7ccd8a433862551bbaaa97f155f2cab4cb` |
| `page:guide`                  | `sha256:f633b1e2ddb1dfbed4fb5045b06ef9742733ef27d5fd48c12e4eadc9f0791997` |
| `page:guide.ai-operator`      | `sha256:cd0c8a7df584c1dcad0672daf65a4d94b65297f405391e7fdf1efc23018038af` |
| `page:guide.cli`              | `sha256:5fb769af7ee418e6969f064600c5249fdbf489c2cf663a0a2851c07447c69fbc` |
| `page:guide.configuration`    | `sha256:49c1db435ada063f2181b0b9e69381f8a8a518ce3742b44de8e7b4ed1054abc1` |
| `page:guide.first-deployment` | `sha256:485cfb018ec5d44ec29e9d14d7901cfc6f78ff790dee979ebaa42b5071c41094` |
| `page:guide.installation`     | `sha256:87fa7aad27ce6c92dd508ba53c736c30ae6c33768ddc9e6f5eae796bd4b877e1` |
| `page:index`                  | `sha256:fa5be57c593750c35275892739b75cfd0d5c552612574e1c7f2adc8b003d8a87` |

`docs/i18n/units.toml` records each translated text hash, named reviewer, reviewer
type, role and UTC timestamp. A later edit requires a fresh review. The current
branch review is not evidence that its Pages deployment has already happened.

## Historical v1.2.1 publication acceptance

The owner accepted PRs #66 and #67. Their final master source is
`d61cf946ade8d7d018f69351e24a3a0ca51d1079`. Its
[strict multilingual build and actual Pages deployment](https://github.com/Fuzzy-Technologies/F-Layer/actions/runs/37861711338)
passed, including tracked-file coverage, installed-wheel parity, rendered links
and anchors, and nine approved authored pages in each locale. Live
`/F-Layer/en/`, `/F-Layer/ru/` and `/F-Layer/zh-CN/` routes were verified with
neutral language names, the company slide and Quick Start. Approved pages keep
hidden provenance; missing generated-reference translations retain English fallback.

[Task #27](https://github.com/Fuzzy-Technologies/F-Layer/issues/27#issuecomment-6071386490)
and [Feature #8](https://github.com/Fuzzy-Technologies/F-Layer/issues/8#issuecomment-6071392694)
record completion after publication acceptance. All three native Feature children
are complete. The native
[release-1.2 milestone](https://github.com/Fuzzy-Technologies/F-Layer/milestone/3)
was closed with zero open items before stable publication.

[F-Layer v1.2.1](https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.2.1)
was published after the
[annotated-tag and reproducible-artifact audit](https://github.com/Fuzzy-Technologies/F-Layer/actions/runs/37862618156).
Its tag owns that exact master source; downloaded wheel, source archive and build
evidence matched their audited hashes and sizes. Preliminary v1.2.0 remains immutable.
These receipts establish this publication's acceptance, not future translation approval.
