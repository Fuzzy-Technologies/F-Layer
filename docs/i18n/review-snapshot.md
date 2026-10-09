# Multilingual review evidence

## Current authored-page review

AIna-Dev reviewed all **11 authored English pages** against their Russian and
Simplified Chinese translations on `2026-10-09T07:31:37Z`. This covers 22 translations
and 44 editorial/technical AI review records. No human approvals are claimed.
The authority and source/translation hash contract are recorded in
[ADR 0015](../adr/0015-accountable-ai-translation-review.md).

The review checks meaning, natural engineering terminology, command and code
parity, cloud mutation consent, ownership and cleanup, headings, links and
actual release availability. Russian prose now explains concrete settings and
actions; Linux and Yandex Cloud directories use «каталог». The Russian Yandex
CLI link opens the vendor's Russian instructions. Install precedes Quick Start,
which leads with a concrete Yandex Cloud walkthrough. Installation uses the
existing release wheel; future PyPI or 2.0 publication is not claimed.

The API landing page and project identity page are now translated as well.
The API landing no longer repeats the obsolete pre-1.0 compatibility notice.
Localized links stay in their language's API route. Missing generated API and
engineering-reference translations remain separately visible; this authored
review does not approve content absent from the registry.

| Canonical unit                | Reviewed canonical hash                                                   |
| ----------------------------- | ------------------------------------------------------------------------- |
| `page:api`                    | `sha256:5d6a97e054991df75bd7d964df247aa0e77b3fa70251866f4f8ec19f1cd24728` |
| `page:architecture`           | `sha256:ec88468bbf2a50a96f2365f47035ffbf747d6be85bbedaa558eaf04364a19df7` |
| `page:brand`                  | `sha256:7dc4a34669dc538db351ce211014c64ea31d79c00d540badb364bce3c4d620aa` |
| `page:development`            | `sha256:3e13b58ec7a14f97c5d4f774a4727fe67aeaf9ba91a4720972768bd8154450a2` |
| `page:documentation`          | `sha256:c80e615173c62b32beb8d6e363eedd39657c2c4357ebbe43518d4fbc5b76e4a0` |
| `page:guide`                  | `sha256:a537c4f70104ba93e298f8846f0f9b7aa66bf668bdf4a29e624978195ae90c7e` |
| `page:guide.cli`              | `sha256:5fb769af7ee418e6969f064600c5249fdbf489c2cf663a0a2851c07447c69fbc` |
| `page:guide.configuration`    | `sha256:49c1db435ada063f2181b0b9e69381f8a8a518ce3742b44de8e7b4ed1054abc1` |
| `page:guide.first-deployment` | `sha256:485cfb018ec5d44ec29e9d14d7901cfc6f78ff790dee979ebaa42b5071c41094` |
| `page:guide.installation`     | `sha256:14fcabcd286e8caf4852d0965b8e417cb66b449621cd70e66278442de3d8c09c` |
| `page:index`                  | `sha256:a8bfac93bc8384f9d5d2a5949dc821f753db0cc780a9ad5539ae62a25477f690` |

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
