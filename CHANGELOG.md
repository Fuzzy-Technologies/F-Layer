# F-Layer Changelog

A chronological record of shipped F-Layer behavior, compatibility, documentation,
and security boundaries. Release entries follow [ADR 0014](docs/adr/0014-scoped-releases-and-changelog.md).

# Major 1

The first versioned infrastructure foundation. Operational validation against a
real cloud account remains the operator's responsibility.

## Minor 1.2

### Patch 1 — v1.2.1 — 2026-10-09

#### Digest

- Start with practical setup instructions and read clearer English, Russian and
  Chinese guides. Authored translations have been verified by AIna and no longer
  display draft notices. Runtime and CLI contracts remain compatible with 1.1.0.
- Finalize release-1.2 with a closed-milestone publication gate; preserve the
  preliminary v1.2.0 tag and artifacts.

#### Added

- A three-language Quick Start with offline checks, help and deployment entry points.
- The company slide in the README and documentation, a compact header logo and favicon.
- Editorial and technical AI review records for all 18 authored RU/ZH-CN pages,
  tied to both current English sources and reviewed translation text.

#### Changed

- Explain supported cloud-server, secure SSH gateway and diagnostic workflows
  directly for engineers and prospective customers.
- Require a completed, closed native milestone before stable release publication.
- Keep approved-page review provenance in metadata without a visible review notice;
  missing and outdated translations retain explicit English fallback.

#### Fixed

- Clipped documentation slides and oversized header branding.
- Russian resource-ownership wording, Chinese virtual-machine terminology,
  localized links and consistent v1.2.1 installation instructions.
- Reject unauthorized AI approval and invalidate it on source or translation drift.

### Patch 0 — v1.2.0 — 2026-10-08

#### Digest

- Preliminary artifact: its premature stable classification was withdrawn on
  2026-10-08 because release-1.2 acceptance remains incomplete. The existing
  v1.2.0 tag and assets are preserved; the latest stable release is v1.1.0.
- Browse complete repository documentation and EN/RU/ZH-CN routes with explicit
  translation status, and use a patched documentation build dependency. Existing
  1.1.0 runtime and CLI contracts remain supported; RU/ZH-CN prose is still draft.

#### Added

- A file-by-file documentation inventory with an explicit category and rationale
  for every tracked file, including future files in established categories.
- Navigable canonical Markdown covering repository entry points, policies,
  architecture, ADRs and templates, development guides, and release history.
- Installed-wheel API coverage for the executable CLI module and callable
  protocols, plus accountable source-only records for private definitions.
- An implemented architecture reference with composition, lifecycle/recovery,
  and documentation/distribution diagrams.
- Strict EN/RU/ZH-CN builds, localized navigation, 18 authored draft pages,
  explicit English fallback, and source-hash-bound review handoff materials.

#### Fixed

- Generated repository pages now retain RU/ZH-CN draft links as source references
  instead of linking to nonexistent canonical pages. Regression checks cover
  both locales and preserved heading fragments.
- Snapshot installation examples select `v1.2.0` in all three languages instead
  of sending readers to an advanced development checkout.

#### Changed

- Require exact source/installed-wheel file and byte parity for the entire
  package, including private modules and the executable entry point.
- Verify rendered API anchors, all local links, repository-page reachability,
  Markdown table alignment, and explicit file classification before publishing.
- Tie current draft translations to their actual English source hashes. Draft,
  stale, missing, review, and approved states remain distinct; generated API
  translations remain explicitly missing.

#### Security

- Update the exact documentation setuptools pin from `80.9.0` to patched
  `83.0.0` for GHSA-h35f-9h28-mq5c / CVE-2026-59890. Other documentation pins
  and the Hatchling distribution backend are unchanged.
- Preserve static API discovery and its runtime import guard, source ownership,
  bounded cloud mutation, and master-only Pages publication. Human translation
  approvals, live cloud readiness, and PyPI uploads are not implied by this release.

## Minor 1.1

### Patch 0 — v1.1.0 — 2026-10-05

#### Digest

- Install F-Layer as a typed Python package with a `flayer` console command,
  follow practical setup and gateway guides, and inspect audited reproducible
  release artifacts. Existing 1.0.0 runtime contracts remain supported.

#### Added

- PEP 561 typing metadata, installed console entry point, and a single literal
  version source shared by runtime and distribution metadata.
- Offline distribution installation and source-archive rebuild checks.
- Reproducible wheel/source-archive audits, metadata/RECORD verification,
  tracked-source ownership checks, and downloadable build evidence.
- CI artifact previews and a separately guarded manual PyPI publishing workflow.
  The workflow requires explicit owner configuration and confirmation.
- User guides covering installation, provider configuration, CLI output, and
  the first explicitly owned secure gateway deployment.

#### Changed

- Use the FuzzyRoutines-style FL logo family and clearer guide navigation.
- Align Markdown table columns by their contents and check formatting in CI.
- Document stable-tag installation and the released console command; include
  release history in source archives and generated documentation.

#### Security

- Reject unowned, modified, missing, or unsafe archive payloads and recognizable
  credential material; include the changelog as one explicitly owned root file.
- Preserve 1.0.0's resource ownership and mutation-consent requirements. GitHub
  release publication does not enable PyPI uploads or validate live cloud access.

## Minor 1.0

### Patch 0 — v1.0.0 — 2026-10-05

#### Digest

- Establish the first versioned F-Layer baseline for explicitly owned Yandex
  Cloud environments: configure, inspect, create and remove infrastructure,
  prepare a secure SSH gateway, and run bounded diagnostics.

#### Added

- Strict TOML configuration, explicit stack ownership, durable state, and
  separate desired/observed resource contracts.
- Yandex Cloud inventory and six-resource lifecycle support for networks,
  subnets, firewall groups, public addresses, boot disks, and instances.
- Recoverable create/status/destroy orchestration with scoped mutation consent,
  idempotency, interrupted-operation recovery, and reverse-order cleanup.
- A secure SSH gateway deployment profile, root-owned guest configuration,
  explicit administrator/device access rules, and verified owned artifacts.
- Local status/check commands and opt-in HTTP health/benchmark probes with
  bounded time, request count, and response size.
- English installed-wheel API documentation, Fuzzy Technologies branding,
  explicit RU/ZH unavailable-translation routes, and master-only Pages deployment.
- Offline test isolation, deterministic Python CI, linked-Task completion, and
  safe merged-branch cleanup.

#### Changed

- Replace bootstrap version metadata with the explicit 1.0.0 source/package
  identity. Include the changelog and gateway example in source distributions.
- Document milestone-scoped release selection and human-readable changelogs in
  ADR 0014; record the exact accepted source changes in the release notes.

#### Security

- Require explicit ownership and mutation consent before cloud changes;
  reject foreign resources and unsafe artifact substitutions.
- Persist only the resource identifiers needed for recovery and cleanup.
  Credentials, private keys, generated bundles, and local state stay untracked.
- Diagnostics do not discover targets implicitly. Cloud RUNNING status does not
  establish guest service readiness. Tests use isolated fakes rather than real
  cloud mutations; live deployment and SSH access are not release-gate evidence.

[v1.0.0]: https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.0.0

[v1.1.0]: https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.1.0

[v1.2.0]: https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.2.0
