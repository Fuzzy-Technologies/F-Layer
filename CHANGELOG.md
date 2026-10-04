# F-Layer Changelog

A chronological record of shipped F-Layer behavior, compatibility, documentation,
and security boundaries. Release entries follow [ADR 0014](docs/adr/0014-scoped-releases-and-changelog.md).

# Major 1

The first versioned infrastructure foundation. Operational validation against a
real cloud account remains the operator's responsibility.

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
