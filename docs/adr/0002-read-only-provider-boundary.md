# ADR 0002: Establish a read-only provider boundary using explicit folder scope

- Status: Accepted
- Date: 2026-10-04
- Related issue: #19

## Context

A-VPN combines Yandex SDK discovery, authentication, deployment policy and resource mutation. F-Layer needs a provider-independent observation boundary before lifecycle orchestration can safely consume provider resources. Diagnostics and future lifecycle planning are distinct consumers. The first parallel implementation wave must not depend on unfinished core configuration or deployment-profile contracts.

Provider initialization must not inspect credentials or access infrastructure implicitly. Resource identifiers must retain their provider and scope, and failures must not leak captured CLI output. Real cloud access and mutation are outside this implementation's validation authorization.

## Decision

Create `flayer.providers.contracts` with immutable identities, resource references, normalized observations, capability declarations, probe results, sanitized failures and a structural `CloudProvider` protocol.

Implement the first adapter with the existing Yandex Cloud CLI through a standard-library, injectable `CommandRunner`. Require an explicit folder ID and profile selector. Use existing CLI authentication; do not export or persist credentials. Bound subprocess execution, close stdin, disable browser authentication and CLI retries, and execute without a shell.

Expose only local availability, folder-access probing, typed resource-kind listing, reference lookup and complete inventory composition. Support instances, disks, networks, subnets, reserved addresses and security groups. Preserve only normalized identifiers, names, states, zones, ownership labels and public IPv4 addresses. Do not retain raw provider metadata in resource objects.

Validate references before lookup and returned folder scope after every read because the CLI's resource-ID lookup may resolve across accessible folders. Reject possibly truncated lists instead of presenting them as complete. Propagate stable failure categories without vendor stdout/stderr or subprocess/JSON exception chains.

## Consequences

- Providers are independent of core configuration, deployment profiles, credentials and lifecycle mutation.
- Deterministic fakes can verify production command vectors and failure behavior without infrastructure access.
- No provider SDK or protobuf dependency is required for this first boundary.
- The adapter depends on an externally installed and authenticated `yc` CLI. Real account compatibility has not been exercised by this change.
- CLI JSON and error-marker compatibility require maintenance. Unrecognized failures retain a safe generic category.
- Saturated inventory is conservatively rejected, and sequential discovery is not an atomic snapshot.
- Resource names and labels remain public observations; owners must not use those fields to store credentials.
- Creation, mutation, cleanup, rollback, destructive authorization, idempotency and operation polling require explicit future contracts in issue #20.

## Alternatives considered

- **Immediate SDK extraction:** credible for lifecycle work, but introduces authentication/token handling, generated API dependencies and mutation concerns before the core boundary is settled.
- **Copying A-VPN's manager:** retains deployment-specific ownership and profile assumptions in the provider boundary.
- **Fake-only provider:** cannot verify a concrete production connector's scope selectors or CLI translation.
- **Raw JSON as observed state:** exposes unstable vendor structure and potentially secret metadata to all consumers.
- **Implicit profile folder:** hides scope selection and cannot prove that a caller intended the observed account boundary.

## Validation

Unit tests exercise immutable identity, invalid selectors, capability declarations, all supported resource commands, availability and folder access, complete inventory, ID lookup, cross-folder rejection, saturation, malformed JSON/resources/endpoints, duplicate IDs, timeouts, subprocess argument safety and sanitized errors. All execution boundaries are fake or monkeypatched. Run the repository's compile, Ruff, mypy and pytest gates before review.
