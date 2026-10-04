# ADR 0008: Reproducible distributions and explicit owner publication

## Status

Accepted for implementation; PyPI account configuration remains an owner action.

## Context

F-Layer has local/CI Python and documentation gates and safe post-merge Task and
branch housekeeping. A package release additionally needs evidence that its wheel
and source distribution own only accepted project files, carry one consistent
version, rebuild consistently, and belong to the stable branch. Publishing a
bootstrap package or automatically uploading on every tag would exceed that
contract. Package ownership on PyPI has not yet been configured or verified.

## Decision

Build read-only previews from clean tracked-file snapshots on PRs and integration
pushes. Fix timestamps from the source commit, require pinned Hatchling, compare two
independent builds byte for byte, and rebuild the wheel from the audited source
archive. Validate archive paths, member types/limits, source ownership, metadata,
common credential signatures, and complete wheel `RECORD` hashes. Emit SHA256 and
source/version/build evidence with the audited artifacts under ignored `_build`.

Accept the static bootstrap version only for previews. Tagged releases require a
non-bootstrap literal package version and static/dynamic metadata parity. Require
an annotated stable `vX.Y.Z` tag resolving to the exact checkout and current fetched
`origin/master`. Publication additionally requires a manual `master` dispatch in
the canonical repository by the configured release owner, affirmative per-run
confirmation, and an explicit repository-variable opt-in.

Keep build/test and upload jobs separate. Only the upload job receives OIDC
permission, downloads this run's audited artifacts, and invokes the pinned PyPA
publisher against the fixed production PyPI endpoint. It never checks out project
code. Use PyPI Trusted Publishing; configure no token, account, environment or
branch-protection prerequisite automatically. PR/tag validation never uploads.

## Consequences

- Read-only artifact validation is operational without a PyPI account.
- Metadata/source versions can migrate from bootstrap static metadata to the
  canonical Hatch package source without changing the release gate.
- Enabling publication requires deliberate owner configuration and manual dispatch;
  name availability, account ownership and real OIDC upload compatibility remain
  unverified until then.
- Stable releases cannot be cut from an old master commit or `develop` directly.
- Source review remains responsible for secrets whose arbitrary values do not match
  the limited credential signatures; no scanner can establish absence of every
  possible secret.
- Existing native Task/branch housekeeping remains unchanged. Feature/Milestone
  completion and GitHub Release creation are separate explicit operations.

## Alternatives

Automatic tag publication would remove the explicit per-release owner confirmation.
Token-based uploads would introduce persistent credentials. Building from the live
working tree could accidentally include ignored/private files. Metadata-only checks
would miss unsafe member names, altered package source or incomplete `RECORD` data.

## References

- [Release workflow](../RELEASE_WORKFLOW.md)
- [PyPI Trusted Publisher guidance](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
- [PyPA build/publish job separation](https://packaging.python.org/en/latest/guides/publishing-package-distribution-releases-using-github-actions-ci-cd-workflows/)
