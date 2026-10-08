# Documentation dependency security

The documentation toolchain is locked in `docs/requirements-api.txt`. Its
dependencies are development/build tools; the `f-layer` runtime distribution
has no runtime dependencies and continues to use the reviewed Hatchling backend.

## Setuptools advisory remediation

[Task #54](https://github.com/Fuzzy-Technologies/F-Layer/issues/54) tracks
[Dependabot alert #1](https://github.com/Fuzzy-Technologies/F-Layer/security/dependabot/1)
for [GHSA-h35f-9h28-mq5c / CVE-2026-59890](https://github.com/advisories/GHSA-h35f-9h28-mq5c).
The release-1.2 correction changes the exact setuptools pin from `80.9.0` to
the patched `83.0.0` release while preserving the other documentation pins.

The advisory concerns Unicode normalization collisions in setuptools
`MANIFEST.in` exclusion matching on macOS APFS/HFS+. Intended excluded files can
enter a source archive. F-Layer's own distributions use Hatchling and explicit
tracked-payload audits; the alert identifies a vulnerable documentation-tool
dependency, rather than evidence that a F-Layer archive leaked private data.

## Validation and release follow-up

Install the exact documentation lock in a disposable environment and verify
dependency compatibility and documentation imports. Local development runs
targeted checks; PR CI builds the strict installed-wheel EN/RU/ZH-CN site and
audits release distributions using the same locked tools.

The correction enters `develop` through its Task PR. Dependabot scans the default
branch, so an open alert remains expected while released `master` still carries
the previous pin. When the release-1.2 selection reaches master, inspect the
default-branch dependency graph and alert status again. Do not manually dismiss
the alert as fixed before the patched dependency is present there.

Published 1.0.0 and 1.1.0 tags remain historical. New remediation evidence belongs
to the new source revision and release; it does not rewrite earlier artifacts.
