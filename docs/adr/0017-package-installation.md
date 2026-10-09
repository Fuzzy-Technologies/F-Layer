# ADR 0017: Package installation and the optional VPN dependency

## Status

Proposed for release 2.0.

## Context

F-Layer already builds reproducible wheels and source distributions. Its user
instructions still require a source checkout, obscuring the installed application
contract. The release-2.0 gateway workflow also needs local generation of VPN keys,
while diagnostics and other core consumers do not need a cryptography dependency.
PyPI publishing automation exists, but account ownership and the first upload have
not been verified.

## Decision

Use the existing `f-layer` distribution and `flayer` console command as the normal
installation interface. Recommend pipx for the command and pip in a virtual
environment for Python consumers. Official GitHub release wheels provide the
immediate installation channel. Installation by PyPI package name becomes a
supported documented channel only after verified publication.

Add a `vpn` optional extra pinned to `cryptography==50.0.2`, the current released
version verified against the upstream changelog on 2026-10-09. Keep the minimal
core free of required third-party runtime dependencies; VPN code imports its
cryptography backend only when needed. Include the same dependency in the
existing `dev` extra so the standard test environment covers VPN behavior. This
extends ADR 0009's zero-dependency contract without changing core installation.

Run distribution integration tests against the exact audited wheel and sdist
before release preview upload and before PyPI publication. Rebuild parity, isolated
core installation, console execution and dependency checks are required. Install
the VPN extra into a separate fresh environment using predownloaded binary wheels;
verify the backend can generate the keys required by the protocols. Installation
checks must not use editable source imports or access a real cloud account.

Keep the explicit owner-controlled OIDC publication contract from ADR 0008. Do not
create account ownership, upload a package or advertise an unverified PyPI name as
an implementation side effect. The initial gateway controller is supported on
Linux and WSL because its private artifact handling relies on POSIX permissions.
A container image is not part of this distribution decision.

## Consequences

Users can install a reviewed release without Git or development dependencies. VPN
users explicitly install the cryptography extra, and the dependency resolver can
select compatible binary wheels for their platform. The source distribution
remains available for rebuilding. The controlled CI gate covers both installed
variants using the artifacts that publication will upload.

The first PyPI publication remains a concrete release task involving verified
project ownership and a configured publisher. Wheel availability alone does not
prove successful real-cloud deployment or VPN client interoperability; those are
separate acceptance checks for release 2.0.

## Alternatives

A source checkout as the primary installation path exposes build tooling to every
user. A mandatory cryptography dependency adds unused code for core consumers.
A Docker-only controller complicates access to the user's cloud CLI profile and
private project files. Automatic uploads on every tag would remove the existing
owner publication gate.

## References

- [Distribution and installation](../development/distribution.md)
- [ADR 0008](0008-reproducible-release-automation.md)
- [ADR 0009](0009-distribution-version-source.md)
- [Cryptography changelog](https://cryptography.io/en/latest/changelog/)
