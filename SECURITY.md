# Security Policy

## Reporting a vulnerability

Do not publish exploitable vulnerability details, credentials, tokens, private keys, or sensitive provider information in a public issue.

Use GitHub private security reporting when available. Until that channel is enabled, contact the repository owner through a private Fuzzy Technologies channel.

## Scope

Security reports should describe vulnerabilities in F-Layer itself: its code, generated artifacts, provider integration boundaries, lifecycle behavior, configuration/state handling, or release artifacts.

Misconfiguration or compromise of infrastructure independently managed by a user is not automatically an F-Layer vulnerability, although reproducible unsafe defaults or defects in generated configuration should be reported.

## Development boundary

Tests must not mutate or probe real third-party infrastructure without explicit authorization. Use repository-defined synthetic fixtures, mocks, and isolated test resources by default.
