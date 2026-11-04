# ADR 0021: Python naming and stable wire formats

- Status: Proposed
- Date: 2026-11-04
- Task: [#116](https://github.com/Fuzzy-Technologies/F-Layer/issues/116)

## Context

The owner requires camelCase owned variables, parameters and fields, PascalCase
functions/methods/types and UPPER_SNAKE_CASE constants. The foundation recorded
snake_case variables incorrectly and no CI gate checked the intended convention.
Dataclass field names also participate in JSON, private manifests and project
fingerprints, so renaming Python attributes alone would break durable contracts.

## Decision

Correct only the naming clauses of the policy under the owner's explicit
instruction. Refactor Python bindings, fields and keyword calls consistently,
including tests, stubs, fixtures and documentation examples. Imported external
names, registered framework hooks, external keyword arguments and CLI/TOML/JSON
names keep their external spelling.

Retain all existing wire schemas and ownership fingerprints. Serialization
boundaries use an internal dataclass adapter that maps owned camelCase fields
to their established snake_case wire names. Raw dictionary keys, including
protocol-native camelCase keys, are preserved. Public parsers/codecs remain the
supported interface for persisted data. Direct Python keyword and attribute
callers migrate to the new names; that source compatibility change is explicit.

Add a deterministic AST naming stage to the canonical local/CI gate. Review
external exceptions by exact source path and qualified definition rather than
broad path or underscore exemptions. Test violations and exceptions and compare
wire output against independent pre-refactor records.

## Consequences

This is a repository-wide source refactor with no deployment, network, key or
VPN-profile changes. The dedicated PR must pass the complete Linux quality,
distribution and documentation gates on its exact revision before review.
No merge, release or production acceptance follows from the refactor alone.
