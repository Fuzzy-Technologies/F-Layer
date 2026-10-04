# ADR 0009: One source for distribution and runtime versions

- Status: Accepted
- Date: 2026-10-04
- Task: [#25](https://github.com/Fuzzy-Technologies/F-Layer/issues/25)

## Context

F-Layer needs buildable distributions and a console command before release
automation is enabled. Duplicating versions in package metadata and source
would make artifact and release-tag parity harder to verify.

## Decision

Keep a literal `__version__` in the top-level package. Hatchling reads it with
its regex source rather than executing runtime code. Declare the project
version dynamic and keep release versions in the existing `X.Y.Z` convention.
Preserve the bootstrap value `0.0.0` until an explicit reviewed version bump.

Provide the `flayer` console script through the existing `Main()` CLI, retain
zero runtime dependencies, and ship the PEP 561 type marker. Add distribution
metadata without claiming that PyPI publication has happened.

## Consequences

Wheel metadata, sdist metadata and runtime version have one source. Offline
tests install the actual wheel and rebuild it from the sdist, so missing
sources, package data or entry points become validation failures. Repository
examples join the explicit sdist include list.

## Alternatives

A duplicated static version permits drift. A Git-derived version couples
rebuilds to Git metadata and does not suit a clean exported sdist. An executing
version plugin can import provider/runtime code during packaging.

## Compatibility

Existing Python modules and `python -m flayer` remain available. `flayer` is an
additional installed entry point; `__version__` is additive metadata. No tag,
release or real package publication is created by this change.
