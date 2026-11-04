"""Typed boundary for the semantically preserved corporate locale validator port."""

import ast
from argparse import Namespace
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT: Path
PROJECT_MANIFEST: Path
HASH_SCHEME: str

@dataclass(frozen=True)
class CanonicalUnit:
    """Canonical English page or symbol, discovered without runtime imports."""

    identifier: str
    kind: str
    sourcePath: str
    signature: str
    body: str

@dataclass(frozen=True)
class ValidationReport:
    """Deterministic diagnostics and computed translation states."""

    diagnostics: tuple[str, ...]
    states: dict[str, dict[str, str]]

def CanonicalHash(unit: CanonicalUnit) -> str:
    """Compute the unchanged fuzzy-doc-unit-v1 source hash."""

    ...

def DiscoverCanonicalUnits(
    projectRoot: Path,
    projectManifest: dict[str, Any],
    knownPageIds: dict[str, str] | None = ...,
) -> tuple[CanonicalUnit, ...]:
    """Discover authored English pages and statically declared API symbols."""

    ...

def ValidateLocales(
    projectRoot: Path = ...,
    projectManifestPath: Path | None = ...,
) -> ValidationReport:
    """Validate hashes, review evidence, terminology, and explicit missing states."""

    ...

def ParseArguments(arguments: Sequence[str] | None = ...) -> Namespace:
    """Parse the stable locale-validator command interface."""

    ...

def Main(arguments: Sequence[str] | None = ...) -> int:
    """Run inventory or deterministic locale validation."""

    ...


def _AuthoredUnits(moduleName: str, sourcePath: Path, projectRoot: Path) -> tuple[CanonicalUnit, ...]:
    """Discover exact public authored contracts for generated-reference translation."""

    ...


def _NodeUnit(identifier: str, sourcePath: str, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> CanonicalUnit:
    """Bind statically rendered constructor prose to its exact callable signature."""

    ...
