"""Tests for the F-Layer package bootstrap contract."""

import flayer


def test_PackageImports() -> None:
    """The top-level package imports without exposing accidental public symbols."""

    assert flayer.__all__ == [], "Bootstrap package unexpectedly exposes public symbols"
