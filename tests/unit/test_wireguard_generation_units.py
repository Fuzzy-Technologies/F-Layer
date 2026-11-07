"""Prove generation-specific unit selection and stale-name refusal with isolated POSIX files only."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_wireguard_generation_lifecycle import Candidate, PublishFixture
from test_wireguard_lifecycle import Seed

from flayer.profiles import _wireguard_guest as guest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owned unit/lock fixtures require POSIX; no desktop network is used")


def test_ReceiptSelectsExactGenerationAndEveryHealthCommandUsesItsUnit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default metadata selection is not health; full validation targets the exact nonce-specific service."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    legacy = guest._Paths(model.owner)[1]
    PublishFixture(model, candidate, receipt, monkeypatch)
    assert guest._ActivePaths(model.owner)[1] == model.unit != legacy
    assert model.unit.name.endswith("-" + receipt["nonce"] + ".service")
    assert guest.Main(["--start", "--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]) == 0
    model.active = True
    before = len(model.commands)
    assert guest._Status(model.root, model.request)["status"] == "active"
    units = [command[-1] for command in model.commands[before:] if command[0] == "systemctl"]
    assert units == [model.unit.name, model.unit.name]
    assert legacy not in guest._OwnedUnits(model.owner)


@pytest.mark.parametrize("stale", ["legacy", "generation", "broken-link", "unknown"])
def test_ForeignOrOldUnitNamesBlockHealthAndCannotReceiveTheNewGeneration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale: str,
) -> None:
    """Retain stale names for explicit recovery; neither adoption nor deleting another generation is implicit."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)
    name = guest._Paths(model.owner)[1].name if stale == "legacy" else guest._Paths(model.owner, nonce="1" * 32)[1].name
    path = guest.SYSTEMD / (guest._Service(model.owner) + "-unknown" if stale == "unknown" else name)

    if stale == "broken-link":
        path = guest.SYSTEMD / "multi-user.target.wants" / name
        path.symlink_to(guest.SYSTEMD / name)

    else:
        path.write_bytes(b"foreign unit bytes")
        path.chmod(0o644)

    before = len(model.commands)

    with pytest.raises(guest.GuestError, match="namespace"):
        guest._Check(model.root, model.unit, model.request)

    if stale == "legacy":
        # Even copied current bytes cannot make the stable legacy name an alias for this generation.
        path.write_bytes((model.root / "service.service").read_bytes())

        with pytest.raises(guest.GuestError, match="generation"):
            guest._Receipt(model.root, path, model.owner)

    assert len(model.commands) == before and (path.exists() or path.is_symlink())


@pytest.mark.parametrize("stale", ["unit", "enablement", "unknown"])
def test_AbsentRootDoesNotHideRetainedGenerationUnitsOrAllowAFreshInstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale: str,
) -> None:
    """Complete absence and ordinary installation refuse any retained owner unit before build or native mutation."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    path = guest._Paths(model.owner, nonce="1" * 32)[1]

    if stale == "enablement":
        parent = guest.SYSTEMD / "multi-user.target.wants"
        parent.mkdir(mode=0o755)
        path = parent / path.name
        path.symlink_to(guest.SYSTEMD / path.name)

    else:
        if stale == "unknown":
            path = path.with_name(guest._Service(model.owner) + "-foreign")

        path.write_bytes(b"retained unit")
        path.chmod(0o644)

    with pytest.raises(guest.GuestError, match="not completely absent"):
        guest._RequireAbsent(model.owner)

    before = len(model.commands)

    with pytest.raises(guest.GuestError, match="occupied"):
        guest._Install(stage, request)

    assert len(model.commands) == before and not guest.BASE.exists()
    assert path.exists() or path.is_symlink()


def test_UnitSelectionDoesNotAdoptChangedReceiptBytesAsHealthyState(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A safe path selector grants no ownership or runtime authority for a forged nonce."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)
    forged = {**receipt, "status": "installed", "nonce": "3" * 32}
    guest._Atomic(model.root / "receipt.json", guest._Encode(forged))
    assert guest._ActivePaths(model.owner)[1] == guest._Paths(model.owner, nonce="3" * 32)[1]
    before = len(model.commands)

    with pytest.raises(guest.GuestError):
        guest._Check(model.root, model.unit, model.request)

    assert len(model.commands) == before


@pytest.mark.parametrize("count", [4096, 4097])
def test_UnitNamespaceEnumerationHasABoundedReadBudget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int,
) -> None:
    """Stop before scanning an unbounded systemd namespace, without opening unrelated unit content."""

    _, _, model = Seed(tmp_path, monkeypatch)
    original = Path.iterdir

    def Entries(path: Path) -> Any:
        if path == guest.SYSTEMD:
            return (path / ("unrelated-" + str(index)) for index in range(count))

        return original(path)

    monkeypatch.setattr(Path, "iterdir", Entries)

    if count == 4096:
        assert guest._OwnedUnits(model.owner) == frozenset()

    else:
        with pytest.raises(guest.GuestError, match="bound"):
            guest._OwnedUnits(model.owner)
