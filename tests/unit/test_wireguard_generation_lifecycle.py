"""Exercise actual private generation files with synthetic service/kernel effects on POSIX only."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_wireguard_lifecycle import Seed
from test_wireguard_peer_lifecycle import Environment

from flayer.profiles import _wireguard_generation as generations
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private generation/lock tests require POSIX; no desktop VPN is started")


def Candidate(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Path, dict[str, Any], dict[str, bytes]]:
    """Build a real unpublished candidate while every command remains intercepted by the guest model."""

    stage, request, model = Seed(tmpPath, monkeypatch)
    guest._Install(stage, request)
    original = {path.name: path.read_bytes() for path in model.root.iterdir()}
    destination = tmpPath / "candidate"
    destination.mkdir(mode=0o700)
    maintenance = (stage / "install.py").read_bytes()
    receipt = generations.PrepareCached(guest, model.root, destination, guest._Digest(original["receipt.json"]),
                                       "2" * 32, maintenance, guest._Digest(maintenance))

    return model, destination, receipt, original


def PublishFixture(model: Any, candidate: Path, receipt: dict[str, Any], monkeypatch: pytest.MonkeyPatch, *, staged: bool = False) -> None:
    """Install only test fixture files; production generation publication remains unavailable."""

    request = guest._Request(model.root)[0]
    guest._Stop(model.root, model.unit, request)
    model.active = False
    model.root.rename(model.root.parent.parent.parent.parent / "cached-root")
    model.unit.unlink()
    guest._Publish(candidate, model.root)
    guest._Atomic(model.unit, (model.root / "service.service").read_bytes(), 0o644)
    guest._Atomic(model.root / "receipt.json", guest._Encode(receipt if staged else {**receipt, "status": "installed"}))
    monkeypatch.setattr(guest, "__file__", str(model.root / "lifecycle.py"))


def test_CachedPreparationPreservesSourceCredentialsRuntimeAndKernelEvidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Change only nonce, scoped policy/unit and helper; never fetch, build, generate keys or publish active state."""

    model, candidate, receipt, original = Candidate(tmp_path, monkeypatch)
    assert {path.name: path.read_bytes() for path in model.root.iterdir()} == original
    assert model.active and model.interface is not None
    assert receipt["status"] == "staged" and receipt["nonce"] != json.loads(original["receipt.json"])["nonce"]
    assert set(receipt["files"]) == guest._GENERATION_FILES
    assert receipt["kernel"] == json.loads(original["receipt.json"])["kernel"]
    assert receipt["build"] == json.loads(original["receipt.json"])["build"]

    for name in ("server.conf", "deployment.json", "install.py", "wg", "COPYING"):
        assert (candidate / name).read_bytes() == original[name]

    assert guest._Request(candidate)[0] == model.request
    assert guest._Receipt(candidate, candidate / ".unpublished-unit", model.owner, staged=True) == receipt
    assert not guest._Paths(model.owner)[2].exists()


@pytest.mark.parametrize("fault", ["receipt", "nonce", "maintenance", "extra", "kernel", "source", "canonical"])
def test_CachedCandidateRefusesDriftWithoutTouchingTheSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """No incomplete or independently changed cache grants a complete new candidate."""

    model, _, _, original = Candidate(tmp_path, monkeypatch)
    destination = tmp_path / "second"
    destination.mkdir(mode=0o700)
    maintenance = original["install.py"]
    expected = guest._Digest(original["receipt.json"])
    nonce = "3" * 32
    digest = guest._Digest(maintenance)

    if fault == "receipt":
        expected = "f" * 64

    elif fault == "nonce":
        nonce = json.loads(original["receipt.json"])["nonce"]

    elif fault == "maintenance":
        digest = "f" * 64

    elif fault == "extra":
        (destination / "foreign").write_bytes(b"retained")

    elif fault == "kernel":
        monkeypatch.setattr(guest, "_KernelFacts", lambda: {"release": "changed"})

    elif fault == "source":
        (model.root / "COPYING").write_bytes(b"changed")

    else:
        (model.root / "receipt.json").write_bytes(b" " + original["receipt.json"])

    snapshot = {path.name: path.read_bytes() for path in model.root.iterdir()}
    before = len(model.commands)

    with pytest.raises(guest.GuestError):
        generations.PrepareCached(guest, model.root, destination, expected, nonce, maintenance, digest)

    assert {path.name: path.read_bytes() for path in model.root.iterdir()} == snapshot
    assert not (destination / "receipt.json").exists()
    assert len(model.commands) == before


def test_NonceBoundCallbacksStartStopAndRefuseStaleOrUnboundActions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delayed old callback cannot mutate a later generation sharing the same owner and unit name."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)
    options = ["--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]
    assert guest.Main(["--start", *options]) == 0
    model.active = True
    assert guest._Check(model.root, model.unit, model.request)["schema_version"] == 2
    assert guest.Main(["--stop", *options]) == 0
    assert model.interface is None and not model.network and model.forwarding
    before = len(model.commands)
    assert guest.Main(["--start", "--allow-mutation", "--expected-generation-nonce", "1" * 32]) == 1
    assert guest.Main(["--start", "--allow-mutation"]) == 1
    assert guest.Main(["--status", "--expected-generation-nonce", receipt["nonce"]]) == 1
    monkeypatch.setattr(guest, "__file__", str(model.root / "install.py"))
    assert guest.Main(["--start", *options]) == 1
    assert len(model.commands) == before and guest._callbackFds == ()


def test_CallbackChecksNonceInsideTheExistingWgLockAndKeepsItAcrossAllCommands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lock contention refuses; each native subprocess runs while the exact protecting lock remains held."""

    import fcntl

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)
    descriptor = guest._OpenLock(readOnly=False)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    options = ["--start", "--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]
    before = len(model.commands)

    try:
        assert guest.Main(options) == 1
        assert len(model.commands) == before

    finally:
        os.close(descriptor)

    original = model.Run

    def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        assert len(guest._callbackFds) == 1
        os.fstat(guest._callbackFds[0])
        probe = guest._OpenLock(readOnly=False)

        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

        finally:
            os.close(probe)

        return original(command, **kwargs)

    monkeypatch.setattr(guest, "_Run", Run)
    assert guest.Main(options) == 0
    assert len(model.commands) > before and guest._callbackFds == ()


@pytest.mark.parametrize("fault", ["helper", "unit", "missing-helper", "pending"])
def test_CallbackRejectsDriftAndUnintegratedReservationsBeforeRuntimeMutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Do not turn a schema-2 receipt or current nonce into permission to bypass pending protocol coordination."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)

    if fault == "pending":
        ingress = guest.BASE.parent / "ingress"
        ingress.mkdir(mode=0o700)
        (ingress / "pending.json").write_bytes(b"retained unknown outcome")

    elif fault == "missing-helper":
        (model.root / "lifecycle.py").unlink()

    else:
        (model.root / ("lifecycle.py" if fault == "helper" else "service.service")).write_bytes(b"foreign")

    before = len(model.commands)
    assert guest.Main(["--start", "--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]) == 1
    assert len(model.commands) == before and guest._callbackFds == ()


def test_StagedGenerationNeedsItsExactJournalAndCannotUseOrdinaryRemovalRecovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provisional service callbacks require their complete receipt; old maintenance cannot erase generation evidence."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch, staged=True)
    _, _, transaction = guest._Paths(model.owner)
    transaction.mkdir(mode=0o700)
    journal = {"schema_version": 1, "owner": model.owner, "phase": "prepared", "receipt": receipt}
    guest._Atomic(transaction / "transaction.json", guest._Encode(journal))
    assert guest.Main(["--start", "--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]) == 0
    before = len(model.commands)

    with pytest.raises(guest.GuestError, match="protocol coordinator"):
        guest._Recover(model.owner, guest._Digest(guest._Encode(receipt)))

    guest._Atomic(transaction / "transaction.json", guest._Encode({**journal, "phase": "cleanup"}))
    assert guest.Main(["--stop", "--allow-mutation", "--expected-generation-nonce", receipt["nonce"]]) == 1
    assert len(model.commands) == before


def test_OrdinaryRemovalCannotPublishAProtocolGenerationCleanupJournal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unsupported legacy path refuses before retaining a misleading removal intent or stopping a service."""

    model, candidate, receipt, _ = Candidate(tmp_path, monkeypatch)
    PublishFixture(model, candidate, receipt, monkeypatch)
    before = len(model.commands)

    with pytest.raises(guest.GuestError, match="protocol coordinator"):
        guest._Remove(model.owner, guest._Digest((model.root / "receipt.json").read_bytes()))

    assert len(model.commands) == before and not guest._Paths(model.owner)[2].exists()


@pytest.mark.parametrize("action", ["enroll", "revoke"])
def test_PeerChangesPreserveTheGenerationHelperAndNonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    """The actual peer transaction carries all eight pinned files without authorizing runtime/helper replacement."""

    model, desired, _, _ = Environment(tmp_path, monkeypatch, action)
    candidate = tmp_path / "candidate"
    candidate.mkdir(mode=0o700)
    helper = (model.root / "install.py").read_bytes()
    receipt = generations.PrepareCached(guest, model.root, candidate, guest._Digest((model.root / "receipt.json").read_bytes()),
                                       "2" * 32, helper, guest._Digest(helper))
    # This fixture upgrades only private root metadata and the already synthetic policy/interface marker.
    old = model.root.parent / "old-fixture"
    model.root.rename(old)
    guest._Publish(candidate, model.root)
    receipt = {**receipt, "status": "installed"}
    guest._Atomic(model.root / "receipt.json", guest._Encode(receipt))
    guest._Atomic(model.unit, (model.root / "service.service").read_bytes(), 0o644)
    model.policy = (model.root / "firewall.nft").read_bytes()
    model.interface["ifalias"] = guest._Alias(model.owner, receipt["nonce"])
    expected = guest._Digest(guest._Encode(receipt))
    peers._Cancel(guest, receipt, "revoke", "protocol-" + "2" * 32, peers._History(guest, model.owner))
    history = peers._History(guest, model.owner)
    assert peers.Apply(guest, desired, action, model.deviceId, expected, history) == "applied"
    observed = guest._Check(model.root, model.unit, guest._Request(model.root)[0])
    assert observed["nonce"] == receipt["nonce"] and observed["files"]["lifecycle.py"] == receipt["files"]["lifecycle.py"]
    assert (model.root / "lifecycle.py").read_bytes() == helper
