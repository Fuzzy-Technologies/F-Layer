"""Regress the independently reviewed native-generation recovery, ownership and durability boundaries."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from test_protocol_runtime import Environment, Execute, Input
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Native fault tests use POSIX files/locks and fully intercepted service/network effects")


@pytest.mark.parametrize("fault", ["old-contract", "historical-helper"])
def test_HistoricalPreparationCannotAcquireNativePermissionBeforeOriginalDisarm(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """The old helper's exact valid cache remains readable, but it cannot satisfy first native admission."""

    helper = b"# Historical callback refuses all pending common reservations.\n" if fault == "historical-helper" else None
    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, version=2 if fault == "old-contract" else 3, helper=helper)
    before = Snapshot(tmp_path)
    effects = tuple(controller.effects)

    with pytest.raises(runtime.RuntimeError):
        Execute(controller, request, intent)

    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects
    assert model.active and model.interface is not None and model.network
    assert not (authority._Root(guest) / "runtime.json").exists()


def test_AdmittedCompatibleAbiCanRecoverAfterReceiverSourceUpdateWithoutReplacingItsCandidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact source attestation gates first admission; durable admitted-helper identity permits the same ABI's later receiver."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch)
    Execute(controller, request, intent)
    admitted = request["generation"]["candidate_receipt"]["files"]["lifecycle.py"]
    updated = guest.BASE / "compatible-receiver.py"
    updated.write_bytes(Path(guest.__file__).read_bytes() + b"\n# Compatible receiver build fixture.\n")
    updated.chmod(0o600)
    monkeypatch.setattr(guest, "__file__", str(updated))
    controller.program = guest._Digest(updated.read_bytes())
    assert controller.program != admitted
    result = Execute(controller, request, intent, rollback=True)
    assert result["phase"] == "restored" and model.active
    assert guest._Digest((model.root / "lifecycle.py").read_bytes()) == admitted
    assert authority._Decode(guest, authority._Root(guest) / "runtime.json")["admitted_program_sha256"] == admitted


@pytest.mark.parametrize("fault", ["reset-peers", "reset-addresses"])
def test_InterruptedInstalledRemovalNeverAdoptsPartialKernelDrift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Original removal can delete the whole interface; resetting individual peer/address policy is not its known prefix."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch)
    write = runtime._Write

    def Write(*arguments: Any, **options: Any) -> dict[str, Any]:
        record = write(*arguments, **options)

        if record["phase"] == "removing-original":
            raise Interrupted

        return record

    with monkeypatch.context() as crash:
        crash.setattr(runtime, "_Write", Write)

        with pytest.raises(Interrupted):
            Execute(controller, request, intent)

    if fault == "reset-peers":
        controller.resetPeers = True

    else:
        model.addresses = []

    before = Snapshot(tmp_path)
    effects = tuple(controller.effects)

    with pytest.raises(ValueError):
        Execute(controller, request, intent)

    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects
    assert model.interface is not None and model.network and controller.oldUnit.exists()


@pytest.mark.parametrize("fault", ["job", "main", "control", "cgroup"])
def test_UnknownNativeWorkBlocksUnitRetirementAndFreshRestoration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """A client return or inherited descriptor alone cannot prove that PID1 callbacks and descendants have drained."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch)
    controller.fault = "after-stop"

    with pytest.raises(Interrupted):
        Execute(controller, request, intent)

    if fault == "cgroup":
        directory = runtime.CGROUPS / "system.slice" / controller.oldUnit.name
        directory.mkdir(parents=True, mode=0o755)
        events = directory / "cgroup.events"
        events.write_bytes(b"populated 1\nfrozen 0\n")
        events.chmod(0o644)

    else:
        {"job": controller.jobs, "main": controller.mains, "control": controller.controls}[fault][controller.oldUnit.name] = "17"

    with pytest.raises(runtime.RuntimeError):
        Execute(controller, request, intent, rollback=True)

    assert not model.root.exists() and controller.oldUnit.exists() and not controller.newUnit.exists()
    assert not any(action == "start" for action, _ in controller.effects)
    controller.jobs.clear()
    controller.mains.clear()
    controller.controls.clear()

    if fault == "cgroup":
        events.write_bytes(b"populated 0\nfrozen 0\n")

    assert Execute(controller, request, intent, rollback=True)["phase"] == "restored"
    assert not controller.oldUnit.exists() and controller.newUnit.exists()


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_RebootAfterCompleteTerminalTemporaryCanRecoverMetadataBeforeActivationHealth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """The exact forward journal temp can block boot callbacks; recovery must not require the activation it prevents."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, change)

    if change == "disable":
        Execute(controller, request, intent)

    publish = authority._Publish
    terminal = "active" if change == "enable" else "restored"
    fired = False

    def Publish(backend: Any, filename: str, record: dict[str, Any], **options: Any) -> None:
        nonlocal fired

        if filename == "runtime.json" and record["phase"] == terminal and not fired:
            fired = True
            path = authority._Root(guest) / ".runtime.json.new"
            path.write_bytes(guest._Encode(record))
            path.chmod(0o600)

            raise Interrupted

        publish(backend, filename, record, **options)

    with monkeypatch.context() as crash:
        crash.setattr(authority, "_Publish", Publish)

        with pytest.raises(Interrupted):
            Execute(controller, request, intent, rollback=change == "disable")

    assert fired
    model.interface, model.network, model.addresses, model.configured, model.active = None, False, [], False, False
    controller.active[controller.newUnit.name] = False
    observed = runtime.Status(guest, peers, authority, policy, cache, request, intent)
    assert observed["phase"] == "recovery-required"
    assert Execute(controller, request, intent, rollback=change == "disable")["phase"] == terminal
    assert model.interface is not None and model.network and model.active
    assert not (authority._Root(guest) / ".runtime.json.new").exists()


@pytest.mark.parametrize("target", ["root", "unit"])
@pytest.mark.parametrize("status", ["staged", "installed"])
def test_IdenticalBytePayloadReplacementCannotCrossAPinnedPublicationBarrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str, status: str,
) -> None:
    """Hash equality does not make a new inode durable; the actual published generation is protected through final acknowledgment."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, "enable")
    published = runtime._Published
    sync = os.fsync
    inside = False
    fired = False

    @contextmanager
    def Published(*arguments: Any, **options: Any) -> Iterator[None]:
        nonlocal inside
        inside = True

        try:
            with published(*arguments, **options):
                yield

        finally:
            inside = False

    def Sync(descriptor: int) -> None:
        nonlocal fired
        sync(descriptor)

        if inside and not fired and Path(os.readlink("/proc/self/fd/" + str(descriptor))) == model.root:
            receipt = guest._Json((model.root / "receipt.json").read_bytes())

            if receipt["status"] == status:
                fired = True
                path = model.root / "server.conf" if target == "root" else controller.newUnit
                replacement = path.parent / ".replacement"
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(path.stat().st_mode & 0o777)
                os.replace(replacement, path)

    with monkeypatch.context() as fault:
        fault.setattr(runtime, "_Published", Published)
        fault.setattr(os, "fsync", Sync)

        with pytest.raises(runtime.RuntimeError):
            Execute(controller, request, intent)

    assert fired
    record = authority._Decode(guest, authority._Root(guest) / "runtime.json")
    assert record["phase"] not in {"active", "restored"}
    assert Execute(controller, request, intent)["phase"] == "active"


def test_UnknownFileAppearingDuringCandidateCleanupIsNeverEnumeratedIntoDeletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use only the validated selected member set; a later entry survives and prevents directory retirement."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, "enable")
    Execute(controller, request, intent)
    Input(request, intent, rollback=True)
    prefix = runtime._CandidatePrefix
    foreign = model.root / "foreign-file"
    fired = False

    def Prefix(*arguments: Any, **options: Any) -> set[str]:
        nonlocal fired
        names = prefix(*arguments, **options)

        if not fired and model.interface is None:
            fired = True
            foreign.write_bytes(b"foreign-owned-byte-canary")
            foreign.chmod(0o600)

        return names

    monkeypatch.setattr(runtime, "_CandidatePrefix", Prefix)

    with pytest.raises((runtime.RuntimeError, OSError)):
        Execute(controller, request, intent, rollback=True)

    assert fired and foreign.read_bytes() == b"foreign-owned-byte-canary"
    assert authority._Decode(guest, authority._Root(guest) / "runtime.json")["phase"] == "removing-candidate"
