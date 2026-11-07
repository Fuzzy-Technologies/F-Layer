"""Recover only an exact already-exposed original WG identity, with real POSIX metadata and intercepted effects."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import test_protocol_generation_cache as cacheFixtures
import test_protocol_generation_input as inputFixtures
from test_protocol_runtime import Execute, Input, NativeModel
from test_vpn_project_v2 import Snapshot
from test_wireguard_generation_lifecycle import PublishFixture
from test_wireguard_peer_lifecycle import Interrupted

from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_generation as generations
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Origin recovery uses POSIX fixture locks/files; no WSL, desktop client or real network command is used")


def Environment(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, schema: int = 1) -> tuple[Any, Any, NativeModel, dict[str, Any], dict[str, Any], Path, Path | None]:
    """Expose the same complete plan against either a legacy or nonce-bound installed original, before caching or input changes."""

    active = cacheFixtures.Active

    def Active(path: Path, patch: pytest.MonkeyPatch) -> Any:
        """Install a synthetic schema-2 original before reservation rather than altering an already-authorized plan."""

        model, desired, intent = active(path, patch)
        source = tmpPath / "original-generation"
        source.mkdir(mode=0o700)
        helper = Path(guest.__file__).read_bytes()
        receipt = generations.PrepareCached(guest, model.root, source, guest._Digest((model.root / "receipt.json").read_bytes()),
                                           "1" * 32, helper, guest._Digest(helper))
        original = guest._Run

        def Run(command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
            """Keep the fixture's separate forwarding model synchronized during the one-time original-generation setup."""

            if command[:3] == ["nft", "delete", "table"]:
                model.network = False

                return 0, b""

            if command[:2] == ["nft", "-f"] and command[-1] != "-":
                model.policy = Path(command[-1]).read_bytes()
                model.network = True

                return 0, b""

            return original(command, payload=payload, **options)

        with patch.context() as callback:
            callback.setattr(guest, "_Run", Run)
            PublishFixture(model, source, receipt, callback)
            guest._GenerationCallback(model.root, model.unit, receipt["nonce"], start=True)

        model.active = True
        intent["wireguard_receipt_sha256"] = guest._Digest((model.root / "receipt.json").read_bytes())
        intent["wireguard_history_sha256"] = peers._History(guest, model.owner)

        return model, desired, intent

    if schema == 2:
        monkeypatch.setattr(cacheFixtures, "Active", Active)

    model, network, request, intent, cached, candidate = inputFixtures.Environment(tmpPath, monkeypatch, version=3)
    controller = NativeModel(model, request, monkeypatch)
    groups = tmpPath / "cgroup"
    groups.mkdir(mode=0o755)
    (groups / "cgroup.controllers").write_bytes(b"cpu memory\n")
    monkeypatch.setattr(runtime, "CGROUPS", groups)

    def Run(command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
        """Model the real runner's inactive service error instead of an assertion reserved for healthy-only fixture callers."""

        if command[:2] == ["systemctl", "is-active"] and not controller.active.get(command[-1]):
            if options.get("required", True):
                raise guest.GuestError("Synthetic selected service is inactive")

            return 3, b""

        return controller.Run(command, payload=payload, **options)

    monkeypatch.setattr(guest, "_Run", Run)

    return model, network, controller, request, intent, cached, candidate


def Cache(request: dict[str, Any], intent: dict[str, Any], cached: Path | None, candidate: Path | None) -> dict[str, str]:
    """A trusted runtime backend is an explicit dependency and cannot be selected by request JSON."""

    return cache.Prepare(guest, peers, authority, policy, request, intent, cached, candidate, allowMutation=True, runtimeBackend=runtime)


def PrepareInput(request: dict[str, Any], intent: dict[str, Any]) -> dict[str, str]:
    """Keep the existing exact cache contract and permit only verified pre-native quiescence."""

    return inputs.Prepare(guest, peers, authority, policy, request, intent, allowMutation=True, generationCache=cache, runtimeBackend=runtime)


def Stop(model: Any, controller: NativeModel) -> None:
    """Model complete owned kernel loss and an inactive original unit without changing files, keys or history."""

    model.interface, model.addresses, model.configured = None, [], False
    model.network, model.active = False, False
    controller.active[controller.oldUnit.name] = False


@pytest.mark.parametrize("schema", [1, 2])
@pytest.mark.parametrize("prefix", ["exposed", "cached", "input-prepared", "input-applied", "ready"])
@pytest.mark.parametrize("rollback", [False, True])
def test_ExactQuiescentOriginalRecoversEveryPreNativePrefixWithoutChangingCredentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, schema: int, prefix: str, rollback: bool,
) -> None:
    """The old healthy-only observer refuses the stopped original; the exposed native plan can retire or restore its exact identity."""

    model, network, controller, request, intent, cached, candidate = Environment(tmp_path, monkeypatch, schema)
    original = Snapshot(model.root)
    unrelated = model.unrelated, network.unrelated

    if prefix != "exposed":
        Cache(request, intent, cached, candidate)

    if prefix in {"input-prepared", "input-applied", "ready"}:
        PrepareInput(request, intent)

    if prefix in {"input-applied", "ready"}:
        Input(request, intent)

    if prefix == "ready":
        publish = authority._Publish

        def Publish(receiver: Any, filename: str, record: dict[str, Any], **kwargs: Any) -> None:
            """Interrupt the first native journal, before retirement or any lock handoff."""

            publish(receiver, filename, record, **kwargs)

            if filename == "runtime.json" and record["phase"] == "ready":
                raise Interrupted

        with monkeypatch.context() as crash:
            crash.setattr(authority, "_Publish", Publish)

            with pytest.raises(Interrupted):
                Execute(controller, request, intent)

    Stop(model, controller)
    before, effects = Snapshot(tmp_path), tuple(controller.effects)

    with authority._Locks(guest, readOnly=True):
        with pytest.raises(ValueError):
            authority._Observe(guest, peers, intent)

        observed = runtime.Origin(guest, peers, authority, request, intent)

    assert observed["phase"] == "quiescent" and observed["history_sha256"] == guest._ProtocolHistory(intent, request)
    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects

    if prefix == "ready":
        assert runtime.Status(guest, peers, authority, policy, cache, request, intent)["phase"] == "recovery-required"

    else:
        assert Cache(request, intent, cached, candidate)["phase"] == "prepared"
        assert PrepareInput(request, intent)["phase"] == ("applied" if prefix == "input-applied" else "prepared")
        assert Input(request, intent)["phase"] == "applied"

    result = Execute(controller, request, intent, rollback=rollback)
    assert result["phase"] == ("restored" if rollback else "inactive")
    assert not controller.oldUnit.exists() and (model.unrelated, network.unrelated) == unrelated

    if rollback:
        installed = json.loads((model.root / "receipt.json").read_bytes())
        assert installed == {**request["generation"]["candidate_receipt"], "status": "installed"}
        retained = Snapshot(model.root)

        for name in ("server.conf", "deployment.json", "install.py", "wg", "COPYING"):
            assert retained[name] == original[name]

        assert result["history_sha256"] == runtime._FreshHistory(guest, request, intent)
        assert Input(request, intent, rollback=True)["phase"] == "rolled-back"

    else:
        assert not model.root.exists() and model.interface is None and not model.network

    assert Execute(controller, request, intent, rollback=rollback) == result


@pytest.mark.parametrize("openInput", [False, True])
def test_AnUnchangedRollbackThatLaterBecomesQuiescentRestoresOnlyItsFreshPreplannedIdentity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, openInput: bool,
) -> None:
    """A previous healthy unchanged result is not a health exemption after kernel loss, including after input restoration."""

    model, _, controller, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Cache(request, intent, cached, candidate)
    PrepareInput(request, intent)
    Input(request, intent)
    assert Execute(controller, request, intent, rollback=True)["phase"] == "unchanged"

    if openInput:
        Input(request, intent, rollback=True)

    Stop(model, controller)
    before = Snapshot(tmp_path)
    assert runtime.Status(guest, peers, authority, policy, cache, request, intent)["phase"] == "recovery-required"
    assert Snapshot(tmp_path) == before
    result = Execute(controller, request, intent, rollback=True)
    assert result["phase"] == "restored" and result["history_sha256"] == runtime._FreshHistory(guest, request, intent)
    assert controller.active[controller.newUnit.name] and not controller.oldUnit.exists()
    assert Input(request, intent, rollback=True)["phase"] == "rolled-back"


@pytest.mark.parametrize("phase", ["removing-original", "stopping-original", "inactive", "publishing", "starting", "restored"])
@pytest.mark.parametrize("temporary", [False, True])
def test_InterruptedQuiescentRestorationKeepsAlreadyRestoredInputAcrossEveryForwardPublication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str, temporary: bool,
) -> None:
    """A complete next journal temp and a canonical next phase both retain the exact previously restored input transaction."""

    model, _, controller, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Cache(request, intent, cached, candidate)
    PrepareInput(request, intent)
    Input(request, intent)
    assert Execute(controller, request, intent, rollback=True)["phase"] == "unchanged"
    restored = Input(request, intent, rollback=True)
    boot = inputs.BOOT.read_bytes()
    Stop(model, controller)
    publish, replace = authority._Publish, authority.os.replace

    def Publish(receiver: Any, filename: str, record: dict[str, Any], **kwargs: Any) -> None:
        """Die only after the selected exact canonical next phase has become visible."""

        publish(receiver, filename, record, **kwargs)

        if filename == "runtime.json" and record["phase"] == phase:
            raise Interrupted

    def Replace(source: Any, destination: Any, *args: Any, **kwargs: Any) -> None:
        """Leave the exact complete next temporary publication beside its preceding canonical journal."""

        if Path(destination) == authority._Root(guest) / "runtime.json" and authority._Decode(guest, Path(source))["phase"] == phase:
            raise Interrupted

        replace(source, destination, *args, **kwargs)

    with monkeypatch.context() as crash:
        if temporary:
            crash.setattr(authority.os, "replace", Replace)

        else:
            crash.setattr(authority, "_Publish", Publish)

        with pytest.raises(Interrupted):
            Execute(controller, request, intent, rollback=True)

    assert inputs.BOOT.read_bytes() == boot
    result = Execute(controller, request, intent, rollback=True)
    assert result["phase"] == "restored" and result["history_sha256"] == runtime._FreshHistory(guest, request, intent)
    assert inputs.Status(guest, peers, authority, policy, request, intent, generationCache=cache, runtimeBackend=runtime) == restored
    assert inputs.BOOT.read_bytes() == boot and controller.active[controller.newUnit.name]
    assert not controller.oldUnit.exists()


def test_RestoredInputWithoutItsNativeRecordCannotAcquireFirstAdmission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The continuation exception needs the recorded rollback; losing that journal cannot recreate new native authority."""

    _, _, controller, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Cache(request, intent, cached, candidate)
    PrepareInput(request, intent)
    Input(request, intent)
    assert Execute(controller, request, intent, rollback=True)["phase"] == "unchanged"
    Input(request, intent, rollback=True)
    (authority._Root(guest) / "runtime.json").unlink()
    before, effects = Snapshot(tmp_path), tuple(controller.effects)

    with pytest.raises(ValueError, match="input phase"):
        Execute(controller, request, intent, rollback=True)

    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects


@pytest.mark.parametrize("fault", ["interface", "table", "job", "main", "control", "cgroup", "foreign-file", "history"])
def test_QuiescentOriginNeverAdoptsPartialOrForeignStateBeforeNativeAdmission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Quiescence needs complete files/kernel absence, exact history and a recursively empty drained native identity."""

    model, _, controller, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Cache(request, intent, cached, candidate)
    PrepareInput(request, intent)
    Input(request, intent)
    interface = model.interface
    Stop(model, controller)

    if fault == "interface":
        model.interface = interface

    elif fault == "table":
        model.network = True

    elif fault == "job":
        controller.jobs[controller.oldUnit.name] = "123"

    elif fault == "main":
        controller.mains[controller.oldUnit.name] = "123"

    elif fault == "control":
        controller.controls[controller.oldUnit.name] = "123"

    elif fault == "cgroup":
        group = runtime.CGROUPS / "system.slice" / controller.oldUnit.name
        group.mkdir(parents=True)
        (group / "cgroup.events").write_bytes(b"populated 1\nfrozen 0\n")

    elif fault == "foreign-file":
        (model.root / "foreign.txt").write_bytes(b"preserve unknown data")

    else:
        monkeypatch.setattr(peers, "_History", lambda *args: "0" * 64)

    before, effects = Snapshot(tmp_path), tuple(controller.effects)

    with pytest.raises(ValueError):
        Execute(controller, request, intent)

    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects
    assert model.root.exists() and controller.oldUnit.exists()


def test_QuiescenceCannotBypassTheInitialHealthyExposureAdmission(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The recovery observer only accepts an already-exposed exact plan; ordinary reservation and exposure keep their original checks."""

    model, _, controller, request, intent, _, _ = Environment(tmp_path, monkeypatch)
    Stop(model, controller)
    root = authority._Root(guest)
    pending = authority._Decode(guest, root / "pending.json")
    authority._Publish(guest, "pending.json", {**pending, "phase": "reserved"})
    before = Snapshot(tmp_path)

    with authority._Locks(guest, readOnly=True):
        with pytest.raises(ValueError):
            runtime.Origin(guest, peers, authority, request, intent)

    with pytest.raises(ValueError):
        authority.Expose(guest, peers, intent, guest._Digest(guest._Encode({**pending, "phase": "reserved"})), allowMutation=True)

    assert Snapshot(tmp_path) == before


def test_QuiescenceCannotAcquireAnInitialReservation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No exposed journal exists here: a stopped original cannot obtain new protocol authority through the recovery extension."""

    model, _, intent = cacheFixtures.Active(tmp_path, monkeypatch)
    model.interface, model.addresses, model.configured = None, [], False
    model.network, model.active = False, False
    original = guest._Run

    def Run(command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
        """Expose the original pre-reservation service failure through the same sanitized runner contract."""

        if command[:2] == ["systemctl", "is-active"]:
            raise guest.GuestError("Synthetic selected service is inactive")

        return original(command, payload=payload, **options)

    monkeypatch.setattr(guest, "_Run", Run)

    with authority._Locks(guest, readOnly=False):
        pass

    before = Snapshot(tmp_path)

    with pytest.raises(ValueError):
        authority.Reserve(guest, peers, intent, allowMutation=True)

    assert Snapshot(tmp_path) == before
