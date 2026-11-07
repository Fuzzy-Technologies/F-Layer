"""Read complete public WG origins for planning without creating state, returning keys or weakening source/history admission."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_protocol_completion_codec import Envelope
from test_protocol_preparation import Generation
from test_protocol_preparation_lifecycle import Setup
from test_protocol_rpc import Frame, Operation
from test_protocol_runtime import NativeModel
from test_vpn_project_v2 import Snapshot

from flayer import _vpn_protocol_transport as transport
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_rpc as rpc
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers
from flayer.profiles.vpn import VpnError

POSIX = pytest.mark.skipif(os.name != "posix", reason="Origin observation uses real isolated POSIX locks; no WSL or desktop networking is used")


def Result(operation: dict[str, Any], *, completed: bool = False) -> dict[str, Any]:
    """Provide only public synthetic receipts; this fixture never claims that its metadata proves an actual server."""

    intent = operation["intent"]
    active = intent["wireguard_state"] == "active"
    receipt = Envelope("inactive")[0]["request"]["generation"]["cached_receipt"] if active else None
    head = {"name": "done-" + "b" * 32 + ".json", "sha256": "c" * 64} if completed else None

    return {"status": "protocol-origin-observation", "head": head, "authority_sha256": head["sha256"] if head else authority._Initial(guest, intent),
            "history_sha256": intent["wireguard_history_sha256"], "wireguard_state": intent["wireguard_state"],
            "wireguard_receipt": receipt, "completion_count": 1 if completed else 0}


@pytest.mark.parametrize("phase", ["active", "inactive"])
@pytest.mark.parametrize("completed", [False, True])
def test_OriginReceiptAndCommonHeadAreOneClosedRequestBoundPublicObservation(phase: str, completed: bool) -> None:
    """An active source has a full installed receipt; absence remains explicit and no file body or key can enter the model."""

    operation = Operation("origin-status", phase)

    if completed:
        operation["intent"]["previous_authority_sha256"] = "c" * 64

    result = Result(operation, completed=completed)
    assert transport.Decode(operation, Frame(operation, result), 0) == result


@pytest.mark.parametrize("fault", ["body", "schema", "path", "files", "mutation", "source", "private"])
def test_MalformedOriginOrMutationConsentIsRejectedBeforeProgramPacking(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """The observation surface cannot be repurposed as arbitrary file access or a reserved mutation."""

    operation = Operation("origin-status", "inactive")

    if fault == "body":
        operation["body"] = None
    elif fault == "schema":
        operation["body"]["schema_version"] = True
    elif fault == "path":
        operation["body"]["path"] = "/private-marker"
    elif fault == "files":
        operation["body"]["source_files"] = {"/private-marker": "a" * 64}
    elif fault == "mutation":
        operation.update(allow_mutation=True, scope_confirm=operation["identity"]["scope_id"])
    elif fault == "source":
        operation["sources"] = [{"private": "private-marker"}]
    else:
        operation["bundles"] = [{"private": "private-marker"}]

    monkeypatch.setattr(transport.receiver, "Programs", lambda: pytest.fail("Invalid origin must not reach packing"))

    with pytest.raises(VpnError) as failure:
        transport.Encode(operation)

    assert failure.value.__context__ is None and "private-marker" not in str(failure.value)


@pytest.mark.parametrize("fault", ["head", "authority", "expected-authority", "count", "bool-count", "history", "state", "receipt", "private", "file", "extra"])
def test_AnAuthenticatedReplyCannotRebindTheOriginReceiptHeadOrSource(fault: str) -> None:
    """Closed raw JSON and matching transport identity still require the exact expected WG receipt and history."""

    operation = Operation("origin-status", "inactive")
    operation["intent"]["previous_authority_sha256"] = "c" * 64
    result = Result(operation, completed=True)

    if fault == "head":
        result["head"]["name"] = "../private-marker"
    elif fault == "authority":
        result["authority_sha256"] = "0" * 64
    elif fault == "expected-authority":
        operation["intent"]["previous_authority_sha256"] = authority._Initial(guest, operation["intent"])
    elif fault == "count":
        result["completion_count"] = 0
    elif fault == "bool-count":
        result["completion_count"] = True
    elif fault == "history":
        result["history_sha256"] = "0" * 64
    elif fault == "state":
        result["wireguard_state"] = "absent"
    elif fault == "receipt":
        result["wireguard_receipt"] = None
    elif fault == "private":
        result["wireguard_receipt"]["private_key"] = "private-marker"
    elif fault == "file":
        result["wireguard_receipt"]["files"]["server.conf"] = "0" * 64
    else:
        result["private_key"] = "private-marker"

    with pytest.raises(VpnError) as failure:
        transport.Decode(operation, Frame(operation, result), 0)

    assert failure.value.__context__ is None and "private-marker" not in str(failure.value)


@pytest.mark.parametrize("fault", ["source", "absence", "backend"])
def test_InvalidSourceOrMissingTrustedBackendCannotInspectAnyGuestLock(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Only valid input and an explicit package-selected backend may proceed beyond the pure observation model."""

    operation = Operation("origin-status", "active" if fault == "absence" else "inactive")

    if fault == "source":
        operation["body"]["source_files"]["unexpected"] = "a" * 64
    elif fault == "absence":
        operation["intent"]["wireguard_absence_sha256"] = "0" * 64

    monkeypatch.setattr(authority, "_Locks", lambda *args, **kwargs: pytest.fail("Refused observation must not access guest locks"))

    with pytest.raises(ValueError):
        authority.OriginStatus(guest, peers, operation["intent"], operation["body"]["source_files"], runtimeBackend=None if fault == "backend" else runtime)


def Environment(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> tuple[Any, Any, dict[str, Any], dict[str, str], dict[str, bytes]]:
    """Reuse real temporary owned roots and the independent native unit/cgroup model without a preparation write."""

    model, selected, files = Setup(tmpPath, monkeypatch, kind)
    intent = {**selected["origin"], "plan_sha256": "f" * 64}
    controller = NativeModel(model, {"generation": Generation(selected)}, monkeypatch)
    groups = tmpPath / "origin-cgroups"
    groups.mkdir(mode=0o755)
    (groups / "cgroup.controllers").write_bytes(b"cpu memory\n")
    monkeypatch.setattr(runtime, "CGROUPS", groups)
    monkeypatch.setattr(guest, "_Run", controller.Run)
    sources = selected["source_files"] if kind == "disable" else {}

    return model, controller, intent, sources, files


@POSIX
@pytest.mark.parametrize("kind", ["fresh", "disable"])
@pytest.mark.parametrize("cancelled", [False, True])
def test_OriginReadsActualUnreservedAuthorityAndReceiptWithoutCreatingRepairingOrReturningKeys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, cancelled: bool) -> None:
    """The pointer remains available after a common cancellation; healthy origin proof and metadata-only status stay distinct."""

    _, _, intent, sources, files = Environment(tmp_path, monkeypatch, kind)

    if cancelled:
        authority.Reserve(guest, peers, intent, allowMutation=True)
        cancelledRecord = authority.Cancel(guest, peers, intent, allowMutation=True)
        intent = {**intent, "operation_id": "d" * 32, "wireguard_history_sha256": peers._History(guest, intent["owner"]),
                  "previous_authority_sha256": cancelledRecord["authority_sha256"]}

    before = Snapshot(tmp_path)
    monkeypatch.setattr(guest, "_SyncDirectory", lambda *args: pytest.fail("Read-only origin must not synchronize or repair state"))
    monkeypatch.setattr(authority, "_Publish", lambda *args, **kwargs: pytest.fail("Read-only origin must not publish metadata"))
    monkeypatch.setattr(guest, "_Fetch", lambda *args: pytest.fail("Origin observation must not fetch build evidence"))
    result = authority.OriginStatus(guest, peers, intent, sources, runtimeBackend=runtime)
    assert result["wireguard_state"] == intent["wireguard_state"] and result["completion_count"] == int(cancelled)
    assert (result["head"] is not None) == cancelled and Snapshot(tmp_path) == before

    if kind == "disable":
        key = next(line.split(b" = ", 1)[1] for line in files["server.conf"].splitlines() if line.startswith(b"PrivateKey = "))
        assert key not in rpc.Json(result)
        assert guest._Digest(rpc.Json(result["wireguard_receipt"])) == intent["wireguard_receipt_sha256"]

    else:
        assert result["wireguard_receipt"] is None

        if not cancelled:
            assert not guest.LOCK.exists() and not guest.LOCK.with_name("flayer-ingress.lock").exists()


@POSIX
@pytest.mark.parametrize("fault", ["history", "source", "pending", "job", "pid", "quiescent"])
def test_UnreservedOriginRefusesDriftPendingAuthorityAndNonterminalServiceWithoutRepair(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Matching file digests alone cannot turn queued or inactive native state into the origin of a new plan."""

    model, controller, intent, sources, _ = Environment(tmp_path, monkeypatch, "disable")

    if fault == "history":
        intent["wireguard_history_sha256"] = "0" * 64
    elif fault == "source":
        sources = {**sources, "server.conf": "0" * 64}
    elif fault == "pending":
        authority.Reserve(guest, peers, intent, allowMutation=True)
    elif fault == "job":
        controller.jobs[controller.oldUnit.name] = "123"
    elif fault == "pid":
        controller.mains[controller.oldUnit.name] = "123"
    else:
        model.active = False
        model.interface = None
        model.network = False
        controller.active[controller.oldUnit.name] = False

    before = Snapshot(tmp_path)

    with pytest.raises(ValueError):
        authority.OriginStatus(guest, peers, intent, sources, runtimeBackend=runtime)

    assert Snapshot(tmp_path) == before


@POSIX
@pytest.mark.parametrize("kind", ["fresh", "disable"])
def test_AdvancedCommonAuthorityRefusesAStaleProbeBeforeReadingItsOtherwiseUnchangedOrigin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Absence may leave H unchanged across cancellation; the expected common authority still cannot be silently refreshed."""

    _, _, intent, sources, _ = Environment(tmp_path, monkeypatch, kind)
    authority.Reserve(guest, peers, intent, allowMutation=True)
    authority.Cancel(guest, peers, intent, allowMutation=True)
    intent = {**intent, "operation_id": "d" * 32, "wireguard_history_sha256": peers._History(guest, intent["owner"])}
    before = Snapshot(tmp_path)
    monkeypatch.setattr(authority, "_Observe", lambda *args: pytest.fail("Stale common authority must refuse before inspecting the original WG state"))

    with pytest.raises(authority.ReservationError):
        authority.OriginStatus(guest, peers, intent, sources, runtimeBackend=runtime)

    assert Snapshot(tmp_path) == before
