"""Fence delayed peer work and copied controllers with durable common protocol authority, using no real networking."""

from __future__ import annotations

import copy
import os
import time
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project_v2 import Snapshot
from test_wireguard_lifecycle import Seed
from test_wireguard_peer_lifecycle import Envelope, Environment, Interrupted

from flayer.profiles import _protocol_reservation as reservations
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private guest reservation files require POSIX; no WSL or desktop network is started")


def Header(owner: str = "a" * 64) -> dict[str, Any]:
    """Build only public synthetic intent without observing any real guest path or resource."""

    value = {"schema_version": 1, "owner": owner, "creation_sha256": "b" * 64, "previous_authority_sha256": "c" * 64,
             "previous_state_sha256": "d" * 64, "operation_id": "e" * 32, "plan_sha256": "f" * 64, "plan_expires_at": int(time.time()) + 600,
             "wireguard_state": "active", "wireguard_receipt_sha256": "1" * 64, "wireguard_absence_sha256": "", "wireguard_history_sha256": "2" * 64}
    value["previous_authority_sha256"] = reservations._Initial(guest, value)

    return value


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("unknown", "suppressed-fixture"), ("owner", "../elsewhere"),
    ("creation_sha256", ["b" * 64]), ("previous_authority_sha256", "short"), ("previous_state_sha256", ""),
    ("operation_id", "../unknown"), ("operation_id", "f" * 33), ("plan_expires_at", True),
    ("wireguard_state", "assumed-running"), ("wireguard_state", "absent"),
    ("wireguard_absence_sha256", "3" * 64), ("wireguard_receipt_sha256", ""), ("wireguard_history_sha256", {}),
])
def test_IntentIsClosedBoundedAndRequiresActualActiveOrAbsentProofKinds(field: str, value: object) -> None:
    """Neither a fake running receipt nor an unknown private field can enter reservation metadata."""

    data = Header()
    data[field] = value

    with pytest.raises(reservations.ReservationError):
        reservations.Intent(data)


def test_CancellationFenceUsesTheExistingExactV1AuditWithoutAnyPrivateBody() -> None:
    """Old driver bytes recognize the changed history while original running/configuration receipts remain unchanged."""

    data = Header()
    expected = {"schema_version": 1, "owner": data["owner"], "action": "revoke", "device_id": "protocol-" + data["operation_id"],
                "previous_receipt_sha256": data["wireguard_receipt_sha256"], "receipt_sha256": data["wireguard_receipt_sha256"],
                "deployment_sha256": "3" * 64, "previous_history_sha256": data["wireguard_history_sha256"]}

    assert reservations._FencedHistory(guest, data, "3" * 64) == guest._Digest(guest._Encode(expected))
    absent = {**data, "wireguard_state": "absent", "wireguard_receipt_sha256": "", "wireguard_absence_sha256": "4" * 64}
    assert reservations.Intent(absent) == absent
    assert reservations._FencedHistory(guest, absent, "") == data["wireguard_history_sha256"]


def Active(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Path, dict[str, Any]]:
    """Install and independently model a synthetic WG service, then bind intent to its exact current receipt/history."""

    model, desired, receipt, _ = Environment(tmpPath, monkeypatch, "enroll")
    data = Header(model.originalRequest["owner"])
    data["wireguard_receipt_sha256"] = receipt
    data["wireguard_history_sha256"] = peers._History(guest, data["owner"])

    return model, desired, data


@POSIX
def test_ReservationFencesOldQueuedPeerWorkWithoutChangingKeysConfigRuntimeOrInput(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The reserved history rejects an already prepared old apply while all retained root and live model bytes stay unchanged."""

    model, desired, data = Active(tmp_path, monkeypatch)
    original = Snapshot(model.root)
    network, config = guest._Digest(model.policy), guest._Digest(model.kernelConfig)
    before = Snapshot(tmp_path)
    status = reservations.Status(guest, peers, data)
    assert status["phase"] == "initial" and Snapshot(tmp_path) == before
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    after = Snapshot(tmp_path)
    assert reservations.Reserve(guest, peers, data, allowMutation=True) == reserved
    assert Snapshot(tmp_path) == after
    assert reserved["history_sha256"] != data["wireguard_history_sha256"]
    assert peers._Audit(guest, data["owner"])["receipt_sha256"] == data["wireguard_receipt_sha256"]

    with pytest.raises(guest.GuestError):
        peers.Apply(guest, desired, "enroll", model.deviceId, data["wireguard_receipt_sha256"], data["wireguard_history_sha256"])

    with pytest.raises(guest.GuestError, match="protocol reservation"):
        peers._ProtocolGate(guest)

    assert Snapshot(model.root) == original and guest._Digest(model.policy) == network and guest._Digest(model.kernelConfig) == config
    assert reservations.Status(guest, peers, data)["reservation_sha256"] == reserved["reservation_sha256"]


@POSIX
def test_CopyCannotReplaceReservationAndCancellationConsumesAuthorityWithoutRestoringOldHistory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Copied local project locks cannot override the guest; exact cancellation retries keep one immutable completed generation."""

    model, _, data = Active(tmp_path, monkeypatch)
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    other = {**data, "operation_id": "f" * 32}
    before = Snapshot(tmp_path)

    with pytest.raises(reservations.ReservationError):
        reservations.Reserve(guest, peers, other, allowMutation=True)

    assert Snapshot(tmp_path) == before
    cancelled = reservations.Cancel(guest, peers, data, allowMutation=True)
    after = Snapshot(tmp_path)
    assert reservations.Cancel(guest, peers, data, allowMutation=True) == cancelled
    assert Snapshot(tmp_path) == after and cancelled["authority_sha256"] != data["previous_authority_sha256"]
    assert cancelled["history_sha256"] == reserved["history_sha256"]
    peers._ProtocolGate(guest)

    for request in (data, other):
        with pytest.raises(reservations.ReservationError):
            reservations.Reserve(guest, peers, request, allowMutation=True)

    nextIntent = {**other, "previous_authority_sha256": cancelled["authority_sha256"], "wireguard_history_sha256": cancelled["history_sha256"]}
    current = reservations.Reserve(guest, peers, nextIntent, allowMutation=True)
    assert current["history_sha256"] != cancelled["history_sha256"]
    assert reservations.Cancel(guest, peers, nextIntent, allowMutation=True)["authority_sha256"] != cancelled["authority_sha256"]
    assert reservations.Status(guest, peers, nextIntent)["completion_count"] == 2
    assert model.active


@POSIX
def test_ExposedAuthorizationNeverRepeatsOrCancelsOnAnOldLookingGuest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dispatch grant is consumed durably once; no claim about a later cloud outcome is inferred from unchanged local service bytes."""

    _, _, data = Active(tmp_path, monkeypatch)
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    exposed = reservations.Expose(guest, peers, data, reserved["reservation_sha256"], allowMutation=True)
    before = Snapshot(tmp_path)

    for action in (lambda: reservations.Expose(guest, peers, data, reserved["reservation_sha256"], allowMutation=True),
                   lambda: reservations.Cancel(guest, peers, data, allowMutation=True),
                   lambda: reservations.Reserve(guest, peers, data, allowMutation=True)):
        with pytest.raises(reservations.ReservationError):
            action()

    assert reservations.Status(guest, peers, data)["phase"] == "exposed" and Snapshot(tmp_path) == before
    assert exposed["history_sha256"] == reserved["history_sha256"]


@POSIX
def test_FullyWrittenExposureBeforeRenameIsAlreadyUncertainAndCannotGrantAgain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A lost local publication acknowledgment cannot silently turn an exposed temporary prefix into an undispatched reservation."""

    _, _, data = Active(tmp_path, monkeypatch)
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    original = reservations.os.replace

    def Fail(source: Any, destination: Any) -> None:
        """Interrupt before the exact exposed journal rename, leaving its complete canonical private bytes."""

        path = Path(source)

        if path.name == ".pending.json.new" and reservations._Decode(guest, path)["phase"] == "exposed":
            raise OSError("Synthetic exposure publication interruption")

        original(source, destination)

    monkeypatch.setattr(reservations.os, "replace", Fail)

    with pytest.raises(OSError, match="Synthetic exposure"):
        reservations.Expose(guest, peers, data, reserved["reservation_sha256"], allowMutation=True)

    monkeypatch.setattr(reservations.os, "replace", original)
    before = Snapshot(tmp_path)
    assert reservations.Status(guest, peers, data)["phase"] == "exposed"

    for action in (lambda: reservations.Expose(guest, peers, data, reserved["reservation_sha256"], allowMutation=True),
                   lambda: reservations.Cancel(guest, peers, data, allowMutation=True)):
        with pytest.raises(reservations.ReservationError):
            action()

    assert Snapshot(tmp_path) == before


@POSIX
def test_NormalPeerAndMaintenanceEntrypointsRefusePendingAuthorityButAllowHistoryObservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Actual entrypoints check the reservation under existing WG coordination instead of bypassing it via a direct SDK command."""

    model, desired, data = Active(tmp_path, monkeypatch)
    reservations.Reserve(guest, peers, data, allowMutation=True)
    Envelope(tmp_path, monkeypatch, model, desired)
    before = Snapshot(tmp_path)
    arguments = ["--change", "enroll", "--device-id", model.deviceId]

    assert peers.Main(["--status", *arguments]) == 1
    assert "protocol reservation" in capsys.readouterr().err
    assert peers.Main(["--history-status", *arguments]) == 0
    assert "history_sha256" in capsys.readouterr().out

    with pytest.raises(guest.GuestError, match="protocol reservation"):
        guest._ProtocolGate()

    assert Snapshot(tmp_path) == before


@POSIX
def test_CommonThenWgCoordinationProtectsTheActualFenceAndRejectsAnotherController(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both real advisory locks remain held while the legacy-compatible audit is published, without a reverse lock order."""

    import fcntl

    _, _, data = Active(tmp_path, monkeypatch)
    original = peers._Cancel
    observed = []

    def Fence(*args: Any, **options: Any) -> None:
        """A second independent handle cannot obtain either mutating coordination lock during the history change."""

        for path in (guest.LOCK.with_name("flayer-ingress.lock"), guest.LOCK):
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)

            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

                observed.append(path.name)

            finally:
                os.close(descriptor)

        original(*args, **options)

    monkeypatch.setattr(peers, "_Cancel", Fence)
    reservations.Reserve(guest, peers, data, allowMutation=True)
    assert observed == ["flayer-ingress.lock", guest.LOCK.name]


@POSIX
def test_AbsentWgUsesActualNamespaceAbsenceAndNeverCreatesARunningReceipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No WG root, interface, unit or owned NAT table is created merely to serialize a different protocol's intent."""

    _, request, model = Seed(tmp_path, monkeypatch)
    owner = request["owner"]
    data = Header(owner)
    data.update(wireguard_state="absent", wireguard_receipt_sha256="", wireguard_absence_sha256=guest._AbsenceDigest(owner),
                wireguard_history_sha256=peers._History(guest, owner))
    root, unit, _ = guest._Paths(owner)
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    cancelled = reservations.Cancel(guest, peers, data, allowMutation=True)

    assert reserved["history_sha256"] == data["wireguard_history_sha256"] == cancelled["history_sha256"]
    assert not root.exists() and not unit.exists() and not model.network and not model.active
    assert peers._Audit(guest, owner) is None


@POSIX
@pytest.mark.parametrize("boundary", ["before-fence", "after-fence", "reserved-record", "cancelling-record", "completion-record", "head-record", "journal-removal"])
def test_RecoveryRetainsExactAuthorityAcrossEveryReservationAndCancellationPublicationBoundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """A complete unpublished record can finish only its own reservation/cancellation, without repeating a fence or granting a stale dispatch."""

    _, _, data = Active(tmp_path, monkeypatch)
    originalPublish, originalCancel, originalSync = reservations._Publish, peers._Cancel, guest._SyncDirectory
    failure = {"triggered": False}

    def Publish(current: Any, filename: str, record: dict[str, Any], *, immutable: bool = False) -> None:
        """Interrupt after one exact durable metadata boundary."""

        originalPublish(current, filename, record, immutable=immutable)
        point = ("reserved-record" if filename == "pending.json" and record["phase"] == "reserved" else
                 "cancelling-record" if filename == "pending.json" and record["phase"] == "cancelling" else
                 "completion-record" if immutable else "head-record" if filename == "head.json" else "")

        if point == boundary and not failure["triggered"]:
            failure["triggered"] = True
            raise Interrupted

    def Fence(*args: Any, **options: Any) -> None:
        """Model process death immediately before or after the legacy-compatible audit fence."""

        if boundary == "before-fence" and not failure["triggered"]:
            failure["triggered"] = True
            raise Interrupted

        originalCancel(*args, **options)

        if boundary == "after-fence" and not failure["triggered"]:
            failure["triggered"] = True
            raise Interrupted

    def Sync(path: Path) -> None:
        """Model a lost acknowledgment after actual journal retirement."""

        originalSync(path)

        if (boundary == "journal-removal" and path == reservations._Root(guest) and not (path / "pending.json").exists()
                and (path / "head.json").exists() and not failure["triggered"]):
            failure["triggered"] = True
            raise Interrupted

    monkeypatch.setattr(reservations, "_Publish", Publish)
    monkeypatch.setattr(peers, "_Cancel", Fence)
    monkeypatch.setattr(guest, "_SyncDirectory", Sync)

    with pytest.raises(Interrupted):
        reservations.Reserve(guest, peers, data, allowMutation=True)
        reservations.Cancel(guest, peers, data, allowMutation=True)

    monkeypatch.setattr(reservations, "_Publish", originalPublish)
    monkeypatch.setattr(peers, "_Cancel", originalCancel)
    monkeypatch.setattr(guest, "_SyncDirectory", originalSync)

    if boundary in {"before-fence", "after-fence", "reserved-record"}:
        reservations.Reserve(guest, peers, data, allowMutation=True)

    result = reservations.Cancel(guest, peers, data, allowMutation=True)
    assert failure["triggered"] and reservations.Status(guest, peers, data)["completion_count"] == 1
    assert reservations.Cancel(guest, peers, data, allowMutation=True) == result


@POSIX
@pytest.mark.parametrize("fault", ["pending-peer", "receipt", "history", "expired", "consent", "lost-head", "unknown-file"])
def test_UnprovedOrExpiredIntentAndMissingAuthorityNeverMutateOrAdoptGuestState(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """No parent, key/configuration, completed proof or unrelated file is silently replaced during refusal."""

    _, _, data = Active(tmp_path, monkeypatch)

    if fault == "pending-peer":
        guest._Paths(data["owner"])[2].mkdir(mode=0o700)

    elif fault in {"receipt", "history"}:
        data["wireguard_" + fault + "_sha256"] = "3" * 64

    elif fault == "expired":
        data["plan_expires_at"] = int(time.time())

    elif fault in {"lost-head", "unknown-file"}:
        reservations.Reserve(guest, peers, data, allowMutation=True)
        completed = reservations.Cancel(guest, peers, data, allowMutation=True)
        data.update(previous_authority_sha256=completed["authority_sha256"], wireguard_history_sha256=completed["history_sha256"], operation_id="f" * 32)

        if fault == "lost-head":
            (reservations._Root(guest) / "head.json").unlink()
            data["previous_authority_sha256"] = reservations._Initial(guest, data)

        else:
            guest._Atomic(reservations._Root(guest) / "unknown.json", b"{}\n")

    before = Snapshot(guest.BASE)
    common = reservations._Root(guest)
    beforeCommon = Snapshot(common) if common.exists() else {}

    with pytest.raises((reservations.ReservationError, guest.GuestError)):
        reservations.Reserve(guest, peers, data, allowMutation=fault != "consent")

    assert Snapshot(guest.BASE) == before
    assert (Snapshot(common) if common.exists() else {}) == beforeCommon


@POSIX
def test_DispatchExpiryAndCapacityAreCheckedBeforeGrantingAuthority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A fenced but expired reservation can only cancel, and history capacity cannot authorize an unreadable completion chain."""

    _, _, data = Active(tmp_path, monkeypatch)
    reserved = reservations.Reserve(guest, peers, data, allowMutation=True)
    monkeypatch.setattr(reservations.time, "time", lambda: data["plan_expires_at"])

    with pytest.raises(reservations.ReservationError):
        reservations.Expose(guest, peers, data, reserved["reservation_sha256"], allowMutation=True)

    completed = reservations.Cancel(guest, peers, data, allowMutation=True)
    following = {**data, "operation_id": "f" * 32, "previous_authority_sha256": completed["authority_sha256"], "wireguard_history_sha256": completed["history_sha256"],
                 "plan_expires_at": data["plan_expires_at"] + 600}
    monkeypatch.setattr(reservations, "MAX_COMPLETIONS", 1)

    with pytest.raises(reservations.ReservationError):
        reservations.Reserve(guest, peers, following, allowMutation=True)

    assert reservations.Cancel(guest, peers, data, allowMutation=True) == completed


def test_IntentCopyCannotCarryMutablePrivateExtensionData() -> None:
    """Only exact primitive fields survive a caller-owned dictionary copy."""

    data = Header()
    copyValue = reservations.Intent(data)
    data["owner"] = "different"
    assert copyValue["owner"] == "a" * 64
    extended = copy.deepcopy(copyValue)
    extended["private_key"] = "suppressed-fixture"

    with pytest.raises(reservations.ReservationError):
        reservations.Intent(extended)
