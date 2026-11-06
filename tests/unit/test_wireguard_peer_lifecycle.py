"""Exercise actual peer transaction files and atomic publication with entirely simulated guest networking."""

from __future__ import annotations

import copy
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_wireguard_lifecycle import Seed

from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers
from flayer.profiles.vpn import VpnDevice
from flayer.profiles.wireguard import GenerateWireGuardMaterial, WireGuardSettings

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Atomic guest filesystem tests require POSIX; no WSL or desktop VPN is started")


class Interrupted(BaseException):
    """Model process death that cannot trigger controller exception handling."""


def Environment(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, action: str) -> tuple[Any, Path, str, bytes]:
    """Install in private temporary files, then model independent kernel configuration and scoped nft policy."""

    from test_wireguard_guest import Prepared

    stage, request, model = Seed(tmpPath, monkeypatch)
    guest._Install(stage, request)
    root, unit, _ = guest._Paths(request["owner"])
    original = model.Run
    model.kernelConfig = (root / "server.conf").read_bytes()
    model.kernelRequest = request
    model.policy = (root / "firewall.nft").read_bytes()
    model.unrelated = b"unrelated AWG/VLESS policy and credentials"
    model.events = []
    model.failure = ""
    model.failed = False

    def Point(name: str) -> None:
        """Interrupt once at a named actual transition boundary."""

        if model.failure == name and not model.failed:
            model.failed = True

            raise Interrupted

    def Run(command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
        """Keep kernel/nft state independent from the currently published private directory."""

        name = Path(command[0]).name

        if name == "wg" and command[1] == "syncconf":
            Point("before-wg")
            model.events.append("wg")
            directory = Path(command[-1]).parent
            model.kernelConfig = (directory / "server.conf").read_bytes()
            model.kernelRequest = json.loads((directory / "deployment.json").read_bytes())
            Point("after-wg")

            return 0, b""

        if name == "wg" and command[1] == "show":
            private, public, entries = guest._Config(model.kernelConfig, model.kernelRequest, root / "wg")
            lines = [f"{private}\t{public}\t{model.kernelRequest['port']}\toff"]
            lines.extend(f"{key}\t{value[0]}\t(none)\t{value[1]}\t0\t0\t0\toff" for key, value in entries.items())

            return 0, ("\n".join(lines) + "\n").encode()

        if name == "nft":
            assert command == ["nft", "-f", "-"] and payload is not None
            prefix = ("delete table ip " + guest._Table(request["owner"]) + "\n").encode()
            assert payload.startswith(prefix) and b"flush ruleset" not in payload
            Point("before-nft")
            model.events.append("nft")
            model.policy = payload[len(prefix):]
            Point("after-nft")

            return 0, b""

        return original(command, payload=payload, **options)

    monkeypatch.setattr(guest, "_Run", Run)
    # This model records exact policy bytes. Real nft JSON compilation/readback is covered by isolated Linux conformance.
    monkeypatch.setattr(guest, "_ExpectedNetwork", lambda path, owner, nonce: guest._Digest(path.read_bytes()))
    monkeypatch.setattr(guest, "_NftState", lambda owner, nonce: guest._Digest(model.policy) if model.network else None)
    receipt = json.loads((root / "receipt.json").read_bytes())
    receipt["network_sha256"] = guest._Digest(model.policy)
    guest._Atomic(root / "receipt.json", guest._Encode(receipt))
    expected = guest._Digest((root / "receipt.json").read_bytes())
    desired = tmpPath / "desired"
    desired.mkdir(mode=0o700)
    config = guest._Config(model.kernelConfig, request, root / "wg")
    descriptor = copy.deepcopy(request)
    clientSecret = b"unused-for-revocation"

    if action == "enroll":
        profile = replace(Prepared().profile, devices=(VpnDevice("tablet", "10.67.0.4"),))
        peer = GenerateWireGuardMaterial(profile, WireGuardSettings()).peers[0]
        model.deviceId = "tablet"
        descriptor["peers"].append({"device_id": "tablet", "public_key": peer.PublicKey, "ipv4_address": "10.67.0.4"})
        content = model.kernelConfig.rstrip() + ("\n\n[Peer]\n# Device: tablet\nPublicKey = " + peer.PublicKey
                  + "\nPresharedKey = " + peer.presharedKey + "\nAllowedIPs = 10.67.0.4/32\n").encode()
        clientSecret = peer.privateKey.encode()

    else:
        model.deviceId = "phone"
        descriptor["peers"] = [item for item in descriptor["peers"] if item["device_id"] != model.deviceId]
        lines = ["[Interface]", "PrivateKey = " + config[0], "ListenPort = " + str(request["port"])]

        for item in descriptor["peers"]:
            key = item["public_key"]
            lines.extend(["", "[Peer]", "# Device: " + item["device_id"], "PublicKey = " + key,
                          "PresharedKey = " + config[2][key][0], "AllowedIPs = " + config[2][key][1]])

        content = ("\n".join(lines) + "\n").encode()

    descriptor["config_sha256"] = guest._Digest(content)
    guest._Atomic(desired / "server.conf", content)
    guest._Atomic(desired / "deployment.json", guest._Encode(descriptor))
    guest._Atomic(desired / "install.py", (root / "install.py").read_bytes())
    model.originalRequest = request
    model.originalConfig = model.kernelConfig
    model.oldReceipt = receipt
    model.history = peers._History(guest, request["owner"])
    model.point = Point
    model.unit = unit
    model.root = root
    model.action = action
    model.desiredRequest = descriptor

    return model, desired, expected, clientSecret


def Envelope(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, model: Any, desired: Path) -> None:
    """Create only the exact private receiver input shape for package-mode entrypoint tests."""

    envelope = tmpPath / "envelope"
    envelope.mkdir(mode=0o700)

    for name in ("server.conf", "deployment.json"):
        guest._Atomic(envelope / name, (desired / name).read_bytes())

    guest._Atomic(envelope / "install.py", Path(peers.__file__).read_bytes())
    guest._Atomic(envelope / "maintenance.py", (model.root / "install.py").read_bytes())
    monkeypatch.setattr(peers, "__file__", str(envelope / "install.py"))


@pytest.mark.parametrize("action", ["enroll", "revoke"])
def test_PeerApplyRepeatsWithoutRestartOrRotationAndKeepsOriginalProgram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    """Publish complete private files atomically while preserving all unrelated service state."""

    model, desired, previous, clientSecret = Environment(tmp_path, monkeypatch, action)
    owner = model.originalRequest["owner"]
    root, unit, transaction = guest._Paths(owner)
    original = {path.name: path.read_bytes() for path in root.iterdir()}
    unitBytes = unit.read_bytes()

    assert peers.Status(guest, desired, action, model.deviceId)["is_desired"] is False
    assert peers.Apply(guest, desired, action, model.deviceId, previous, model.history) == "committed"
    assert not transaction.exists() and model.unrelated == b"unrelated AWG/VLESS policy and credentials"
    assert model.events == (["wg", "nft"] if action == "enroll" else ["nft", "wg"])
    assert unit.read_bytes() == unitBytes
    assert all((root / name).read_bytes() == original[name] for name in ("install.py", "wg", "COPYING", "service.service"))
    assert clientSecret not in (root / "server.conf").read_bytes()
    assert model.kernelConfig == (root / "server.conf").read_bytes()
    assert model.policy == (root / "firewall.nft").read_bytes()
    assert peers.Status(guest, desired, action, model.deviceId)["is_desired"] is True
    before = {path.name: path.read_bytes() for path in root.iterdir()}
    model.events.clear()

    assert peers.Apply(guest, desired, action, model.deviceId, previous, model.history) == "committed"
    assert not model.events and {path.name: path.read_bytes() for path in root.iterdir()} == before


@pytest.mark.parametrize("action", ["enroll", "revoke"])
@pytest.mark.parametrize("failure", ["before-wg", "after-wg", "before-nft", "after-nft", "before-exchange", "after-exchange"])
def test_InterruptedPeerChangeReconcilesOnlyItsRecordedPrefixAndPreservesPublishedCommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str, failure: str,
) -> None:
    """Real directory exchange determines commit; early recovery restores old files/peer policy without restarting."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, action)
    model.failure = failure
    exchange = peers._Exchange

    def Exchange(guest: Any, left: Path, right: Path) -> None:
        """Interrupt only active-root publication, allowing the earlier isolated filesystem probe."""

        if left == model.root:
            model.point("before-exchange")

        exchange(guest, left, right)

        if left == model.root:
            model.point("after-exchange")

    monkeypatch.setattr(peers, "_Exchange", Exchange)

    with pytest.raises(Interrupted):
        peers.Apply(guest, desired, action, model.deviceId, previous, model.history)

    root, unit, transaction = guest._Paths(model.originalRequest["owner"])
    status = peers.Status(guest, desired, action, model.deviceId)

    assert status["status"] == "peer-recovery-required" and transaction.exists()
    outcome = peers.Recover(guest, desired, action, model.deviceId, str(status["receipt_sha256"]), previous, model.history)

    assert outcome == ("committed" if failure == "after-exchange" else "not-applied")
    assert not transaction.exists() and model.unrelated == b"unrelated AWG/VLESS policy and credentials"
    expectedConfig = (desired / "server.conf").read_bytes() if outcome == "committed" else model.originalConfig
    assert (root / "server.conf").read_bytes() == expectedConfig
    assert model.kernelConfig == (root / "server.conf").read_bytes()
    assert model.policy == (root / "firewall.nft").read_bytes()
    guest._Check(root, unit, guest._Request(root)[0])


@pytest.mark.parametrize("fault", ["receipt", "history", "noncanonical-receipt", "config", "unit", "kernel", "firewall", "listener"])
def test_ForeignOrChangedStateStopsBeforeAnyPeerOrTableMutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Expected-old proof covers both retained private state and actual runtime observations."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    root, _, transaction = guest._Paths(model.originalRequest["owner"])

    if fault == "receipt":
        previous = "0" * 64

    elif fault == "history":
        model.history = "0" * 64

    elif fault == "noncanonical-receipt":
        path = root / "receipt.json"
        path.write_text(json.dumps(json.loads(path.read_bytes()), indent=2))

    elif fault == "config":
        (root / "server.conf").write_bytes((root / "server.conf").read_bytes() + b"# foreign change\n")

    elif fault == "unit":
        model.unit.write_bytes(b"# foreign unit\n")

    elif fault == "kernel":
        model.kernelConfig = model.kernelConfig.replace(b"ListenPort = 51821", b"ListenPort = 51822")

    elif fault == "firewall":
        model.policy = b"foreign policy"

    else:
        data = json.loads((desired / "deployment.json").read_bytes())
        data["port"] = 51822
        guest._Atomic(desired / "deployment.json", guest._Encode(data))

    with pytest.raises(guest.GuestError):
        peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

    assert not model.events and not transaction.exists() and model.unrelated == b"unrelated AWG/VLESS policy and credentials"


@pytest.mark.parametrize("filename", sorted(guest._FILES | {"receipt.json"}))
def test_PartialBackupDeletionCanResumeWithoutRollingBackTheCommittedPeer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str,
) -> None:
    """Interrupt every backup file deletion while proving that the complete active new directory remains authoritative."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    _, _, transaction = guest._Paths(model.originalRequest["owner"])
    unlink = Path.unlink

    def Unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        """Die only after removing the selected old backup file, never a current configuration file."""

        unlink(path, *args, **kwargs)

        if path == transaction / "new" / filename:
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", Unlink)

        with pytest.raises(Interrupted):
            peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

    status = peers.Status(guest, desired, "enroll", model.deviceId)
    events = list(model.events)

    assert peers.Recover(guest, desired, "enroll", model.deviceId, str(status["receipt_sha256"]), previous, model.history) == "committed"
    assert model.events == events and not transaction.exists()


def test_HistoryObservationBeforeFirstInstallationCreatesNoBaseOrLock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Initial audit absence is owner-bound and requires no installed root, managed directory or network command."""

    _, request, _ = Seed(tmp_path, monkeypatch)

    def Forbidden(*arguments: Any, **options: Any) -> Any:
        """Refuse any service/kernel command during metadata-only history observation."""

        raise AssertionError("History observation crossed the external command boundary")

    monkeypatch.setattr(guest, "_Run", Forbidden)
    facts = peers.HistoryStatus(guest, request["owner"])

    assert facts == {"status": "peer-history", "owner": request["owner"], "tools_version": guest.TOOLS_VERSION,
                     "history_sha256": guest._Digest(guest._Encode({"domain": "f-layer/wireguard/peer-history/v1", "owner": request["owner"]}))}
    assert not guest.BASE.exists() and not guest.LOCK.exists()


def InstallEnvelope(tmpPath: Path, stage: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Stage the packed driver plus original program while keeping the existing synthetic guest effect model."""

    envelope = tmpPath / "install-envelope"
    envelope.mkdir(mode=0o700)

    for name in ("server.conf", "deployment.json"):
        guest._Atomic(envelope / name, (stage / name).read_bytes())

    guest._Atomic(envelope / "original.py", (stage / "install.py").read_bytes())
    guest._Atomic(envelope / "maintenance.py", (stage / "install.py").read_bytes())
    guest._Atomic(envelope / "install.py", Path(peers.__file__).read_bytes())
    monkeypatch.setattr(peers, "__file__", str(envelope / "install.py"))

    def Original(helper: Any, supplied: Path, digest: str) -> Any:
        """Keep all installation effects in the existing model; the real loader's hash gate is tested in memory."""

        assert guest._Digest((supplied / "original.py").read_bytes()) == digest

        return guest

    monkeypatch.setattr(peers, "_OriginalGuest", Original)

    return envelope


def test_GuardedInstallAndReadOnlyCheckRetainTheOriginalProgramAndExactHistory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Run actual private installer files under the shared lock while every kernel/service boundary stays modeled."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    envelope = InstallEnvelope(tmp_path, stage, monkeypatch)
    history = peers.HistoryStatus(guest, request["owner"])["history_sha256"]
    common = ["--change", "enroll", "--device-id", "flayer-installation", "--expected-history-sha256", history]

    assert peers.Main(["--install", "--allow-mutation", *common]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "install-complete"}
    assert (model.root / "install.py").read_bytes() == (envelope / "original.py").read_bytes()
    before = {path.name: guest._Digest(path.read_bytes()) for path in model.root.iterdir()}

    assert peers.Main(["--check-install", *common]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "install-checked"}
    assert {path.name: guest._Digest(path.read_bytes()) for path in model.root.iterdir()} == before
    assert peers.Main(["--install", "--allow-mutation", *common]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "install-complete"}


def test_InstallRechecksHistoryUnderTheMutatingLockBeforeLoadingTheOriginalProgram(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A controller changing audit after observation cannot make the guarded install revive old keys."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    InstallEnvelope(tmp_path, stage, monkeypatch)
    history = peers.HistoryStatus(guest, request["owner"])["history_sha256"]
    openLock = guest._OpenLock
    loaded: list[bool] = []

    def Open(*, readOnly: bool = False) -> int:
        """Model another completed actor immediately before the installing process acquires its exclusive lock."""

        descriptor = openLock(readOnly=readOnly)

        for directory in (guest.BASE.parent.parent, guest.BASE.parent, guest.BASE):
            guest._Directory(directory, create=True)

        guest._Atomic(guest.BASE / ("peer-" + request["owner"] + ".json"), guest._Encode({
            "schema_version": 1, "owner": request["owner"], "action": "revoke", "device_id": "phone",
            "previous_receipt_sha256": "a" * 64, "receipt_sha256": "b" * 64,
            "deployment_sha256": "c" * 64, "previous_history_sha256": history}))

        return descriptor

    def Forbidden(*arguments: Any) -> Any:
        """Refuse any installer load once the actual history precondition differs."""

        loaded.append(True)

        raise AssertionError("Changed history reached the original installer")

    monkeypatch.setattr(guest, "_OpenLock", Open)
    monkeypatch.setattr(peers, "_OriginalGuest", Forbidden)

    assert peers.Main(["--install", "--allow-mutation", "--change", "enroll", "--device-id", "flayer-installation",
                       "--expected-history-sha256", history]) == 1
    capsys.readouterr()
    assert not loaded and peers._History(guest, request["owner"]) != history
    assert not model.root.exists() and not model.unit.exists() and not model.interface and not model.network


def test_HistoryEntrypointReadsRetainedAuditAfterTheInstalledRootWasRemoved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Removed root/unit files cannot hide non-initial peer history from the next installer preflight."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)
    owner = model.originalRequest["owner"]
    expected = peers._History(guest, owner)
    Envelope(tmp_path, monkeypatch, model, desired)
    assert model.root.parent == guest.BASE
    shutil.rmtree(model.root)
    model.unit.unlink()
    guest.LOCK.unlink(missing_ok=True)
    events = list(model.events)

    assert peers.Main(["--history-status", "--change", "enroll", "--device-id", model.deviceId]) == 0
    assert json.loads(capsys.readouterr().out)["history_sha256"] == expected != model.history
    assert not model.root.exists() and not guest.LOCK.exists() and model.events == events


@pytest.mark.parametrize("fault", ["symlink", "writable", "foreign-audit"])
def test_HistoryObservationRejectsUnsafeAbsenceOrForeignAudit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """An absent installation cannot bypass ancestry, directory ownership or complete audit-owner validation."""

    _, request, _ = Seed(tmp_path, monkeypatch)
    guest.BASE.parent.mkdir(parents=True, mode=0o755)

    if fault == "symlink":
        target = tmp_path / "foreign-base"
        target.mkdir()
        guest.BASE.symlink_to(target)

    else:
        guest.BASE.mkdir(mode=0o755)

        if fault == "writable":
            guest.BASE.chmod(0o777)

        else:
            guest._Atomic(guest.BASE / ("peer-" + request["owner"] + ".json"), guest._Encode({
                "schema_version": 1, "owner": "f" * 64, "action": "enroll", "device_id": "phone",
                "previous_receipt_sha256": "a" * 64, "receipt_sha256": "b" * 64,
                "deployment_sha256": "c" * 64, "previous_history_sha256": "d" * 64}))

    with pytest.raises(guest.GuestError):
        peers.HistoryStatus(guest, request["owner"])

    assert not guest.LOCK.exists()


def test_MainReadOnlyStatusNeedsNoVolatileLockAndMutationConsentPrecedesLockCreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise the actual entrypoint through its exact private flat staging envelope."""

    model, desired, _, _ = Environment(tmp_path, monkeypatch, "enroll")
    Envelope(tmp_path, monkeypatch, model, desired)
    common = ["--change", "enroll", "--device-id", model.deviceId]

    assert peers.Main(["--status", *common]) == 0
    status = json.loads(capsys.readouterr().out)

    assert status["status"] == "active" and status["is_desired"] is False and not guest.LOCK.exists()
    assert peers.Main(["--apply", *common]) == 1
    assert not guest.LOCK.exists() and not model.events
    assert "private" not in capsys.readouterr().out


@pytest.mark.parametrize("boundary", ["exchange-fsync", "audit-publication"])
def test_FailedPostPublicationDurabilityDoesNotAuthorizeRollbackOfAHealthyCommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """Retain the new peer and the journal after uncertain durability, then re-establish commit before cleanup."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    sync, atomic = guest._SyncDirectory, guest._Atomic
    failed = False

    def Sync(path: Path) -> None:
        """Fail only after the complete desired root became visible through atomic exchange."""

        nonlocal failed

        if (boundary == "exchange-fsync" and not failed and path == guest.BASE
                and (model.root / "server.conf").read_bytes() == (desired / "server.conf").read_bytes()):
            failed = True

            raise OSError("Synthetic post-exchange durability failure")

        sync(path)

    def Atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
        """Fail after the commit proof was replaced, preserving recovery metadata and the old backup."""

        nonlocal failed
        atomic(path, content, mode)

        if boundary == "audit-publication" and not failed and path.name == "peer-" + model.originalRequest["owner"] + ".json":
            failed = True

            raise OSError("Synthetic commit-proof durability failure")

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)
    monkeypatch.setattr(guest, "_Atomic", Atomic)

    with pytest.raises((guest.GuestError, OSError)):
        peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

    status = peers.Status(guest, desired, "enroll", model.deviceId)
    events = list(model.events)

    assert status["is_desired"] is True
    assert peers.Recover(guest, desired, "enroll", model.deviceId, str(status["receipt_sha256"]), previous, model.history) == "committed"
    assert model.events == events


def test_UnknownTransitionPrefixCannotBeRepairedByGuessingItsOrigin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An enrollment cannot produce a permissive new firewall while the old kernel configuration remains active."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    _, transaction = peers._Publish(guest, desired, "enroll", model.deviceId, previous, model.history)
    model.policy = (transaction / "new" / "firewall.nft").read_bytes()

    with pytest.raises(guest.GuestError, match="unrecorded"):
        peers.Status(guest, desired, "enroll", model.deviceId)

    with pytest.raises(guest.GuestError, match="unrecorded"):
        peers.Recover(guest, desired, "enroll", model.deviceId, previous, previous, model.history)

    assert not model.events and transaction.exists()


@pytest.mark.parametrize("committed", [False, True])
@pytest.mark.parametrize("priorCommit", [False, True])
def test_EmptyFinalJournalAfterLockLossCanRecoverThroughMainWithTheCorrectPreviousProof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], committed: bool, priorCommit: bool,
) -> None:
    """A prior historical audit must not replace the current pending plan's old receipt after rollback cleanup."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    owner = model.originalRequest["owner"]
    _, _, transaction = guest._Paths(owner)

    if priorCommit:
        guest._Atomic(guest.BASE / ("peer-" + owner + ".json"), guest._Encode({
            "schema_version": 1, "owner": owner, "action": "revoke", "device_id": "retired",
            "previous_receipt_sha256": "e" * 64, "receipt_sha256": previous,
            "deployment_sha256": model.oldReceipt["deployment_sha256"],
            "previous_history_sha256": model.history,
        }))

    model.history = peers._History(guest, owner)

    if not committed:
        model.failure = "after-wg"

        with pytest.raises(Interrupted):
            peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

    unlink = Path.unlink

    def Unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        """Leave an empty transaction directory after retiring its complete metadata file."""

        unlink(path, *args, **kwargs)

        if path == transaction / "transaction.json":
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", Unlink)

        with pytest.raises(Interrupted):
            if committed:
                peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

            else:
                peers.Recover(guest, desired, "enroll", model.deviceId, previous, previous, model.history)

    assert transaction.exists() and not tuple(transaction.iterdir()) and not guest.LOCK.exists()
    Envelope(tmp_path, monkeypatch, model, desired)
    common = ["--change", "enroll", "--device-id", model.deviceId]

    assert peers.Main(["--status", *common]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["is_desired"] is committed and status["previous_receipt_sha256"] == previous
    assert status["previous_history_sha256"] == model.history
    assert not guest.LOCK.exists()
    events = list(model.events)

    assert peers.Main(["--recover", *common, "--allow-mutation", "--expected-receipt-sha256", status["receipt_sha256"],
                       "--expected-previous-receipt-sha256", status["previous_receipt_sha256"],
                       "--expected-history-sha256", status["previous_history_sha256"]]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result == {"status": "complete", "outcome": "committed" if committed else "not-applied"}
    assert guest.LOCK.exists() and not transaction.exists() and model.events == events


def test_ConfigurationAbaCannotReplayAnOldEnrollmentOrRevocationPlan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Returning to identical installed bytes must not restore a stale plan's authority over later revocation."""

    model, expanded, firstReceipt, _ = Environment(tmp_path, monkeypatch, "enroll")
    owner = model.originalRequest["owner"]
    original = tmp_path / "original"
    original.mkdir(mode=0o700)

    for name in ("server.conf", "deployment.json", "install.py"):
        guest._Atomic(original / name, (model.root / name).read_bytes())

    firstHistory = model.history
    assert peers.Apply(guest, expanded, "enroll", model.deviceId, firstReceipt, firstHistory) == "committed"
    secondReceipt = guest._Digest((model.root / "receipt.json").read_bytes())
    secondHistory = peers._History(guest, owner)
    assert peers.Apply(guest, original, "revoke", model.deviceId, secondReceipt, secondHistory) == "committed"
    thirdHistory = peers._History(guest, owner)

    assert guest._Digest((model.root / "receipt.json").read_bytes()) == firstReceipt, "The regression must exercise a real byte-identical A -> B -> A cycle"
    events = list(model.events)

    with pytest.raises(guest.GuestError, match="history"):
        peers.Apply(guest, expanded, "enroll", model.deviceId, firstReceipt, firstHistory)

    with pytest.raises(guest.GuestError):
        peers.Recover(guest, expanded, "enroll", model.deviceId, firstReceipt, firstReceipt, firstHistory)

    assert model.events == events
    assert peers.Apply(guest, expanded, "enroll", model.deviceId, firstReceipt, thirdHistory) == "committed"
    fourthHistory = peers._History(guest, owner)

    assert guest._Digest((model.root / "receipt.json").read_bytes()) == secondReceipt
    assert len({firstHistory, secondHistory, thirdHistory, fourthHistory}) == 4, "A last-action digest without its parent would repeat on A -> B -> A -> B"
    events = list(model.events)

    with pytest.raises(guest.GuestError, match="history"):
        peers.Apply(guest, original, "revoke", model.deviceId, secondReceipt, secondHistory)

    assert model.events == events and model.unrelated == b"unrelated AWG/VLESS policy and credentials"


def test_ResumedCommitSyncsBothExchangeParentsBeforeErasingAnyBackup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A retry of post-exchange durability must leave every backup byte intact if transaction-parent fsync still fails."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    exchange = peers._Exchange

    def Exchange(guest: Any, left: Path, right: Path) -> None:
        """Model a lost acknowledgement after publishing the complete desired root."""

        exchange(guest, left, right)

        if left == model.root:
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(peers, "_Exchange", Exchange)

        with pytest.raises(Interrupted):
            peers.Apply(guest, desired, "enroll", model.deviceId, previous, model.history)

    _, _, transaction = guest._Paths(model.originalRequest["owner"])
    backup = transaction / "new"
    before = {path.name: path.read_bytes() for path in backup.iterdir()}
    status = peers.Status(guest, desired, "enroll", model.deviceId)
    sync = guest._SyncDirectory

    def Sync(path: Path) -> None:
        """Refuse the missing durable parent boundary before any exchanged old file can be erased."""

        if path == transaction:
            raise OSError("Synthetic transaction-parent durability failure")

        sync(path)

    with monkeypatch.context() as patch:
        patch.setattr(guest, "_SyncDirectory", Sync)

        with pytest.raises(OSError):
            peers.Recover(guest, desired, "enroll", model.deviceId, str(status["receipt_sha256"]), previous, model.history)

    assert {path.name: path.read_bytes() for path in backup.iterdir()} == before
    assert peers.Recover(guest, desired, "enroll", model.deviceId, str(status["receipt_sha256"]), previous, model.history) == "committed"
