"""Exercise actual peer transaction files and atomic publication with entirely simulated guest networking."""

from __future__ import annotations

import copy
import json
import os
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
    model.point = Point
    model.unit = unit
    model.root = root
    model.action = action
    model.desiredRequest = descriptor

    return model, desired, expected, clientSecret


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
    assert peers.Apply(guest, desired, action, model.deviceId, previous) == "committed"
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

    assert peers.Apply(guest, desired, action, model.deviceId, previous) == "committed"
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
        peers.Apply(guest, desired, action, model.deviceId, previous)

    root, unit, transaction = guest._Paths(model.originalRequest["owner"])
    status = peers.Status(guest, desired, action, model.deviceId)

    assert status["status"] == "peer-recovery-required" and transaction.exists()
    outcome = peers.Recover(guest, desired, action, model.deviceId, str(status["receipt_sha256"]), previous)

    assert outcome == ("committed" if failure == "after-exchange" else "not-applied")
    assert not transaction.exists() and model.unrelated == b"unrelated AWG/VLESS policy and credentials"
    expectedConfig = (desired / "server.conf").read_bytes() if outcome == "committed" else model.originalConfig
    assert (root / "server.conf").read_bytes() == expectedConfig
    assert model.kernelConfig == (root / "server.conf").read_bytes()
    assert model.policy == (root / "firewall.nft").read_bytes()
    guest._Check(root, unit, guest._Request(root)[0])


@pytest.mark.parametrize("fault", ["receipt", "config", "unit", "kernel", "firewall", "listener"])
def test_ForeignOrChangedStateStopsBeforeAnyPeerOrTableMutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Expected-old proof covers both retained private state and actual runtime observations."""

    model, desired, previous, _ = Environment(tmp_path, monkeypatch, "enroll")
    root, _, transaction = guest._Paths(model.originalRequest["owner"])

    if fault == "receipt":
        previous = "0" * 64

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
        peers.Apply(guest, desired, "enroll", model.deviceId, previous)

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
            peers.Apply(guest, desired, "enroll", model.deviceId, previous)

    status = peers.Status(guest, desired, "enroll", model.deviceId)
    events = list(model.events)

    assert peers.Recover(guest, desired, "enroll", model.deviceId, str(status["receipt_sha256"]), previous) == "committed"
    assert model.events == events and not transaction.exists()


def test_MainReadOnlyStatusNeedsNoVolatileLockAndMutationConsentPrecedesLockCreation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise the actual entrypoint through its exact private flat staging envelope."""

    model, desired, _, _ = Environment(tmp_path, monkeypatch, "enroll")
    envelope = tmp_path / "envelope"
    envelope.mkdir(mode=0o700)

    for name in ("server.conf", "deployment.json"):
        guest._Atomic(envelope / name, (desired / name).read_bytes())

    guest._Atomic(envelope / "install.py", Path(peers.__file__).read_bytes())
    guest._Atomic(envelope / "maintenance.py", (model.root / "install.py").read_bytes())
    monkeypatch.setattr(peers, "__file__", str(envelope / "install.py"))
    common = ["--change", "enroll", "--device-id", model.deviceId]

    assert peers.Main(["--status", *common]) == 0
    status = json.loads(capsys.readouterr().out)

    assert status["status"] == "active" and status["is_desired"] is False and not guest.LOCK.exists()
    assert peers.Main(["--apply", *common]) == 1
    assert not guest.LOCK.exists() and not model.events
    assert "private" not in capsys.readouterr().out
