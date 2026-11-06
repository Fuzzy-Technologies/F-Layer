"""Exercise owned guest transactions with POSIX files and a synthetic kernel/service model."""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from test_wireguard_guest import Nft, Prepared, Vendor

from flayer.profiles import _wireguard_guest as guest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owned guest lifecycle requires POSIX files; no desktop VPN is exercised")


class Interrupted(BaseException):
    """Model an abrupt process death which ordinary exception rollback cannot catch."""


class GuestModel:
    """Keep every networking/service operation inside deterministic memory, without subprocesses."""

    def __init__(self, request: dict[str, Any], root: Path, unit: Path) -> None:
        """Retain only synthetic desired intent and isolated file paths."""

        self.request, self.root, self.unit = request, root, unit
        self.owner = request["owner"]
        self.interface: dict[str, Any] | None = None
        self.configured = False
        self.addresses: list[dict[str, Any]] = []
        self.network = False
        self.forwarding = False
        self.active = False
        self.commands: list[list[str]] = []
        self.fault = ""
        self.failed = False

    def Nonce(self) -> str:
        """Read the current operation marker from its exact owned private receipt."""

        return json.loads((self.root / "receipt.json").read_bytes())["nonce"]

    def Run(self, command: list[str], *, payload: bytes | None = None, **kwargs: Any) -> tuple[int, bytes]:
        """Implement only the selected inventory and mutation operations; unknown commands fail the test."""

        self.commands.append(command)
        name = Path(command[0]).name
        failure = " ".join(command[:2])

        if self.fault and not self.failed and self.fault in {failure, name + " " + command[1]}:
            self.failed = True

            raise guest.GuestError("Synthetic command failure")

        if name == "wg" and command[1] == "pubkey":
            assert payload is not None
            key = X25519PrivateKey.from_private_bytes(base64.b64decode(payload.strip()))

            return 0, base64.b64encode(key.public_key().public_bytes_raw()) + b"\n"

        if name == "wg" and command[1] == "syncconf":
            self.configured = True

            return 0, b""

        if name == "wg" and command[1] == "show":
            if not self.configured:
                return 0, b"(none)\t(none)\t0\toff\n"

            privateKey, publicKey, peers = guest._Config((self.root / "server.conf").read_bytes(), self.request, self.root / "wg")
            lines = [f"{privateKey}\t{publicKey}\t{self.request['port']}\toff"]
            lines.extend(f"{key}\t{value[0]}\t(none)\t{value[1]}\t0\t0\t0\toff" for key, value in peers.items())

            return 0, ("\n".join(lines) + "\n").encode()

        if name == "ip":
            if command[1:4] == ["-j", "link", "show"]:
                return (0, guest._Encode([self.interface])) if self.interface else (1, b"") if "dev" in command else (0, b"[]")

            if command[1:5] == ["-j", "-4", "route", "show"]:
                return 0, b"[]"

            if command[1:4] == ["-j", "address", "show"]:
                return 0, guest._Encode([{"addr_info": self.addresses}])

            if command[1:3] == ["link", "add"]:
                assert self.interface is None
                self.interface = {"ifname": guest._Interface(self.owner), "ifalias": command[6], "mtu": 1420, "flags": []}

            elif command[1:3] == ["link", "set"]:
                assert self.interface is not None
                self.interface["mtu"] = int(command[6])
                self.interface["flags"] = ["UP"]

            elif command[1:3] == ["address", "add"]:
                address, prefix = command[3].split("/")
                self.addresses = [{"family": "inet", "local": address, "prefixlen": int(prefix)}]

            elif command[1:3] == ["link", "delete"]:
                self.interface, self.configured, self.addresses = None, False, []

            else:
                raise AssertionError("Unexpected synthetic IP command")

            return 0, b""

        if name == "nft":
            if command[1:] == ["-j", "list", "tables"]:
                return 0, guest._Encode({"nftables": [{"table": {"family": "ip", "name": guest._Table(self.owner)}}] if self.network else []})

            if command[1:4] == ["-j", "list", "table"]:
                return 0, Nft(self.owner, self.Nonce())

            if command[1] == "-f":
                self.network = True

            elif command[1:3] == ["delete", "table"]:
                self.network = False

            else:
                raise AssertionError("Unexpected synthetic nft command")

            return 0, b""

        if name == "ss":
            return 0, b"UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\n"

        if name == "sysctl":
            if command[-1] == "net.ipv6.conf.all.disable_ipv6":
                return 0, b"1\n"

            if command[-1] == "net.ipv4.ip_forward":
                return 0, b"1\n" if self.forwarding else b"0\n"

            assert command[-1] == "net.ipv4.ip_forward=1"
            self.forwarding = True

            return 0, b""

        if name == "systemctl":
            assert command[1] == "daemon-reload" or command[-1] == guest._Service(self.owner) + ".service"
            link = self.unit.parent / "multi-user.target.wants" / self.unit.name

            if command[1] == "enable":
                link.parent.mkdir(exist_ok=True, mode=0o755)
                link.symlink_to(self.unit)

            elif command[1] == "disable":
                if link.is_symlink():
                    link.unlink()

            elif command[1] == "start":
                guest._Start(self.root, self.unit, self.request)
                self.active = True

            elif command[1] == "stop":
                receipt = json.loads((self.root / "receipt.json").read_bytes())
                guest._Stop(self.root, self.unit, self.request, partial=receipt["status"] == "staged")
                self.active = False

            elif command[1] == "is-active":
                assert self.active

            elif command[1] == "is-enabled":
                assert link.is_symlink()

            else:
                assert command[1] == "daemon-reload"

            return 0, b""

        raise AssertionError("Unexpected command escaped the synthetic guest model")


def Seed(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, dict[str, Any], GuestModel]:
    """Stage a complete real bundle with private POSIX files and intercept every external effect."""

    base, units, stage = tmpPath / "opt/flayer/wireguard", tmpPath / "units", tmpPath / "stage"
    units.mkdir(mode=0o755)
    stage.mkdir(mode=0o700)

    for item in Prepared().serverBundle.files:
        (stage / item.name).write_bytes(item.content)
        (stage / item.name).chmod(0o600)

    monkeypatch.setattr(guest, "BASE", base)
    monkeypatch.setattr(guest, "SYSTEMD", units)
    monkeypatch.setattr(guest, "LOCK", tmpPath / "operation.lock")
    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(guest, "_KernelFacts", lambda: {"release": "6.8.0-999-generic", "package_version": "6.8.0-999.999",
                        "signature": "Ubuntu 6.8.0-999.999-generic 6.8.12", "module_sha256": "d" * 64, "module_srcversion": "D" * 24})
    monkeypatch.setattr(guest, "_Fetch", lambda url, limit: Vendor())
    monkeypatch.setattr(guest, "_BuildTools", lambda work: (b"synthetic-private-wg", b"Synthetic license fixture\n"))
    monkeypatch.setattr(guest, "_BuildFacts", lambda: {"compiler_version": "synthetic gcc", "compiler_target": "x86_64-linux-gnu",
                        "make_version": "GNU Make fixture", "libc_headers_version": "1.0", "kernel_headers_version": "1.0",
                        "compiler_sha256": "e" * 64, "make_sha256": "f" * 64, "options": list(guest.BUILD_OPTIONS)})
    module = tmpPath / "loaded-wireguard"
    module.mkdir()
    (module / "srcversion").write_text("D" * 24, encoding="ascii")
    monkeypatch.setattr(guest, "MODULE_STATE", module)
    monkeypatch.setattr(guest, "_ExpectedNetwork", lambda path, owner, nonce: guest._NftFingerprint(Nft(owner, nonce), owner, nonce))
    monkeypatch.setattr(guest, "__file__", str(stage / "install.py"))
    request, _, _ = guest._Request(stage)
    root, unit, _ = guest._Paths(request["owner"])
    model = GuestModel(request, root, unit)
    monkeypatch.setattr(guest, "_Run", model.Run)

    return stage, request, model


def test_InstallRepeatStatusRebootAndRemovalPreserveOtherResources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise actual owned files, receipt validation and live-model checks throughout the lifecycle."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated-service.conf"
    unrelated.write_bytes(b"unrelated AWG/VLESS credentials remain unchanged")
    guest._Install(stage, request)
    root, unit, transaction = guest._Paths(request["owner"])
    receipt = guest._Check(root, unit, request)
    original = {path.name: path.read_bytes() for path in root.iterdir()}

    assert receipt["status"] == "installed" and not transaction.exists()
    policyIndex = next(index for index, command in enumerate(model.commands) if command[:2] == ["nft", "-f"])
    upIndex = next(index for index, command in enumerate(model.commands) if command[:3] == ["ip", "link", "set"])

    assert policyIndex < upIndex, "The complete scoped firewall must exist before the interface can carry traffic"
    assert all(stat.S_IMODE(path.stat().st_mode) == (0o755 if path.name == "wg" else 0o600) for path in root.iterdir())
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    model.commands.clear()
    monkeypatch.setattr(guest, "_Fetch", lambda *args: pytest.fail("Idempotent checks must not download anything"))
    guest._Install(stage, request)

    assert {path.name: path.read_bytes() for path in root.iterdir()} == original
    assert not any(command[:2] in (["systemctl", "start"], ["systemctl", "stop"]) for command in model.commands)
    status = guest._Status(stage, request)

    assert status["status"] == "active" and "private" not in json.dumps(status)
    guest._Stop(root, unit, request)

    assert model.interface is None and not model.network and model.forwarding
    guest._Start(root, unit, request)
    guest._Check(root, unit, request)
    guest._Remove(request["owner"], guest._Digest((root / "receipt.json").read_bytes()))

    assert not root.exists() and not unit.exists() and not transaction.exists()
    assert model.interface is None and not model.network and model.forwarding
    assert unrelated.read_bytes() == b"unrelated AWG/VLESS credentials remain unchanged"


@pytest.mark.parametrize("failure", ["systemctl enable", "wg syncconf", "ip address", "nft -f", "systemctl start"])
def test_InstallFailureRollsBackOnlyItsProvedObjects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    """Fail at real transaction boundaries, including an empty or partially configured owned interface."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    model.fault = failure

    with pytest.raises(guest.GuestError, match="rolled back"):
        guest._Install(stage, request)

    root, unit, transaction = guest._Paths(request["owner"])

    assert model.failed and not root.exists() and not unit.exists() and not transaction.exists()
    assert model.interface is None and not model.network
    assert tuple(sorted(path.name for path in stage.iterdir())) == ("deployment.json", "install.py", "server.conf")


@pytest.mark.parametrize("phase", ["staged", "published", "unit", "configured"])
def test_AbruptInstallationDeathHasReceiptBoundRecovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    """Recover a published journal without guessing which of the staged or active roots is authoritative."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    root, unit, transaction = guest._Paths(request["owner"])

    if phase == "staged":
        guest._PrepareRoot(stage, request, root, unit)

    else:
        replace = guest.os.replace
        atomic = guest._Atomic
        run = model.Run

        def Replace(source: Any, destination: Any) -> None:
            """Die immediately after publishing the complete active directory."""

            replace(source, destination)

            if phase == "published" and Path(destination) == root:
                raise Interrupted

        def Atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
            """Die after publishing the unit but before enabling it."""

            atomic(path, content, mode)

            if phase == "unit" and path == unit:
                raise Interrupted

        def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
            """Die after the owned kernel peer state has been configured."""

            result = run(command, **kwargs)

            if phase == "configured" and len(command) > 1 and command[1] == "syncconf":
                raise Interrupted

            return result

        with monkeypatch.context() as patch:
            patch.setattr(guest.os, "replace", Replace)
            patch.setattr(guest, "_Atomic", Atomic)
            patch.setattr(guest, "_Run", Run)

            with pytest.raises(Interrupted):
                guest._Install(stage, request)

    status = guest._Status(stage, request)

    with pytest.raises(guest.GuestError):
        guest._Recover(request["owner"], "0" * 64)

    guest._Recover(request["owner"], str(status["receipt_sha256"]))

    assert not root.exists() and not unit.exists() and not transaction.exists()
    assert model.interface is None and not model.network


@pytest.mark.parametrize("drift", ["config", "binary", "unit", "extra", "alias", "peer", "address", "link", "kernel", "down", "parent"])
def test_DriftPreventsAnyServiceOrNetworkDeletion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift: str,
) -> None:
    """An exact receipt grants no permission to delete changed or foreign state."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    root, unit, _ = guest._Paths(request["owner"])
    expected = guest._Digest((root / "receipt.json").read_bytes())

    if drift in {"config", "binary"}:
        (root / ("server.conf" if drift == "config" else "wg")).write_bytes(b"foreign-change")

    elif drift == "unit":
        unit.write_bytes(b"foreign-unit")

    elif drift == "extra":
        (root / "foreign").touch()

    elif drift == "alias":
        assert model.interface is not None
        model.interface["ifalias"] = "foreign"

    elif drift == "peer":
        model.configured = False

    elif drift == "address":
        model.addresses.append({"family": "inet", "local": "10.67.0.9", "prefixlen": 32})

    elif drift == "link":
        link = unit.parent / "multi-user.target.wants" / unit.name
        link.unlink()
        link.symlink_to(stage / "install.py")

    elif drift == "kernel":
        monkeypatch.setattr(guest, "_KernelFacts", lambda: {"release": "changed", "package_version": "6.8.0-1000.1000", "module_sha256": "e" * 64})

    elif drift == "down":
        assert model.interface is not None
        model.interface["flags"] = []

    else:
        guest.BASE.chmod(0o777)

    model.commands.clear()

    with pytest.raises((guest.GuestError, OSError)):
        if drift in {"kernel", "down"}:
            guest._Check(root, unit, request)

        else:
            guest._Remove(request["owner"], expected)

    assert root.exists() and unit.exists() and model.interface is not None and model.network
    assert not any(command[:2] in (["systemctl", "stop"], ["ip", "link"], ["nft", "delete"]) for command in model.commands)


@pytest.mark.parametrize("phase", ["unit", "payload", "root"])
def test_InterruptedFileDeletionCanResumeFromExternalReceipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    """Keep the exact allowed file hashes outside the tree being removed, including its final empty stage."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    root, unit, transaction = guest._Paths(request["owner"])
    expected = guest._Digest((root / "receipt.json").read_bytes())
    unlink = Path.unlink
    rmdir = Path.rmdir

    def Unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        """Die after one real file deletion, leaving a partial private directory."""

        unlink(path, *args, **kwargs)

        if path == (root / "server.conf" if phase == "payload" else unit):
            if phase != "root":
                raise Interrupted

    def Rmdir(path: Path) -> None:
        """Interrupt after the root entry disappears but before its parent durability step."""

        rmdir(path)

        if phase == "root" and path == root:
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", Unlink)
        patch.setattr(Path, "rmdir", Rmdir)

        with pytest.raises(Interrupted):
            guest._Remove(request["owner"], expected)

    assert transaction.exists() and root.exists() == (phase != "root") and not unit.exists()
    assert model.interface is None and not model.network
    assert guest._Status(stage, request)["status"] == "recovery-required"
    sync = guest._SyncDirectory
    durable = set()

    def Sync(path: Path) -> None:
        """Persist and record observed absence after recovery skips an earlier completed unlink/rmdir."""

        sync(path)

        if path == guest.SYSTEMD and not unit.exists():
            durable.add("unit")

        if path == guest.BASE and not root.exists():
            durable.add("root")

    def Retire(path: Path, *args: Any, **kwargs: Any) -> None:
        """The journal must survive until both current parent-directory states are durable."""

        if path == transaction / "transaction.json":
            assert durable == {"unit", "root"}

        unlink(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(guest, "_SyncDirectory", Sync)
        patch.setattr(Path, "unlink", Retire)
        guest._Recover(request["owner"], expected)

    assert not transaction.exists() and not root.exists() and not unit.exists()


@pytest.mark.parametrize("fault", ["pending", "port", "interface", "subnet"])
def test_PreflightRefusesBeforeManagedConfigurationOrBuild(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Do not create an owned root, download a runtime or modify a service when admission fails."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    run = model.Run
    monkeypatch.setattr(guest, "_BuildTools", lambda *args: pytest.fail("A refused preflight must not build tools"))

    if fault == "pending":
        monkeypatch.setattr(guest, "_Fetch", lambda *args: Vendor("pending"))

    elif fault == "interface":
        model.interface = {"ifname": guest._Interface(request["owner"]), "ifalias": "foreign"}

    else:
        def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
            """Provide an occupied listener or overlapping pre-existing subnet."""

            if fault == "port" and command[0] == "ss":
                return 0, b"UNCONN 0 0 0.0.0.0:51821 0.0.0.0:*\n"

            if fault == "subnet" and command[1:5] == ["-j", "-4", "route", "show"]:
                return 0, b'[{"dst":"10.67.0.0/24"}]'

            return run(command, **kwargs)

        monkeypatch.setattr(guest, "_Run", Run)

    with pytest.raises(guest.GuestError):
        guest._Install(stage, request)

    assert not guest.BASE.exists()
    assert not tuple(guest.SYSTEMD.iterdir())


@pytest.mark.parametrize("arguments", [[], ["--remove"], ["--recover", "--allow-mutation"], ["--check", "--allow-mutation"], ["--start", "--allow-mutation"]])
def test_EntryPointRequiresActionConsentAndInstalledServiceBinding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], arguments: list[str],
) -> None:
    """Reject ambiguous options without creating the managed store or operation lock."""

    Seed(tmp_path, monkeypatch)

    assert guest.Main(arguments) == 1
    assert "private" not in capsys.readouterr().err
    assert not guest.BASE.exists() and not guest.LOCK.exists()


def test_EntryPointInstallAndReadOnlyStatusUsePrivateLock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise explicit fresh installation and a side-effect-free status through the actual entrypoint."""

    _, request, model = Seed(tmp_path, monkeypatch)

    assert guest.Main(["--allow-mutation"]) == 0
    capsys.readouterr()
    before = guest.LOCK.stat().st_mtime_ns

    assert guest.Main(["--status"]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "active" and guest.LOCK.stat().st_mtime_ns == before
    assert guest.Main(["--remove", "--allow-mutation", "--expected-receipt-sha256", result["receipt_sha256"]]) == 0
    assert model.interface is None and not guest._Paths(request["owner"])[0].exists()


def test_BootCallbackRestoresVolatileLockForReadOnlyStatus(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A healthy service restarted after /run is cleared must remain observable without a mutating deploy retry."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    guest._Stop(model.root, model.unit, request)
    assert not guest.LOCK.exists()
    monkeypatch.setattr(guest, "__file__", str(model.root / "install.py"))

    assert guest.Main(["--start", "--allow-mutation"]) == 0
    assert guest.LOCK.exists() and stat.S_IMODE(guest.LOCK.stat().st_mode) == 0o600
    model.active = True

    assert guest.Main(["--status"]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["status"] == "active"
    assert (stage / "server.conf").read_bytes() == (model.root / "server.conf").read_bytes()


def test_EmptyRemovedNamespaceRecoveryUsesAnActualAbsenceProof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not fabricate a previous receipt when a crash left only an empty recovery directory."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    _, _, transaction = guest._Paths(request["owner"])
    unlink = Path.unlink
    model.fault = ""
    expected = guest._Digest((model.root / "receipt.json").read_bytes())

    def Unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        """Interrupt final removal metadata after all owned runtime objects and payloads were erased."""

        unlink(path, *args, **kwargs)

        if path == transaction / "transaction.json":
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", Unlink)

        with pytest.raises(Interrupted):
            guest._Remove(request["owner"], expected)

    status = guest._Status(stage, request)

    assert status["status"] == "absent" and status["receipt_sha256"] == "" and status["cleanup_required"] is True

    with pytest.raises(guest.GuestError):
        guest._Recover(request["owner"], "", expectedAbsence="0" * 64)

    guest._Recover(request["owner"], "", expectedAbsence=str(status["absence_sha256"]))

    assert not transaction.exists() and model.interface is None and not model.network
    assert guest._Status(stage, request)["cleanup_required"] is False


def test_EmptyFinalJournalExposesNewReceiptAndPreservesCommittedService(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash while retiring journal metadata must leave status able to obtain recovery consent."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    root, unit, transaction = guest._Paths(request["owner"])
    unlink = Path.unlink

    def Unlink(path: Path, *args: Any, **kwargs: Any) -> None:
        """Interrupt the tiny boundary after deleting the final journal but before removing its directory."""

        unlink(path, *args, **kwargs)

        if path == transaction / "transaction.json":
            raise Interrupted

    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", Unlink)

        with pytest.raises(Interrupted):
            guest._Install(stage, request)

    assert transaction.exists() and not tuple(transaction.iterdir()) and model.active
    snapshot = {path.name: path.read_bytes() for path in root.iterdir()}
    status = guest._Status(stage, request)
    model.commands.clear()
    guest._Recover(request["owner"], str(status["receipt_sha256"]))

    assert not transaction.exists() and unit.exists() and model.active
    assert {path.name: path.read_bytes() for path in root.iterdir()} == snapshot
    assert not any(command[:2] == ["systemctl", "stop"] for command in model.commands)


@pytest.mark.parametrize("fault", ["none", "unloaded", "running-revision", "loaded-source", "missing-source", "disk-source", "module-package"])
def test_KernelFactsBindExecutingBuildAndModuleSource(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Exercise the actual admission observation rather than replacing it wholesale with a success fake."""

    modules = tmp_path / "modules"
    module = modules / "6.8.0-999-generic/kernel/drivers/net/wireguard/wireguard.ko"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"synthetic kernel module disk artifact")
    module.chmod(0o644)
    signature = tmp_path / "signature"
    signature.write_text("Ubuntu 6.8.0-999." + ("998" if fault == "running-revision" else "999") + "-generic 6.8.12\n", encoding="ascii")
    state = tmp_path / "sys-module"

    if fault != "unloaded":
        state.mkdir()

        if fault != "missing-source":
            (state / "srcversion").write_text(("E" if fault == "loaded-source" else "D") * 24, encoding="ascii")

    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(guest, "KERNEL_SIGNATURE", signature)
    monkeypatch.setattr(guest, "MODULES", modules)
    monkeypatch.setattr(guest, "MODULE_STATE", state)
    monkeypatch.setattr(guest.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    monkeypatch.setattr(guest.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(guest.platform, "release", lambda: "6.8.0-999-generic")

    def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        """Expose only synthetic package/module metadata, never the workstation's kernel."""

        if command[0] == "dpkg-query":
            revision = "998" if fault == "module-package" and command[-1].startswith("linux-modules-") else "999"

            return 0, ("6.8.0-999." + revision).encode()

        if command[:2] == ["modinfo", "-n"]:
            return 0, str(module).encode()

        assert command[:3] == ["modinfo", "-F", "srcversion"]

        return 0, b"" if fault == "disk-source" else b"D" * 24

    monkeypatch.setattr(guest, "_Run", Run)

    if fault in {"none", "unloaded"}:
        facts = guest._KernelFacts()

        assert facts["signature"] == "Ubuntu 6.8.0-999.999-generic 6.8.12"
        assert facts["module_srcversion"] == "D" * 24
        assert facts["module_sha256"] == guest._Digest(module.read_bytes())

        if fault == "unloaded":
            with pytest.raises(guest.GuestError, match="unavailable"):
                guest._LoadedSource("D" * 24, required=True)

    else:
        with pytest.raises((guest.GuestError, OSError)):
            guest._KernelFacts()


def test_RequestedRouteChangeCannotPassInstalledHealth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bind all descriptor intent even when wg setconf bytes would remain identical."""

    stage, request, _ = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    root, unit, _ = guest._Paths(request["owner"])

    with pytest.raises(guest.GuestError, match="differs"):
        guest._Check(root, unit, {**request, "ipv4_routes": ["1.1.1.1/32"]})


def test_ModuleLoadedDuringInterfaceCreationMustMatchBeforeTraffic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admission of an available module cannot authorize a different module loaded by ip link add."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    run = model.Run

    def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        """Introduce a changed loaded source exactly after creating the still-down interface."""

        result = run(command, **kwargs)

        if command[:3] == ["ip", "link", "add"]:
            (guest.MODULE_STATE / "srcversion").write_text("E" * 24, encoding="ascii")

        return result

    monkeypatch.setattr(guest, "_Run", Run)

    with pytest.raises(guest.GuestError, match="rolled back"):
        guest._Install(stage, request)

    assert model.interface is None and not model.network
    assert not any(command[:3] == ["ip", "link", "set"] for command in model.commands)


def test_StagedDurabilityFailureCannotActivateTheService(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed staged-directory fsync must stop before publishing a journal, unit or network object."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    sync = guest._SyncDirectory

    def Sync(path: Path) -> None:
        """Fail the actual staging durability boundary, leaving normal temporary cleanup available."""

        if path.name == "new":
            raise OSError("Synthetic fsync failure")

        sync(path)

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)

    with pytest.raises(OSError):
        guest._Install(stage, request)

    root, unit, transaction = guest._Paths(request["owner"])

    assert not root.exists() and not unit.exists() and not transaction.exists()
    assert model.interface is None and not model.network
    assert not any(command[0] == "systemctl" for command in model.commands)


def test_NewEnablementDirectoryAndParentAreDurableBeforeCommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Creating multi-user.target.wants needs both its link entries and SYSTEMD's new directory entry persisted."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    events: list[tuple[str, Path | str]] = []
    sync, run, atomic = guest._SyncDirectory, model.Run, guest._Atomic

    def Sync(path: Path) -> None:
        """Retain real fsync behavior and record the directory boundary."""

        sync(path)
        events.append(("sync", path))

    def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        """Record enablement after the synthetic systemd has actually created its new directory."""

        result = run(command, **kwargs)

        if command[:2] == ["systemctl", "enable"]:
            events.append(("enable", "complete"))

        return result

    def Atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
        """Reject a commit unless both post-enablement parent levels have already been persisted."""

        if path == model.root / "receipt.json" and json.loads(content)["status"] == "installed":
            after = events[events.index(("enable", "complete")) + 1:]
            wants = ("sync", guest.SYSTEMD / "multi-user.target.wants")
            parent = ("sync", guest.SYSTEMD)

            assert wants in after and parent in after and after.index(wants) < after.index(parent)

        atomic(path, content, mode)

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)
    monkeypatch.setattr(guest, "_Run", Run)
    monkeypatch.setattr(guest, "_Atomic", Atomic)
    guest._Install(stage, request)


def test_ReceiptFsyncFailureRetriesCommitDurabilityBeforeJournalRetirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An already published healthy receipt needs durable retry, without a false rollback report."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    sync = guest._SyncDirectory
    failed = False
    committed = False
    observations: list[str] = []

    def Sync(path: Path) -> None:
        """Fail once after installed receipt rename and require the root retry before removing its journal."""

        nonlocal failed, committed

        if path == model.root and (path / "receipt.json").exists():
            if json.loads((path / "receipt.json").read_bytes())["status"] == "installed":
                if not failed:
                    failed = True
                    observations.append("commit-fsync-failed")

                    raise OSError("Synthetic committed receipt fsync failure")

                committed = True
                observations.append("commit-durable")

        if path.name == "txn-" + request["owner"] and not (path / "transaction.json").exists():
            assert committed, "Recovery evidence cannot be retired before retrying committed root durability"
            observations.append("journal-retired")

        sync(path)

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)
    guest._Install(stage, request)

    assert failed and model.active and model.interface is not None
    assert observations == ["commit-fsync-failed", "commit-durable", "journal-retired"]
    assert guest._Check(model.root, model.unit, request)["status"] == "installed"
    assert not guest._Paths(request["owner"])[2].exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "permissions"])
def test_LinkedOrOverexposedPrivateFilesCannotBeAdoptedForCleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str,
) -> None:
    """Even byte-identical configuration is foreign when its filesystem ownership boundary changes."""

    stage, request, model = Seed(tmp_path, monkeypatch)
    guest._Install(stage, request)
    root, _, _ = guest._Paths(request["owner"])
    expected = guest._Digest((root / "receipt.json").read_bytes())
    config = root / "server.conf"
    external = tmp_path / "foreign-copy"

    if kind == "permissions":
        config.chmod(0o644)

    else:
        config.rename(external)

        if kind == "symlink":
            config.symlink_to(external)

        else:
            os.link(external, config)

    model.commands.clear()

    with pytest.raises((guest.GuestError, OSError)):
        guest._Remove(request["owner"], expected)

    assert not model.commands and model.interface is not None and model.network

    if kind != "permissions":
        assert external.read_bytes() == config.read_bytes()
