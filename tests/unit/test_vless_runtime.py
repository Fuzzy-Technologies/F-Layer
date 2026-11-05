"""Exercise runtime replacement, crash recovery and drift refusal with isolated POSIX files."""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

if os.name == "posix":
    from flayer.profiles import _vless_guest as guest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owned guest transactions require POSIX filesystem semantics")
OLD_BINARY = b"\x7fELFlegacy-runtime"
NEW_BINARY = b"\x7fELFcurrent-runtime"
CONFIG = b'{"private-fixture":"retain-exact-bytes"}\n'
SUBPROCESS_RUN = subprocess.run


def Seed(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, dict[str, Any], str, list[list[str]]]:
    """Create the exact old receipt/layout without installing anything or contacting a service."""

    base, systemd = tmpPath / "owned", tmpPath / "units"
    base.mkdir()
    systemd.mkdir()
    owner = "b" * 64
    root = base / owner[:24]
    root.mkdir(mode=0o755)
    service = systemd / f"flayer-vless-{owner[:24]}.service"
    service.write_bytes(guest._Unit(root))
    service.chmod(0o644)
    (root / "server.json").write_bytes(CONFIG)
    (root / "server.json").chmod(0o600)
    (root / "xray").write_bytes(OLD_BINARY)
    (root / "xray").chmod(0o755)
    receipt = {"owner": owner, "xray_version": guest.LEGACY_VERSION, "files": {
        "xray": guest._Digest(OLD_BINARY), "server.json": guest._Digest(CONFIG),
        "service": guest._Digest(service.read_bytes()),
    }}
    raw = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    (root / "owner.json").write_bytes(raw)
    (root / "owner.json").chmod(0o600)
    (base / f".{owner[:24]}.lock").touch(mode=0o600)
    monkeypatch.setattr(guest, "BASE", base)
    monkeypatch.setattr(guest, "SYSTEMD", systemd)
    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(guest, "_DownloadBinary", lambda: NEW_BINARY)
    commands: list[list[str]] = []
    monkeypatch.setattr(guest, "_Command", lambda command, **kwargs: commands.append(command))
    monkeypatch.setattr(guest, "_Health", lambda *args: None)
    monkeypatch.setattr(guest.platform, "release", lambda: "6.8.0-fixture")
    monkeypatch.setattr(guest.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0, b"6.8.0-fixture", b""))
    request = {"schema_version": 1, "owner": owner, "config_sha256": guest._Digest(CONFIG),
               "port": 443, "xray_version": guest.LEGACY_VERSION}

    return root, service, request, guest._Digest(raw), commands


def Snapshot(root: Path, service: Path) -> dict[str, tuple[bytes, int]]:
    """Capture exact managed bytes and permissions without following journal directories."""

    return {path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in (*root.iterdir(), service) if path.is_file()}


def test_UpgradePreservesCredentialsAndRetainsVerifiedRollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the executable and receipt may change, and repeats must not restart a working service."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    original = Snapshot(root, service)
    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
    receipt = guest._Existing(root, service, request["owner"])

    assert receipt is not None and receipt["xray_version"] == guest.XRAY_VERSION
    assert (root / "xray").read_bytes() == NEW_BINARY
    assert (root / "server.json").read_bytes() == original["server.json"][0]
    assert service.read_bytes() == original[service.name][0]
    assert stat.S_IMODE((root / "server.json").stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "runtime-upgrade").stat().st_mode) == 0o700
    assert (root / "runtime-upgrade/old-xray").read_bytes() == OLD_BINARY
    assert guest._RuntimeStatus(root, service, request)["upgrade_status"] == "rollback-available"
    after = list(commands)
    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)

    assert commands == after, "An identical upgrade must not stop or restart the service"
    assert [command[:2] for command in commands if command[0] == "systemctl"] == [
        ["systemctl", "stop"], ["systemctl", "start"],
    ]


@pytest.mark.parametrize("precondition", ["version", "receipt", "config", "service", "binary", "owner", "foreign-file"])
def test_UnexpectedOldStateRefusesBeforeServiceMutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, precondition: str,
) -> None:
    """Receipt consent never permits replacing changed or foreign managed content."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    version = guest.LEGACY_VERSION

    if precondition == "version":
        version = guest.XRAY_VERSION

    elif precondition == "receipt":
        expected = "a" * 64

    elif precondition == "config":
        (root / "server.json").write_bytes(CONFIG + b"changed")

    elif precondition == "service":
        service.write_bytes(b"changed")

    elif precondition == "binary":
        (root / "xray").write_bytes(b"changed")

    elif precondition == "owner":
        request = {**request, "owner": "c" * 64}

    else:
        (root / "foreign").touch()

    snapshot = Snapshot(root, service)

    with pytest.raises(guest.GuestError):
        guest._Upgrade(root, service, request, version, expected)

    assert not commands
    assert Snapshot(root, service) == snapshot
    assert not (root / "runtime-upgrade").exists()


@pytest.mark.parametrize("failure", ["syntax", "stop", "new-binary", "new-receipt", "start", "health"])
def test_UpgradeFailureRestoresOriginalRuntimeOrFailsBeforeSwitch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    """Exercise failures at distinct transaction boundaries, not just a mocked final success."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    before = Snapshot(root, service)
    atomic = guest._Atomic
    failed = False

    def Write(path: Path, content: bytes, mode: int) -> None:
        """Fail after one actual replacement so automatic rollback must repair a mixed crash state."""

        nonlocal failed
        atomic(path, content, mode)

        if not failed and ((failure == "new-binary" and path == root / "xray")
                           or (failure == "new-receipt" and path == root / "owner.json")):
            failed = True

            raise OSError("fixture write failure")

    def Command(command: list[str], **kwargs: object) -> None:
        """Fail one syntax or service operation while permitting the restoration attempt."""

        nonlocal failed
        commands.append(command)

        if not failed and ((failure == "syntax" and command[0] != "systemctl")
                           or (failure in {"stop", "start"} and command[:2] == ["systemctl", failure])):
            failed = True

            raise guest.GuestError("fixture command failure")

    def Health(*args: object) -> None:
        """Reject the new runtime while accepting the restored old executable."""

        if failure == "health" and (root / "xray").read_bytes() == NEW_BINARY:
            raise guest.GuestError("fixture new-runtime health failure")

    monkeypatch.setattr(guest, "_Atomic", Write)
    monkeypatch.setattr(guest, "_Command", Command)
    monkeypatch.setattr(guest, "_Health", Health)

    with pytest.raises(guest.GuestError):
        guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)

    assert Snapshot(root, service) == before
    assert not (root / "runtime-upgrade").exists()


@pytest.mark.parametrize("boundary", ["published", "binary", "receipt", "started", "rollback"])
def test_ForcedInterruptionCanBeRecoveredWithOriginalReceipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """A killed operation must leave a journal that supports a separately authorized restoration."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    before = Snapshot(root, service)
    atomic = guest._Atomic

    class PowerLoss(BaseException):
        """Bypass ordinary exception rollback to model a process kill."""

    def Write(path: Path, content: bytes, mode: int) -> None:
        """Interrupt immediately after an atomic binary or receipt replacement."""

        atomic(path, content, mode)

        if (boundary == "binary" and path == root / "xray"
                or boundary == "receipt" and path == root / "owner.json"):
            raise PowerLoss

    def Command(command: list[str], **kwargs: object) -> None:
        """Interrupt after journal publication or the runtime start command."""

        commands.append(command)

        if (boundary == "published" and command[:2] == ["systemctl", "stop"]
                or boundary == "started" and command[:2] == ["systemctl", "start"]):
            raise PowerLoss

    def Health(*args: object) -> None:
        """Make both new-runtime health and the first automatic restoration fail."""

        if boundary == "rollback":
            raise guest.GuestError("fixture unavailable health")

    monkeypatch.setattr(guest, "_Atomic", Write)
    monkeypatch.setattr(guest, "_Command", Command)

    if boundary == "rollback":
        calls = 0

        def FailAfterPreflight(*args: object) -> None:
            """Allow the old preflight, then fail new health and automatic rollback health."""

            nonlocal calls
            calls += 1

            if calls > 1:
                Health()

        monkeypatch.setattr(guest, "_Health", FailAfterPreflight)

    with pytest.raises((PowerLoss, guest.GuestError)):
        guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)

    assert guest._RuntimeStatus(root, service, request)["upgrade_status"] == "interrupted"

    with pytest.raises(guest.GuestError, match="interrupted"):
        guest._Existing(root, service, request["owner"])

    monkeypatch.setattr(guest, "_Atomic", atomic)
    monkeypatch.setattr(guest, "_Command", lambda command, **kwargs: None)
    monkeypatch.setattr(guest, "_Health", lambda *args: None)
    guest._RollbackRuntime(root, service, request, guest.LEGACY_VERSION, expected, recover=True)

    assert Snapshot(root, service) == before
    assert not (root / "runtime-upgrade").exists()


@pytest.mark.parametrize("tamper", ["extra", "backup", "owner", "journal", "config", "service", "current", "symlink", "permissions"])
def test_ChangedTransactionBlocksRollbackWithoutCommands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tamper: str,
) -> None:
    """Even a valid initial authorization cannot bypass later journal or managed-file drift."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
    newReceipt = guest._Digest((root / "owner.json").read_bytes())
    directory = root / "runtime-upgrade"

    if tamper == "extra":
        (directory / "foreign").touch()

    elif tamper in {"backup", "owner", "journal"}:
        name = {"backup": "old-xray", "owner": "old-owner.json", "journal": "transaction.json"}[tamper]
        (directory / name).write_bytes(b"changed")

    elif tamper == "config":
        (root / "server.json").write_bytes(b"changed")

    elif tamper == "service":
        service.write_bytes(b"changed")

    elif tamper == "current":
        (root / "xray").write_bytes(b"changed")

    elif tamper == "symlink":
        (directory / "old-xray").unlink()
        (directory / "old-xray").symlink_to(root / "xray")

    else:
        directory.chmod(0o755)

    commands.clear()

    with pytest.raises((guest.GuestError, OSError, ValueError)):
        guest._RollbackRuntime(root, service, request, guest.XRAY_VERSION, newReceipt)

    assert not commands
    assert (root / "runtime-upgrade").exists(), "Never erase a transaction whose ownership is uncertain"


def test_ExplicitRollbackRestoresExactOldBytesAndRemovalCleansBackup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rollback consumes the new receipt and normal owned removal includes verified saved binaries."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    before = Snapshot(root, service)
    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
    current = guest._Digest((root / "owner.json").read_bytes())

    with pytest.raises(guest.GuestError):
        guest._RollbackRuntime(root, service, request, guest.XRAY_VERSION, expected)

    guest._RollbackRuntime(root, service, request, guest.XRAY_VERSION, current)

    assert Snapshot(root, service) == before
    assert guest._RuntimeStatus(root, service, request)["upgrade_status"] == "none"

    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
    guest._Remove(root, service, request["owner"])

    assert not root.exists() and not service.exists()


def test_OrdinaryDeployCannotImplicitlyUpgradeOrDowngrade(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A current installer can maintain an old prepared project without replacing its runtime implicitly."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    monkeypatch.setattr(guest, "_TargetHealth", lambda *args: None)

    with pytest.raises(guest.GuestError, match="explicit upgrade"):
        guest._Install(root, service, {**request, "xray_version": guest.XRAY_VERSION}, CONFIG)

    assert not commands

    guest._Install(root, service, request, CONFIG)

    assert (root / "xray").read_bytes() == OLD_BINARY

    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
    commands.clear()
    guest._Install(root, service, request, CONFIG)

    assert (root / "xray").read_bytes() == NEW_BINARY
    assert commands == [["systemctl", "enable", "--now", service.name]]


def test_RuntimeMainRequiresConsentAndStatusDoesNotModifyOwnedFiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise the uploaded entrypoint rather than only calling the transaction helpers."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    stage = tmp_path / "upload"
    stage.mkdir()
    (stage / "deployment.json").write_text(json.dumps(request))
    (stage / "server.json").write_bytes(CONFIG)
    (stage / "server.json").chmod(0o600)
    monkeypatch.setattr(guest, "__file__", str(stage / "install.py"))
    monkeypatch.setattr(guest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guest.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    before = Snapshot(root, service)

    assert guest.Main(["--runtime-status"]) == 0

    status = json.loads(capsys.readouterr().out)

    assert status["kernel_patch_status"] == "not-assessed"
    assert status["kernel_release"] == "6.8.0-fixture"
    assert status["kernel_package_version"] == "6.8.0-fixture"
    assert Snapshot(root, service) == before and not commands
    assert guest.Main(["--upgrade", "--expected-version", guest.LEGACY_VERSION,
                       "--expected-receipt-sha256", expected]) == 1
    assert Snapshot(root, service) == before and not commands
    assert guest.Main(["--upgrade", "--allow-mutation", "--expected-version", guest.LEGACY_VERSION,
                       "--expected-receipt-sha256", expected]) == 0

    output = capsys.readouterr()

    assert json.loads(output.out)["version"] == guest.XRAY_VERSION
    assert CONFIG.decode().strip() not in output.err


def test_RealPinnedRuntimesUpgradeAndRollbackWithUnchangedConfig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Execute both verified binaries through the real transaction while systemd remains an isolated fake."""

    oldPath = os.environ.get("FLAYER_LEGACY_XRAY_BINARY")
    newPath = os.environ.get("FLAYER_XRAY_BINARY")

    if not oldPath or not newPath:
        pytest.skip("Both checksum-verified pinned binaries are required for runtime transition validation")

    from flayer.core.contracts import StackIdentity
    from flayer.profiles.vless import GenerateVlessMaterial, RenderVlessServer, VlessRealitySettings
    from flayer.profiles.vpn import VpnDevice, VpnListener, VpnProfile, VpnRoutes

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    identity = StackIdentity("example", "runtime", "yandex-cloud", "example-folder", "example-owner")
    profile = VpnProfile(identity, (VpnDevice("phone"),),
                         VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
                         (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),))
    config = RenderVlessServer(profile, VlessRealitySettings("www.example.org", "www.example.org"),
                               GenerateVlessMaterial(profile))
    oldBinary, newBinary = Path(oldPath).read_bytes(), Path(newPath).read_bytes()
    receipt = json.loads((root / "owner.json").read_bytes())
    receipt["files"]["xray"] = guest._Digest(oldBinary)
    receipt["files"]["server.json"] = guest._Digest(config)
    raw = (json.dumps(receipt, sort_keys=True) + "\n").encode()
    (root / "xray").write_bytes(oldBinary)
    (root / "server.json").write_bytes(config)
    (root / "owner.json").write_bytes(raw)
    request["config_sha256"] = guest._Digest(config)
    expected = guest._Digest(raw)
    before = Snapshot(root, service)
    monkeypatch.setattr(guest, "_DownloadBinary", lambda: newBinary)

    def Command(command: list[str], **kwargs: object) -> None:
        """Run syntax validation with the actual ELF, never host systemd or a cloud command."""

        if command[0] == "systemctl":
            commands.append(command)

            return

        result = SUBPROCESS_RUN(command, capture_output=True, timeout=15, check=False)

        assert result.returncode == 0, "Pinned Xray rejected the unchanged server configuration"

    def Health(*args: object) -> None:
        """Check version identity and syntax without claiming a running tunnel or client traffic."""

        result = SUBPROCESS_RUN([str(root / "xray"), "version"], capture_output=True, timeout=15, check=True)

        assert any(f"Xray {version}".encode() in result.stdout for version in (guest.LEGACY_VERSION, guest.XRAY_VERSION))

        Command([str(root / "xray"), "run", "-test", "-config", str(root / "server.json")])

    monkeypatch.setattr(guest, "_Command", Command)
    monkeypatch.setattr(guest, "_Health", Health)
    guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)

    assert (root / "xray").read_bytes() == newBinary

    guest._RollbackRuntime(root, service, request, guest.XRAY_VERSION, guest._Digest((root / "owner.json").read_bytes()))

    assert Snapshot(root, service) == before


def test_ProcessExitDuringAtomicWriteLeavesRecoverableJournal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real killed child bypasses finally cleanup, so its temporary file must not block recovery."""

    root, service, request, expected, commands = Seed(tmp_path, monkeypatch)
    before = Snapshot(root, service)
    process = os.fork()

    if process == 0:
        replaceFile = guest.os.replace

        def ExitBeforeRename(source: object, destination: object) -> None:
            """Exit after fsync of a replacement but before its atomic rename."""

            if Path(destination) == root / "xray":
                os._exit(19)

            replaceFile(source, destination)

        guest.os.replace = ExitBeforeRename
        guest._Upgrade(root, service, request, guest.LEGACY_VERSION, expected)
        os._exit(20)

    _, waitStatus = os.waitpid(process, 0)

    assert os.waitstatus_to_exitcode(waitStatus) == 19
    assert any(path.name.startswith(".flayer-") for path in root.parent.iterdir())
    assert guest._RuntimeStatus(root, service, request)["upgrade_status"] == "interrupted"

    guest._RollbackRuntime(root, service, request, guest.LEGACY_VERSION, expected, recover=True)

    assert Snapshot(root, service) == before
