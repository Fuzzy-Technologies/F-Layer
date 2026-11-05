"""Install, check, or remove one private F-Layer Xray deployment on Ubuntu 24.04."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import io
import json
import os
import platform
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

XRAY_VERSION = "26.10.31"
LEGACY_VERSION = "26.9.30"
ARCHIVES = {
    "x86_64": ("Xray-linux-64.zip", "e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214"),
    "aarch64": ("Xray-linux-arm64-v8a.zip", "1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d"),
}
_TRANSACTION_FILES = frozenset({"old-xray", "new-xray", "old-owner.json", "new-owner.json", "transaction.json"})
_ROOT_UID = 0
BASE = Path("/opt/flayer/vless")
SYSTEMD = Path("/etc/systemd/system")
MAX_BINARY_BYTES = 96 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024


class GuestError(ValueError):
    """A bounded installation check failed without exposing private payloads."""


def _Digest(value: bytes) -> str:
    """Hash exact managed bytes for drift detection and ownership receipts."""

    return hashlib.sha256(value).hexdigest()


def _Read(path: Path, limit: int, *, rootOwned: bool = False) -> bytes:
    """Read a bounded regular non-linked file, keeping filesystem errors private."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise GuestError("Managed input must be a bounded regular file without hardlinks")

        if path.name == "server.json" and stat.S_IMODE(info.st_mode) != 0o600:
            raise GuestError("Server credential files must use private mode 0600")

        if rootOwned and (info.st_uid != _ROOT_UID or info.st_mode & 0o022):
            raise GuestError("Managed files must be root-owned and not writable by other users")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)

        if len(content) > limit:
            raise GuestError("Managed input exceeds its size bound")

        return content

    finally:
        os.close(descriptor)


def _Directory(path: Path, *, create: bool = False) -> None:
    """Reject symlink ancestry and require a root-owned non-writable managed directory."""

    if any(item.is_symlink() for item in (path, *path.parents)):
        raise GuestError("Managed directory paths must not contain symbolic links")

    if create:
        path.mkdir(mode=0o755, exist_ok=True)

    info = path.stat()

    if not stat.S_ISDIR(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022:
        raise GuestError("Managed directories must be root-owned and not writable by other users")


def _Atomic(path: Path, content: bytes, mode: int) -> None:
    """Replace one bounded owned file atomically without following its destination."""

    descriptor, temporary = tempfile.mkstemp(prefix=".flayer-", dir=path.parent)

    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        _Sync(path.parent)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _Sync(directory: Path) -> None:
    """Persist directory entries after a managed atomic replacement or journal publication."""

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def _Command(arguments: list[str], *, timeout: int = 30) -> None:
    """Run fixed commands with bounded time and suppress credential-bearing daemon errors."""

    try:
        result = subprocess.run(
            arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
        )

    except (OSError, subprocess.TimeoutExpired):
        raise GuestError("Required guest command failed or timed out") from None

    if result.returncode != 0:
        raise GuestError("Required guest command returned an unsuccessful status")


def _DownloadBinary() -> bytes:
    """Download only a pinned official asset and extract one verified regular ELF entry."""

    architecture = platform.machine()

    if architecture not in ARCHIVES:
        raise GuestError("Xray deployment supports only amd64 and arm64 guests")

    filename, expectedHash = ARCHIVES[architecture]
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{filename}"

    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read(MAX_ARCHIVE_BYTES + 1)

    if len(content) > MAX_ARCHIVE_BYTES or _Digest(content) != expectedHash:
        raise GuestError("Xray archive does not match the pinned release checksum")

    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        entries = archive.infolist()

        if len(entries) > 16 or len({item.filename for item in entries}) != len(entries):
            raise GuestError("Xray archive contains unexpected or duplicate entries")

        for entry in entries:
            if (
                entry.filename not in {"xray", "geoip.dat", "geosite.dat", "LICENSE", "README.md"}
                or entry.file_size > MAX_BINARY_BYTES
                or stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG}
            ):
                raise GuestError("Xray archive contains an unsafe path or entry")

        binary = archive.read("xray")

    if not 4 <= len(binary) <= MAX_BINARY_BYTES or not binary.startswith(b"\x7fELF"):
        raise GuestError("Xray archive must contain a bounded Linux executable")

    return binary


def _Request(directory: Path) -> tuple[dict[str, Any], bytes]:
    """Bind private configuration bytes to a strict nonsecret deployment descriptor."""

    deployment = json.loads(_Read(directory / "deployment.json", 4096))
    expected = {"schema_version", "owner", "config_sha256", "port", "xray_version"}

    if not isinstance(deployment, dict) or set(deployment) != expected:
        raise GuestError("Deployment descriptor has an unsupported schema")

    if (type(deployment["schema_version"]) is not int or deployment["schema_version"] != 1
            or not isinstance(deployment["xray_version"], str)
            or deployment["xray_version"] not in {LEGACY_VERSION, XRAY_VERSION}):
        raise GuestError("Deployment descriptor has an unsupported version")

    if any(not isinstance(deployment[key], str) or re.fullmatch(r"[0-9a-f]{64}", deployment[key])
           is None for key in ("owner", "config_sha256")):
        raise GuestError("Deployment descriptor requires exact ownership and content hashes")

    if type(deployment["port"]) is not int or not 1 <= deployment["port"] <= 65535:
        raise GuestError("Deployment descriptor requires one TCP port")

    config = _Read(directory / "server.json", 1048576)

    if _Digest(config) != deployment["config_sha256"]:
        raise GuestError("Server configuration differs from the prepared private bundle")

    return deployment, config


def _Unit(root: Path) -> bytes:
    """Run the daemon under a transient unprivileged identity with a private config credential."""

    return ("\n".join((
        "[Unit]", "Description=F-Layer VLESS Reality gateway", "After=network-online.target",
        "Wants=network-online.target", "", "[Service]", "Type=simple", "DynamicUser=yes",
        f"LoadCredential=server.json:{root}/server.json",
        f"ExecStart={root}/xray run -config %d/server.json", "Restart=on-failure", "RestartSec=3",
        "NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
        "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
        "ProtectControlGroups=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
        "RestrictAddressFamilies=AF_INET AF_UNIX", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE", "StandardOutput=null", "StandardError=null",
        "", "[Install]", "WantedBy=multi-user.target", "",
    ))).encode("utf-8")


def _Existing(root: Path, service: Path, owner: str) -> dict[str, Any] | None:
    """Refuse foreign, drifted, or incomplete installations before any managed mutation."""

    if not root.exists() and not root.is_symlink():
        if service.exists() or service.is_symlink():
            raise GuestError("An unowned systemd service already occupies this deployment name")

        return None

    _Directory(root)

    if (root / "runtime-upgrade").exists() or (root / "runtime-upgrade").is_symlink():
        transaction = _Transaction(root, service, owner)

        if transaction["phase"] != "committed":
            raise GuestError("Runtime upgrade is interrupted; use explicit recover-upgrade")

        return _Receipt(_Read(root / "owner.json", 4096, rootOwned=True), owner)

    receipt = json.loads(_Read(root / "owner.json", 4096, rootOwned=True))

    if not isinstance(receipt, dict) or set(receipt) != {"owner", "files", "xray_version"} or receipt["owner"] != owner:
        raise GuestError("Existing deployment does not belong to the requested stack")

    if not isinstance(receipt["xray_version"], str) or receipt["xray_version"] not in {LEGACY_VERSION, XRAY_VERSION}:
        raise GuestError("Existing deployment uses a different pinned Xray version")

    hashes = receipt["files"]

    if not isinstance(hashes, dict) or set(hashes) != {"xray", "server.json", "service"}:
        raise GuestError("Existing deployment has an invalid ownership receipt")

    _Receipt(_Read(root / "owner.json", 4096, rootOwned=True), owner)

    if {item.name for item in root.iterdir()} != {"xray", "server.json", "owner.json"}:
        raise GuestError("Existing deployment contains untracked or interrupted files")

    for name, path in (("xray", root / "xray"), ("server.json", root / "server.json"), ("service", service)):
        if _Digest(_Read(path, MAX_BINARY_BYTES, rootOwned=True)) != hashes[name]:
            raise GuestError("Existing deployment changed outside F-Layer; refusing replacement")

    if stat.S_IMODE((root / "server.json").stat().st_mode) != 0o600:
        raise GuestError("Managed server credentials must retain private permissions")

    return receipt



def _TargetHealth(config: bytes) -> None:
    """Require the configured Reality target to offer certificate-valid TLS 1.3 and HTTP/2."""

    try:
        settings = json.loads(config)["inbounds"][0]["streamSettings"]["realitySettings"]
        host, port = settings["target"].rsplit(":", 1)
        serverName = settings["serverNames"][0]
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])

        with socket.create_connection((host, int(port)), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=serverName) as channel:
                if channel.version() != "TLSv1.3" or channel.selected_alpn_protocol() != "h2":
                    raise GuestError("Reality target must support TLS 1.3 and HTTP/2")

    except (OSError, ValueError, KeyError, IndexError, TypeError):
        raise GuestError(
            "Reality target preflight failed: verify its TLS 1.3/HTTP2 support, certificate name, and guest reachability"
        ) from None


def _Health(root: Path, service: Path, port: int) -> None:
    """Check daemon syntax, systemd state, and a loopback listener without claiming tunnel health."""

    _TargetHealth(_Read(root / "server.json", 1048576, rootOwned=True))
    _Command([str(root / "xray"), "run", "-test", "-config", str(root / "server.json")])
    _Command(["systemctl", "is-active", "--quiet", service.name])

    deadline = time.monotonic() + 5

    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return

        except OSError:
            if time.monotonic() >= deadline:
                raise GuestError("VLESS process has no reachable local TCP listener") from None

            time.sleep(0.1)


def _Install(root: Path, service: Path, request: dict[str, Any], config: bytes) -> None:
    """Install or retry exact owned bytes; reject implicit credential replacement."""

    previous = _Existing(root, service, request["owner"])
    unit = _Unit(root)

    if previous is not None:
        if previous["files"]["server.json"] != _Digest(config):
            raise GuestError("VLESS credential replacement requires an explicit expected-old authorization")

        if previous["files"]["service"] != _Digest(unit):
            raise GuestError("Owned service layout differs from this installer version")

        if previous["xray_version"] == LEGACY_VERSION and request["xray_version"] == XRAY_VERSION:
            raise GuestError("Existing runtime requires an explicit upgrade; ordinary deploy cannot upgrade it")

        _TargetHealth(config)
        _Command(["systemctl", "enable", "--now", service.name])
        _Health(root, service, request["port"])

        return

    if request["xray_version"] != XRAY_VERSION:
        raise GuestError("Legacy bundles can retry existing installations but cannot create an outdated runtime")

    _TargetHealth(config)
    binary = _DownloadBinary()

    with tempfile.TemporaryDirectory(prefix=".verify-", dir=BASE) as temporary:
        staged = Path(temporary)
        _Atomic(staged / "xray", binary, 0o700)
        _Atomic(staged / "server.json", config, 0o600)
        _Command([str(staged / "xray"), "run", "-test", "-config", str(staged / "server.json")])

    _Directory(root, create=True)
    receipt = {"owner": request["owner"], "xray_version": XRAY_VERSION, "files": {
        "xray": _Digest(binary), "server.json": _Digest(config), "service": _Digest(unit),
    }}

    try:
        _Atomic(root / "xray", binary, 0o755)
        _Atomic(root / "server.json", config, 0o600)
        _Atomic(service, unit, 0o644)
        _Command(["systemctl", "daemon-reload"])
        _Command(["systemctl", "enable", service.name])
        _Command(["systemctl", "restart", service.name])
        _Health(root, service, request["port"])
        _Atomic(root / "owner.json", (json.dumps(receipt, sort_keys=True) + "\n").encode(), 0o600)

    except (GuestError, OSError):
        _Command(["systemctl", "disable", "--now", service.name])

        for path in (service, root / "xray", root / "server.json", root / "owner.json"):
            path.unlink(missing_ok=True)

        root.rmdir()
        _Command(["systemctl", "daemon-reload"])

        raise GuestError("VLESS installation failed; this attempt's owned files were removed") from None


def _Remove(root: Path, service: Path, owner: str) -> None:
    """Delete only an unchanged owned daemon and its exact three tracked local files."""

    if _Existing(root, service, owner) is None:
        return

    _Command(["systemctl", "disable", "--now", service.name])

    if (root / "runtime-upgrade").exists():
        _ClearTransaction(root, service, owner)

    for path in (service, root / "xray", root / "server.json", root / "owner.json"):
        path.unlink()

    root.rmdir()
    _Command(["systemctl", "daemon-reload"])


def _Receipt(content: bytes, owner: str) -> dict[str, Any]:
    """Validate a bounded receipt without trusting its version, owner or file hash shapes."""

    receipt = json.loads(content)

    if (not isinstance(receipt, dict) or set(receipt) != {"owner", "files", "xray_version"}
            or receipt["owner"] != owner or not isinstance(receipt["xray_version"], str)
            or receipt["xray_version"] not in {LEGACY_VERSION, XRAY_VERSION}):
        raise GuestError("Runtime receipt has an unsupported owner or version")

    hashes = receipt["files"]

    if (not isinstance(hashes, dict) or set(hashes) != {"xray", "server.json", "service"}
            or any(not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
                   for value in hashes.values())):
        raise GuestError("Runtime receipt requires exact owned file hashes")

    return receipt


def _Transaction(root: Path, service: Path, owner: str) -> dict[str, Any]:
    """Verify both saved runtimes and every allowed current crash state before recovery."""

    _Directory(root)
    directory = root / "runtime-upgrade"
    _Directory(directory)

    if (stat.S_IMODE(directory.stat().st_mode) != 0o700
            or {path.name for path in directory.iterdir()} != _TRANSACTION_FILES
            or {path.name for path in root.iterdir()} != {"xray", "server.json", "owner.json", "runtime-upgrade"}):
        raise GuestError("Runtime transaction contains unexpected or incomplete files")

    record = json.loads(_Read(directory / "transaction.json", 4096, rootOwned=True))

    if (not isinstance(record, dict)
            or set(record) != {"schema_version", "owner", "phase", "old_receipt_sha256", "new_receipt_sha256"}
            or type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["owner"] != owner or not isinstance(record["phase"], str)
            or record["phase"] not in {"prepared", "committed"}):
        raise GuestError("Runtime transaction has invalid ownership or phase")

    receipts = {}

    for label, version in (("old", LEGACY_VERSION), ("new", XRAY_VERSION)):
        raw = _Read(directory / f"{label}-owner.json", 4096, rootOwned=True)
        receipt = _Receipt(raw, owner)

        if receipt["xray_version"] != version or _Digest(raw) != record[f"{label}_receipt_sha256"]:
            raise GuestError("Runtime transaction receipt differs from its recorded version or hash")

        if _Digest(_Read(directory / f"{label}-xray", MAX_BINARY_BYTES, rootOwned=True)) != receipt["files"]["xray"]:
            raise GuestError("Saved runtime changed outside the verified transaction")

        receipts[label] = receipt

    oldFiles, newFiles = receipts["old"]["files"], receipts["new"]["files"]

    for name, path in (("server.json", root / "server.json"), ("service", service)):
        if oldFiles[name] != newFiles[name] or _Digest(_Read(path, MAX_BINARY_BYTES, rootOwned=True)) != oldFiles[name]:
            raise GuestError("Runtime maintenance cannot replace changed configuration or service bytes")

    if oldFiles["service"] != _Digest(_Unit(root)):
        raise GuestError("Runtime transaction has an unsupported service layout")

    currentReceipt = _Digest(_Read(root / "owner.json", 4096, rootOwned=True))
    currentBinary = _Digest(_Read(root / "xray", MAX_BINARY_BYTES, rootOwned=True))

    if (currentReceipt not in {record["old_receipt_sha256"], record["new_receipt_sha256"]}
            or currentBinary not in {oldFiles["xray"], newFiles["xray"]}):
        raise GuestError("Current runtime drifted outside the verified transaction")

    if record["phase"] == "committed" and (
        currentReceipt != record["new_receipt_sha256"] or currentBinary != newFiles["xray"]
    ):
        raise GuestError("Committed runtime differs from its verified transaction")

    return record


def _ClearTransaction(root: Path, service: Path, owner: str) -> None:
    """Atomically detach a verified journal before deleting only its known saved files."""

    _Transaction(root, service, owner)
    detached = Path(tempfile.mkdtemp(prefix=".runtime-removed-", dir=BASE))
    directory = detached / "transaction"
    os.rename(root / "runtime-upgrade", directory)
    _Sync(root)

    for name in _TRANSACTION_FILES:
        (directory / name).unlink()

    directory.rmdir()
    detached.rmdir()


def _SwitchRuntime(root: Path, service: Path, owner: str, label: str, port: int) -> None:
    """Switch only a validated executable/receipt pair and verify the owned VLESS service."""

    record = _Transaction(root, service, owner)
    directory = root / "runtime-upgrade"

    # A recovery can itself be interrupted; keep the journal prepared before its first write.
    record["phase"] = "prepared"
    _Atomic(directory / "transaction.json", (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    _Command(["systemctl", "stop", service.name])
    _Transaction(root, service, owner)
    _Atomic(root / "xray", _Read(directory / f"{label}-xray", MAX_BINARY_BYTES, rootOwned=True), 0o755)
    _Atomic(root / "owner.json", _Read(directory / f"{label}-owner.json", 4096, rootOwned=True), 0o600)
    _Command(["systemctl", "start", service.name])
    _Health(root, service, port)


def _RequireRuntimeConsent(expectedVersion: str, expectedReceipt: str) -> None:
    """Require an exact supported previous version and complete lowercase receipt digest."""

    if (not isinstance(expectedVersion, str) or not isinstance(expectedReceipt, str)
            or expectedVersion not in {LEGACY_VERSION, XRAY_VERSION}
            or re.fullmatch(r"[0-9a-f]{64}", expectedReceipt) is None):
        raise GuestError("Runtime mutation requires an exact expected version and receipt SHA-256")


def _Upgrade(root: Path, service: Path, request: dict[str, Any], expectedVersion: str, expectedReceipt: str) -> None:
    """Publish a durable rollback journal before an explicitly authorized binary-only upgrade."""

    _RequireRuntimeConsent(expectedVersion, expectedReceipt)

    if expectedVersion != LEGACY_VERSION:
        raise GuestError("Only the supported legacy-to-current runtime upgrade is available")

    if (root / "runtime-upgrade").exists() or (root / "runtime-upgrade").is_symlink():
        record = _Transaction(root, service, request["owner"])

        if record["phase"] != "committed" or record["old_receipt_sha256"] != expectedReceipt:
            raise GuestError("Interrupted or unexpected runtime transaction requires explicit recovery")

        _Health(root, service, request["port"])

        return

    previous = _Existing(root, service, request["owner"])

    if previous is None:
        raise GuestError("Runtime upgrade requires an existing owned service")

    raw = _Read(root / "owner.json", 4096, rootOwned=True)

    if previous["xray_version"] != expectedVersion or _Digest(raw) != expectedReceipt:
        raise GuestError("Runtime differs from the explicitly expected version or receipt")

    if (previous["files"]["server.json"] != request["config_sha256"]
            or previous["files"]["service"] != _Digest(_Unit(root))):
        raise GuestError("Runtime upgrade requires the original configuration and service layout")

    _Health(root, service, request["port"])
    binary = _DownloadBinary()
    updated = {**previous, "xray_version": XRAY_VERSION, "files": {**previous["files"], "xray": _Digest(binary)}}
    newRaw = (json.dumps(updated, sort_keys=True) + "\n").encode()
    record = {"schema_version": 1, "owner": request["owner"], "phase": "prepared",
              "old_receipt_sha256": expectedReceipt, "new_receipt_sha256": _Digest(newRaw)}

    with tempfile.TemporaryDirectory(prefix=".runtime-stage-", dir=BASE) as temporary:
        staged = Path(temporary)
        _Atomic(staged / "old-xray", _Read(root / "xray", MAX_BINARY_BYTES, rootOwned=True), 0o600)
        _Atomic(staged / "old-owner.json", raw, 0o600)
        _Atomic(staged / "new-xray", binary, 0o700)
        _Atomic(staged / "new-owner.json", newRaw, 0o600)
        _Atomic(staged / "transaction.json", (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
        _Command([str(staged / "new-xray"), "run", "-test", "-config", str(root / "server.json")])

        if (_Existing(root, service, request["owner"]) != previous
                or _Read(root / "owner.json", 4096, rootOwned=True) != raw):
            raise GuestError("Runtime changed while preparing the upgrade")

        os.rename(staged, root / "runtime-upgrade")
        _Sync(root)

    try:
        _SwitchRuntime(root, service, request["owner"], "new", request["port"])
        record["phase"] = "committed"
        _Atomic(root / "runtime-upgrade/transaction.json", (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)

    except (GuestError, OSError):
        try:
            _SwitchRuntime(root, service, request["owner"], "old", request["port"])
            _ClearTransaction(root, service, request["owner"])

        except (GuestError, OSError):
            raise GuestError("Runtime upgrade failed; verified journal retained for explicit recover-upgrade") from None

        raise GuestError("Runtime upgrade failed; original runtime and receipt were restored") from None


def _RollbackRuntime(
    root: Path, service: Path, request: dict[str, Any], expectedVersion: str,
    expectedReceipt: str, *, recover: bool = False,
) -> None:
    """Restore the saved legacy binary only for an exact committed or interrupted transaction."""

    _RequireRuntimeConsent(expectedVersion, expectedReceipt)
    record = _Transaction(root, service, request["owner"])
    requiredPhase, label, version = ("prepared", "old", LEGACY_VERSION) if recover else ("committed", "new", XRAY_VERSION)

    if (record["phase"] != requiredPhase or expectedVersion != version
            or record[f"{label}_receipt_sha256"] != expectedReceipt):
        raise GuestError("Runtime rollback or recovery differs from the expected transaction")

    if _Digest(_Read(root / "server.json", 1048576, rootOwned=True)) != request["config_sha256"]:
        raise GuestError("Runtime rollback requires the unchanged prepared configuration")

    _SwitchRuntime(root, service, request["owner"], "old", request["port"])
    _ClearTransaction(root, service, request["owner"])


def _RuntimeStatus(root: Path, service: Path, request: dict[str, Any]) -> dict[str, object]:
    """Report bounded version/hash facts without reading keys into diagnostics or assessing patches."""

    upgradeStatus = "none"

    if (root / "runtime-upgrade").exists() or (root / "runtime-upgrade").is_symlink():
        record = _Transaction(root, service, request["owner"])
        upgradeStatus = "rollback-available" if record["phase"] == "committed" else "interrupted"

    elif _Existing(root, service, request["owner"]) is None:
        raise GuestError("Runtime status requires an existing owned service")

    raw = _Read(root / "owner.json", 4096, rootOwned=True)
    receipt = _Receipt(raw, request["owner"])

    if receipt["files"]["server.json"] != request["config_sha256"]:
        raise GuestError("Installed configuration differs from the prepared project")

    kernelRelease = platform.release()
    packageVersion = "unavailable"

    if re.fullmatch(r"[a-zA-Z0-9.+_-]{1,128}", kernelRelease) is None:
        kernelRelease = "unavailable"

    else:
        try:
            observed = subprocess.run(
                ["dpkg-query", "-W", "-f=${Version}", "linux-image-" + kernelRelease],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False,
            )
            value = observed.stdout.decode("ascii").strip()

            if observed.returncode == 0 and re.fullmatch(r"[a-zA-Z0-9.+:~_-]{1,128}", value):
                packageVersion = value

        except (OSError, UnicodeError, subprocess.TimeoutExpired):
            pass

    return {"version": receipt["xray_version"], "receipt_sha256": _Digest(raw),
            "binary_sha256": _Digest(_Read(root / "xray", MAX_BINARY_BYTES, rootOwned=True)),
            "upgrade_status": upgradeStatus, "kernel_release": kernelRelease,
            "kernel_package_version": packageVersion, "kernel_patch_status": "not-assessed"}


def Main(argv: list[str] | None = None) -> int:
    """Require scoped consent for runtime replacement while preserving existing installer actions."""

    parser = argparse.ArgumentParser(description="Manage an owned F-Layer VLESS Reality service")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true")
    action.add_argument("--remove", action="store_true")
    action.add_argument("--runtime-status", action="store_true", dest="runtimeStatus")
    action.add_argument("--upgrade", action="store_true")
    action.add_argument("--rollback-upgrade", action="store_true", dest="rollbackUpgrade")
    action.add_argument("--recover-upgrade", action="store_true", dest="recoverUpgrade")
    parser.add_argument("--allow-mutation", action="store_true", dest="allowMutation")
    parser.add_argument("--expected-version", default="", dest="expectedVersion")
    parser.add_argument("--expected-receipt-sha256", default="", dest="expectedReceipt")
    arguments = parser.parse_args(argv)
    runtimeInfo: dict[str, object] | None = None

    try:
        if os.geteuid() != 0:
            raise GuestError("VLESS guest installation requires sudo on the selected guest")

        release = platform.freedesktop_os_release()

        if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
            raise GuestError("VLESS guest installation supports only Ubuntu 24.04")

        request, config = _Request(Path(__file__).absolute().parent)
        mutation = arguments.upgrade or arguments.rollbackUpgrade or arguments.recoverUpgrade

        if mutation:
            if not arguments.allowMutation:
                raise GuestError("Runtime mutation requires explicit --allow-mutation")

            _RequireRuntimeConsent(arguments.expectedVersion, arguments.expectedReceipt)

        elif arguments.allowMutation or arguments.expectedVersion or arguments.expectedReceipt:
            raise GuestError("Runtime consent options require an explicit runtime mutation action")

        for directory in (BASE.parent.parent, BASE.parent, BASE):
            _Directory(directory, create=not arguments.runtimeStatus)

        _Directory(SYSTEMD)
        root = BASE / request["owner"][:24]
        service = SYSTEMD / f"flayer-vless-{request['owner'][:24]}.service"

        descriptor = os.open(
            BASE / f".{request['owner'][:24]}.lock",
            (os.O_RDONLY if arguments.runtimeStatus else os.O_CREAT | os.O_RDWR) | os.O_NOFOLLOW, 0o600,
        )

        try:
            info = os.fstat(descriptor)

            if not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_nlink != 1:
                raise GuestError("VLESS deployment lock must be an owned regular file")

            fcntl.flock(descriptor, (fcntl.LOCK_SH if arguments.runtimeStatus else fcntl.LOCK_EX) | fcntl.LOCK_NB)

            if arguments.remove:
                _Remove(root, service, request["owner"])

            elif arguments.runtimeStatus or mutation:
                if arguments.upgrade:
                    _Upgrade(root, service, request, arguments.expectedVersion, arguments.expectedReceipt)

                elif arguments.rollbackUpgrade or arguments.recoverUpgrade:
                    _RollbackRuntime(root, service, request, arguments.expectedVersion, arguments.expectedReceipt,
                                     recover=arguments.recoverUpgrade)

                runtimeInfo = _RuntimeStatus(root, service, request)

            elif arguments.check:
                receipt = _Existing(root, service, request["owner"])

                if receipt is None or receipt["files"]["server.json"] != request["config_sha256"]:
                    raise GuestError("Requested VLESS configuration is not installed")

                _Health(root, service, request["port"])

            else:
                _Install(root, service, request, config)

        finally:
            os.close(descriptor)

    except GuestError as error:
        print(f"VLESS guest operation failed: {error}", file=sys.stderr)

        return 1

    except (OSError, ValueError, KeyError, RecursionError, zipfile.BadZipFile):
        print("VLESS guest operation failed; check ownership, pinned download, guest prerequisites, and service state.", file=sys.stderr)

        return 1

    print(json.dumps(runtimeInfo, sort_keys=True) if runtimeInfo is not None else
          "VLESS guest operation completed; end-to-end client connectivity was not tested.")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
