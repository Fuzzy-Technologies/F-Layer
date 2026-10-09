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

XRAY_VERSION = "26.3.27"
ARCHIVES = {
    "x86_64": ("Xray-linux-64.zip", "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"),
    "aarch64": ("Xray-linux-arm64-v8a.zip", "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"),
}
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


def _Read(path: Path, limit: int, *, root_owned: bool = False) -> bytes:
    """Read a bounded regular non-linked file, keeping filesystem errors private."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise GuestError("Managed input must be a bounded regular file without hardlinks")

        if path.name == "server.json" and stat.S_IMODE(info.st_mode) != 0o600:
            raise GuestError("Server credential files must use private mode 0600")

        if root_owned and (info.st_uid != _ROOT_UID or info.st_mode & 0o022):
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

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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

    filename, expected_hash = ARCHIVES[architecture]
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{filename}"

    with urllib.request.urlopen(url, timeout=60) as response:
        content = response.read(MAX_ARCHIVE_BYTES + 1)

    if len(content) > MAX_ARCHIVE_BYTES or _Digest(content) != expected_hash:
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
            or deployment["xray_version"] != XRAY_VERSION):
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
    receipt = json.loads(_Read(root / "owner.json", 4096, root_owned=True))

    if not isinstance(receipt, dict) or set(receipt) != {"owner", "files", "xray_version"} or receipt["owner"] != owner:
        raise GuestError("Existing deployment does not belong to the requested stack")

    if receipt["xray_version"] != XRAY_VERSION:
        raise GuestError("Existing deployment uses a different pinned Xray version")

    hashes = receipt["files"]

    if not isinstance(hashes, dict) or set(hashes) != {"xray", "server.json", "service"}:
        raise GuestError("Existing deployment has an invalid ownership receipt")

    if {item.name for item in root.iterdir()} != {"xray", "server.json", "owner.json"}:
        raise GuestError("Existing deployment contains untracked or interrupted files")

    for name, path in (("xray", root / "xray"), ("server.json", root / "server.json"), ("service", service)):
        if _Digest(_Read(path, MAX_BINARY_BYTES, root_owned=True)) != hashes[name]:
            raise GuestError("Existing deployment changed outside F-Layer; refusing replacement")

    if stat.S_IMODE((root / "server.json").stat().st_mode) != 0o600:
        raise GuestError("Managed server credentials must retain private permissions")

    return receipt



def _TargetHealth(config: bytes) -> None:
    """Require the configured Reality target to offer certificate-valid TLS 1.3 and HTTP/2."""

    try:
        settings = json.loads(config)["inbounds"][0]["streamSettings"]["realitySettings"]
        host, port = settings["target"].rsplit(":", 1)
        server_name = settings["serverNames"][0]
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["h2"])

        with socket.create_connection((host, int(port)), timeout=10) as connection:
            with context.wrap_socket(connection, server_hostname=server_name) as channel:
                if channel.version() != "TLSv1.3" or channel.selected_alpn_protocol() != "h2":
                    raise GuestError("Reality target must support TLS 1.3 and HTTP/2")

    except (OSError, ValueError, KeyError, IndexError, TypeError):
        raise GuestError(
            "Reality target preflight failed: verify its TLS 1.3/HTTP2 support, certificate name, and guest reachability"
        ) from None


def _Health(root: Path, service: Path, port: int) -> None:
    """Check daemon syntax, systemd state, and a loopback listener without claiming tunnel health."""

    _TargetHealth(_Read(root / "server.json", 1048576, root_owned=True))
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
    """Stage syntax-tested bytes, replace owned files, and roll back synchronous failures."""

    previous = _Existing(root, service, request["owner"])
    _TargetHealth(config)
    unit = _Unit(root)

    if previous is not None and previous["files"]["server.json"] == _Digest(config):
        if previous["files"]["service"] != _Digest(unit):
            raise GuestError("Owned service layout differs from this installer version")

        _Health(root, service, request["port"])

        return

    binary = _DownloadBinary()
    backup = None if previous is None else (
        _Read(root / "xray", MAX_BINARY_BYTES, root_owned=True),
        _Read(root / "server.json", 1048576, root_owned=True),
        _Read(service, 16384, root_owned=True),
        _Read(root / "owner.json", 4096, root_owned=True),
    )

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
        if backup is not None:
            for path, content, mode in (
                (root / "xray", backup[0], 0o755), (root / "server.json", backup[1], 0o600),
                (service, backup[2], 0o644), (root / "owner.json", backup[3], 0o600),
            ):
                _Atomic(path, content, mode)

            _Command(["systemctl", "daemon-reload"])
            _Command(["systemctl", "restart", service.name])

        else:
            _Command(["systemctl", "disable", "--now", service.name])

            for path in (service, root / "xray", root / "server.json", root / "owner.json"):
                path.unlink(missing_ok=True)

            root.rmdir()
            _Command(["systemctl", "daemon-reload"])

        raise GuestError("VLESS installation failed; the previous owned installation was restored") from None


def _Remove(root: Path, service: Path, owner: str) -> None:
    """Delete only an unchanged owned daemon and its exact three tracked local files."""

    if _Existing(root, service, owner) is None:
        return

    _Command(["systemctl", "disable", "--now", service.name])

    for path in (service, root / "xray", root / "server.json", root / "owner.json"):
        path.unlink()

    root.rmdir()
    _Command(["systemctl", "daemon-reload"])


def Main(argv: list[str] | None = None) -> int:
    """Accept only install/check/remove for the descriptor next to this private installer."""

    parser = argparse.ArgumentParser(description="Manage an owned F-Layer VLESS Reality service")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true")
    action.add_argument("--remove", action="store_true")
    arguments = parser.parse_args(argv)

    try:
        if os.geteuid() != 0:
            raise GuestError("VLESS guest installation requires sudo on the selected guest")

        release = platform.freedesktop_os_release()

        if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
            raise GuestError("VLESS guest installation supports only Ubuntu 24.04")

        request, config = _Request(Path(__file__).absolute().parent)

        for directory in (BASE.parent.parent, BASE.parent, BASE):
            _Directory(directory, create=True)

        _Directory(SYSTEMD)
        root = BASE / request["owner"][:24]
        service = SYSTEMD / f"flayer-vless-{request['owner'][:24]}.service"

        descriptor = os.open(
            BASE / f".{request['owner'][:24]}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600,
        )

        try:
            info = os.fstat(descriptor)

            if not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_nlink != 1:
                raise GuestError("VLESS deployment lock must be an owned regular file")

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            if arguments.remove:
                _Remove(root, service, request["owner"])

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

    print("VLESS guest operation completed; end-to-end client connectivity was not tested.")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
