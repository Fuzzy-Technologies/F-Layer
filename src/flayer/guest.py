"""Strict host-pinned SSH transport for private VPN installation and service observations."""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import stat
import subprocess
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Protocol

from flayer.profiles.artifacts import ArtifactBundle
from flayer.profiles.vpn import VpnEndpoint, VpnError

MAX_GUEST_REQUEST_BYTES = 4 * 1024 * 1024
_SERVICE = re.compile(r"[a-z][a-z0-9-]{0,79}\.service\Z")


@dataclass(frozen=True, slots=True)
class GuestResult:
    """Transient subprocess output excluded from object representations and error messages."""

    return_code: int
    stdout: bytes = field(default=b"", repr=False)
    stderr: bytes = field(default=b"", repr=False)


class GuestRunner(Protocol):
    """Injectable subprocess boundary for deterministic tests without SSH connections."""

    def Run(self, command: tuple[str, ...], payload: bytes, timeout: float) -> GuestResult:
        """Run a bounded argument vector with private standard input and captured output."""

        ...


class SubprocessGuestRunner:
    """Execute OpenSSH without a local shell or inherited standard input."""

    def Run(self, command: tuple[str, ...], payload: bytes, timeout: float) -> GuestResult:
        """Keep any guest or SSH diagnostic text out of user-visible exception messages."""

        try:
            result = subprocess.run(
                command, input=payload, capture_output=True, check=False, shell=False, timeout=timeout,
            )

        except (OSError, subprocess.TimeoutExpired):
            raise VpnError("Guest connection failed or exceeded its time limit") from None

        return GuestResult(result.returncode, result.stdout, result.stderr)


def ValidateSshPathSyntax(path: Path) -> None:
    """Reject OpenSSH substitutions before authorizing any project or guest operation."""

    if any(character in str(path) for character in ('"', "\n", "\r", "\\", "%", "$")):
        raise VpnError("Project paths must not contain quotes, controls, backslashes, percent signs, or dollar signs")


def PrivatePath(path: Path, *, directory: bool = False) -> Path:
    """Require caller-owned private POSIX objects without symlinks or hardlinked files."""

    if os.name != "posix" or ".." in path.parts:
        raise VpnError("VPN projects require a POSIX host and paths without traversal")

    absolute = path.absolute()

    if any(item.is_symlink() for item in (absolute, *absolute.parents)):
        raise VpnError("VPN project paths must not contain symbolic links")

    try:
        info = absolute.lstat()

    except OSError:
        raise VpnError("Required private project path is unavailable") from None

    kind = stat.S_ISDIR if directory else stat.S_ISREG

    if (
        not kind(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or (not directory and info.st_nlink != 1)
    ):
        raise VpnError("VPN project paths must be caller-owned directories0700 or files0600")

    return absolute


def ReadPrivate(path: Path, *, limit: int = 65536) -> bytes:
    """Read one bounded private file and detect replacements or in-place edits during the read."""

    absolute = PrivatePath(path)
    descriptor: int | None = None

    try:
        before = absolute.lstat()
        descriptor = os.open(absolute, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        opened = os.fstat(descriptor)

        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise VpnError("Private project file changed during read")

        if opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1:
            raise VpnError("Private project file ownership changed during read")

        content = bytearray()

        while len(content) <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(content)))

            if not chunk:
                break

            content.extend(chunk)

        after = os.fstat(descriptor)

        if (
            len(content) > limit or opened.st_size != after.st_size
            or opened.st_mtime_ns != after.st_mtime_ns or opened.st_ctime_ns != after.st_ctime_ns
        ):
            raise VpnError("Private project file is oversized or changed during read")

        return bytes(content)

    except OSError:
        raise VpnError("Unable to read a private project file") from None

    finally:
        if descriptor is not None:
            os.close(descriptor)


def WritePrivate(path: Path, content: bytes) -> None:
    """Create a private project file exclusively without overwriting an existing object."""

    PrivatePath(path.parent, directory=True)

    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    except OSError:
        raise VpnError("Unable to exclusively create a private project file") from None


class SshGuestProvisioner:
    """Connect only to an explicit IPv4 endpoint using an independently pinned Ed25519 host key."""

    def __init__(
        self, endpoint: VpnEndpoint, username: str, identity_file: Path,
        known_hosts_file: Path, runner: GuestRunner | None = None,
    ) -> None:
        """Validate private key/trust paths before constructing any SSH argument vector."""

        import ipaddress

        try:
            ipaddress.IPv4Address(endpoint.host)

        except (AttributeError, ValueError):
            raise VpnError("Guest provisioning requires the actual reserved IPv4 address") from None

        if not isinstance(username, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", username) is None or username == "root":
            raise VpnError("Guest administration requires an explicit non-root username")

        identity_file = PrivatePath(identity_file)
        known_hosts_file = PrivatePath(known_hosts_file)

        ValidateSshPathSyntax(identity_file)
        ValidateSshPathSyntax(known_hosts_file)

        if not ReadPrivate(known_hosts_file).strip():
            raise VpnError("Guest provisioning requires an independently authenticated host-key pin")

        self.runner = runner or SubprocessGuestRunner()
        self.command = (
            "ssh", "-F", "/dev/null", "-T", "-p", str(endpoint.port), "-i", str(identity_file),
            "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f'UserKnownHostsFile="{known_hosts_file}"', "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            f"{username}@{endpoint.host}",
        )

    def Install(self, bundles: tuple[tuple[str, ArtifactBundle], ...]) -> None:
        """Stage only validated sensitive server files on the trusted guest and run installers."""

        if not isinstance(bundles, tuple) or not 1 <= len(bundles) <= 2 or any(
            not isinstance(item, tuple) or len(item) != 2 for item in bundles
        ):
            raise VpnError("Guest installation requires one or two explicit server bundles")

        transports: set[str] = set()
        documents = []

        for transport, bundle in bundles:
            if (
                not isinstance(transport, str) or transport not in {"amneziawg", "vless-reality"} or transport in transports
                or not isinstance(bundle, ArtifactBundle) or bundle.kind != "server"
                or any(not item.sensitive for item in bundle.files)
            ):
                raise VpnError("Guest installation requires unique supported private server bundles")

            transports.add(transport)
            documents.append({"transport": transport, "files": {
                item.name: base64.b64encode(item.content).decode("ascii") for item in bundle.files
            }})

        if len({bundle.identity for _, bundle in bundles}) != 1:
            raise VpnError("Guest installation cannot mix different stack owners")

        payload = json.dumps({"bundles": documents}, sort_keys=True).encode("utf-8")

        if len(payload) > MAX_GUEST_REQUEST_BYTES:
            raise VpnError("Guest installation request exceeds its bounded size")

        command = "sudo -n /usr/bin/python3 -c " + shlex.quote(files("flayer").joinpath("_vpn_guest.py").read_text(encoding="utf-8"))
        result = self.runner.Run((*self.command, command), payload, 3700)

        if result.return_code != 0 or result.stdout.strip() != b"FLAYER_GUEST_INSTALL_OK":
            receipt = result.stdout.strip() if len(result.stdout) <= 128 else b""
            match = re.fullmatch(rb"FLAYER_GUEST_FAILED (amneziawg|vless-reality) (stage|install|check)", receipt)

            if match is not None:
                transport, phase = (item.decode("ascii") for item in match.groups())
                hint = (
                    "Check the Reality target supports TLS 1.3 and HTTP/2, and guest access to the pinned Xray download"
                    if transport == "vless-reality" else
                    "Check Ubuntu 24.04 amd64 compatibility and guest access to the pinned Go and GitHub downloads"
                )

                raise VpnError(f"VPN {transport} {phase} failed. {hint}. Cloud resources and private artifacts were retained for retry")

            raise VpnError("Guest SSH connection or installation failed. Check administrator source CIDRs, host trust, and guest logs; resources and private artifacts were retained for retry")

    def ServiceStatus(self, services: tuple[str, ...]) -> tuple[tuple[str, bool], ...]:
        """Observe service activity without claiming client connectivity or performing guest writes."""

        if not isinstance(services, tuple) or not 1 <= len(services) <= 2 or any(
            not isinstance(item, str) or _SERVICE.fullmatch(item) is None for item in services
        ):
            raise VpnError("Guest status requires bounded explicit service names")

        result = []

        for service in services:
            command = "sudo -n /usr/bin/systemctl is-active --quiet " + shlex.quote(service)
            observed = self.runner.Run((*self.command, command), b"", 30)

            if observed.return_code not in {0, 3}:
                raise VpnError("Unable to observe the owned guest service")

            result.append((service, observed.return_code == 0))

        return tuple(result)
