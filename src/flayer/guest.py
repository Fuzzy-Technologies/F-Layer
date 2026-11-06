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


def ValidateVlessRuntimeOptions(action: str, expectedVersion: str, expectedReceipt: str) -> None:
    """Reject ambiguous runtime actions and incomplete expected-old input before external access."""

    if (not isinstance(action, str) or not isinstance(expectedVersion, str) or not isinstance(expectedReceipt, str)
            or action not in {"runtime-status", "upgrade", "rollback-upgrade", "recover-upgrade"}):
        raise VpnError("VLESS runtime action is unsupported")

    if action == "runtime-status":
        if expectedVersion or expectedReceipt:
            raise VpnError("Runtime status does not accept mutation preconditions")

    elif (expectedVersion not in {"26.9.30", "26.10.31"} or not isinstance(expectedReceipt, str)
          or re.fullmatch(r"[0-9a-f]{64}", expectedReceipt) is None):
        raise VpnError("Runtime mutation requires --expected-version and exact --expected-receipt-sha256")

    if action != "runtime-status" and expectedVersion != ("26.10.31" if action == "rollback-upgrade" else "26.9.30"):
        raise VpnError("Expected version does not match the supported runtime transition")


@dataclass(frozen=True, slots=True)
class GuestResult:
    """Transient subprocess output excluded from object representations and error messages."""

    returnCode: int
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
        self, endpoint: VpnEndpoint, username: str, identityFile: Path,
        knownHostsFile: Path, runner: GuestRunner | None = None,
    ) -> None:
        """Validate private key/trust paths before constructing any SSH argument vector."""

        import ipaddress

        try:
            ipaddress.IPv4Address(endpoint.host)

        except (AttributeError, ValueError):
            raise VpnError("Guest provisioning requires the actual reserved IPv4 address") from None

        if not isinstance(username, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", username) is None or username == "root":
            raise VpnError("Guest administration requires an explicit non-root username")

        identityFile = PrivatePath(identityFile)
        knownHostsFile = PrivatePath(knownHostsFile)

        ValidateSshPathSyntax(identityFile)
        ValidateSshPathSyntax(knownHostsFile)

        if not ReadPrivate(knownHostsFile).strip():
            raise VpnError("Guest provisioning requires an independently authenticated host-key pin")

        self.runner = runner or SubprocessGuestRunner()
        self.command = (
            "ssh", "-F", "/dev/null", "-T", "-p", str(endpoint.port), "-i", str(identityFile),
            "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f'UserKnownHostsFile="{knownHostsFile}"', "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
            f"{username}@{endpoint.host}",
        )

    def Install(self, bundles: tuple[tuple[str, ArtifactBundle], ...]) -> None:
        """Stage only validated sensitive server files on the trusted guest and run installers."""

        if not isinstance(bundles, tuple) or not 1 <= len(bundles) <= 3 or any(
            not isinstance(item, tuple) or len(item) != 2 for item in bundles
        ):
            raise VpnError("Guest installation requires one to three explicit server bundles")

        transports: set[str] = set()
        documents = []

        for transport, bundle in bundles:
            if (
                not isinstance(transport, str) or transport not in {"amneziawg", "vless-reality", "wireguard"} or transport in transports
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
        result = self.runner.Run((*self.command, command), payload, 5500 if len(bundles) == 3 else 3700)

        if result.returnCode != 0 or result.stdout.strip() != b"FLAYER_GUEST_INSTALL_OK":
            receipt = result.stdout.strip() if len(result.stdout) <= 128 else b""
            match = re.fullmatch(rb"FLAYER_GUEST_FAILED (amneziawg|vless-reality|wireguard) (stage|install|check)", receipt)

            if match is not None:
                transport, phase = (item.decode("ascii") for item in match.groups())
                hint = (
                    "Check the executing Ubuntu kernel baseline, private ownership and pinned tools build prerequisites"
                    if transport == "wireguard" else
                    "Check the Reality target supports TLS 1.3 and HTTP/2, and guest access to the pinned Xray download"
                    if transport == "vless-reality" else
                    "Check Ubuntu 24.04 amd64 compatibility and guest access to the pinned Go and GitHub downloads"
                )

                raise VpnError(f"VPN {transport} {phase} failed. {hint}. Cloud resources and private artifacts were retained for retry")

            raise VpnError("Guest SSH connection or installation failed. Check administrator source CIDRs, host trust, and guest logs; resources and private artifacts were retained for retry")

    def VlessRuntime(
        self, bundle: ArtifactBundle, action: str, *, expectedVersion: str = "", expectedReceipt: str = "",
    ) -> dict[str, str]:
        """Run one host-pinned runtime operation and accept only bounded nonsecret receipt facts."""

        ValidateVlessRuntimeOptions(action, expectedVersion, expectedReceipt)

        if (not isinstance(bundle, ArtifactBundle) or bundle.kind != "server"
                or not bundle.name.endswith("-vless-reality")
                or {item.name for item in bundle.files} != {"install.py", "server.json", "deployment.json"}
                or any(not item.sensitive for item in bundle.files)):
            raise VpnError("VLESS runtime maintenance requires one exact private server bundle")

        payload = json.dumps({"bundles": [{"transport": "vless-reality", "files": {
            item.name: base64.b64encode(item.content).decode("ascii") for item in bundle.files
        }}], "runtime": {"action": action, "expected_version": expectedVersion,
                         "expected_receipt_sha256": expectedReceipt}}, sort_keys=True).encode()

        if len(payload) > MAX_GUEST_REQUEST_BYTES:
            raise VpnError("VLESS runtime request exceeds its bounded size")

        command = "sudo -n /usr/bin/python3 -c " + shlex.quote(files("flayer").joinpath("_vpn_guest.py").read_text(encoding="utf-8"))
        result = self.runner.Run((*self.command, command), payload, 420)

        try:
            if result.returnCode != 0 or not 1 <= len(result.stdout) <= 4096:
                raise ValueError

            data = json.loads(result.stdout)
            expected = {"version", "receipt_sha256", "previous_receipt_sha256", "binary_sha256", "upgrade_status",
                        "kernel_release", "kernel_package_version", "kernel_patch_status"}

            if (not isinstance(data, dict) or set(data) != expected
                    or any(not isinstance(value, str) for value in data.values())
                    or data["version"] not in {"26.9.30", "26.10.31"}
                    or data["upgrade_status"] not in {"none", "rollback-available", "interrupted"}
                    or data["kernel_patch_status"] != "not-assessed"
                    or (data["upgrade_status"] == "none" and data["previous_receipt_sha256"] != "")
                    or (data["upgrade_status"] != "none"
                        and re.fullmatch(r"[0-9a-f]{64}", data["previous_receipt_sha256"]) is None)
                    or any(re.fullmatch(r"[0-9a-f]{64}", data[key]) is None
                           for key in ("receipt_sha256", "binary_sha256"))
                    or any(re.fullmatch(r"[a-zA-Z0-9.+:~_-]{1,128}", data[key]) is None
                           for key in ("kernel_release", "kernel_package_version"))):
                raise ValueError

            if (data["upgrade_status"] == "rollback-available" and data["version"] != "26.10.31"
                    or action == "upgrade" and (data["version"] != "26.10.31" or data["upgrade_status"] != "rollback-available")
                    or action in {"rollback-upgrade", "recover-upgrade"}
                    and (data["version"] != "26.9.30" or data["upgrade_status"] != "none")):
                raise ValueError

            return {key: str(value) for key, value in data.items()}

        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise VpnError("VLESS runtime operation failed or returned an invalid receipt. Inspect runtime-status and retained recovery state; private output was suppressed") from None

    def WireGuardOperation(
        self, bundle: ArtifactBundle, action: str, *, allowMutation: bool = False, scopeConfirm: str = "",
        expectedReceipt: str = "", expectedAbsence: str = "",
    ) -> dict[str, object]:
        """Observe or recover one owned WireGuard service using explicit scope and current proof."""

        if (not isinstance(bundle, ArtifactBundle) or bundle.kind != "server" or not bundle.name.endswith("-wireguard")
                or {item.name for item in bundle.files} != {"install.py", "server.conf", "deployment.json"}
                or any(not item.sensitive for item in bundle.files)
                or not isinstance(action, str) or action not in {"status", "recover", "remove"}
                or any(not isinstance(value, str) for value in (scopeConfirm, expectedReceipt, expectedAbsence))):
            raise VpnError("WireGuard maintenance requires an exact private server bundle and supported action")

        if action == "status":
            if allowMutation or scopeConfirm or expectedReceipt or expectedAbsence:
                raise VpnError("WireGuard status is read-only and accepts no mutation preconditions")

        elif (allowMutation is not True or scopeConfirm != bundle.identity.scopeId
              or bool(expectedReceipt) == bool(expectedAbsence)
              or re.fullmatch(r"[0-9a-f]{64}", expectedReceipt or expectedAbsence) is None
              or expectedAbsence and action != "recover"):
            raise VpnError("WireGuard mutation requires exact scope, consent and one current receipt or absence proof")

        payload = json.dumps({"bundles": [{"transport": "wireguard", "files": {
            item.name: base64.b64encode(item.content).decode("ascii") for item in bundle.files
        }}], "wireguard": {"action": action, "expected_receipt_sha256": expectedReceipt,
                           "expected_absence_sha256": expectedAbsence}}, sort_keys=True).encode()

        if len(payload) > MAX_GUEST_REQUEST_BYTES:
            raise VpnError("WireGuard request exceeds its bounded size")

        command = "sudo -n /usr/bin/python3 -c " + shlex.quote(files("flayer").joinpath("_vpn_guest.py").read_text(encoding="utf-8"))
        result = self.runner.Run((*self.command, command), payload, 420)

        try:
            if result.returnCode != 0 or not 1 <= len(result.stdout) <= 4096:
                raise ValueError

            data = json.loads(result.stdout)

            if not isinstance(data, dict):
                raise ValueError

            if action != "status":
                if data != {"status": "complete", "action": action}:
                    raise ValueError

                return data

            common = {"status", "receipt_sha256", "tools_version", "kernel_policy"}
            status = data.get("status")
            expected = common | ({"binary_sha256", "kernel_release", "kernel_package_version", "kernel_cve", "kernel_fixed_version"}
                                 if status == "active" else {"absence_sha256", "cleanup_required"} if status == "absent" else set())

            if (status not in {"active", "absent", "recovery-required"} or set(data) != expected
                    or any(not isinstance(value, str) for key, value in data.items() if key != "cleanup_required")
                    or data["tools_version"] != "1.0.20260223"):
                raise ValueError

            if status == "absent":
                if (data["receipt_sha256"] != "" or data["kernel_policy"] != "not-assessed"
                        or type(data["cleanup_required"]) is not bool or re.fullmatch(r"[0-9a-f]{64}", data["absence_sha256"]) is None):
                    raise ValueError

            elif (data["kernel_policy"] != "cached-named-cve-baseline"
                  or re.fullmatch(r"[0-9a-f]{64}", data["receipt_sha256"]) is None):
                raise ValueError

            if status == "active" and (
                data["kernel_cve"] != "CVE-2026-98432" or re.fullmatch(r"[0-9a-f]{64}", data["binary_sha256"]) is None
                or any(re.fullmatch(r"[a-zA-Z0-9.+:~_-]{1,128}", data[key]) is None
                       for key in ("kernel_release", "kernel_package_version", "kernel_fixed_version"))
            ):
                raise ValueError

            return data

        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise VpnError("WireGuard operation failed or returned invalid bounded status; private diagnostics were suppressed") from None

    def ServiceStatus(self, services: tuple[str, ...]) -> tuple[tuple[str, bool], ...]:
        """Observe service activity without claiming client connectivity or performing guest writes."""

        if not isinstance(services, tuple) or not 1 <= len(services) <= 3 or any(
            not isinstance(item, str) or _SERVICE.fullmatch(item) is None for item in services
        ):
            raise VpnError("Guest status requires bounded explicit service names")

        result = []

        for service in services:
            command = "sudo -n /usr/bin/systemctl is-active --quiet " + shlex.quote(service)
            observed = self.runner.Run((*self.command, command), b"", 30)

            if observed.returnCode not in {0, 3}:
                raise VpnError("Unable to observe the owned guest service")

            result.append((service, observed.returnCode == 0))

        return tuple(result)
