"""Offline private SSH staging, sanitized failures, and root installer payload validation."""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from flayer import _vpn_guest
from flayer.core.contracts import StackIdentity
from flayer.guest import GuestResult, SshGuestProvisioner, SubprocessGuestRunner, WritePrivate
from flayer.profiles.artifacts import Artifact, ArtifactBundle
from flayer.profiles.vpn import VpnEndpoint, VpnError

IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
PRIVATE_PAYLOAD = b"fixture-private-material"


class FakeRunner:
    """Capture argument vectors and private stdin separately without starting SSH."""

    def __init__(self, result: GuestResult | None = None) -> None:
        """Initialize one deterministic command result and an isolated call log."""

        self.result = result or GuestResult(0, b"FLAYER_GUEST_INSTALL_OK\n")
        self.calls: list[tuple[tuple[str, ...], bytes, float]] = []

    def Run(self, command: tuple[str, ...], payload: bytes, timeout: float) -> GuestResult:
        """Record inputs that must never be interpolated into a shell command."""

        self.calls.append((command, payload, timeout))

        return self.result


def Provisioner(tmp_path: Path, runner: FakeRunner | None = None) -> SshGuestProvisioner:
    """Provide explicit private key and independently obtained public host pin fixture files."""

    identity = tmp_path / "identity-key"
    trust = tmp_path / "known-hosts.txt"
    WritePrivate(identity, b"fixture-identity-key")
    WritePrivate(trust, b"203.0.113.20 ssh-ed25519 fixture-public-key\n")

    return SshGuestProvisioner(VpnEndpoint("203.0.113.20", 22), "flayer-admin", identity, trust, runner)


def Bundle() -> ArtifactBundle:
    """Build an explicitly sensitive server fixture with the canonical installer entrypoint."""

    return ArtifactBundle(IDENTITY, "server", "gateway-amneziawg", (
        Artifact("install.sh", b"#!/bin/bash\nexit 0\n"), Artifact("server.conf", PRIVATE_PAYLOAD),
    ))


def test_SshPinsTrustDisablesImplicitConfigurationAndKeepsSecretsOffArguments(tmp_path: Path) -> None:
    """Private transport bytes travel only through authenticated SSH standard input."""

    runner = FakeRunner()
    provisioner = Provisioner(tmp_path, runner)
    provisioner.Install((("amneziawg", Bundle()),))
    command, payload, timeout = runner.calls[0]

    assert command[:4] == ("ssh", "-F", "/dev/null", "-T")
    assert "StrictHostKeyChecking=yes" in command and "IdentityAgent=none" in command
    assert "ProxyCommand=none" in command and "UpdateHostKeys=no" in command
    assert command[-2] == "flayer-admin@203.0.113.20"
    assert command[-1].startswith("sudo -n /usr/bin/python3 -c ")
    assert PRIVATE_PAYLOAD.decode() not in repr(command)
    assert base64.b64encode(PRIVATE_PAYLOAD).decode() not in repr(command)
    assert json.loads(payload)["bundles"][0]["files"]["server.conf"] == base64.b64encode(PRIVATE_PAYLOAD).decode()
    assert timeout == 3700
    assert PRIVATE_PAYLOAD.decode() not in repr(GuestResult(1, PRIVATE_PAYLOAD, PRIVATE_PAYLOAD))


@pytest.mark.parametrize("result", [GuestResult(1, PRIVATE_PAYLOAD, PRIVATE_PAYLOAD), GuestResult(0, PRIVATE_PAYLOAD)])
def test_GuestFailureDoesNotEchoPrivateOutput(tmp_path: Path, result: GuestResult) -> None:
    """Even a successful exit needs the fixed installation receipt; raw output is never an error message."""

    runner = FakeRunner(result)
    provisioner = Provisioner(tmp_path, runner)

    with pytest.raises(VpnError) as caught:
        provisioner.Install((("amneziawg", Bundle()),))

    assert PRIVATE_PAYLOAD.decode() not in str(caught.value)


@pytest.mark.parametrize("case", ["empty", "list", "malformed", "unknown", "duplicate", "public", "device", "foreign"])
def test_InstallerRejectsAmbiguousOrNonprivateBundlesBeforeSsh(tmp_path: Path, case: str) -> None:
    """Local staging rejects unsupported protocols, mixed owners, and nonsecret labeling of opaque payloads."""

    runner = FakeRunner()
    provisioner = Provisioner(tmp_path, runner)
    bundle = Bundle()
    inputs: dict[str, Any] = {
        "empty": (), "list": [], "malformed": (("amneziawg",),),
        "unknown": (("other", bundle),),
        "duplicate": (("amneziawg", bundle), ("amneziawg", bundle)),
        "public": (("amneziawg", replace(bundle, files=(Artifact("server.conf", PRIVATE_PAYLOAD, False),))),),
        "device": (("amneziawg", replace(bundle, kind="device")),),
        "foreign": (("amneziawg", bundle), ("vless-reality", replace(bundle, identity=replace(IDENTITY, scope_id="other")))),
    }

    with pytest.raises(VpnError):
        provisioner.Install(inputs[case])

    assert not runner.calls


def test_ServiceStatusIsReadOnlyAndDoesNotImplyClientConnectivity(tmp_path: Path) -> None:
    """Use one exact service command without sending private payloads or installing packages."""

    runner = FakeRunner(GuestResult(3))
    provisioner = Provisioner(tmp_path, runner)
    report = provisioner.ServiceStatus(("flayer-example.service",))

    assert report == (("flayer-example.service", False),)
    assert runner.calls[0][1] == b""
    assert runner.calls[0][0][-1] == "sudo -n /usr/bin/systemctl is-active --quiet flayer-example.service"
    runner.result = GuestResult(255, PRIVATE_PAYLOAD)

    with pytest.raises(VpnError):
        provisioner.ServiceStatus(("flayer-example.service",))

    for services in ((), ("bad;command",), ["flayer-example.service"]):
        with pytest.raises(VpnError):
            provisioner.ServiceStatus(services)


def test_GuestAuthenticationRejectsUnpinnedTrustAndNonliteralEndpoints(tmp_path: Path) -> None:
    """An absent pin, root login, or resolver-dependent destination cannot authorize guest installation."""

    identity = tmp_path / "key"
    trust = tmp_path / "trust"
    WritePrivate(identity, b"fixture-key")
    WritePrivate(trust, b"\n")

    for endpoint, username in ((VpnEndpoint("example.org", 22), "admin"), (VpnEndpoint("203.0.113.20", 22), "root"), (VpnEndpoint("203.0.113.20", 22), "admin")):
        with pytest.raises(VpnError):
            SshGuestProvisioner(endpoint, username, identity, trust)


def test_SubprocessTransportSanitizesTimeoutAndOperatingSystemErrors(monkeypatch: pytest.MonkeyPatch) -> None:
    """No underlying subprocess exception may leak an input argument or guest response."""

    def Fail(*arguments: object, **options: object) -> Any:
        """Raise an OS failure containing data that must remain outside the public error."""

        raise OSError(PRIVATE_PAYLOAD.decode())

    monkeypatch.setattr(subprocess, "run", Fail)

    with pytest.raises(VpnError) as caught:
        SubprocessGuestRunner().Run(("ssh",), PRIVATE_PAYLOAD, 1)

    assert PRIVATE_PAYLOAD.decode() not in str(caught.value)


def Request() -> dict[str, Any]:
    """Construct one valid bounded JSON envelope for isolated guest decoding tests."""

    return {"bundles": [{"transport": "amneziawg", "files": {
        "install.sh": base64.b64encode(b"#!/bin/bash\nexit 0\n").decode(),
        "server.conf": base64.b64encode(PRIVATE_PAYLOAD).decode(),
    }}]}


@pytest.mark.parametrize("case", ["empty", "unknown", "missing", "traversal", "oversized", "malformed", "duplicate"])
def test_RemoteDecoderRejectsUnsafeRequestBeforeCreatingFiles(case: str) -> None:
    """Decode all files before staging and reject unsafe names, duplicate transports, and missing installers."""

    data = Request()

    if case == "empty":
        data["bundles"] = []

    elif case == "unknown":
        data["bundles"][0]["transport"] = "other"

    elif case == "missing":
        del data["bundles"][0]["files"]["install.sh"]

    elif case == "traversal":
        data["bundles"][0]["files"]["../outside"] = base64.b64encode(PRIVATE_PAYLOAD).decode()

    elif case == "oversized":
        data["bundles"][0]["files"]["server.conf"] = base64.b64encode(b"x" * 1048577).decode()

    elif case == "malformed":
        data["bundles"][0]["files"]["server.conf"] = "invalid-base64"

    elif case == "duplicate":
        data["bundles"].append(data["bundles"][0])

    with pytest.raises(ValueError):
        _vpn_guest.DecodeRequest(json.dumps(data).encode())


def test_RemoteInstallerUsesPrivateRootStageAndCleansOnlyItsTemporaryDirectory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run no installer while checking actual local stage permissions, command boundaries, and cleanup."""

    stages: list[Path] = []
    calls: list[list[str]] = []

    def Stage(*, prefix: str, dir: str) -> str:
        """Substitute an isolated fixture directory for the guest temporary location."""

        path = tmp_path / ("stage-" + str(len(stages)))
        path.mkdir()
        stages.append(path)

        return str(path)

    def Run(command: list[str], **options: Any) -> subprocess.CompletedProcess[bytes]:
        """Inspect staged private files before returning a deterministic fake installer result."""

        stage = Path(options["cwd"])
        assert stat.S_IMODE(stage.stat().st_mode) == 0o700
        assert stat.S_IMODE((stage / "server.conf").stat().st_mode) == 0o600
        assert (stage / "server.conf").read_bytes() == PRIVATE_PAYLOAD
        assert options["stdout"] == options["stderr"] == subprocess.DEVNULL
        calls.append(command)

        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(_vpn_guest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_vpn_guest.tempfile, "mkdtemp", Stage)
    monkeypatch.setattr(_vpn_guest.subprocess, "run", Run)
    bundles = _vpn_guest.DecodeRequest(json.dumps(Request()).encode())
    _vpn_guest.Install(bundles)

    assert len(calls) == 2 and calls[1][-1] == "--check"
    assert all(not stage.exists() for stage in stages)


def test_RemoteInstallerStopsBeforeExecutionWithoutRoot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-root guest session must not leave partial files or attempt privilege escalation itself."""

    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    with pytest.raises(ValueError, match="Root privileges"):
        _vpn_guest.Install(_vpn_guest.DecodeRequest(json.dumps(Request()).encode()))


@pytest.mark.parametrize("transport", ["amneziawg", "vless-reality"])
def test_GuestFailuresPreserveAllowlistedProtocolAndPhase(tmp_path: Path, transport: str) -> None:
    """Safe receipts identify the failed protocol while raw installer output remains suppressed."""

    receipt = f"FLAYER_GUEST_FAILED {transport} install\n".encode()
    runner = FakeRunner(GuestResult(1, receipt, PRIVATE_PAYLOAD))
    provisioner = Provisioner(tmp_path, runner)

    with pytest.raises(VpnError) as caught:
        provisioner.Install((("amneziawg", Bundle()),))

    assert transport in str(caught.value) and "install failed" in str(caught.value)
    assert PRIVATE_PAYLOAD.decode() not in str(caught.value)
