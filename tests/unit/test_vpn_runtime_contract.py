"""Verify runtime CLI consent, private transport and versioned native import contracts without networking."""

from __future__ import annotations

import base64
import json
import struct
import zlib
from typing import Any

import pytest

from flayer import _vpn_guest as receiver
from flayer import vpn_project as vpnProject
from flayer.__main__ import Main, Parser
from flayer.core.contracts import StackIdentity
from flayer.guest import GuestResult, SshGuestProvisioner, ValidateVlessRuntimeOptions
from flayer.profiles._amnezia_export import BuildAmneziaArtifacts, BuildAmneziaWgArtifacts
from flayer.profiles.amneziawg import AmneziaWgSettings, GenerateAmneziaWgSecrets, PrepareAmneziaWg
from flayer.profiles.artifacts import Artifact, ArtifactBundle
from flayer.profiles.vless import GenerateVlessMaterial, RenderVlessClient, VlessRealitySettings
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError, VpnListener, VpnProfile, VpnRoutes
from flayer.vpn_project import VpnRuntimeReport

IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
PRIVATE = b"private-output-fixture"
INFO = {"version": "26.10.31", "receipt_sha256": "a" * 64, "binary_sha256": "b" * 64,
        "upgrade_status": "rollback-available", "kernel_release": "6.8.0-fixture",
        "kernel_package_version": "6.8.0-fixture", "kernel_patch_status": "not-assessed"}


def Bundle() -> ArtifactBundle:
    """Create private transport input whose bytes must never enter SSH arguments."""

    return ArtifactBundle(IDENTITY, "server", "gateway-vless-reality", (
        Artifact("install.py", b"installer-fixture"), Artifact("server.json", PRIVATE),
        Artifact("deployment.json", b"descriptor-fixture"),
    ))


class Runner:
    """Capture one private SSH request without executing any subprocess."""

    def __init__(self, result: GuestResult) -> None:
        """Retain only the configured fake result and captured calls."""

        self.result = result
        self.calls: list[tuple[tuple[str, ...], bytes, float]] = []

    def Run(self, command: tuple[str, ...], payload: bytes, timeout: float) -> GuestResult:
        """Record arguments and standard input separately to assert their secrecy boundary."""

        self.calls.append((command, payload, timeout))

        return self.result


def Provisioner(runner: Runner) -> SshGuestProvisioner:
    """Isolate request handling from the separately tested POSIX key/host-trust constructor."""

    provisioner = object.__new__(SshGuestProvisioner)
    provisioner.runner = runner
    provisioner.command = ("ssh", "pinned-fixture-host")

    return provisioner


@pytest.mark.parametrize("action,version,digest", [
    ("other", "", ""), ("runtime-status", "26.9.30", ""), ("runtime-status", "", "a" * 64),
    ("upgrade", "", ""), ("upgrade", "latest", "a" * 64), ("upgrade", "26.10.31", "a" * 64),
    ("upgrade", "26.9.30", "A" * 64), ("upgrade", "26.9.30", "a" * 63),
    ("rollback-upgrade", "26.9.30", "a" * 64), ("recover-upgrade", "26.10.31", "a" * 64),
    ([], "", ""), ("upgrade", [], "a" * 64), ("upgrade", "26.9.30", None),
])
def test_InvalidRuntimeOptionsFailBeforeAnyRunnerCall(action: Any, version: Any, digest: Any) -> None:
    """Malformed or mismatched transitions must fail before SSH, not merely fail at the guest."""

    runner = Runner(GuestResult(0, json.dumps(INFO).encode()))

    with pytest.raises(VpnError):
        Provisioner(runner).VlessRuntime(Bundle(), action, expectedVersion=version, expectedReceipt=digest)

    assert not runner.calls


@pytest.mark.parametrize("action,version", [
    ("runtime-status", ""), ("upgrade", "26.9.30"),
    ("rollback-upgrade", "26.10.31"), ("recover-upgrade", "26.9.30"),
])
def test_RuntimeTransportValidatesFactsAndKeepsPayloadOffArguments(action: str, version: str) -> None:
    """Only allowlisted nonsecret strings can leave the private host-pinned transport."""

    runner = Runner(GuestResult(0, json.dumps(INFO).encode(), PRIVATE))
    receipt = "" if action == "runtime-status" else "c" * 64
    result = Provisioner(runner).VlessRuntime(Bundle(), action, expectedVersion=version, expectedReceipt=receipt)
    command, payload, timeout = runner.calls[0]
    envelope = json.loads(payload)

    assert result == INFO
    assert PRIVATE.decode() not in repr(command)
    assert base64.b64encode(PRIVATE).decode() not in repr(command)
    assert timeout == 420
    assert envelope["runtime"] == {"action": action, "expected_version": version, "expected_receipt_sha256": receipt}
    assert envelope["bundles"][0]["transport"] == "vless-reality"
    assert base64.b64decode(envelope["bundles"][0]["files"]["server.json"]) == PRIVATE


@pytest.mark.parametrize("change", ["exit", "raw-output", "oversized", "extra", "version", "hash", "kernel", "patch-status", "value-type"])
def test_InvalidRuntimeOutputCannotLeakGuestDiagnostics(change: str) -> None:
    """A guest response cannot smuggle private text into a CLI receipt or exception."""

    info: dict[str, Any] = dict(INFO)
    code, output = 0, b""

    if change == "exit":
        code = 1

    elif change == "extra":
        info["private"] = PRIVATE.decode()

    elif change == "version":
        info["version"] = PRIVATE.decode()

    elif change == "hash":
        info["receipt_sha256"] = PRIVATE.decode()

    elif change == "kernel":
        info["kernel_release"] = "private\ncontrol"

    elif change == "patch-status":
        info["kernel_patch_status"] = "patched"

    elif change == "value-type":
        info["version"] = []

    output = PRIVATE if change == "raw-output" else b"x" * 4097 if change == "oversized" else json.dumps(info).encode()
    runner = Runner(GuestResult(code, output, PRIVATE))

    with pytest.raises(VpnError) as caught:
        Provisioner(runner).VlessRuntime(Bundle(), "runtime-status")

    assert PRIVATE.decode() not in str(caught.value)


def test_RuntimeCliUsesExplicitCamelCaseDestinationsAndReportsFacts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Public argument handling must preserve explicit consent and stable snake-case JSON keys."""

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(vpnProject, "LoadVpnProject", lambda *args: object())

    def Run(project: object, action: str, **options: object) -> VpnRuntimeReport:
        """Replace only orchestration while exercising the real CLI parser and report renderer."""

        calls.append({"action": action, **options})

        return VpnRuntimeReport(action, "complete", version="26.10.31", receiptSha256="a" * 64)

    monkeypatch.setattr(vpnProject, "RunVpnRuntime", Run)
    arguments = ["vpn", "upgrade", "--project", "fixture", "--allow-mutation", "--scope-confirm", "example-folder",
                 "--expected-version", "26.9.30", "--expected-receipt-sha256", "c" * 64, "--format", "json"]

    assert Main(arguments) == 0

    report = json.loads(capsys.readouterr().out)

    assert report["receipt_sha256"] == "a" * 64
    assert report["connectivity_status"] == "not-verified"
    assert report["kernel_patch_status"] == "not-assessed"
    assert calls == [{"action": "upgrade", "allowMutation": True, "scopeConfirm": "example-folder",
                      "expectedVersion": "26.9.30", "expectedReceipt": "c" * 64}]

    with pytest.raises(SystemExit):
        Parser().parse_args(["vpn", "upgrade", "--project", "fixture", "--scope-confirm", "example-folder"])


def test_RemoteRuntimeCannotStageOtherProtocolsOrInvalidConsent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The privileged receiver must reject unsafe envelopes before entering temporary staging."""

    monkeypatch.setattr(receiver.os, "geteuid", lambda: 0, raising=False)
    options = {"action": "upgrade", "expected_version": "26.9.30", "expected_receipt_sha256": "a" * 64}
    files = {"install.sh": base64.b64encode(b"fixture").decode()}
    wrong = {"bundles": [{"transport": "amneziawg", "files": files}], "runtime": options}

    with pytest.raises(ValueError, match="only the owned VLESS"):
        receiver.Runtime(json.dumps(wrong).encode())

    for value in ("", "private", "A" * 64):
        wrong["runtime"]["expected_receipt_sha256"] = value

        with pytest.raises(ValueError, match="exact previous"):
            receiver.Runtime(json.dumps(wrong).encode())


def test_Amnezia5106NativeVlessEnvelopeRetainsExactClientPolicy() -> None:
    """Follow 5.1.0.6 fromJson's third-party last_config path without regenerating server credentials."""

    profile = VpnProfile(IDENTITY, (VpnDevice("phone"),), VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
                         (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),))
    material = GenerateVlessMaterial(profile)
    client = RenderVlessClient(profile, VpnEndpoint("198.51.100.20", 443),
                               VlessRealitySettings("www.example.org", "www.example.org"), material, "phone")
    artifact = BuildAmneziaArtifacts(client, "198.51.100.20", "phone", ("1.1.1.1",), qr=False)[0]
    encoded = artifact.content.strip()[len(b"vpn://"):]
    compressed = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    raw = zlib.decompress(compressed[4:])

    assert struct.unpack(">I", compressed[:4])[0] == len(raw)

    envelope = json.loads(raw)
    container = envelope["containers"][0]
    settings = container["xray"]

    assert envelope["defaultContainer"] == container["container"] == "amnezia-xray"
    assert settings["isThirdPartyConfig"] is True
    assert settings["last_config"].encode() == client
    assert json.loads(settings["last_config"])["outbounds"][0]["streamSettings"]["network"] == "tcp"
    assert base64.urlsafe_b64encode(material.serverPrivateKey).rstrip(b"=") not in raw


def test_Amnezia5106AwgImportRetainsExplicitMtuAndDevicePolicy() -> None:
    """Protect the nonempty imported MTU that 5.1.0.6 now retains instead of substituting a default."""

    profile = VpnProfile(IDENTITY, (VpnDevice("phone", "10.66.0.2"),),
                         VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
                         (VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",)),))
    secrets = GenerateAmneziaWgSecrets(profile)
    prepared = PrepareAmneziaWg(profile, VpnEndpoint("198.51.100.20", 51820),
                                AmneziaWgSettings(mtu=1280), secrets)
    client = prepared.deviceBundles[0].files[0].content
    native = BuildAmneziaWgArtifacts(client, "phone", qr=False)[0].content.strip()[len(b"vpn://"):]
    compressed = base64.urlsafe_b64decode(native + b"=" * (-len(native) % 4))
    envelope = json.loads(zlib.decompress(compressed[4:]))
    settings = envelope["containers"][0]["awg"]
    policy = json.loads(settings["last_config"])

    assert settings["isThirdPartyConfig"] is True
    assert policy["mtu"] == "1280"
    assert policy["allowed_ips"] == ["0.0.0.0/0"]
    assert policy["config"].encode() == client


def test_RuntimeStatusAcceptsNoMutationPreconditions() -> None:
    """Keep the read-only public operation usable without guessed expected-old data."""

    ValidateVlessRuntimeOptions("runtime-status", "", "")
