"""Verify VLESS credentials, imported clients, private bundles, and guest failure boundaries."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
import zipfile
import zlib
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles import _amnezia_export as amnezia_export
from flayer.profiles import _vless_guest as guest
from flayer.profiles import vless
from flayer.profiles.artifacts import WriteArtifactBundle
from flayer.profiles.vless import (
    BuildVlessUri,
    DecodeVlessMaterial,
    EncodeVlessMaterial,
    GenerateVlessMaterial,
    PrepareVless,
    RenderVlessClient,
    RenderVlessServer,
    VlessDeviceCredential,
    VlessError,
    VlessMaterial,
    VlessRealitySettings,
    VlessServiceName,
)
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnListener, VpnProfile, VpnRoutes

IDENTITY = StackIdentity("example", "vpn", "yandex-cloud", "example-folder", "example-owner")
SETTINGS = VlessRealitySettings("www.example.org", "www.example.org")
ENDPOINT = VpnEndpoint("198.51.100.20", 443)


def Profile() -> VpnProfile:
    """Create public example intent without using a cloud account."""

    return VpnProfile(
        IDENTITY, (VpnDevice("laptop"), VpnDevice("phone")),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),),
    )


def test_PackagedInstallerLineEndingsDoNotChangePreparedArtifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Windows checkouts and Linux wheels must render identical installer bytes."""

    profile = Profile()
    material = GenerateVlessMaterial(profile)
    canonical = Path(guest.__file__).read_bytes().replace(b"\r\n", b"\n")
    resource = tmp_path / "_vless_guest.py"
    monkeypatch.setattr(vless, "files", lambda package: tmp_path)
    resource.write_bytes(canonical)
    linux = PrepareVless(profile, ENDPOINT, SETTINGS, material)
    resource.write_bytes(canonical.replace(b"\n", b"\r\n"))
    windows = PrepareVless(profile, ENDPOINT, SETTINGS, material)

    assert linux == windows, "Checkout line endings changed private VPN artifacts"
    assert next(item.content for item in windows.server_bundle.files if item.name == "install.py") == canonical


def test_PrivateKeysAndDeviceCredentialsAreSeparate() -> None:
    """Generate distinct credentials and never disclose secrets through representations."""

    profile = Profile()
    material = GenerateVlessMaterial(profile)
    second = GenerateVlessMaterial(profile)
    prepared = PrepareVless(profile, ENDPOINT, SETTINGS, material)
    server = json.loads(prepared.server_bundle.files[0].content)
    client = json.loads(prepared.device_bundles[0].files[0].content)

    assert material.server_private_key != second.server_private_key
    assert len({item.user_id for item in material.devices}) == 2
    assert prepared.capabilities.network_mode == "application-proxy"
    assert server["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"] not in repr(material)
    assert material.devices[0].user_id not in repr(prepared)
    assert material.devices[0].user_id not in repr(material.devices[0])
    assert server["dns"] == {"servers": ["1.1.1.1"], "queryStrategy": "UseIPv4"}
    assert client["inbounds"][0]["listen"] == "127.0.0.1"
    assert all(item.sensitive for bundle in (prepared.server_bundle, *prepared.device_bundles)
               for item in bundle.files)
    assert material.devices[1].user_id.encode() not in prepared.device_bundles[0].files[0].content
    assert b"privateKey" not in prepared.device_bundles[0].files[0].content
    assert b"169.254.0.0/16" in prepared.server_bundle.files[0].content
    assert client["routing"]["rules"][-1]["outboundTag"] == "blocked"


def test_ImportUriBindsRealityParametersToOneDevice() -> None:
    """Preserve every handshake parameter required by actual VLESS importers."""

    profile = Profile()
    material = GenerateVlessMaterial(profile)
    uri = urlsplit(BuildVlessUri(profile, ENDPOINT, SETTINGS, material, "phone"))
    parameters = parse_qs(uri.query)
    expected_key = base64.urlsafe_b64encode(material.server_public_key).decode().rstrip("=")

    assert uri.username == material.devices[1].user_id
    assert uri.hostname == ENDPOINT.host and uri.port == 443
    assert parameters == {
        "encryption": ["none"], "flow": ["xtls-rprx-vision"], "security": ["reality"],
        "sni": [SETTINGS.server_name], "fp": ["chrome"], "pbk": [expected_key],
        "sid": [material.short_id], "type": ["tcp"], "headerType": ["none"], "spx": ["/"],
    }


@pytest.mark.parametrize("changes", [
    {"target_host": "https://example.org"}, {"server_name": "example.org;id"},
    {"server_name": "198.51.100.1"}, {"target_host": "example..org"},
    {"fingerprint": "unsafe"}, {"socks_port": True}, {"target_port": 65536},
])
def test_RealitySettingsRejectMalformedOrUnsupportedInput(changes: dict[str, object]) -> None:
    """Reject shell-shaped hosts and coercions before rendering a guest program."""

    with pytest.raises(VlessError):
        replace(SETTINGS, **changes)


def test_SecretMaterialCannotCrossDeviceOrKeyBoundaries() -> None:
    """Fail closed on swapped public keys, undeclared devices, or reused UUIDs."""

    profile = Profile()
    material = GenerateVlessMaterial(profile)

    with pytest.raises(VlessError, match="form a pair"):
        RenderVlessServer(profile, SETTINGS, replace(material, server_public_key=b"a" * 32))

    with pytest.raises(VlessError, match="match the declared"):
        RenderVlessServer(profile, SETTINGS, replace(material, devices=material.devices[:1]))

    with pytest.raises(VlessError, match="unique"):
        replace(material, devices=(material.devices[0], material.devices[0]))

    with pytest.raises(VlessError, match="no VLESS credential"):
        BuildVlessUri(profile, ENDPOINT, SETTINGS, material, "undeclared")

    with pytest.raises(VlessError, match="listener port"):
        RenderVlessClient(profile, replace(ENDPOINT, port=8443), SETTINGS, material, "laptop")

    with pytest.raises(VlessError):
        VlessDeviceCredential("laptop", "private-credential-do-not-echo")

    with pytest.raises(VlessError):
        VlessMaterial(bytes(32), b"b" * 32, "a" * 16, material.devices)


def test_SplitClientOnlyAllowsConfiguredDestinations() -> None:
    """Keep split SOCKS routes explicit without sending unmatched traffic directly."""

    profile = replace(Profile(), routes=VpnRoutes(
        "split", ("1.1.1.1/32", "203.0.113.0/24"), ("1.1.1.1",), "disabled",
    ))
    client = json.loads(RenderVlessClient(
        profile, ENDPOINT, SETTINGS, GenerateVlessMaterial(profile), "laptop",
    ))

    assert client["routing"]["rules"][2]["ip"] == ["1.1.1.1/32", "203.0.113.0/24"]
    assert {item["protocol"] for item in client["outbounds"]} == {"vless", "blackhole"}
    assert client["dns"]["queryStrategy"] == "UseIPv4"


def PreparedDirectory(tmp_path: Path) -> Path:
    """Export a real private bundle to exercise the standalone guest descriptor reader."""

    profile = Profile()
    prepared = PrepareVless(profile, ENDPOINT, SETTINGS, GenerateVlessMaterial(profile))

    return WriteArtifactBundle(tmp_path / "artifacts", prepared.server_bundle)


def test_InstallerInputIsBoundToPreparedConfig(tmp_path: Path) -> None:
    """Refuse configuration drift before downloads or privileged commands."""

    directory = PreparedDirectory(tmp_path)
    request, config = guest._Request(directory)

    assert request["config_sha256"] == hashlib.sha256(config).hexdigest()
    assert request["xray_version"] == "26.9.30"
    assert VlessServiceName(Profile()) == f"flayer-vless-{request['owner'][:24]}.service"
    assert stat.S_IMODE((directory / "server.json").stat().st_mode) == 0o600

    (directory / "server.json").write_bytes(config + b" ")

    with pytest.raises(guest.GuestError, match="differs"):
        guest._Request(directory)


def Archive(binary: bytes = b"\x7fELFtest", *, filename: str = "xray", symlink: bool = False) -> bytes:
    """Build small deterministic archive fixtures without executing downloaded files."""

    stream = io.BytesIO()

    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo(filename)
        info.external_attr = (stat.S_IFLNK if symlink else stat.S_IFREG) << 16
        archive.writestr(info, binary)

    return stream.getvalue()


def SetDownload(monkeypatch: pytest.MonkeyPatch, content: bytes, expected: str | None = None) -> None:
    """Replace only network and pin metadata with an in-memory official-asset fixture."""

    monkeypatch.setattr(guest.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(guest, "ARCHIVES", {"x86_64": (
        "Xray-linux-64.zip", expected or hashlib.sha256(content).hexdigest(),
    )})
    monkeypatch.setattr(guest.urllib.request, "urlopen", lambda *args, **kwargs: io.BytesIO(content))


def test_ArchivePinAndSafeExtraction(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify archive digests before parsing and reject traversal, symlinks, and wrong binaries."""

    SetDownload(monkeypatch, Archive())

    assert guest._DownloadBinary() == b"\x7fELFtest"

    SetDownload(monkeypatch, Archive(), "0" * 64)

    with pytest.raises(guest.GuestError, match="checksum"):
        guest._DownloadBinary()

    for content in (Archive(filename="../xray"), Archive(symlink=True), Archive(b"#!/bin/sh")):
        SetDownload(monkeypatch, content)

        with pytest.raises(guest.GuestError):
            guest._DownloadBinary()


def GuestPaths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Route managed guest files to isolated root-owned test directories only."""

    base = tmp_path / "owned"
    systemd = tmp_path / "units"
    base.mkdir()
    systemd.mkdir()
    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(guest, "BASE", base)
    monkeypatch.setattr(guest, "SYSTEMD", systemd)
    monkeypatch.setattr(guest, "_DownloadBinary", lambda: b"\x7fELFtest")
    monkeypatch.setattr(guest, "_Command", lambda *args, **kwargs: None)
    monkeypatch.setattr(guest, "_Health", lambda *args: None)
    monkeypatch.setattr(guest, "_TargetHealth", lambda *args: None)

    return base / "deployment", systemd / "flayer-vless-test.service"


def test_OwnedInstallReapplyAndRemove(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise idempotent installation and exact owned cleanup without running systemd."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)
    guest._Install(root, service, request, config)
    original_inode = (root / "xray").stat().st_ino
    guest._Install(root, service, request, config)

    assert (root / "xray").stat().st_ino == original_inode
    assert b"DynamicUser=yes" in service.read_bytes()
    assert b"LoadCredential=server.json:" in service.read_bytes()
    assert stat.S_IMODE((root / "server.json").stat().st_mode) == 0o600

    guest._Remove(root, service, request["owner"])
    guest._Remove(root, service, request["owner"])

    assert not root.exists() and not service.exists()


def test_GuestRefusesForeignAndChangedFiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never replace or remove an existing service without its exact ownership receipt."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)
    service.write_text("foreign")

    with pytest.raises(guest.GuestError, match="unowned"):
        guest._Install(root, service, request, config)

    service.unlink()
    guest._Install(root, service, request, config)
    (root / "server.json").write_bytes(config + b" ")

    with pytest.raises(guest.GuestError, match="changed outside"):
        guest._Remove(root, service, request["owner"])

    assert root.exists() and service.exists()


@pytest.mark.parametrize("initial_active", [False, True])
def test_OwnedRetryEnsuresServiceRunsWithoutReplacingCredentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, initial_active: bool,
) -> None:
    """An explicit deployment retry must restore an inactive verified service without rewriting it."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)
    guest._Install(root, service, request, config)
    snapshot = {path: (path.stat().st_ino, path.read_bytes()) for path in (*root.iterdir(), service)}
    active = initial_active
    commands: list[list[str]] = []

    def RunCommand(arguments: list[str], **kwargs: object) -> None:
        """Model service activation while rejecting a restart that would interrupt active clients."""

        nonlocal active
        commands.append(arguments)

        assert arguments == ["systemctl", "enable", "--now", service.name], "Retry must only ensure the owned service is enabled and running"

        active = True

    def CheckHealth(*args: object) -> None:
        """Reject the exact stopped-service state that previously made every retry fail."""

        if not active:
            raise guest.GuestError("Owned service is inactive")

    def RejectDownload() -> bytes:
        """Preserve the existing verified executable during an identical deployment retry."""

        pytest.fail("An identical retry must not download or replace the existing executable")

    monkeypatch.setattr(guest, "_Command", RunCommand)
    monkeypatch.setattr(guest, "_Health", CheckHealth)
    monkeypatch.setattr(guest, "_DownloadBinary", RejectDownload)
    guest._Install(root, service, request, config)

    assert active and commands, "Deployment retry must actively restore an inactive owned service"
    assert snapshot == {path: (path.stat().st_ino, path.read_bytes()) for path in (*root.iterdir(), service)}, "Service recovery must preserve all installed credentials and ownership receipts"


def test_ReplacementRequiresExplicitExpectedOldAuthorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A changed input must not revoke existing credentials or touch the active service."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)
    guest._Install(root, service, request, config)
    snapshot = {path: path.read_bytes() for path in (*root.iterdir(), service)}

    def FailHealth(*args: object) -> None:
        """Model a daemon restart that cannot satisfy its local readiness checks."""

        raise guest.GuestError("unhealthy")

    monkeypatch.setattr(guest, "_Health", FailHealth)

    with pytest.raises(guest.GuestError, match="expected-old authorization"):
        guest._Install(root, service, request, config + b" ")

    assert snapshot == {path: path.read_bytes() for path in (*root.iterdir(), service)}


def test_FailedFirstInstallLeavesNoManagedService(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove only this failed attempt's files when the first daemon start is unhealthy."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)

    def FailHealth(*args: object) -> None:
        """Model a failed initial service without touching real guest infrastructure."""

        raise guest.GuestError("unhealthy")

    monkeypatch.setattr(guest, "_Health", FailHealth)

    with pytest.raises(guest.GuestError):
        guest._Install(root, service, request, config)

    assert not root.exists() and not service.exists()


def test_GuestReadRefusesSymlinksAndHardlinks(tmp_path: Path) -> None:
    """Do not let private uploads or installed files redirect the privileged reader."""

    regular = tmp_path / "regular"
    regular.write_bytes(b"data")
    link = tmp_path / "link"
    link.symlink_to(regular)

    with pytest.raises(OSError):
        guest._Read(link, 100)

    link.unlink()
    os.link(regular, link)

    with pytest.raises(guest.GuestError, match="hardlinks"):
        guest._Read(link, 100)


def test_RealPinnedXrayParsesGeneratedConfigs(tmp_path: Path) -> None:
    """Optionally validate actual daemon syntax without opening any cloud resource."""

    binary = os.environ.get("FLAYER_XRAY_BINARY")

    if not binary:
        pytest.skip("Set FLAYER_XRAY_BINARY to the checksum-verified pinned Xray executable")

    profile = Profile()
    material = GenerateVlessMaterial(profile)
    version = subprocess.run([binary, "version"], capture_output=True, check=True, text=True)

    assert "Xray 26.9.30" in version.stdout

    for name, content in (
        ("server", RenderVlessServer(profile, SETTINGS, material)),
        ("client", RenderVlessClient(profile, ENDPOINT, SETTINGS, material, "laptop")),
    ):
        path = tmp_path / f"{name}.json"
        path.write_bytes(content)
        result = subprocess.run(
            [binary, "run", "-test", "-config", str(path)], capture_output=True, timeout=15, check=False,
        )

        assert result.returncode == 0, "Pinned Xray rejected the generated configuration"


def test_PrivateMaterialRoundTripRejectsTampering() -> None:
    """Reuse existing credentials after endpoint allocation without parsing public lifecycle state."""

    material = GenerateVlessMaterial(Profile())
    encoded = EncodeVlessMaterial(material)

    assert DecodeVlessMaterial(encoded) == material

    for payload in (b"null", b"{}", encoded + b"x", b"x" * 16385):
        with pytest.raises(VlessError, match="Private VLESS material"):
            DecodeVlessMaterial(payload)

    data = json.loads(encoded)
    data["server_public_key"] = base64.urlsafe_b64encode(b"q" * 32).decode().rstrip("=")

    with pytest.raises(VlessError, match="Private VLESS material"):
        DecodeVlessMaterial(json.dumps(data).encode())


def test_GuestMainInstallCheckRemove(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the uploaded executable entrypoint against isolated files and fake systemd."""

    directory = PreparedDirectory(tmp_path)
    GuestPaths(tmp_path, monkeypatch)
    monkeypatch.setattr(guest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guest.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    monkeypatch.setattr(guest, "__file__", str(directory / "install.py"))

    assert guest.Main([]) == 0
    assert guest.Main(["--check"]) == 0
    assert guest.Main(["--remove"]) == 0
    assert guest.Main(["--check"]) == 1


def test_GuestMainRejectsWrongHostBeforeWrites(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep privilege and operating-system prerequisites separate from successful deployment."""

    monkeypatch.setattr(guest.os, "geteuid", lambda: 1000)

    assert guest.Main([]) == 1

    monkeypatch.setattr(guest.os, "geteuid", lambda: 0)
    monkeypatch.setattr(guest.platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "12"})

    assert guest.Main([]) == 1


def test_GuestCommandSuppressesSecretsAndReportsFailures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither nonzero exits nor a subprocess timeout may reveal daemon configuration values."""

    def FailedCommand(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        """Return a nonzero daemon result while checking private-output suppression."""

        assert kwargs["stdout"] == subprocess.DEVNULL and kwargs["stderr"] == subprocess.DEVNULL

        return subprocess.CompletedProcess(["xray"], 1)

    monkeypatch.setattr(guest.subprocess, "run", FailedCommand)

    with pytest.raises(guest.GuestError, match="unsuccessful"):
        guest._Command(["xray", "run", "-test"])

    def TimedOut(*args: object, **kwargs: object) -> None:
        """Model a stalled daemon without waiting in the test."""

        raise subprocess.TimeoutExpired("xray", 1, output=b"private-value")

    monkeypatch.setattr(guest.subprocess, "run", TimedOut)

    with pytest.raises(guest.GuestError, match="timed out") as caught:
        guest._Command(["xray"])

    assert "private-value" not in str(caught.value)


def test_ArchiveRejectsDuplicateEntries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject ambiguously named binaries even when the outer archive checksum matches."""

    stream = io.BytesIO()

    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("xray", b"\x7fELFone")

        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("xray", b"\x7fELFtwo")

    SetDownload(monkeypatch, stream.getvalue())

    with pytest.raises(guest.GuestError, match="duplicate"):
        guest._DownloadBinary()


def test_GuestRejectsDirectorySymlinkAndUntrackedFiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse ambiguous filesystem ownership before uninstalling another component's data."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)
    link = tmp_path / "linked"
    link.symlink_to(root.parent, target_is_directory=True)

    with pytest.raises(guest.GuestError, match="symbolic links"):
        guest._Directory(link)

    guest._Install(root, service, request, config)
    (root / "foreign.txt").write_text("do not remove")

    with pytest.raises(guest.GuestError, match="untracked"):
        guest._Remove(root, service, request["owner"])

    assert (root / "foreign.txt").read_text() == "do not remove"


def test_LocalHealthSeparatesReadinessFromTunnelEvidence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Confirm a local listener and report bounded startup failure without claiming VPN traffic."""

    monkeypatch.setattr(guest, "_Command", lambda *args, **kwargs: None)
    monkeypatch.setattr(guest, "_TargetHealth", lambda *args: None)
    monkeypatch.setattr(guest, "_Read", lambda *args, **kwargs: b"{}")

    def Connected(address: tuple[str, int], timeout: int) -> nullcontext[None]:
        """Model one successful local readiness probe without live networking."""

        assert address == ("127.0.0.1", 443) and timeout == 1

        return nullcontext()

    monkeypatch.setattr(guest.socket, "create_connection", Connected)
    guest._Health(Path("/owned"), Path("flayer-test.service"), 443)

    clock = iter((0, 6))
    monkeypatch.setattr(guest.time, "monotonic", lambda: next(clock))

    def Refused(*args: object, **kwargs: object) -> None:
        """Model a guest process that never binds its configured socket."""

        raise OSError("refused")

    monkeypatch.setattr(guest.socket, "create_connection", Refused)

    with pytest.raises(guest.GuestError, match="local TCP listener"):
        guest._Health(Path("/owned"), Path("flayer-test.service"), 443)


@pytest.mark.parametrize("alpn,expected", [("h2", True), ("http/1.1", False)])
def test_RealityTargetRequiresValidatedTlsAndHttp2(
    monkeypatch: pytest.MonkeyPatch, alpn: str, expected: bool,
) -> None:
    """Validate the actual target handshake requirements using a certificate-valid TLS fake."""

    class Channel:
        """Expose only the two negotiated TLS properties required by Reality preflight."""

        def version(self) -> str:
            """Keep the external SSL socket method name unchanged."""

            return "TLSv1.3"

        def selected_alpn_protocol(self) -> str:
            """Keep the external SSL socket method name unchanged."""

            return alpn

    class Context:
        """Represent a verified default SSL context without reaching an external server."""

        minimum_version: object = None

        def set_alpn_protocols(self, protocols: list[str]) -> None:
            """Check the external context API receives only HTTP/2."""

            assert protocols == ["h2"]

        def wrap_socket(self, connection: object, server_hostname: str) -> nullcontext[Channel]:
            """Check the expected certificate identity accompanies the TLS handshake."""

            assert server_hostname == SETTINGS.server_name
            assert self.minimum_version == guest.ssl.TLSVersion.TLSv1_3

            return nullcontext(Channel())

    monkeypatch.setattr(guest.ssl, "create_default_context", Context)
    monkeypatch.setattr(guest.socket, "create_connection", lambda *args, **kwargs: nullcontext())
    config = RenderVlessServer(Profile(), SETTINGS, GenerateVlessMaterial(Profile()))

    if expected:
        guest._TargetHealth(config)

    else:
        with pytest.raises(guest.GuestError, match="preflight failed"):
            guest._TargetHealth(config)


@pytest.mark.parametrize("existing", [False, True])
def test_UnusableRealityTargetPreventsGuestMutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool,
) -> None:
    """A reachable daemon alone must not mask an unusable TLS target during installation."""

    request, config = guest._Request(PreparedDirectory(tmp_path))
    root, service = GuestPaths(tmp_path, monkeypatch)

    if existing:
        guest._Install(root, service, request, config)

    paths = (*root.iterdir(), service) if existing else ()
    snapshot = {path: path.read_bytes() for path in paths}

    def FailPreflight(*args: object) -> None:
        """Model an unavailable or incompatible Reality target before managed writes."""

        raise guest.GuestError("Reality target preflight failed")

    def RejectMutation(*args: object, **kwargs: object) -> None:
        """Forbid activation or other guest commands after an unsuccessful target preflight."""

        pytest.fail("An unusable Reality target must fail before guest service mutation")

    monkeypatch.setattr(guest, "_TargetHealth", FailPreflight)
    monkeypatch.setattr(guest, "_Command", RejectMutation)

    with pytest.raises(guest.GuestError, match="preflight failed"):
        guest._Install(root, service, request, config)

    if existing:
        assert snapshot == {path: path.read_bytes() for path in (*root.iterdir(), service)}, "Failed retry preflight must preserve installed credentials and service files"

    else:
        assert not root.exists() and not service.exists()


@pytest.mark.parametrize("mode", ["full", "split"])
def test_AmneziaExportPreservesDevicePolicyAndPrivatePermissions(tmp_path: Path, mode: str) -> None:
    """Decode the native container independently and compare its exact per-device Xray policy."""

    profile = replace(Profile(), routes=VpnRoutes(
        mode, ("0.0.0.0/0",) if mode == "full" else ("1.1.1.1/32", "8.8.8.8/32", "198.51.100.0/24"),
        ("1.1.1.1", "8.8.8.8"), "disabled",
    ))
    material = GenerateVlessMaterial(profile)
    bundle = PrepareVless(profile, ENDPOINT, SETTINGS, material).device_bundles[0]
    artifacts = {item.name: item.content for item in bundle.files}
    encoded = artifacts["amnezia.vpn"].strip().removeprefix(b"vpn://")
    compressed = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    decoded = zlib.decompress(compressed[4:])

    assert int.from_bytes(compressed[:4], "big") == len(decoded)

    native = json.loads(decoded)

    assert native["defaultContainer"] == "amnezia-xray"
    assert native["hostName"] == ENDPOINT.host
    assert (native["dns1"], native["dns2"]) == profile.routes.dns_servers
    assert set(native) == {"containers", "defaultContainer", "hostName", "description", "dns1", "dns2"}

    protocol = native["containers"][0]["xray"]

    assert protocol["isThirdPartyConfig"] is True
    assert protocol["last_config"].encode() == artifacts["client.json"]
    assert material.devices[0].user_id in protocol["last_config"]
    assert material.devices[1].user_id not in decoded.decode()
    assert b"privateKey" not in decoded
    assert artifacts["import.txt"].startswith(b"vless://")
    assert all(item.sensitive for item in bundle.files)

    directory = WriteArtifactBundle(tmp_path / "device", bundle)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE((directory / item.name).stat().st_mode) == 0o600 for item in bundle.files)


def test_AmneziaQrFramesReassembleLikeTheNativeScanner(monkeypatch: pytest.MonkeyPatch) -> None:
    """Decode multi-frame QDataStream headers and qCompress bytes without the export encoder."""

    import segno

    captured = []
    original = segno.make_qr

    def Capture(payload: str, **options: object) -> object:
        """Retain the actual text encoded into each real SVG QR."""

        captured.append(payload)

        return original(payload, **options)

    monkeypatch.setattr(segno, "make_qr", Capture)
    client = json.dumps({"fixture": [hashlib.sha256(str(index).encode()).hexdigest()
                                     for index in range(100)]}).encode()
    artifacts = amnezia_export.BuildAmneziaArtifacts(client, ENDPOINT.host, "phone", ("1.1.1.1",))

    assert len(captured) > 1

    chunks = []

    for index, payload in enumerate(captured):
        frame = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))

        assert int.from_bytes(frame[:2], "big") == 1984
        assert frame[2] == len(captured) and frame[3] == index
        assert int.from_bytes(frame[4:8], "big") == len(frame[8:]) <= 850
        assert artifacts[index + 1].name == f"amnezia-qr-{index + 1:02d}.svg"
        assert b"<svg" in artifacts[index + 1].content

        chunks.append(frame[8:])

    compressed = b"".join(chunks)
    native = json.loads(zlib.decompress(compressed[4:]))

    assert native["containers"][0]["xray"]["last_config"].encode() == client
    assert native["dns1"] == native["dns2"] == "1.1.1.1"
    assert artifacts[0].content == b"vpn://" + base64.urlsafe_b64encode(compressed).rstrip(b"=") + b"\n"


def test_AmneziaExportExplainsMissingOptionalDependency(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail before publishing a partial bundle when QR support is missing."""

    def Missing(name: str) -> None:
        """Simulate installation without the vpn extra."""

        raise ImportError(name)

    monkeypatch.setattr(amnezia_export.importlib, "import_module", Missing)

    with pytest.raises(ValueError, match="vpn.*extra"):
        amnezia_export.BuildAmneziaArtifacts(b"{}", ENDPOINT.host, "phone", ("1.1.1.1",))
