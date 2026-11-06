"""Verify offline export preserves existing device bytes, policy, and private ownership."""

from __future__ import annotations

import base64
import configparser
import json
import stat
import zlib
from dataclasses import replace
from pathlib import Path

import pytest
from test_vpn_project import FakeCloud, Project, Run
from test_vpn_project import ResetGuest as ResetGuest

from flayer.__main__ import Main
from flayer.profiles import _amnezia_export as native
from flayer.profiles.artifacts import ArtifactError
from flayer.profiles.vpn import VpnDevice, VpnError, VpnRoutes
from flayer.vpn_export import ExportVpnDevice
from flayer.vpn_project import VpnProject


def Snapshot(root: Path) -> dict[str, bytes]:
    """Capture exact source files while ignoring read-only access timestamps."""

    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def Decode(connection: bytes) -> tuple[bytes, dict[str, object]]:
    """Independently decode the Qt qCompress payload in a vpn connection key."""

    encoded = connection.strip().removeprefix(b"vpn://")
    compressed = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    raw = zlib.decompress(compressed[4:])

    assert len(raw) == int.from_bytes(compressed[:4], "big"), "Qt uncompressed length differs"

    return compressed, json.loads(raw)


def Deployed(tmpPath: Path, mode: str = "full") -> VpnProject:
    """Use real renderers and owned artifacts with synthetic cloud/guest boundaries."""

    project = Project(tmpPath)
    vpn = replace(project.vpn, devices=(VpnDevice("laptop", "10.66.0.2"), VpnDevice("phone", "10.66.0.3")),
                  routes=VpnRoutes(mode, ("0.0.0.0/0",) if mode == "full" else ("1.1.1.1/32", "8.8.8.8/32"),
                                   ("1.1.1.1", "8.8.8.8"), "disabled"))
    project = replace(project, vpn=vpn)
    Run(project, "deploy", FakeCloud(project))

    return project


@pytest.mark.parametrize("protocol", ["amneziawg", "vless-reality"])
@pytest.mark.parametrize("qr", [False, True])
@pytest.mark.parametrize("mode", ["full", "split"])
def test_ExportRoundtripPreservesCredentialsRoutesAndPermissions(
    tmp_path: Path, protocol: str, qr: bool, mode: str,
) -> None:
    """Retain selected device policy and reject cross-device or server secret leakage."""

    project = Deployed(tmp_path, mode)
    before = Snapshot(project.root)
    report = ExportVpnDevice(project, "laptop", protocol, tmp_path / "exports", qr=qr)
    destination = Path(report.clientExports[0])
    _, profile = Decode((destination / "amnezia.vpn").read_bytes())
    container = profile["containers"][0]  # type: ignore[index]
    source = project.Artifacts / f"device-laptop-{protocol}"

    assert Snapshot(project.root) == before, "Export changed source state or credentials"
    assert report.cloudStatus == report.guestStatus == "not-requested"
    assert report.connectivityStatus == "not-verified"
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in destination.iterdir())
    assert bool(tuple(destination.glob("amnezia-qr-*.svg"))) is qr

    if protocol == "amneziawg":
        conf = (destination / "amneziawg.conf").read_bytes()

        assert conf == (source / "amneziawg.conf").read_bytes()
        assert container["container"] == profile["defaultContainer"] == "amnezia-awg"

        values = json.loads(container["awg"]["last_config"])
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(conf.decode())

        assert values["config"].encode() == conf
        assert values["client_priv_key"] == parser["Interface"]["PrivateKey"]
        assert values["server_pub_key"] == parser["Peer"]["PublicKey"]
        assert values["client_ip"] == "10.66.0.2"
        assert values["allowed_ips"] == list(project.vpn.routes.ipv4Cidrs)
        assert values["mtu"] == "1280" and values["persistent_keep_alive"] == "25"

        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey", "ContentPaddingAddition", "RandomTrailers"):
            assert values[key] == parser["Interface"][key], f"AWG parameter {key} changed during export"

        other = configparser.ConfigParser(interpolation=None)
        other.read_string((project.Artifacts / "device-phone-amneziawg" / "amneziawg.conf").read_text())

        assert other["Interface"]["PrivateKey"] not in json.dumps(profile)
        assert "server_priv_key" not in json.dumps(profile)

    else:
        for filename in ("client.json", "import.txt", "amnezia.vpn"):
            assert (destination / filename).read_bytes() == (source / filename).read_bytes()

        assert container["xray"]["last_config"].encode() == (source / "client.json").read_bytes()

    repeated = ExportVpnDevice(project, "laptop", protocol, tmp_path / "exports", qr=qr)

    assert repeated == report, "Identical export should reuse the unchanged owned output"


def test_NativeAwgMultipartFramesMatchProfile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Reconstruct actual QR inputs independently, including reversed scan order."""

    import segno

    project = Deployed(tmp_path)
    client = (project.Artifacts / "device-laptop-amneziawg" / "amneziawg.conf").read_bytes()
    captured: list[str] = []
    original = segno.make_qr

    def Capture(payload: str, **options: object) -> object:
        """Retain the real QR payload before rendering its SVG."""

        captured.append(payload)

        return original(payload, **options)

    monkeypatch.setattr(segno, "make_qr", Capture)
    monkeypatch.setattr(native, "QR_CHUNK_BYTES", 100)
    artifacts = native.BuildAmneziaWgArtifacts(client, "laptop", qr=True)
    compressed, _ = Decode(artifacts[0].content)
    frames = {}

    for payload in reversed(captured):
        frame = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))

        assert int.from_bytes(frame[:2], "big") == 1984
        assert frame[2] == len(captured)
        assert int.from_bytes(frame[4:8], "big") == len(frame[8:]) <= 100

        frames[frame[3]] = frame[8:]

    assert len(frames) > 1
    assert b"".join(frames[index] for index in range(len(frames))) == compressed
    assert all(b"<svg" in item.content for item in artifacts[1:])


@pytest.mark.parametrize("case", ["missing", "changed", "foreign", "unowned", "symlink", "permissions", "hardlink"])
def test_ExportRejectsUntrustedSourceBeforeWriting(tmp_path: Path, case: str) -> None:
    """Keep output absent when ownership, exact contents or filesystem safety fail."""

    import os

    project = Deployed(tmp_path)
    source = project.Artifacts / "device-laptop-amneziawg"
    conf = source / "amneziawg.conf"

    if case == "missing":
        conf.unlink()

    elif case == "changed":
        conf.write_bytes(conf.read_bytes() + b"# fixture-secret\n")

    elif case == "foreign":
        manifest = source / "manifest.json"
        payload = json.loads(manifest.read_bytes())
        payload["identity"]["owner_id"] = "another-owner"
        manifest.write_text(json.dumps(payload))

    elif case == "unowned":
        (source / "unknown.txt").write_bytes(b"unowned-fixture")

    elif case == "symlink":
        held = tmp_path / "held.conf"
        conf.rename(held)
        conf.symlink_to(held)

    elif case == "permissions":
        conf.chmod(0o644)

    else:
        os.link(conf, tmp_path / "linked.conf")

    before = Snapshot(project.root)

    with pytest.raises(ArtifactError):
        ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "exports", qr=True)

    assert Snapshot(project.root) == before
    assert not (tmp_path / "exports").exists()


@pytest.mark.parametrize("case", ["different", "extra", "root-permissions", "symlink", "source", "traversal", "missing-parent"])
def test_ExportPreservesUnsafeOrChangedOutput(tmp_path: Path, case: str) -> None:
    """Do not replace files, accept broader permissions or write through unsafe paths."""

    project = Deployed(tmp_path)
    output = tmp_path / "exports"

    if case in {"different", "extra", "root-permissions", "symlink"}:
        report = ExportVpnDevice(project, "laptop", "amneziawg", output)
        destination = Path(report.clientExports[0])

        if case == "different":
            (destination / "amnezia.vpn").write_bytes(b"foreign-fixture")

        elif case == "extra":
            (destination / "unknown.txt").write_bytes(b"foreign-fixture")

        elif case == "root-permissions":
            output.chmod(0o755)

        else:
            output.rename(tmp_path / "held-output")
            output.symlink_to(tmp_path / "held-output", target_is_directory=True)

    elif case == "source":
        output = project.Artifacts

    elif case == "traversal":
        output = tmp_path / "exports" / ".." / "escape"

    else:
        output = tmp_path / "missing" / "exports"

    before = Snapshot(tmp_path)

    with pytest.raises(ValueError):
        ExportVpnDevice(project, "laptop", "amneziawg", output, qr=True)

    assert Snapshot(tmp_path) == before, "Failure modified foreign output or source files"


@pytest.mark.parametrize("protocol", ["amneziawg", "vless-reality"])
def test_PublicCliExportDoesNotContactCloudOrRevealSecrets(
    tmp_path: Path, protocol: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Invoke only public commands and prove there is no provider, guest or key-generation call."""

    import flayer.vpn_project as projects

    project = Project(tmp_path)
    Run(project, "deploy", FakeCloud(project))

    def Forbidden(*arguments: object, **options: object) -> None:
        """Reject unexpected network or credential side effects."""

        pytest.fail("Offline export attempted cloud access or credential generation")

    for name in ("RunVpnProject", "GenerateAmneziaWgSecrets", "GenerateVlessMaterial", "_CheckCloudAccess"):
        monkeypatch.setattr(projects, name, Forbidden)

    arguments = ["vpn", "export", "--project", str(project.root), "--device", "laptop", "--protocol", protocol,
                 "--output", str(tmp_path / "exports"), "--qr", "--format", "json"]

    assert Main(arguments) == 0

    printed = capsys.readouterr().out
    report = json.loads(printed)

    assert report["action"] == "export" and report["status"] == "complete"
    assert "vpn://" not in printed and "vless://" not in printed
    assert "PrivateKey" not in printed and "client_priv_key" not in printed
    assert Main([*arguments[:arguments.index("--device") + 1], "unknown", *arguments[arguments.index("--device") + 2:]]) == 2

    assert "declared" in capsys.readouterr().out


def test_ExportWithoutQrDoesNotLoadSegno(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Native files remain exportable when QR support was not requested."""

    project = Deployed(tmp_path)

    def Missing(name: str) -> None:
        """Simulate a missing optional QR renderer."""

        raise ImportError(name)

    monkeypatch.setattr(native.importlib, "import_module", Missing)
    ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "files")

    with pytest.raises(VpnError, match="vpn.*extra"):
        ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "qr", qr=True)

    assert not (tmp_path / "qr").exists()


@pytest.mark.parametrize("replacement", ["[Interface]\nPrivateKey = fixture-secret", "[Interface]\n[Interface]\n", "fixture-secret"])
def test_InvalidAwgConfigNeverEchoesInput(replacement: str) -> None:
    """Reject malformed or duplicate configurations with a fixed message."""

    with pytest.raises(VpnError) as caught:
        native.BuildAmneziaWgArtifacts(replacement.encode(), "phone")

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("connection", [b"secret", b"vpn://!secret", b"vpn://", b"vpn://AA=="])
def test_InvalidConnectionKeysFailClosed(connection: bytes) -> None:
    """Reject invalid scanner input rather than generating misleading QR frames."""

    with pytest.raises(VpnError):
        native.BuildAmneziaQrArtifacts(connection)


def test_ChangingExportSelectionDoesNotModifyExistingFiles(tmp_path: Path) -> None:
    """Switching QR options requires a separate output root instead of pruning owned files."""

    project = Deployed(tmp_path)
    ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "exports", qr=True)
    before = Snapshot(tmp_path)

    with pytest.raises(VpnError, match="selection"):
        ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "exports")

    assert Snapshot(tmp_path) == before


@pytest.mark.parametrize('outputFormat', ["text", "json"])
def test_CliMissingDeviceFilesExplainsLocalExportFailure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], outputFormat: str,
) -> None:
    """Explain an absent owned source without misleading cloud-access advice."""

    project = Project(tmp_path)
    before = Snapshot(project.root)

    assert Main(["vpn", "export", "--project", str(project.root), "--device", "laptop",
                 "--protocol", "amneziawg", "--output", str(tmp_path / "exports"),
                 "--format", outputFormat]) == 2

    printed = capsys.readouterr().out

    assert "export failed" in printed.lower(), "Local export error must identify the failing operation"
    assert "source manifests" in printed.lower()
    assert Snapshot(project.root) == before
    assert not (tmp_path / "exports").exists()


@pytest.mark.parametrize("original,replacement", [
    ("MTU = 1280", "MTU = 9000"),
    ("DNS = 1.1.1.1, 8.8.8.8", "DNS = 1.1.1.1, 8.8.8.8, 9.9.9.9"),
    ("Address = 10.66.0.2/32", "Address = 10.66.0.2/24"),
    ("AllowedIPs = 0.0.0.0/0", "AllowedIPs = ::/0"),
    ("PersistentKeepalive = 25", "PersistentKeepalive = -1"),
])
def test_NativeAwgRejectsUnrepresentableOrInvalidPolicy(
    tmp_path: Path, original: str, replacement: str,
) -> None:
    """Do not silently truncate DNS or normalize unsupported endpoint/route policy."""

    project = Deployed(tmp_path)
    client = (project.Artifacts / "device-laptop-amneziawg" / "amneziawg.conf").read_text()

    assert original in client, "Policy fixture no longer matches the generated configuration"

    with pytest.raises(VpnError, match="invalid or unsupported"):
        native.BuildAmneziaWgArtifacts(client.replace(original, replacement).encode(), "laptop")


@pytest.mark.parametrize("tlsFragment,allowQuic", [(True, False), (False, True), (True, True)])
@pytest.mark.parametrize("qr", [False, True])
@pytest.mark.parametrize("mode", ["full", "split"])
def test_DerivedVlessExportPreservesSourceAndNativePolicy(
    tmp_path: Path, tlsFragment: bool, allowQuic: bool, qr: bool, mode: str,
) -> None:
    """Export complete opt-in native profiles without source writes or ambiguous URI output."""

    project = Deployed(tmp_path, mode)
    before = Snapshot(project.root)
    original = json.loads((project.Artifacts / "device-laptop-vless-reality/client.json").read_bytes())
    report = ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "derived", qr=qr,
                             tlsFragment=tlsFragment, allowQuic=allowQuic)
    destination = Path(report.clientExports[0])
    client = (destination / "client.json").read_bytes()
    _, profile = Decode((destination / "amnezia.vpn").read_bytes())
    decoded = json.loads(client)

    assert Snapshot(project.root) == before, "Derived export changed prepared artifacts or source state"
    assert profile["containers"][0]["xray"]["last_config"].encode() == client  # type: ignore[index]
    assert not (destination / "import.txt").exists(), "A URI cannot represent the derived client policy"
    assert decoded["dns"] == original["dns"] and decoded["routing"] == original["routing"]
    assert decoded["outbounds"][0]["streamSettings"]["realitySettings"] == original["outbounds"][0]["streamSettings"]["realitySettings"]
    assert decoded["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"] == original["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"]
    assert decoded["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == (
        "xtls-rprx-vision-udp443" if allowQuic else "xtls-rprx-vision"
    )
    assert bool(tuple(destination.glob("amnezia-qr-*.svg"))) is qr
    assert report.cloudStatus == report.guestStatus == "not-requested"
    assert report.connectivityStatus == "not-verified"
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in destination.iterdir())
    assert stat.S_IMODE(destination.stat().st_mode) == stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "derived", qr=qr,
                           tlsFragment=tlsFragment, allowQuic=allowQuic) == report


@pytest.mark.parametrize("tlsFragment,allowQuic", [(True, False), (False, True), (True, True)])
def test_DerivedExportPreservesPreparedDnsAfterDesiredConfigurationDrifts(
    tmp_path: Path, tlsFragment: bool, allowQuic: bool,
) -> None:
    """Keep the prepared native policy even when current desired DNS differs from the device."""

    project = Deployed(tmp_path)
    source = project.Artifacts / "device-laptop-vless-reality"
    _, original = Decode((source / "amnezia.vpn").read_bytes())
    project = replace(project, vpn=replace(project.vpn, routes=replace(
        project.vpn.routes, dnsServers=("9.9.9.9",),
    )))
    before = Snapshot(project.root)
    report = ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "derived",
                             tlsFragment=tlsFragment, allowQuic=allowQuic)
    destination = Path(report.clientExports[0])
    _, profile = Decode((destination / "amnezia.vpn").read_bytes())
    profile["containers"][0]["xray"]["last_config"] = original["containers"][0]["xray"]["last_config"]  # type: ignore[index]

    assert profile == original, "Derived export changed prepared native metadata or DNS"
    assert Snapshot(project.root) == before, "Configuration drift export rewrote the source"


@pytest.mark.parametrize("tlsFragment,allowQuic", [(True, False), (False, True), (True, True)])
def test_ChangingTransportOptionsLeavesAnExistingExportIntact(
    tmp_path: Path, tlsFragment: bool, allowQuic: bool,
) -> None:
    """Require separate output when the selected transport policy changes any existing bytes."""

    project = Deployed(tmp_path)
    ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "exports")
    before = Snapshot(tmp_path)

    with pytest.raises(VpnError, match="differs"):
        ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "exports",
                        tlsFragment=tlsFragment, allowQuic=allowQuic)

    assert Snapshot(tmp_path) == before


@pytest.mark.parametrize("flags", [{"tlsFragment": 1}, {"allowQuic": "yes"}, {"tlsFragment": None}])
def test_TransportOptionsRequireActualBooleans(tmp_path: Path, flags: dict[str, object]) -> None:
    """Reject truthy non-boolean API options before creating an export destination."""

    project = Deployed(tmp_path)

    with pytest.raises(VpnError, match="boolean"):
        ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "invalid", **flags)  # type: ignore[arg-type]

    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("flags", [{"tlsFragment": True}, {"allowQuic": True}])
def test_AwgRejectsVlessOnlyOptions(tmp_path: Path, flags: dict[str, bool]) -> None:
    """Keep AWG exports unchanged and refuse transport settings it cannot represent."""

    project = Deployed(tmp_path)

    with pytest.raises(VpnError, match="only for VLESS"):
        ExportVpnDevice(project, "laptop", "amneziawg", tmp_path / "invalid", **flags)

    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("filename", ["client.json", "import.txt", "amnezia.vpn"])
def test_DerivedExportStillVerifiesEverySourceArtifact(tmp_path: Path, filename: str) -> None:
    """Verify the complete original manifest even when an artifact is omitted from derived output."""

    project = Deployed(tmp_path)
    source = project.Artifacts / "device-laptop-vless-reality" / filename
    source.write_bytes(b"fixture-secret-corruption")
    before = Snapshot(project.root)

    with pytest.raises(ArtifactError):
        ExportVpnDevice(project, "laptop", "vless-reality", tmp_path / "invalid", tlsFragment=True)

    assert Snapshot(project.root) == before
    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("tlsFragment,allowQuic", [(False, True), (True, False), (True, True)])
def test_CliWiresIndependentTransportFlags(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], tlsFragment: bool, allowQuic: bool,
) -> None:
    """Exercise public CLI parsing through a real private offline export and native envelope."""

    project = Deployed(tmp_path)
    arguments = ["vpn", "export", "--project", str(project.root), "--device", "laptop",
                 "--protocol", "vless-reality", "--output", str(tmp_path / "cli"), "--format", "json"]

    if tlsFragment:
        arguments.append("--tls-fragment")

    if allowQuic:
        arguments.append("--allow-quic")

    assert Main(arguments) == 0

    report = json.loads(capsys.readouterr().out)
    destination = Path(report["client_exports"][0])
    client = json.loads((destination / "client.json").read_bytes())

    assert not (destination / "import.txt").exists()
    assert client["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == (
        "xtls-rprx-vision-udp443" if allowQuic else "xtls-rprx-vision"
    )
    assert ("sockopt" in client["outbounds"][0]["streamSettings"]) is tlsFragment
