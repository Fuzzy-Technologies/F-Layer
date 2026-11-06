"""Exercise public selected-project preparation on isolated POSIX files, without providers or guests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from flayer import vpn_project as projects
from flayer import vpn_project_v2 as selected
from flayer.__main__ import Main
from flayer.profiles.artifacts import ArtifactBundle, ArtifactError
from flayer.profiles.vpn import VpnError
from flayer.vpn_export import ExportVpnDevice
from flayer.vpn_project import (
    CompileVpnProject,
    InitializeVpnProject,
    LoadVpnProject,
    PrepareVpnProject,
    RunVpnRuntime,
    SelectedVpnProject,
    VpnProject,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private project files require POSIX; no WSL or desktop VPN is started")


def Editable(template: str) -> str:
    """Replace only documented public placeholders with synthetic example cloud identifiers."""

    return template.replace("replace-with-folder-id", "example-folder").replace(
        "replace-with-ubuntu-2404-amd64-image-id", "example-image")


def Project(tmpPath: Path, protocols: tuple[str, ...] = ("amneziawg", "vless-reality", "wireguard")) -> SelectedVpnProject:
    """Initialize real private files and a fresh synthetic SSH key through the public API."""

    root = InitializeVpnProject(tmpPath / "project", protocols=protocols)
    path = root / "project.toml"
    path.write_text(Editable(path.read_text(encoding="utf-8")), encoding="utf-8")
    project = LoadVpnProject(root)
    assert isinstance(project, SelectedVpnProject)

    return project


def Snapshot(root: Path) -> dict[str, tuple[str, int]]:
    """Compare all retained bytes and modes without exposing synthetic private keys in assertion output."""

    return {str(path.relative_to(root)): (hashlib.sha256(path.read_bytes()).hexdigest(), stat.S_IMODE(path.stat().st_mode))
            for path in root.rglob("*") if path.is_file()}


@pytest.mark.parametrize("protocols", [
    ("amneziawg",), ("vless-reality",), ("wireguard",), ("amneziawg", "vless-reality"),
    ("amneziawg", "wireguard"), ("vless-reality", "wireguard"), ("amneziawg", "vless-reality", "wireguard"),
])
def test_PublicCliPreparesOnlySelectedProtocolsAndRepeatsWithoutRotation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], protocols: tuple[str, ...],
) -> None:
    """Verify actual init/load/prepare CLI dispatch and separate exact per-protocol sensitive stores."""

    root = tmp_path / "project"
    options = [option for protocol in reversed(protocols) for option in ("--protocol", protocol)]

    assert Main(["project", "init", str(root), *options]) == 0
    config = root / "project.toml"
    config.write_text(Editable(config.read_text(encoding="utf-8")), encoding="utf-8")
    capsys.readouterr()

    assert Main(["vpn", "prepare", "--project", str(root), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "complete" and report["cloud_status"] == "not-requested"
    assert report["client_exports"] == [] and "192.0.2.1" not in json.dumps(report)
    project = LoadVpnProject(root)
    assert isinstance(project, SelectedVpnProject)
    stores = {path.name for path in project.Artifacts.iterdir() if path.is_dir()}

    assert stores == {"server-gateway-creation", *("server-gateway-" + suffix for protocol in protocols for suffix in (protocol, protocol + "-credentials"))}
    before = Snapshot(project.Artifacts)

    assert all(mode == 0o600 for _, mode in before.values())
    assert Main(["vpn", "prepare", "--project", str(root), "--format", "json"]) == 0
    assert Snapshot(project.Artifacts) == before


def test_DefaultInitializationAndLegacyPreparationRemainByteCompatible(tmp_path: Path) -> None:
    """An omitted selection keeps schema 1, its template and the original combined credential store."""

    root = InitializeVpnProject(tmp_path / "legacy")
    config = root / "project.toml"

    assert config.read_bytes() == projects.PROJECT_TEMPLATE.encode()
    config.write_text(Editable(config.read_text(encoding="utf-8")), encoding="utf-8")
    project = LoadVpnProject(root)

    assert isinstance(project, VpnProject) and PrepareVpnProject(project).status == "complete"
    assert (project.Artifacts / "server-gateway-credentials").is_dir()
    assert not (project.Artifacts / "server-gateway-amneziawg-credentials").exists()


def test_UnrelatedDeviceDoesNotInvalidateOrRewriteRetainedTransportMaterial(tmp_path: Path) -> None:
    """Preserve all protocol bytes when a declared but unselected device is added for future enrollment."""

    project = Project(tmp_path)
    PrepareVpnProject(project)
    before = Snapshot(project.Artifacts)
    config = project.root / "project.toml"
    config.write_text(config.read_text(encoding="utf-8") + '\n[[devices]]\ndevice_id = "unassigned"\n', encoding="utf-8")
    changed = LoadVpnProject(project.root)
    assert isinstance(changed, SelectedVpnProject)

    assert changed.Fingerprint() != project.Fingerprint()
    assert all(changed.TransportFingerprint(item.protocol) == project.TransportFingerprint(item.protocol)
               for item in project.protocolSelections)
    assert PrepareVpnProject(changed).status == "complete"
    assert Snapshot(project.Artifacts) == before


def test_ChangedWireGuardMembershipCannotRotateOrRewriteAnyPreparedProtocol(tmp_path: Path) -> None:
    """Ordinary preparation refuses affected intent and preserves unrelated AWG/VLESS profiles exactly."""

    project = Project(tmp_path)
    PrepareVpnProject(project)
    before = Snapshot(project.Artifacts)
    config = project.root / "project.toml"
    text = config.read_text(encoding="utf-8").replace('[wireguard]\ndevice_ids = ["laptop"]', '[wireguard]\ndevice_ids = ["phone"]')
    text = text.replace('laptop = "10.67.0.2"', 'phone = "10.67.0.9"')
    config.write_text(text + '\n[[devices]]\ndevice_id = "phone"\n', encoding="utf-8")
    changed = LoadVpnProject(project.root)
    assert isinstance(changed, SelectedVpnProject)

    with pytest.raises(VpnError, match="explicit peer/protocol transition"):
        PrepareVpnProject(changed)

    assert Snapshot(project.Artifacts) == before
    assert changed.TransportFingerprint("amneziawg") == project.TransportFingerprint("amneziawg")
    assert changed.TransportFingerprint("vless-reality") == project.TransportFingerprint("vless-reality")


@pytest.mark.parametrize("fault", ["changed", "missing", "extra", "symlink"])
def test_RetainedMaterialOrServerDriftRefusesWithoutPublishingNewFiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Complete manifest and exact file-set checks precede any publication or credential regeneration."""

    project = Project(tmp_path, ("wireguard",))
    PrepareVpnProject(project)
    folder = project.Artifacts / "server-gateway-wireguard-credentials"
    path = folder / "material.json"

    if fault == "changed":
        path.write_bytes(b"changed-private-fixture")

    elif fault == "missing":
        path.unlink()

    elif fault == "extra":
        (folder / "extra").write_bytes(b"retain")

    else:
        source = project.root / "other-material.json"
        path.rename(source)
        path.symlink_to(source)

    before = Snapshot(project.Artifacts)
    monkeypatch.setattr(selected, "GenerateWireGuardMaterial", lambda *args: pytest.fail("Retained credential drift must never regenerate keys"))
    monkeypatch.setattr(selected, "WriteArtifactBundle", lambda *args: pytest.fail("Drift refusal must not publish anything"))

    with pytest.raises((ArtifactError, VpnError)):
        PrepareVpnProject(project)

    assert Snapshot(project.Artifacts) == before


@pytest.mark.parametrize("action", ["runtime-status", "compile", "export"])
def test_UnpreparedCompileAndPendingRuntimeExportRefuseBeforeExternalAccess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    """Unimplemented maintenance/export and an absent original baseline fail without provider access."""

    project = Project(tmp_path, ("wireguard",))
    monkeypatch.setattr(projects, "VpnYandexProvider", lambda *args: pytest.fail("Unsupported selection must not construct a provider"))

    with pytest.raises(VpnError, match="Schema-2"):
        if action == "runtime-status":
            RunVpnRuntime(project, action)

        elif action == "compile":
            CompileVpnProject(project)

        elif action == "export":
            ExportVpnDevice(project, "laptop", "wireguard", tmp_path / "exports")

    assert not tuple(project.Artifacts.iterdir())
    assert not (project.root / "state.json").exists() and not (tmp_path / "exports").exists()


def test_EditingLegacyProjectToSchema2CannotAdoptItsKeysOrArtifacts(tmp_path: Path) -> None:
    """Require an explicit future migration instead of overwriting a working legacy project's profiles."""

    root = InitializeVpnProject(tmp_path / "project")
    config = root / "project.toml"
    config.write_text(Editable(config.read_text(encoding="utf-8")), encoding="utf-8")
    legacy = LoadVpnProject(root)
    PrepareVpnProject(legacy)
    before = Snapshot(legacy.Artifacts)
    config.write_text(Editable(selected.SelectedProjectTemplate(("wireguard",))), encoding="utf-8")
    changed = LoadVpnProject(root)
    assert isinstance(changed, SelectedVpnProject)

    with pytest.raises(VpnError, match="explicit migration"):
        PrepareVpnProject(changed)

    assert Snapshot(legacy.Artifacts) == before


@pytest.mark.parametrize("marker", ["state", "journal", "journal-symlink", "bootstrap", "trust", "device"])
def test_UnknownDeploymentFootprintsRefuseBeforeGeneratingAnyMaterial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker: str,
) -> None:
    """Missing legacy credentials are not proof that a retained deployment or client profile is absent."""

    project = Project(tmp_path, ("wireguard",))

    if marker == "state":
        (project.root / "state.json").write_bytes(b"retain-unknown-state")

    elif marker in {"journal", "journal-symlink"}:
        path = project.root / ".state.json.operation.json"

        if marker == "journal-symlink":
            path.symlink_to(project.root / "missing-operation")

        else:
            path.write_bytes(b"retain-pending-operation")

    else:
        folder = project.Artifacts / ("device-laptop-amneziawg" if marker == "device" else "server-gateway-" + marker)
        folder.mkdir(mode=0o700)
        (folder / "retain").write_bytes(b"retain-unknown-owned-footprint")

    before = Snapshot(project.root)
    monkeypatch.setattr(selected, "GenerateWireGuardMaterial", lambda *args: pytest.fail("Existing deployment requires explicit migration"))
    monkeypatch.setattr(selected, "WriteArtifactBundle", lambda *args: pytest.fail("Pending deployment state must not publish material"))

    with pytest.raises(VpnError, match="explicit migration"):
        PrepareVpnProject(project)

    assert Snapshot(project.root) == before

    if marker == "journal-symlink":
        assert (project.root / ".state.json.operation.json").is_symlink()


def test_PartialLocalPublicationRetainsCredentialsForSafeRetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later server-bundle write failure cannot require a second generation of already stored keys."""

    project = Project(tmp_path, ("wireguard",))
    write = selected.WriteArtifactBundle

    def Write(root: Path, bundle: ArtifactBundle) -> Path:
        """Fail only after the separately owned credential bundle has been fully committed."""

        if bundle.name == "gateway-wireguard":
            raise OSError("Synthetic server publication failure")

        return write(root, bundle)

    with monkeypatch.context() as patch:
        patch.setattr(selected, "WriteArtifactBundle", Write)

        with pytest.raises(OSError):
            PrepareVpnProject(project)

    credentials = project.Artifacts / "server-gateway-wireguard-credentials"
    before = Snapshot(credentials)
    monkeypatch.setattr(selected, "GenerateWireGuardMaterial", lambda *args: pytest.fail("Retry must decode previously retained material"))

    assert PrepareVpnProject(project).status == "complete"
    assert Snapshot(credentials) == before
    assert (project.Artifacts / "server-gateway-wireguard").is_dir()


@pytest.mark.parametrize("protocols", [(), ("wireguard", "wireguard"), ("openvpn",)])
def test_InvalidExplicitInitDoesNotCreateProjectOrSshKey(tmp_path: Path, protocols: tuple[str, ...]) -> None:
    """Validate requested selection before the first directory or key-generation side effect."""

    path = tmp_path / "invalid"

    with pytest.raises(VpnError):
        InitializeVpnProject(path, protocols=protocols)

    assert not path.exists()
