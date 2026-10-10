"""Private project preparation and two-protocol deployment using a fake cloud and guest."""

from __future__ import annotations

import base64
import json
import os
import stat
import struct
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from flayer import vpn_project
from flayer.__main__ import Main
from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LifecycleEngine
from flayer.core.state import LoadState
from flayer.guest import PrivatePath, ReadPrivate, WritePrivate
from flayer.profiles.artifacts import ArtifactError
from flayer.profiles.vpn import VpnError
from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ProviderStatus,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import MutationError, ResourceSpec
from flayer.providers.yandex import CommandResult, YandexCloudSettings
from flayer.vpn_project import (
    MAX_SERIAL_BYTES,
    CloudPlacement,
    CompileVpnProject,
    InitializeVpnProject,
    LoadVpnProject,
    PrepareVpnProject,
    RunVpnProject,
    VpnProject,
    VpnResources,
    VpnYandexProvider,
    _HostTrust,
    _OwnedEndpoints,
    _PublicKey,
)

PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"p" * 32).decode("ascii")
OTHER_KEY = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"q" * 32).decode("ascii")
SIZING_TOML = '''
[resources]
platform_id = "standard-v3"
cores = 2
core_fraction = 50
memory_gib = 2
disk_size_gib = 10
disk_type = "network-hdd"
'''


def Project(tmp_path: Path) -> VpnProject:
    """Create an actual private local project with example placement and no cloud connection."""

    directory = InitializeVpnProject(tmp_path / "project")
    config = directory / "project.toml"
    config.write_text(config.read_text().replace("replace-with-folder-id", "example-folder").replace("replace-with-ubuntu-2404-amd64-image-id", "example-image"))

    return LoadVpnProject(directory)


def SizedProject(tmp_path: Path) -> VpnProject:
    """Configure the economical Intel shape through the actual public TOML loader."""

    project = Project(tmp_path)
    config = project.root / "project.toml"
    config.write_text(config.read_text() + SIZING_TOML)

    return LoadVpnProject(project.root)


def test_LegacySizingPreservesFingerprintAndPlan(tmp_path: Path) -> None:
    """Keep the fingerprint captured from develop 4d75acc and its implicit resource plan."""

    project = Project(tmp_path)
    fixed_key_project = replace(project, ssh_public_key=PUBLIC_KEY)

    assert fixed_key_project.Fingerprint() == "2fef1d60f4a576029e9066c73ea2bbfd43397197a8f0de52a196bc0a342a21e5", "Legacy prepared credentials would become unusable"
    assert project.resources is None
    PrepareVpnProject(project)
    plan = CompileVpnProject(project)
    disk, instance = (dict(item.parameters) for item in plan.resources[-2:])

    assert disk == {"zone_id": "ru-central1-a", "image_id": "example-image", "size_gib": 20}
    assert (instance["cores"], instance["memory_gib"]) == (2, 2)
    assert "platform_id" not in instance and "core_fraction" not in instance, "Legacy resource ownership digest changed"


@pytest.mark.parametrize("disk_type,disk_size,cores,memory,fraction", [
    ("network-hdd", 10, 2, 2, 50), ("network-ssd", 80, 4, 8, 100),
])
def test_PublicSizingCompilesIntoOwnedProviderResources(
    tmp_path: Path, disk_type: str, disk_size: int, cores: int, memory: int, fraction: int,
) -> None:
    """Propagate all public sizing settings into validated independent disk and VM resources."""

    project = SizedProject(tmp_path)
    project = replace(project, resources=VpnResources("standard-v3", cores, fraction, memory, disk_size, disk_type))
    PrepareVpnProject(project)
    plan = CompileVpnProject(project)
    cloud = FakeCloud(project)

    for spec in plan.resources:
        cloud.ValidateSpec(spec)

    disk, instance = (dict(item.parameters) for item in plan.resources[-2:])

    assert (disk["size_gib"], disk["type"]) == (disk_size, disk_type), "Requested disk was replaced by the preset"
    assert (instance["cores"], instance["memory_gib"], instance["platform_id"], instance["core_fraction"]) == (cores, memory, "standard-v3", fraction), "Requested compute shape was lost"


@pytest.mark.parametrize("field,value", [
    ("cores", "true"), ("cores", "3"), ("cores", "8"), ("cores", "0"),
    ("memory_gib", "1.5"), ("memory_gib", "0"), ("memory_gib", "129"),
    ("core_fraction", "5"), ("core_fraction", "51"), ("core_fraction", '"50"'),
    ("disk_size_gib", "9"), ("disk_size_gib", "1025"), ("disk_size_gib", "false"),
    ("disk_type", '"local-ssd"'), ("platform_id", '"standard-v3 --preemptible"'),
])
def test_InvalidSizingFailsDuringLoadWithoutArtifacts(tmp_path: Path, field: str, value: str) -> None:
    """Reject malformed requests before prepare can generate transport credentials."""

    project = SizedProject(tmp_path)
    config = project.root / "project.toml"
    lines = config.read_text().splitlines()
    config.write_text("\n".join(f"{field} = {value}" if line.startswith(field + " =") else line for line in lines))

    with pytest.raises(VpnError):
        LoadVpnProject(project.root)

    assert not tuple(project.Artifacts.iterdir()), "Invalid sizing produced owned artifacts"


@pytest.mark.parametrize("change", ["missing", "unknown", "not-table", "region"])
def test_SizingSchemaAndRegionFailClosed(tmp_path: Path, change: str) -> None:
    """Reject incomplete blocks, unknown keys and unsupported Kazakhstan platform choices."""

    project = SizedProject(tmp_path)
    config = project.root / "project.toml"
    text = config.read_text()

    if change == "missing":
        text = text.replace('disk_type = "network-hdd"\n', "")

    elif change == "unknown":
        text += "preemptible = true\n"

    elif change == "not-table":
        text = 'resources = "small"\n' + text.replace(SIZING_TOML, "")

    else:
        text = text.replace('zone_id = "ru-central1-a"', 'zone_id = "kz1-a"').replace('platform_id = "standard-v3"', 'platform_id = "standard-v2"')

    config.write_text(text)

    with pytest.raises(VpnError):
        LoadVpnProject(project.root)


@pytest.mark.parametrize("action", ["prepare", "deploy", "status", "recover", "destroy"])
@pytest.mark.parametrize("change", [{"cores": 4}, {"memory_gib": 4}, {"platform_id": "standard-v2"},
                                    {"core_fraction": 20}, {"disk_size_gib": 20}, {"disk_type": "network-ssd"}, None])
def test_PreparedSizingCannotChangeBeforeAnyCloudAccess(tmp_path: Path, action: str, change: dict[str, Any] | None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bind every sizing field, including removal of the block, across all lifecycle commands."""

    project = SizedProject(tmp_path)
    PrepareVpnProject(project)
    assert project.resources is not None
    altered = replace(project, resources=None if change is None else replace(project.resources, **change))

    def RejectCloud(*args: Any, **kwargs: Any) -> None:
        """Fail if a mismatched project reaches even provider construction."""

        pytest.fail("Changed sizing accessed the cloud")

    monkeypatch.setattr("flayer.vpn_project.VpnYandexProvider", RejectCloud)

    with pytest.raises(VpnError, match="changed after preparation|does not match"):
        RunVpnProject(altered, action, allow_mutation=True, scope_confirm="example-folder")


class FakeCloud(VpnYandexProvider):
    """Keep real specification validation while modeling cloud resources entirely in memory."""

    def __init__(self, project: VpnProject) -> None:
        """Create an isolated resource inventory, injectable failure windows, and public host key."""

        super().__init__(YandexCloudSettings(project.vpn.identity.scope_id, project.cloud.yc_profile))
        self.resources: dict[str, ProviderResource] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.fail_create: str | None = None
        self.fail_delete: str | None = None
        self.uncertain_create: str | None = None
        self.host_key: str | None = PUBLIC_KEY
        self.host_key_reads = 0
        self.authentication_checks = 0
        self.authentication_status = ProviderStatus(self.Identity, True, True)

    def CheckAuthentication(self) -> ProviderStatus:
        """Return explicit fixture access without executing the external CLI."""

        self.authentication_checks += 1

        return self.authentication_status

    def FindResource(self, spec: ResourceSpec, identity: StackIdentity) -> ProviderResource | None:
        """Return only an existing fixture resource under its declared logical ID."""

        return self.resources.get(spec.logical_id)

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Respect exact resource references while distinguishing absence from an observation."""

        for resource in self.resources.values():
            if resource.reference == reference:
                return resource

        raise ProviderError(ProviderErrorCode.NOT_FOUND, "get")

    def CreateResource(self, spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource], operation_id: str) -> ProviderResource:
        """Model dependency ordering, failure before dispatch, and uncertain submission."""

        assert set(dependencies) == set(spec.dependencies), "Resources must be created in dependency order"

        if spec.logical_id == self.fail_create:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "create", False)

        addresses = ("203.0.113.20",) if spec.kind in {ResourceKind.INSTANCE, ResourceKind.ADDRESS} else ()
        resource = ProviderResource(
            ResourceReference(identity.provider, identity.scope_id, spec.kind, "id-" + spec.logical_id),
            spec.name, "RUNNING" if spec.kind == ResourceKind.INSTANCE else "READY", "ru-central1-a",
            tuple(sorted((*spec.OwnershipLabels(identity), ("flayer-operation", operation_id)))), addresses,
        )
        self.resources[spec.logical_id] = resource
        self.created.append(spec.logical_id)

        if spec.logical_id == self.uncertain_create:
            raise MutationError(ProviderErrorCode.TIMEOUT, "create", True)

        return resource

    def DeleteResource(self, reference: ResourceReference, identity: StackIdentity, logical_id: str, operation_id: str | None = None) -> None:
        """Delete one exactly owned fixture while allowing interrupted cleanup tests."""

        assert reference.scope_id == identity.scope_id, "Deletion must remain inside the confirmed scope"

        if logical_id == self.fail_delete:
            raise MutationError(ProviderErrorCode.TIMEOUT, "delete", True)

        self.deleted.append(logical_id)
        del self.resources[logical_id]

    def ReadHostKey(self, instance: ProviderResource, fingerprint: str) -> str | None:
        """Return a public fixture key representing the separately authenticated IAM channel."""

        self.host_key_reads += 1

        return self.host_key


class FakeGuest:
    """Record private installation input without running a process or connecting to a network."""

    instances: list[FakeGuest] = []
    fail_install = False
    active = True

    def __init__(self, endpoint: object, username: str, identity_file: Path, known_hosts_file: Path) -> None:
        """Verify that the controller already pinned host trust and retained private key modes."""

        PrivatePath(identity_file)
        self.trust = ReadPrivate(known_hosts_file)
        self.installations: list[object] = []
        self.instances.append(self)

    def Install(self, bundles: object) -> None:
        """Simulate successful or failed guest installation without reporting live health."""

        if self.fail_install:
            raise VpnError("Fixture guest installation failed")

        self.installations.append(bundles)

    def ServiceStatus(self, services: tuple[str, ...]) -> tuple[tuple[str, bool], ...]:
        """Observe configured fixture service activity independently of client reachability."""

        return tuple((service, self.active) for service in services)


@pytest.fixture(autouse=True)
def ResetGuest() -> None:
    """Prevent fixture settings from leaking between independent deployment tests."""

    FakeGuest.instances = []
    FakeGuest.fail_install = False
    FakeGuest.active = True


def Run(project: VpnProject, action: str, cloud: FakeCloud, **options: Any) -> Any:
    """Dispatch only through the real orchestration with fake external boundaries."""

    return RunVpnProject(project, action, allow_mutation=True, scope_confirm=project.vpn.identity.scope_id,
                         provider=cloud, guest_factory=FakeGuest, **options)


def test_ProjectInitializationIsPrivateAndExclusive(tmp_path: Path) -> None:
    """Generate an administration key and editable project without accepting an existing directory."""

    directory = InitializeVpnProject(tmp_path / "project")

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE((directory / "admin-key").stat().st_mode) == 0o600
    assert stat.S_IMODE((directory / "project.toml").stat().st_mode) == 0o600
    assert b"PRIVATE KEY" in ReadPrivate(directory / "admin-key")
    assert "replace-with-folder-id" in (directory / "project.toml").read_text()

    with pytest.raises(VpnError, match="must be new"):
        InitializeVpnProject(directory)

    with pytest.raises(VpnError, match="folder ID"):
        LoadVpnProject(directory)


def test_PreparationIsIdempotentAndKeepsClientKeysOutOfBootstrap(tmp_path: Path) -> None:
    """Preparation validates both renderers, retains credentials, and exports no example endpoints."""

    project = Project(tmp_path)
    first = PrepareVpnProject(project)
    material = ReadPrivate(project.Artifacts / "server-gateway-credentials" / "amneziawg.json")
    second = PrepareVpnProject(project)
    plan = CompileVpnProject(project)
    cloud = FakeCloud(project)

    for spec in plan.resources:
        cloud.ValidateSpec(spec)

    bootstrap = ReadPrivate(project.Artifacts / "server-gateway-bootstrap" / "cloud-init.json")
    settings = json.loads(material)

    assert first.status == second.status == "complete"
    assert material == ReadPrivate(project.Artifacts / "server-gateway-credentials" / "amneziawg.json")
    assert settings["server_private_key"].encode() not in bootstrap
    assert settings["device_private_keys"][0]["private_key"].encode() not in bootstrap
    assert "private_key" not in repr(plan)
    assert not tuple(project.Artifacts.glob("device-*")), "Offline preparation must not export a fake endpoint"
    assert len(plan.resources) == 6 and not cloud.created
    assert b"FLAYER_HOSTKEY " + project.Fingerprint().encode() in bootstrap
    assert b"chain forward" not in bootstrap, "Bootstrap must not override the transport-owned forwarding rules"

    document = json.loads(bootstrap.removeprefix(b"#cloud-config\n"))
    ssh_configuration = next(item["content"] for item in document["write_files"] if item["path"] == "/etc/ssh/sshd_config")

    assert document["users"][0]["lock_passwd"] is True
    assert "UsePAM yes" in ssh_configuration, "Locked Ubuntu accounts need PAM for public-key administration"
    assert "PasswordAuthentication no" in ssh_configuration and "KbdInteractiveAuthentication no" in ssh_configuration


@pytest.mark.parametrize("explicit_sizing", [False, True])
def test_RealOrchestrationCreatesExportsObservesAndDestroys(tmp_path: Path, explicit_sizing: bool) -> None:
    """Exercise the complete controller flow with real durable state and isolated cloud/guest fakes."""

    project = SizedProject(tmp_path) if explicit_sizing else Project(tmp_path)
    cloud = FakeCloud(project)
    deployed = Run(project, "deploy", cloud)

    assert deployed.status == "complete" and deployed.guest_status == "services-active"
    assert deployed.connectivity_status == "not-verified"
    assert len(cloud.created) == 6 and len(FakeGuest.instances[-1].installations) == 1
    assert PUBLIC_KEY.encode() in FakeGuest.instances[-1].trust
    assert deployed.client_exports == ("artifacts/device-laptop-amneziawg", "artifacts/device-laptop-vless-reality")
    assert "203.0.113.20:51820" in ReadPrivate(project.Artifacts / "device-laptop-amneziawg" / "amneziawg.conf").decode()
    assert "203.0.113.20:443" in ReadPrivate(project.Artifacts / "device-laptop-vless-reality" / "import.txt").decode()

    state = json.loads(ReadPrivate(project.root / "state.json"))

    assert set(state) == {"schema_version", "identity", "resources"}
    assert "private_key" not in json.dumps(state) and "user_id" not in json.dumps(state)
    assert Run(project, "deploy", cloud).status == "complete" and len(cloud.created) == 6

    observed = Run(project, "status", cloud)

    assert observed.status == "complete" and not FakeGuest.instances[-1].installations
    assert observed.connectivity_status == "not-verified"

    destroyed = Run(project, "destroy", cloud)

    assert destroyed.status == "complete" and not cloud.resources
    assert cloud.deleted[0] == "instance" and cloud.deleted[-1] == "network"
    assert (project.Artifacts / "server-gateway-credentials").exists(), "Cloud deletion must preserve local private files"


@pytest.mark.parametrize("action", ["deploy", "destroy", "recover"])
def test_MutationRequiresExactScopeBeforePreparation(tmp_path: Path, action: str) -> None:
    """No provider or credential generation may occur under absent or mismatched authorization."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)

    for allow, scope in ((False, "example-folder"), (True, "other-folder")):
        with pytest.raises(VpnError, match="exact --scope-confirm"):
            RunVpnProject(project, action, allow_mutation=allow, scope_confirm=scope, provider=cloud)

    assert not cloud.created and not tuple(project.Artifacts.iterdir())
    assert cloud.authentication_checks == 0, "Consent rejection accessed the cloud"


@pytest.mark.parametrize("action", ["deploy", "status", "destroy", "recover"])
@pytest.mark.parametrize("pending", [False, True])
def test_AuthenticationFailurePreservesProjectBeforeAnyLifecycleOperation(tmp_path: Path, action: str, pending: bool) -> None:
    """Refuse expired access without allocating, observing, rolling back, or rewriting recovery evidence."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    PrepareVpnProject(project)

    if pending:
        cloud.uncertain_create = "instance"
        assert Run(project, "deploy", cloud).recovery_required

    snapshot = {path: path.read_bytes() for path in project.root.rglob("*") if path.is_file()}
    inventory = dict(cloud.resources)
    created, deleted = tuple(cloud.created), tuple(cloud.deleted)
    checks, host_reads = cloud.authentication_checks, cloud.host_key_reads
    cloud.authentication_status = ProviderStatus(cloud.Identity, True, False, ProviderErrorCode.AUTHENTICATION)

    with pytest.raises(VpnError, match=r"preflight failed \(authentication\).*Reauthenticate"):
        Run(project, action, cloud, rollback=action == "recover")

    assert cloud.authentication_checks == checks + 1, "Cloud access must be checked on each invocation"
    assert cloud.resources == inventory and tuple(cloud.created) == created and tuple(cloud.deleted) == deleted
    assert cloud.host_key_reads == host_reads, "Failed authentication reached guest discovery"
    assert {path: path.read_bytes() for path in project.root.rglob("*") if path.is_file()} == snapshot, "Failed preflight changed retained state or artifacts"


@pytest.mark.parametrize("code,expected", [
    (ProviderErrorCode.PERMISSION_DENIED, "read permission"),
    (ProviderErrorCode.TIMEOUT, "timeout alone does not prove"),
    (ProviderErrorCode.UNAVAILABLE, "controller environment"),
    (ProviderErrorCode.SCOPE_MISMATCH, "read-only query"),
    (None, "read-only query"),
])
def test_AccessPreflightDistinguishesFailuresAndUnknownAuthentication(tmp_path: Path, code: ProviderErrorCode | None, expected: str) -> None:
    """Require positive access evidence and retain distinct remediation for sanitized failure categories."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    PrepareVpnProject(project)
    cloud.authentication_status = ProviderStatus(cloud.Identity, code != ProviderErrorCode.UNAVAILABLE, None, code)

    with pytest.raises(VpnError, match=expected):
        Run(project, "status", cloud)

    assert not cloud.created and cloud.authentication_checks == 1


def test_PrepareSkipsCloudAuthentication(tmp_path: Path) -> None:
    """Keep offline credential preparation independent from expired cloud access."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    cloud.authentication_status = ProviderStatus(cloud.Identity, True, False, ProviderErrorCode.AUTHENTICATION)

    assert Run(project, "prepare", cloud).status == "complete"
    assert cloud.authentication_checks == 0 and not cloud.created


@pytest.mark.parametrize("output_format", ["json", "text"])
def test_PublicCliReportsExpiredProfileWithoutVendorSecrets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], output_format: str) -> None:
    """Exercise the real provider probe and console error path with captured secret-bearing rejection."""

    project = Project(tmp_path)
    config = project.root / "project.toml"
    config.write_text(config.read_text().replace('yc_profile = "default"', 'yc_profile = "fixture-vpn-profile"'))
    project = LoadVpnProject(project.root)
    PrepareVpnProject(project)
    calls: list[tuple[str, ...]] = []

    def RunCommand(self: object, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Allow only the selected read-only authentication probe and return an expired fixture token."""

        calls.append(command)

        return CommandResult(1, "", "rpc error: code = Unauthenticated desc = token expired fixture-secret")

    monkeypatch.setattr("flayer.providers.yandex.SubprocessCommandRunner.Run", RunCommand)

    assert Main(["vpn", "deploy", "--project", str(project.root), "--allow-mutation", "--scope-confirm", "example-folder", "--format", output_format]) == 2
    output = capsys.readouterr().out
    message = json.loads(output)["message"] if output_format == "json" else output

    assert "preflight failed (authentication)" in message and "Reauthenticate" in message
    assert "fixture-secret" not in output and "rpc error" not in output, "Vendor output escaped sanitization"
    assert len(calls) == 1 and calls[0][1:6] == ("resource-manager", "folder", "get", "--id", "example-folder")
    assert calls[0][calls[0].index("--profile") + 1] == project.cloud.yc_profile
    assert not (project.root / "state.json").exists() and not (project.root / ".state.json.operation.json").exists()


def test_CreateFailureRollsBackOnlyNewCloudResources(tmp_path: Path) -> None:
    """A rejected instance creation retains local material and reports actual cloud rollback."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    cloud.fail_create = "instance"
    report = Run(project, "deploy", cloud)

    assert report.status == "incomplete" and report.cloud_status == "rolled-back"
    assert not cloud.resources and not FakeGuest.instances
    assert (project.Artifacts / "server-gateway-credentials").exists()


def test_UncertainCreationRequiresExplicitRecovery(tmp_path: Path) -> None:
    """Interrupted provider calls keep their journal and cannot be hidden by guest installation."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    cloud.uncertain_create = "instance"
    report = Run(project, "deploy", cloud)

    assert report.recovery_required and report.cloud_status == "uncertain"
    assert (project.root / ".state.json.operation.json").exists()
    assert not FakeGuest.instances

    cloud.uncertain_create = None
    arriving = cloud.resources.pop("instance")
    unresolved = Run(project, "recover", cloud)

    assert unresolved.recovery_required and unresolved.cloud_status == "uncertain"

    cloud.resources["instance"] = arriving
    recovered = Run(project, "recover", cloud)

    assert recovered.status == "complete" and not FakeGuest.instances
    assert Run(project, "deploy", cloud).status == "complete"


def test_GuestFailureRetainsCloudAndCredentialsForRetry(tmp_path: Path) -> None:
    """A guest failure must not destroy paid resources or rotate already issued device material."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    FakeGuest.fail_install = True

    with pytest.raises(VpnError, match="Fixture guest installation failed"):
        Run(project, "deploy", cloud)

    assert len(cloud.resources) == 6 and len(LoadState(project.root / "state.json", project.vpn.identity).resources) == 6

    material = ReadPrivate(project.Artifacts / "server-gateway-credentials" / "amneziawg.json")
    FakeGuest.fail_install = False

    assert Run(project, "deploy", cloud).status == "complete"
    assert material == ReadPrivate(project.Artifacts / "server-gateway-credentials" / "amneziawg.json")
    assert len(cloud.created) == 6


def test_ServiceInactivityIsNotReportedAsVpnReadiness(tmp_path: Path) -> None:
    """Guest observations remain distinct from successful cloud resource creation."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    FakeGuest.active = False
    report = Run(project, "deploy", cloud)

    assert report.status == "incomplete" and report.guest_status == "inactive"
    assert not tuple(project.Artifacts.glob("device-*"))


def test_ModifiedArtifactsAndChangedProjectSettingsBlockReuse(tmp_path: Path) -> None:
    """Neither credential rotation nor guest replacement may happen as a side effect of retry."""

    project = Project(tmp_path)
    PrepareVpnProject(project)
    changed = replace(project, cloud=replace(project.cloud, zone_id="another-zone"))

    with pytest.raises(VpnError, match="changed after preparation"):
        PrepareVpnProject(changed)

    material = project.Artifacts / "server-gateway-credentials" / "amneziawg.json"
    material.write_bytes(b"operator-modified-private-fixture")

    with pytest.raises(ArtifactError):
        PrepareVpnProject(project)

    assert material.read_bytes() == b"operator-modified-private-fixture"


@pytest.mark.parametrize("variation", ["crlf", "changed", "tampered", "configuration"])
def test_LegacyInstallerNewlinesReuseOnlyVerifiedEquivalentContent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variation: str,
) -> None:
    """Retain old CRLF bundles intact without accepting code drift or bypassing manifests."""

    project = Project(tmp_path)
    prepare = vpn_project.PrepareVless

    def PrepareLegacy(*args: Any, **kwargs: Any) -> Any:
        """Emulate a previous package while preserving the actual artifact writer contract."""

        prepared = prepare(*args, **kwargs)
        filename = "server.json" if variation == "configuration" else "install.py"
        bundle = prepared.server_bundle
        artifacts = tuple(replace(item, content=(
            item.content.replace(b"\n", b"\r\n")
            + (b"# different implementation\r\n" if variation == "changed" else b"")
        )) if item.name == filename else item for item in bundle.files)

        return replace(prepared, server_bundle=replace(bundle, files=artifacts))

    with monkeypatch.context() as patch:
        patch.setattr(vpn_project, "PrepareVless", PrepareLegacy)
        PrepareVpnProject(project)

    installer = project.Artifacts / "server-gateway-vless-reality" / "install.py"

    if variation == "tampered":
        installer.write_bytes(installer.read_bytes().replace(b"\r\n", b"\n"))

    before = {path: path.read_bytes() for path in project.root.rglob("*") if path.is_file()}

    if variation == "crlf":
        assert PrepareVpnProject(project).status == "complete", "Equivalent legacy installer blocked retry"

    else:
        with pytest.raises(ArtifactError if variation == "tampered" else VpnError):
            PrepareVpnProject(project)

    after = {path: path.read_bytes() for path in project.root.rglob("*") if path.is_file()}

    assert after == before, "Retry rewrote credentials, manifests, state, or prepared artifacts"


def test_ForeignOrMismatchedEndpointsBlockTrustAndGuestAccess(tmp_path: Path) -> None:
    """Reserved address and guest ownership must agree with exact durable state before SSH."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    PrepareVpnProject(project)
    LifecycleEngine(CompileVpnProject(project), cloud, project.root / "state.json").Create()
    original = cloud.resources["instance"]
    cloud.resources["instance"] = replace(original, public_addresses=("203.0.113.21",))

    with pytest.raises(VpnError, match="reserved address"):
        _OwnedEndpoints(project, cloud)

    cloud.resources["instance"] = replace(original, labels=(("flayer-owner", "foreign"),))

    with pytest.raises(VpnError, match="persisted ownership"):
        _OwnedEndpoints(project, cloud)

    assert not FakeGuest.instances


def test_AuthenticatedHostKeyPinCannotChangeSilently(tmp_path: Path) -> None:
    """A later cloud-console key change must not overwrite the previously trusted host identity."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    Run(project, "deploy", cloud)
    instance, endpoint = _OwnedEndpoints(project, cloud)
    cloud.host_key = OTHER_KEY

    with pytest.raises(VpnError, match="artifacts differ"):
        _HostTrust(project, cloud, instance, endpoint, wait=False)

    assert PUBLIC_KEY.encode() in ReadPrivate(project.Artifacts / "server-gateway-trust" / "known-hosts.txt")

    cloud.host_key = None
    delays: list[float] = []

    with pytest.raises(VpnError, match="not available yet"):
        _HostTrust(project, cloud, instance, endpoint, wait=True, sleep=delays.append)

    assert len(delays) == 24 and sum(delays) == 120


class SerialCloud(FakeCloud):
    """Exercise production serial parsing through an injected authenticated response."""

    ReadHostKey = VpnYandexProvider.ReadHostKey
    payload: object = {}

    def _ReadJson(self, arguments: tuple[str, ...], operation: str) -> object:
        """Return only fixture serial data after checking exact-instance command construction."""

        assert arguments == ("compute", "instance", "get-serial-port-output", "--id", "id-instance", "--port", "1")

        return self.payload


def test_SerialTrustAcceptsOnlyUnambiguousExactFingerprintMarkers(tmp_path: Path) -> None:
    """Ignore unrelated output and reject conflicting keys or malformed authenticated data."""

    project = Project(tmp_path)
    cloud = SerialCloud(project)
    PrepareVpnProject(project)
    LifecycleEngine(CompileVpnProject(project), cloud, project.root / "state.json").Create()
    instance = cloud.resources["instance"]
    marker = "FLAYER_HOSTKEY " + project.Fingerprint() + " "
    cloud.payload = {"contents": "unrelated text\nFLAYER_HOSTKEY wrong " + OTHER_KEY + "\n" + marker + PUBLIC_KEY + "\n"}

    assert cloud.ReadHostKey(instance, project.Fingerprint()) == PUBLIC_KEY

    cloud.payload = {"contents": marker + PUBLIC_KEY + "\n" + marker + OTHER_KEY}

    with pytest.raises(VpnError, match="conflicting"):
        cloud.ReadHostKey(instance, project.Fingerprint())

    for payload in ({}, {"contents": 1}, {"contents": "x" * (MAX_SERIAL_BYTES + 1)}, {"contents": marker + "invalid-key"}, {"contents": marker + "é"}, {"contents": "\ud800"}):
        cloud.payload = payload

        with pytest.raises(VpnError):
            cloud.ReadHostKey(instance, project.Fingerprint())


@pytest.mark.parametrize("content", [b"private-fixture", b"ssh-rsa AAAA", b"ssh-ed25519 invalid", b"\xff"])
def test_PublicKeysFailWithoutEchoingPrivateInput(content: bytes) -> None:
    """Wrong key files must produce fixed messages without exposing their content."""

    with pytest.raises(VpnError) as caught:
        _PublicKey(content)

    assert "private-fixture" not in str(caught.value)


@pytest.mark.parametrize("changes", [
    {"image_id": "replace-with-image"}, {"subnet_cidr": "8.8.0.0/16"},
    {"subnet_cidr": "10.0.0.1/24"}, {"management_cidrs": ("0.0.0.0/0",)},
    {"management_cidrs": ("198.51.100.0/24", "198.51.100.42/32")},
])
def test_PlacementRejectsUnsafeAdministrationAndPublicSubnets(changes: dict[str, Any]) -> None:
    """Keep cloud management access narrow and separate from protocol ingress."""

    placement = CloudPlacement("default", "example-zone", "example-image", "10.42.0.0/24", ("198.51.100.42/32",))

    with pytest.raises(VpnError):
        replace(placement, **changes)


def test_ProjectConfigurationRejectsInlineCredentialsAndOverlappingNetworks(tmp_path: Path) -> None:
    """Editable project data stays public-only and cannot overlap its VPC and VPN networks."""

    project = Project(tmp_path)
    config = project.root / "project.toml"
    original = config.read_text()
    config.write_text(original.replace('schema_version = 1', 'schema_version = 1\nprivate_key = "fixture-secret"'))

    with pytest.raises(VpnError) as caught:
        LoadVpnProject(project.root)

    assert "fixture-secret" not in str(caught.value)

    config.write_text(original.replace('subnet_cidr = "10.42.0.0/24"', 'subnet_cidr = "10.66.0.0/24"'))

    with pytest.raises(VpnError, match="must not overlap"):
        LoadVpnProject(project.root)


def test_PrivateFilesRejectLinksPermissionsAndOversizeReads(tmp_path: Path) -> None:
    """Editable project files still enforce private ownership and safe filesystem object types."""

    path = tmp_path / "secret.txt"
    WritePrivate(path, b"private-fixture")

    with pytest.raises(VpnError, match="exclusively"):
        WritePrivate(path, b"replacement")

    with pytest.raises(VpnError, match="oversized"):
        ReadPrivate(path, limit=2)

    path.chmod(0o644)

    with pytest.raises(VpnError):
        ReadPrivate(path)

    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)

    with pytest.raises(VpnError):
        ReadPrivate(link)

    link.unlink()
    os.link(path, link)

    with pytest.raises(VpnError):
        ReadPrivate(path)


def test_CliProjectInitAndPrepareFromEditableLocalProject(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Expose a working installed-entrypoint shape without requiring git or live cloud access."""

    directory = tmp_path / "cli-project"

    assert Main(["project", "init", str(directory)]) == 0

    config = directory / "project.toml"
    config.write_text(config.read_text().replace("replace-with-folder-id", "example-folder").replace("replace-with-ubuntu-2404-amd64-image-id", "example-image"))

    assert Main(["vpn", "prepare", "--project", str(directory), "--format", "json"]) == 0

    output = capsys.readouterr().out

    assert '"status": "complete"' in output
    assert "PRIVATE KEY" not in output and "server_private_key" not in output
    assert Main(["vpn", "deploy", "--project", str(directory), "--scope-confirm", "example-folder", "--format", "json"]) == 2

    error = capsys.readouterr().out

    assert '"status": "failed"' in error
    assert not (directory / "state.json").exists()


def test_CliReportsActionableSafeProjectErrors(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    """Users see fixed corrective guidance for placeholders, collisions, and a missing VPN extra."""

    import flayer.vpn_project as projects

    directory = tmp_path / "project"

    assert Main(["project", "init", str(directory)]) == 0

    capsys.readouterr()

    assert Main(["vpn", "prepare", "--project", str(directory), "--format", "json"]) == 2

    result = json.loads(capsys.readouterr().out)

    assert "folder ID" in result["message"] and not result["recovery_required"]
    assert Main(["project", "init", str(directory)]) == 2
    assert "must be new" in capsys.readouterr().out

    config = directory / "project.toml"
    config.write_text(config.read_text().replace("replace-with-folder-id", "example-folder").replace("replace-with-ubuntu-2404-amd64-image-id", "example-image"))

    def MissingExtra(profile: object) -> object:
        """Model the concrete transport's safe optional-dependency failure."""

        raise VpnError("AmneziaWG requires the f-layer[vpn] optional dependency")

    monkeypatch.setattr(projects, "GenerateAmneziaWgSecrets", MissingExtra)

    assert Main(["vpn", "prepare", "--project", str(directory), "--format", "json"]) == 2

    result = json.loads(capsys.readouterr().out)

    assert "f-layer[vpn]" in result["message"]


def test_CloudCleanupDoesNotRequireLostGuestPrivateKey(tmp_path: Path) -> None:
    """Cloud destruction must remain possible through IAM when the local SSH key was lost."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)

    assert Run(project, "deploy", cloud).status == "complete"

    (project.root / "admin-key").unlink()
    public_project = LoadVpnProject(project.root)

    assert Run(public_project, "destroy", cloud).status == "complete"
    assert not cloud.resources


def test_PrepareChecksAdministrationKeyPairBeforeCloudCreation(tmp_path: Path) -> None:
    """A mismatched public key must fail locally before leaving an inaccessible paid instance."""

    project = Project(tmp_path)
    (project.root / "admin-key.pub").write_text(OTHER_KEY + "\n")
    mismatched = LoadVpnProject(project.root)

    with pytest.raises(VpnError, match="does not match"):
        PrepareVpnProject(mismatched)

    assert not tuple(project.Artifacts.iterdir())


def test_DestroyedProjectCannotAllocateAgainBeforeResolvingOldEndpointArtifacts(tmp_path: Path) -> None:
    """Retained old pins must block before allocating a new paid guest with a different host key."""

    project = Project(tmp_path)
    cloud = FakeCloud(project)

    assert Run(project, "deploy", cloud).status == "complete"
    assert Run(project, "destroy", cloud).status == "complete"

    cloud.host_key = OTHER_KEY
    created = tuple(cloud.created)

    with pytest.raises(VpnError, match="Initialize a new private project"):
        Run(project, "deploy", cloud)

    assert tuple(cloud.created) == created and not cloud.resources


@pytest.mark.parametrize("name", ["vpn-%h", "vpn-${USER}"])
def test_OpenSshPathSubstitutionsFailBeforeLocalOrCloudCreation(tmp_path: Path, name: str) -> None:
    """A project path cannot be expanded by SSH into a different unverified key or trust file."""

    path = tmp_path / name

    with pytest.raises(VpnError, match="percent signs"):
        InitializeVpnProject(path)

    assert not path.exists()

    project = Project(tmp_path)
    cloud = FakeCloud(project)
    moved = replace(project, root=path)

    with pytest.raises(VpnError, match="percent signs"):
        Run(moved, "deploy", cloud)

    assert not cloud.created
