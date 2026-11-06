"""Compose real selected-project APIs with in-memory cloud, vendor and guest boundaries on POSIX."""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project import PUBLIC_KEY, FakeCloud
from test_vpn_project_v2 import Project, Snapshot
from test_wireguard_guest import Vendor

from flayer import _vpn_selected_lifecycle as lifecycle
from flayer import vpn_project_v2 as selected
from flayer.__main__ import Main
from flayer._vpn_creation import LoadCreationBaseline, ReadPinnedBundle
from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LifecycleError, _LoadJournal
from flayer.core.state import LoadState
from flayer.guest import PrivatePath, ReadPrivate
from flayer.profiles.artifacts import ArtifactBundle, ArtifactError
from flayer.profiles.vpn import VpnEndpoint, VpnError
from flayer.providers._yandex_firewall import (
    ExpectedRules,
    InstanceAttachments,
    SecurityGroupRule,
    SecurityGroupSnapshot,
)
from flayer.providers.contracts import ProviderResource, ProviderStatus, ResourceKind
from flayer.providers.lifecycle import ResourceSpec
from flayer.vpn_project import (
    CompileVpnProject,
    LoadVpnProject,
    PrepareVpnProject,
    RunVpnProject,
    SelectedVpnProject,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private lifecycle requires POSIX; no WSL or desktop VPN is started")


class SelectedCloud(FakeCloud):
    """Override every selected cloud boundary, including policy reads and creation-bound deletion."""

    def __init__(self, project: SelectedVpnProject) -> None:
        """Retain only synthetic resource metadata and explicit policy fault injection."""

        super().__init__(project)
        self.firewallSpec: ResourceSpec | None = None
        self.rules: tuple[SecurityGroupRule, ...] | None = None
        self.networkId = "id-network"
        self.fingerprints: list[str] = []
        self.policyReads = 0
        self.subnetId = "id-subnet"
        self.groups = ("id-firewall",)
        self.bootDiskId = "id-boot-disk"
        self.publicAddress = "203.0.113.20"
        self.privateAddress = "10.42.0.2"

    def CreateResource(self, spec: ResourceSpec, *args: Any) -> ProviderResource:
        """Remember the submitted original firewall parameters without invoking the real adapter."""

        if spec.kind == ResourceKind.SECURITY_GROUP:
            self.firewallSpec = spec

        return super().CreateResource(spec, *args)

    def ReadSecurityGroupRules(self, resource: ProviderResource) -> SecurityGroupSnapshot:
        """Model exact complete policy observation; never execute the inherited CLI reader."""

        assert self.firewallSpec is not None
        self.policyReads += 1

        return SecurityGroupSnapshot(resource, self.networkId, self.rules if self.rules is not None else ExpectedRules(self.firewallSpec))

    def DeleteCreationResource(
        self, resource: ProviderResource, spec: ResourceSpec, identity: StackIdentity, *,
        policy: SecurityGroupSnapshot | None = None, attachments: InstanceAttachments | None = None,
        operationId: str | None = None,
    ) -> None:
        """Model the final checked deletion boundary without executing any real provider command."""

        assert resource.HasLabels(spec.OwnershipLabels(identity))
        assert operationId is None or dict(resource.labels)["flayer-operation"] == operationId
        assert spec.kind != ResourceKind.SECURITY_GROUP or policy == self.ReadSecurityGroupRules(resource)
        assert spec.kind != ResourceKind.INSTANCE or attachments == self.ReadInstanceAttachments(resource)
        super().DeleteResource(resource.reference, identity, spec.logicalId, operationId)

    def ReadInstanceAttachments(self, resource: ProviderResource) -> InstanceAttachments:
        """Model the separate actual attachment read without falling through to any real CLI boundary."""

        return InstanceAttachments(resource, self.subnetId, self.groups, self.privateAddress, self.publicAddress, self.bootDiskId)

    def ReadHostKey(self, instance: ProviderResource, fingerprint: str) -> str | None:
        """Require the original bootstrap marker to remain independently observable."""

        self.fingerprints.append(fingerprint)

        return super().ReadHostKey(instance, fingerprint)


class SelectedGuest:
    """Keep SSH and all guest mutations in a resettable in-memory model."""

    calls: list[tuple[str, object]] = []
    state = "active"
    cleanup = False
    failInstall = False

    def __init__(self, endpoint: VpnEndpoint, username: str, identityFile: Path, knownHostsFile: Path) -> None:
        """Assert actual observed IPv4, private administration key and IAM-authenticated trust."""

        assert endpoint == VpnEndpoint("203.0.113.20", 22) and username == "flayer-admin"
        PrivatePath(identityFile)
        assert ReadPrivate(knownHostsFile) == ("203.0.113.20 " + PUBLIC_KEY + "\n").encode()

    def Install(self, bundles: tuple[tuple[str, ArtifactBundle], ...]) -> None:
        """Capture retained original server programs and simulate a transaction refusal."""

        self.calls.append(("install", bundles))

        if self.failInstall:
            raise VpnError("Synthetic interrupted guest operation")

    def WireGuardOperation(self, bundle: ArtifactBundle, action: str, **options: Any) -> dict[str, object]:
        """Separate current receipt and explicit absence recovery without running a guest program."""

        self.calls.append((action, options))

        if action == "status":
            return {"status": self.state, "receipt_sha256": "a" * 64 if self.state != "absent" else "",
                    "absence_sha256": "b" * 64, "cleanup_required": self.cleanup}

        assert action == "recover" and options["allowMutation"] is True and options["scopeConfirm"] == "example-folder"
        assert options.get("expectedAbsence" if self.state == "absent" else "expectedReceipt") == ("b" if self.state == "absent" else "a") * 64
        type(self).state = "active"
        type(self).cleanup = False

        return {"status": "complete", "action": action}

    def ServiceStatus(self, services: tuple[str, ...]) -> tuple[tuple[str, bool], ...]:
        """Observe exactly the requested owned services, with no connectivity claim."""

        self.calls.append(("services", services))

        return tuple((service, True) for service in services)

    def WireGuardPeerOperation(self, bundle: ArtifactBundle, action: str, change: str, deviceId: str, **options: Any) -> dict[str, object]:
        """Model only the initial committed history observation without executing a peer driver."""

        from flayer._vpn_revisions import Digest

        owner = json.loads(next(item.content for item in bundle.files if item.name == "deployment.json"))["owner"]
        self.calls.append(("peer-status", bundle))
        assert action == "status" and not options

        return {"status": "active", "is_desired": True, "receipt_sha256": "a" * 64,
                "history_sha256": Digest(lifecycle.wireguardGuest._Encode({"domain": "f-layer/wireguard/peer-history/v1", "owner": owner}))}


@pytest.fixture(autouse=True, name="vendorReads")
def VendorReadsFixture(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Deny real vendor downloads and reset all fake guest state for each case."""

    reads: list[str] = []

    def Fetch(url: str, limit: int) -> bytes:
        """Use a visibly synthetic future vendor fixture, never real network access."""

        reads.append(url)

        return Vendor()

    monkeypatch.setattr(lifecycle.wireguardGuest, "_Fetch", Fetch)
    SelectedGuest.calls = []
    SelectedGuest.state = "active"
    SelectedGuest.cleanup = False
    SelectedGuest.failInstall = False

    return reads


def Run(project: SelectedVpnProject, action: str, cloud: SelectedCloud, **options: Any) -> Any:
    """Call the public lifecycle with modeled external boundaries and explicit mutation consent."""

    return RunVpnProject(project, action, provider=cloud, guestFactory=SelectedGuest,
                         **({} if action == "status" else {"allowMutation": True, "scopeConfirm": "example-folder"}), **options)


@pytest.mark.parametrize("protocols", [("wireguard",), ("amneziawg",), ("vless-reality",),
                                       ("amneziawg", "vless-reality", "wireguard")])
def test_FreshDeployRetryStatusAndDestroyUseExactlyOriginalSixResources(
    tmp_path: Path, protocols: tuple[str, ...], vendorReads: list[str],
) -> None:
    """Exercise full public orchestration while retaining keys, locator IDs, cloud labels and server bytes."""

    project = Project(tmp_path, protocols)
    cloud = SelectedCloud(project)

    assert Run(project, "deploy", cloud).status == "complete"
    before = Snapshot(project.Artifacts)
    baseline = LoadCreationBaseline(project)
    resources = dict(cloud.resources)
    created = tuple(cloud.created)

    assert len(resources) == 6 and set(resources) == {spec.logicalId for spec in baseline.plan.resources}
    assert all(resource.HasLabels(next(spec for spec in baseline.plan.resources if spec.logicalId == logicalId).OwnershipLabels(project.vpn.identity))
               for logicalId, resource in resources.items())
    assert Run(project, "deploy", cloud).status == Run(project, "status", cloud).status == "complete"
    assert cloud.resources == resources and tuple(cloud.created) == created and Snapshot(project.Artifacts) == before
    assert len(vendorReads) == int("wireguard" in protocols), "A healthy retry/status must use cached guest policy instead of a fresh vendor download"
    assert set(cloud.fingerprints) == {baseline.projectFingerprint}
    installed = next(value for action, value in SelectedGuest.calls if action == "install")
    assert installed[0][0] == ("wireguard" if "wireguard" in protocols else protocols[0])

    for protocol, bundle in installed:
        pin = next(pin for pin in baseline.protocols if pin.protocol == protocol)
        assert bundle == ReadPinnedBundle(project, pin)

    for bundlePath in project.Artifacts.glob("device-*/*"):
        assert b"192.0.2.1" not in bundlePath.read_bytes(), "A placeholder endpoint escaped offline preparation"

    assert Run(project, "destroy", cloud).status == "complete" and not cloud.resources
    assert Snapshot(project.Artifacts) == before

    with pytest.raises(VpnError, match="Previous trust"):
        Run(project, "deploy", cloud)


@pytest.mark.parametrize("action", ["deploy", "destroy", "recover"])
@pytest.mark.parametrize("options", [{}, {"allowMutation": True}, {"allowMutation": True, "scopeConfirm": "foreign"}])
def test_MutationConsentPrecedesPreparationProviderAndPublicDownloads(
    tmp_path: Path, action: str, options: dict[str, Any], vendorReads: list[str],
) -> None:
    """Missing exact authorization must leave a fresh project's artifact directory empty."""

    project = Project(tmp_path, ("wireguard",))
    cloud = SelectedCloud(project)

    with pytest.raises(VpnError, match="scope-confirm"):
        RunVpnProject(project, action, provider=cloud, guestFactory=SelectedGuest, **options)

    assert not cloud.authenticationChecks and not cloud.created and not cloud.deleted and not SelectedGuest.calls and not vendorReads
    assert not tuple(project.Artifacts.iterdir())


@pytest.mark.parametrize("vendorStatus", ["pending", "needed", "deferred"])
def test_UnreleasedKernelFixBlocksBeforeAnyPaidResourceOrAuthentication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, vendorStatus: str,
) -> None:
    """Never treat the announced pending target as an already released and installed fix."""

    project = Project(tmp_path, ("wireguard",))
    cloud = SelectedCloud(project)
    monkeypatch.setattr(lifecycle.wireguardGuest, "_Fetch", lambda *args: Vendor(vendorStatus))

    with pytest.raises(VpnError, match="fix is released"):
        Run(project, "deploy", cloud)

    assert not cloud.created and not cloud.authenticationChecks and not SelectedGuest.calls
    assert not (project.root / "state.json").exists()


@pytest.mark.parametrize("fault", ["labels", "name", "zone", "rules", "network", "duplicate-rule",
                                  "extra-group", "replaced-group", "subnet", "boot-disk", "private-address", "nat-address"])
@pytest.mark.parametrize("action", ["deploy", "status", "destroy"])
def test_AnyFrozenOwnershipOrPolicyDriftStopsBeforeCloudOrGuestMutation(
    tmp_path: Path, fault: str, action: str,
) -> None:
    """A firewall changed outside F-Layer must be discovered before deleting even the first VM."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    before = Snapshot(project.Artifacts)
    SelectedGuest.calls.clear()

    if fault == "labels":
        original = cloud.resources["instance"]
        cloud.resources["instance"] = replace(original, labels=tuple((key, "0" * 63 if key == "flayer-spec" else value) for key, value in original.labels))

    elif fault in {"name", "zone"}:
        original = cloud.resources["instance"]
        cloud.resources["instance"] = replace(original, **({"name": "other-instance"} if fault == "name" else {"zoneId": "kz1-a"}))

    elif fault == "network":
        cloud.networkId = "foreign-network"

    elif fault in {"extra-group", "replaced-group", "subnet", "boot-disk", "private-address", "nat-address"}:
        if fault == "extra-group":
            cloud.groups += ("foreign-firewall",)

        elif fault == "replaced-group":
            cloud.groups = ("foreign-firewall",)

        else:
            field, value = {"subnet": ("subnetId", "foreign-subnet"), "boot-disk": ("bootDiskId", "foreign-disk"),
                            "private-address": ("privateAddress", "10.45.0.2"), "nat-address": ("publicAddress", "203.0.113.21")}[fault]
            setattr(cloud, field, value)

    else:
        assert cloud.firewallSpec is not None
        rules = ExpectedRules(cloud.firewallSpec)
        cloud.rules = rules[:-1] if fault == "rules" else (*rules, replace(rules[0], ruleId="duplicate"))

    created = list(cloud.created)

    with pytest.raises(VpnError):
        Run(project, action, cloud)

    assert cloud.created == created and not cloud.deleted and not SelectedGuest.calls
    assert Snapshot(project.Artifacts) == before


def test_UnselectedDeviceAndAuthAliasRetainOriginalBootstrapSshMarkerAndPlan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutable unrelated intent cannot turn an established plan or trust marker into a newly compiled one."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    before = Snapshot(project.Artifacts)
    baseline = CompileVpnProject(project)
    path = project.root / "project.toml"
    path.write_text(path.read_text().replace('yc_profile = "default"', 'yc_profile = "second-alias"') + '\n[[devices]]\ndevice_id = "unassigned"\n')
    changed = LoadVpnProject(project.root)
    assert isinstance(changed, SelectedVpnProject)
    assert changed.Fingerprint() != project.Fingerprint() and CompileVpnProject(changed) == baseline

    assert Run(changed, "deploy", cloud).status == "complete"
    assert Run(changed, "status", cloud).status == "complete" and Snapshot(project.Artifacts) == before
    assert set(cloud.fingerprints) == {project.Fingerprint()}

    # Offline verification must not re-render an installer shipped by a newer controller package.
    (project.root / "state.json").unlink()
    shutil.rmtree(project.Artifacts / "server-gateway-trust")
    for directory in project.Artifacts.glob("device-*"):
        shutil.rmtree(directory)
    monkeypatch.setattr(selected, "_Transport", lambda *args: pytest.fail("Retained installer programs must not be regenerated"))

    assert PrepareVpnProject(changed).status == "complete"


@pytest.mark.parametrize("fault", ["material", "server", "bootstrap", "extra-baseline"])
def test_BundlePinOrBootstrapDriftFailsBeforeProviderAuthentication(tmp_path: Path, fault: str) -> None:
    """Manifest/file-set and original content pins are mandatory before deployment or status."""

    project = Project(tmp_path, ("wireguard",))
    PrepareVpnProject(project)
    paths = {"material": "server-gateway-wireguard-credentials/material.json", "server": "server-gateway-wireguard/install.py",
             "bootstrap": "server-gateway-creation/cloud-init.json", "extra-baseline": "server-gateway-creation/extra"}
    path = project.Artifacts / paths[fault]
    path.write_bytes(b"synthetic-drift")
    cloud = SelectedCloud(project)

    with pytest.raises((VpnError, ArtifactError)):
        Run(project, "deploy", cloud)

    assert not cloud.authenticationChecks and not cloud.created and not SelectedGuest.calls


def test_CloudCleanupSurvivesMissingPrivateMaterialAndUnavailableVendor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the original nonsecret ownership snapshot for destruction without demanding unrelated client secrets."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    (project.root / "admin-key").unlink()
    shutil.rmtree(project.Artifacts / "server-gateway-wireguard-credentials")
    monkeypatch.setattr(lifecycle.wireguardGuest, "_Fetch", lambda *args: pytest.fail("Cleanup must not require a new public CVE download"))
    reloaded = LoadVpnProject(project.root)
    assert isinstance(reloaded, SelectedVpnProject)

    assert Run(reloaded, "destroy", cloud).status == "complete" and not cloud.resources


def test_UncertainCloudCreationRequiresExplicitOriginalPlanRecovery(tmp_path: Path) -> None:
    """A timeout after submission must retain its operation identity and never duplicate the submitted resource."""

    project = Project(tmp_path, ("wireguard",))
    cloud = SelectedCloud(project)
    cloud.uncertainCreate = "instance"
    report = Run(project, "deploy", cloud)

    assert report.status == "incomplete" and report.recoveryRequired
    assert _LoadJournal(project.root / "state.json", CompileVpnProject(project)) is not None

    with pytest.raises(LifecycleError, match="explicit recovery"):
        Run(project, "deploy", cloud)

    cloud.uncertainCreate = None

    assert Run(project, "recover", cloud).status == "complete"
    assert cloud.created.count("instance") == 1
    assert Run(project, "deploy", cloud).status == "complete"


@pytest.mark.parametrize("rollback", [False, True])
def test_PartialCloudDestroyRecoveryUsesFrozenBaselineWithoutGuestOrVendor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rollback: bool,
) -> None:
    """An interrupted destructive operation is resumable, never silently inverted into a new deployment."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    cloud.failDelete = "boot-disk"

    assert Run(project, "destroy", cloud).recoveryRequired
    cloud.failDelete = None
    SelectedGuest.calls.clear()
    monkeypatch.setattr(lifecycle.wireguardGuest, "_Fetch", lambda *args: pytest.fail("Destroy recovery must not download a CVE"))

    if rollback:
        with pytest.raises(LifecycleError, match="cannot be rolled back"):
            Run(project, "recover", cloud, rollback=True)

    assert Run(project, "recover", cloud).status == "complete" and not cloud.resources and not SelectedGuest.calls


@pytest.mark.parametrize("state,cleanup", [("recovery-required", False), ("absent", True)])
def test_ExplicitGuestRecoveryUsesObservedReceiptOrAbsenceProofAndPreservesCloud(
    tmp_path: Path, state: str, cleanup: bool,
) -> None:
    """The generic recover command may finish only a proven interrupted WG guest transaction."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    resources = dict(cloud.resources)
    SelectedGuest.calls.clear()
    SelectedGuest.state, SelectedGuest.cleanup = state, cleanup

    assert Run(project, "status", cloud).recoveryRequired
    assert Run(project, "recover", cloud).status == "complete"
    assert cloud.resources == resources and not cloud.deleted
    assert any(action == "recover" for action, _ in SelectedGuest.calls)
    assert Run(project, "status", cloud).status == "complete"


def test_AuthenticationFailurePreservesCloudJournalAndDoesNotReachGuest(tmp_path: Path) -> None:
    """Credentials remain external; an unavailable selected profile cannot mutate retained lifecycle state."""

    project = Project(tmp_path, ("wireguard",))
    cloud = SelectedCloud(project)
    PrepareVpnProject(project)
    cloud.authenticationStatus = ProviderStatus(cloud.Identity, True, False)
    before = Snapshot(project.root)

    with pytest.raises(VpnError, match="preflight failed"):
        Run(project, "deploy", cloud)

    assert not cloud.created and not SelectedGuest.calls and Snapshot(project.root) == before


def test_KnownPreDispatchFailureRollsBackOnlyThisCreationAndRetainsPrivateBundles(tmp_path: Path) -> None:
    """A declared failed mutation follows the existing journal rollback contract using exact original ownership."""

    project = Project(tmp_path)
    PrepareVpnProject(project)
    before = Snapshot(project.Artifacts)
    cloud = SelectedCloud(project)
    cloud.failCreate = "instance"
    report = Run(project, "deploy", cloud)

    assert report.status == "incomplete" and not report.recoveryRequired and not cloud.resources
    assert len(cloud.created) == len(cloud.deleted) == 5
    assert Snapshot(project.Artifacts) == before and not SelectedGuest.calls

    cloud.failCreate = None

    assert Run(project, "deploy", cloud).status == "complete"


def test_DestroyRefusesUnrecordedCreationInsteadOfClaimingCleanupComplete(tmp_path: Path) -> None:
    """A lost local state cannot authorize adopting and deleting a same-identity cloud inventory."""

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    Run(project, "deploy", cloud)
    (project.root / "state.json").unlink()

    with pytest.raises(VpnError, match="unrecorded"):
        Run(project, "destroy", cloud)

    assert not cloud.deleted and len(cloud.resources) == 6


def test_PublicCliDispatchesSelectedLifecycleWithoutLegacyFallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Exercise actual CLI parsing and JSON reporting while replacing only its cloud/guest constructor boundary."""

    from flayer import vpn_project as projects

    project = Project(tmp_path)
    cloud = SelectedCloud(project)
    publicRun = RunVpnProject

    def Dispatch(project: SelectedVpnProject, action: str, **options: Any) -> Any:
        """Keep complete original lifecycle behavior with explicitly isolated external fixtures."""

        return publicRun(project, action, provider=cloud, guestFactory=SelectedGuest, **options)

    monkeypatch.setattr(projects, "RunVpnProject", Dispatch)

    assert Main(["vpn", "deploy", "--project", str(project.root), "--allow-mutation", "--scope-confirm", "example-folder", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "complete" and len(report["client_exports"]) == 3
    assert "not verified" in report["details"] and LoadState(project.root / "state.json", project.vpn.identity) is not None
