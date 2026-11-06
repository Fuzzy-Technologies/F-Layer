"""Exercise public peer plans, crash recovery and lifecycle integration with independent in-memory cloud/guest models."""

from __future__ import annotations

import base64
import json
import os
import shutil
import struct
from dataclasses import replace
from functools import partial
from pathlib import Path
from typing import Any

import pytest
from test_selected_lifecycle import SelectedCloud, SelectedGuest
from test_vpn_project_selection import PUBLIC_KEY, Configuration
from test_vpn_project_v2 import Project, Snapshot
from test_wireguard_guest import Vendor

from flayer import _vpn_peer_controller as controller
from flayer import _vpn_revisions as revisions
from flayer import _vpn_selected_lifecycle as lifecycle
from flayer import vpn_peers as peers
from flayer import vpn_project as projects
from flayer.__main__ import Main
from flayer.core.state import LoadState, SaveState
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    RemoveArtifactBundle,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import VpnDevice, VpnError
from flayer.vpn_peers import RunVpnPeer
from flayer.vpn_project import RunVpnProject, SelectedVpnProject
from flayer.vpn_project_v2 import ParseSelectedProject, PrepareSelectedProject
from flayer.vpn_selection import VpnProtocolSelection

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private peer integration requires POSIX; no WSL or desktop VPN is started")


class PeerGuest(SelectedGuest):
    """Model guest root publication and its chained audit independently from controller storage."""

    project: SelectedVpnProject
    server: ArtifactBundle | None = None
    receipt = ""
    history = ""
    journal: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None
    fail = ""
    peerCalls: list[tuple[str, str, str]] = []

    def Install(self, bundles: tuple[tuple[str, ArtifactBundle], ...], *, expectedWireGuardHistory: str = "") -> None:
        """Accept original or effective server bytes only, without simulating any unrelated installer mutation."""

        cls = type(self)

        if any(protocol == "wireguard" for protocol, _ in bundles) and (cls.history or revisions.InitialHistory(cls.project)) != expectedWireGuardHistory:
            raise VpnError("Model refused changed history under the install lock")

        super().Install(bundles, expectedWireGuardHistory=expectedWireGuardHistory)

        for protocol, bundle in bundles:
            if protocol == "wireguard":
                if cls.server is not None and cls.server != bundle:
                    raise VpnError("Model refused obsolete server bytes")

                cls.server = bundle
                cls.receipt = self.Receipt(bundle)

                if not cls.history:
                    cls.history = revisions.InitialHistory(cls.project)

    @staticmethod
    def Descriptor(bundle: ArtifactBundle) -> str:
        """Identify exact server intent bytes while keeping all synthetic keys out of assertion output."""

        return revisions.Digest(next(item.content for item in bundle.files if item.name == "deployment.json"))

    @staticmethod
    def Receipt(bundle: ArtifactBundle) -> str:
        """Allow configuration ABA deliberately; only chained history must distinguish repeated cycles."""

        return revisions.Digest(b"independent-guest-runtime" + next(item.content for item in bundle.files if item.name == "deployment.json"))

    def WireGuardOperation(self, bundle: ArtifactBundle, action: str, **options: Any) -> dict[str, object]:
        """Expose initial absence or the currently installed model receipt without any real guest process."""

        assert action == "status" and not options

        if self.server is None:
            return {"status": "absent", "cleanup_required": False}

        assert self.server == bundle, "Ordinary lifecycle sent obsolete peer configuration"

        return {"status": "recovery-required" if self.journal is not None else "active", "receipt_sha256": self.receipt}

    def WireGuardPeerOperation(self, bundle: ArtifactBundle, action: str, change: str, deviceId: str, **options: Any) -> dict[str, object]:
        """Simulate old/new guest roots, original proofs and lost responses; never call SSH or kernel tools."""

        cls = type(self)
        cls.peerCalls.append((action, change, deviceId))

        if action == "history-status":
            assert not options
            owner = json.loads(next(item.content for item in bundle.files if item.name == "deployment.json"))["owner"]

            return {"status": "peer-history", "owner": owner, "history_sha256": cls.history or revisions.InitialHistory(cls.project), "tools_version": "1.0.20260223"}

        assert cls.server is not None

        if action == "status":
            assert not options
            desired = self.Descriptor(bundle)

            if cls.journal is not None:
                assert (change, deviceId, desired) == (cls.journal["change"], cls.journal["device_id"], cls.journal["desired"])

            original = cls.journal or cls.audit

            return {"status": "peer-recovery-required" if cls.journal is not None else "active", "receipt_sha256": cls.receipt,
                    "previous_receipt_sha256": original["receipt"] if original else "", "deployment_sha256": self.Descriptor(cls.server),
                    "history_sha256": cls.history, "previous_history_sha256": original["history"] if original else "",
                    "desired_deployment_sha256": desired, "is_desired": desired == self.Descriptor(cls.server),
                    "action": change, "device_id": deviceId, "tools_version": "1.0.20260223", "kernel_policy": "cached-named-cve-baseline"}

        assert options["allowMutation"] is True and options["scopeConfirm"] == "example-folder"
        assert options["expectedReceipt"] == cls.receipt

        if action == "recover":
            if cls.receipt == options["expectedPrevious"] and cls.history == options["expectedHistory"]:
                cls.journal = None

                return {"status": "complete", "outcome": "not-applied"}

            original = cls.journal or cls.audit
            assert original is not None and cls.server == bundle
            assert (options["expectedPrevious"], options["expectedHistory"], change, deviceId) == (
                original["receipt"], original["history"], original["change"], original["device_id"])
            cls.journal = None

            return {"status": "complete", "outcome": "committed"}

        assert action == "apply" and options["expectedHistory"] == cls.history
        failure, cls.fail = cls.fail, ""

        if failure == "before":
            raise VpnError("Synthetic lost response before guest publication")

        original = {"receipt": cls.receipt, "history": cls.history, "change": change, "device_id": deviceId, "desired": self.Descriptor(bundle)}
        cls.journal = original

        if failure == "prefix":
            raise VpnError("Synthetic uncommitted guest prefix")

        cls.server = bundle
        cls.receipt = self.Receipt(bundle)
        cls.history = revisions.CommittedHistory(cls.project, change, deviceId, original["receipt"], cls.receipt, self.Descriptor(bundle), original["history"])
        cls.audit = original

        if failure == "published":
            raise VpnError("Synthetic lost response after guest publication")

        cls.journal = None

        if failure == "response":
            raise VpnError("Synthetic lost completed response")

        return {"status": "complete", "outcome": "committed"}


@pytest.fixture(name="deployment")
def DeploymentFixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[SelectedVpnProject, SelectedCloud]:
    """Provision only synthetic model resources through the actual public lifecycle and private filesystem."""

    monkeypatch.setattr(lifecycle.wireguardGuest, "_Fetch", lambda *arguments: Vendor())
    project = Project(tmp_path)
    PeerGuest.project = project
    PeerGuest.server = None
    PeerGuest.receipt = PeerGuest.history = PeerGuest.fail = ""
    PeerGuest.journal = PeerGuest.audit = None
    PeerGuest.failInstall = False
    PeerGuest.calls = []
    PeerGuest.peerCalls = []
    cloud = SelectedCloud(project)

    assert RunVpnProject(project, "deploy", allowMutation=True, scopeConfirm="example-folder", provider=cloud, guestFactory=PeerGuest).status == "complete"
    PeerGuest.peerCalls.clear()

    return project, cloud


def Desired(project: SelectedVpnProject, *, revoke: bool = False) -> SelectedVpnProject:
    """Change only the WireGuard phone membership while leaving its shared device declaration and other protocols alone."""

    members = VpnProtocolSelection("wireguard", ("laptop",) if revoke else ("laptop", "phone"),
        (("laptop", "10.67.0.2"),) if revoke else (("laptop", "10.67.0.2"), ("phone", "10.67.0.9")))
    devices = project.vpn.devices if any(device.deviceId == "phone" for device in project.vpn.devices) else (*project.vpn.devices, VpnDevice("phone"))

    return replace(project, vpn=replace(project.vpn, devices=devices), protocolSelections=tuple(
        members if item.protocol == "wireguard" else item for item in project.protocolSelections))


def Run(project: SelectedVpnProject, cloud: SelectedCloud, action: str, *, change: str = "enroll", **options: Any) -> Any:
    """Call the real public peer API using only model cloud/SSH boundaries."""

    return RunVpnPeer(project, action, change, "phone", provider=cloud, guestFactory=PeerGuest, **options)


def Apply(project: SelectedVpnProject, cloud: SelectedCloud, *, change: str = "enroll") -> Any:
    """Use a freshly observed plan and echo its exact baseline/expiry before mutation."""

    plan = Run(project, cloud, "plan", change=change)

    return Run(project, cloud, change, change=change, allowMutation=True, scopeConfirm="example-folder",
               expectedBaseline=plan.baselineSha256, planExpiresAt=plan.planExpiresAt)


@pytest.mark.parametrize("action,overrides", [
    ("enroll", {}), ("enroll", {"allowMutation": True}), ("enroll", {"allowMutation": True, "scopeConfirm": "foreign"}),
    ("enroll", {"allowMutation": True, "scopeConfirm": "example-folder", "expectedBaseline": "a" * 64, "planExpiresAt": 0}),
    ("status", {"allowMutation": True}), ("plan", {"planExpiresAt": 1}), ("recover", {"allowMutation": True}),
    ("enroll", {"allowMutation": 1}), ("plan", {"protocol": "amneziawg"}), ("plan", {"protocol": "vless-reality"}),
])
def test_PeerConsentAndSupportedScopeAreCheckedBeforeAnyPrivateIo(action: str, overrides: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """No invalid action can touch coordination files, retained keys, a provider or an SSH channel."""

    project = ParseSelectedProject(Path("fixture-unopened-project"), Configuration(), PUBLIC_KEY)

    def Forbidden(*arguments: object, **options: object) -> Any:
        """Fail if invalid input crosses the first private filesystem boundary."""

        raise AssertionError("Invalid peer consent reached project locking")

    monkeypatch.setattr(revisions, "ProjectLock", Forbidden)

    with pytest.raises(VpnError):
        RunVpnPeer(project, action, "enroll", "phone", **overrides)


@POSIX
def test_PublicEnrollmentRetryRevocationAndLifecycleUseEffectiveRevisionWithoutCloudChanges(deployment: tuple[SelectedVpnProject, SelectedCloud]) -> None:
    """Preserve all original keys/exports/resources while changing one peer and retaining correct status/retry behavior."""

    project, cloud = deployment
    original = Snapshot(project.Artifacts)
    resources, created = dict(cloud.resources), list(cloud.created)
    updated = Desired(project)
    before = Snapshot(project.root)
    plan = Run(updated, cloud, "plan")

    assert Snapshot(project.root) == before and plan.baselineSha256 and plan.planExpiresAt > 0
    assert not any(action not in {"status", "history-status"} for action, _, _ in PeerGuest.peerCalls)
    result = Run(updated, cloud, "enroll", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=plan.baselineSha256, planExpiresAt=plan.planExpiresAt)

    assert result.status == "complete" and revisions.Pending(updated) is None
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in original.items())
    assert cloud.resources == resources and list(cloud.created) == created and not cloud.deleted
    before = Snapshot(project.root)
    calls = len(PeerGuest.peerCalls)
    retry = Run(updated, cloud, "enroll", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=plan.baselineSha256, planExpiresAt=plan.planExpiresAt)

    assert retry.status == "complete" and Snapshot(project.root) == before
    assert all(action in {"status", "history-status"} for action, _, _ in PeerGuest.peerCalls[calls:])
    assert PrepareSelectedProject(updated).status == "complete"
    assert RunVpnProject(updated, "status", provider=cloud, guestFactory=PeerGuest).status == "complete"
    assert RunVpnProject(updated, "deploy", allowMutation=True, scopeConfirm="example-folder", provider=cloud, guestFactory=PeerGuest).status == "complete"
    assert cloud.resources == resources and list(cloud.created) == created
    revoked = Desired(updated, revoke=True)

    assert Apply(revoked, cloud, change="revoke").status == "complete"
    assert PeerGuest.server is not None and b"# Device: phone" not in next(item.content for item in PeerGuest.server.files if item.name == "server.conf")
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in original.items())
    assert revisions.LoadRevisions(revoked).recordCount == 2


@POSIX
@pytest.mark.parametrize("failure", ["before", "prefix", "published", "response"])
def test_LostPeerResponseRequiresExplicitRecoveryAndNeverRegeneratesPreparedKeys(
    deployment: tuple[SelectedVpnProject, SelectedCloud], failure: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A local journal distinguishes a rolled-back prefix from a durable guest commit despite an unknown SSH result."""

    project, cloud = deployment
    updated = Desired(project)
    generated: list[str] = []
    generate = controller._PrivateKey

    def Generate() -> str:
        """Count exactly one new device key without changing the cryptographic generator."""

        generated.append("peer")

        return generate()

    monkeypatch.setattr(controller, "_PrivateKey", Generate)
    PeerGuest.fail = failure

    with pytest.raises(VpnError, match="Synthetic"):
        Apply(updated, cloud)

    assert generated == ["peer"] and revisions.Pending(updated) is not None
    status = Run(updated, cloud, "status")

    assert status.recoveryRequired and status.baselineSha256 and status.ExitCode() != 0
    before = len(PeerGuest.peerCalls)

    with pytest.raises(VpnError, match="exact retained"):
        Run(updated, cloud, "recover", allowMutation=True, scopeConfirm="example-folder", expectedBaseline="f" * 64)

    assert len(PeerGuest.peerCalls) == before

    for action in ("prepare", "deploy", "status", "recover"):
        with pytest.raises(VpnError, match="peer"):
            RunVpnProject(updated, action, provider=cloud, guestFactory=PeerGuest,
                          **({} if action in {"prepare", "status"} else {"allowMutation": True, "scopeConfirm": "example-folder"}))

    result = Run(updated, cloud, "recover", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=status.baselineSha256)

    assert result.status == "complete" and generated == ["peer"] and revisions.Pending(updated) is None

    if failure in {"before", "prefix"}:
        assert "not-applied" in result.details
        assert Apply(updated, cloud).status == "complete" and generated == ["peer"], "Reuse a complete identical rolled-back candidate"

    else:
        assert "committed" in result.details

    assert RunVpnProject(updated, "status", provider=cloud, guestFactory=PeerGuest).status == "complete"


@POSIX
def test_RecoveryFinalizesAnAlreadyAdvancedLocalHeadWithoutReplayOrKeyRotation(
    deployment: tuple[SelectedVpnProject, SelectedCloud], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Failure retiring the journal after head publication cannot roll a committed peer back."""

    project, cloud = deployment
    updated = Desired(project)
    publish = revisions.AtomicRecord

    def Interrupt(current: SelectedVpnProject, filename: str, data: dict[str, Any] | None) -> None:
        """Keep the actual committed head but simulate an unacknowledged journal cleanup."""

        if filename == "wireguard-pending.json" and data is None:
            raise OSError("Synthetic pending retirement failure")

        publish(current, filename, data)

    monkeypatch.setattr(revisions, "AtomicRecord", Interrupt)

    with pytest.raises(OSError):
        Apply(updated, cloud)

    before = PeerGuest.receipt, PeerGuest.history
    monkeypatch.setattr(revisions, "AtomicRecord", publish)
    status = Run(updated, cloud, "status")
    result = Run(updated, cloud, "recover", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=status.baselineSha256)

    assert result.status == "complete" and (PeerGuest.receipt, PeerGuest.history) == before
    assert revisions.LoadRevisions(updated).recordCount == 1 and revisions.Pending(updated) is None


@POSIX
@pytest.mark.parametrize("case", ["expired", "future", "baseline", "history"])
def test_ChangedOrExpiredPlanFailsBeforeGeneratingKeysOrWritingIntent(
    deployment: tuple[SelectedVpnProject, SelectedCloud], case: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plan cannot survive changed guest history or be extended by editing only its expiration argument."""

    project, cloud = deployment
    updated = Desired(project)
    monkeypatch.setattr(controller.time, "time", lambda: 100000)
    plan = Run(updated, cloud, "plan")
    before = Snapshot(project.root)

    def Forbidden() -> str:
        """Refuse any credential generator call before exact preconditions are satisfied."""

        raise AssertionError("Invalid peer plan generated a key")

    monkeypatch.setattr(controller, "_PrivateKey", Forbidden)

    if case == "expired":
        monkeypatch.setattr(controller.time, "time", lambda: plan.planExpiresAt)

    elif case == "history":
        PeerGuest.history = "e" * 64

    with pytest.raises(VpnError):
        Run(updated, cloud, "enroll", allowMutation=True, scopeConfirm="example-folder",
            expectedBaseline="f" * 64 if case == "baseline" else plan.baselineSha256,
            planExpiresAt=plan.planExpiresAt + 1 if case == "future" else plan.planExpiresAt)

    assert Snapshot(project.root) == before and revisions.Pending(project) is None


@POSIX
def test_CloudDriftDuringStagingKeepsOneRetainedRequestAndPreventsRemoteApply(
    deployment: tuple[SelectedVpnProject, SelectedCloud], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-observe ownership and attachments after local staging instead of applying an obsolete cloud plan."""

    project, cloud = deployment
    updated = Desired(project)
    plan = Run(updated, cloud, "plan")
    connection = controller.Connection
    count = 0

    def Connect(*arguments: Any, **options: Any) -> Any:
        """Introduce actual model attachment drift only at the post-staging observation."""

        nonlocal count
        count += 1

        if count == 2:
            cloud.groups = ("foreign-firewall",)

        return connection(*arguments, **options)

    monkeypatch.setattr(controller, "Connection", Connect)

    with pytest.raises(ValueError):
        Run(updated, cloud, "enroll", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=plan.baselineSha256, planExpiresAt=plan.planExpiresAt)

    assert revisions.Pending(project) is not None and not any(action == "apply" for action, _, _ in PeerGuest.peerCalls)
    cloud.groups = ("id-firewall",)
    status = Run(updated, cloud, "status")

    assert Run(updated, cloud, "recover", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=status.baselineSha256).status == "complete"


@POSIX
def test_WholeStackDestroyAfterPeerCommitDoesNotNeedClientOrAdministrationPrivateKeys(deployment: tuple[SelectedVpnProject, SelectedCloud]) -> None:
    """Cleanup verifies frozen cloud ownership/nonsecret revisions and never opens a guest channel after key loss."""

    project, cloud = deployment
    updated = Desired(project)
    Apply(updated, cloud)
    state = revisions.LoadRevisions(updated)
    assert state.activeRecord is not None
    (project.Artifacts / ("server-" + state.activeRecord["request_name"]) / "material.json").unlink()
    (project.root / "admin-key").unlink()
    before = len(PeerGuest.peerCalls)

    assert RunVpnProject(updated, "destroy", allowMutation=True, scopeConfirm="example-folder", provider=cloud, guestFactory=PeerGuest).status == "complete"
    assert not cloud.resources and len(PeerGuest.peerCalls) == before


@POSIX
def test_PublicCliPrintsTheExactPlanAndDispatchesEnrollmentAndRecovery(
    deployment: tuple[SelectedVpnProject, SelectedCloud], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Exercise the real argparse/API boundary while all provider/SSH effects remain in model objects."""

    project, cloud = deployment
    updated = Desired(project)
    monkeypatch.setattr(projects, "LoadVpnProject", lambda directory: updated)
    monkeypatch.setattr(peers, "RunVpnPeer", partial(RunVpnPeer, provider=cloud, guestFactory=PeerGuest))
    base = ["--project", str(project.root), "--protocol", "wireguard", "--device", "phone", "--format", "json"]

    assert Main(["vpn", "peer", "plan", *base, "--change", "enroll"]) == 0
    plan = json.loads(capsys.readouterr().out)
    PeerGuest.fail = "response"

    assert Main(["vpn", "peer", "enroll", *base, "--allow-mutation", "--scope-confirm", "example-folder", "--expected-baseline-sha256", plan["baseline_sha256"],
                 "--plan-expires-at", str(plan["plan_expires_at"])]) == 2
    capsys.readouterr()
    assert Main(["vpn", "peer", "status", *base, "--change", "enroll"]) == 1
    status = json.loads(capsys.readouterr().out)

    assert Main(["vpn", "peer", "recover", *base, "--change", "enroll", "--allow-mutation", "--scope-confirm", "example-folder",
                 "--expected-baseline-sha256", status["baseline_sha256"]]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


@POSIX
@pytest.mark.parametrize("absent", [False, True])
def test_RestoringOldControllerFilesCannotAdoptARepeatedGuestConfiguration(deployment: tuple[SelectedVpnProject, SelectedCloud], absent: bool) -> None:
    """An ABA cycle retains changed guest history even after all local overlay files are lost."""

    project, cloud = deployment
    updated = Desired(project)
    Apply(updated, cloud)
    revoked = Desired(updated, revoke=True)
    Apply(revoked, cloud, change="revoke")
    assert PeerGuest.history != revisions.InitialHistory(project)
    (project.root / "wireguard-head.json").unlink()

    for path in project.Artifacts.iterdir():
        if path.name.startswith(("server-gateway-wp-", "server-gateway-wc-")):
            assert path.parent == project.Artifacts
            shutil.rmtree(path)

    if absent:
        PeerGuest.server = None

    PeerGuest.calls.clear()
    created = list(cloud.created)

    with pytest.raises(VpnError, match="history"):
        RunVpnProject(revoked, "deploy", allowMutation=True, scopeConfirm="example-folder", provider=cloud, guestFactory=PeerGuest)

    assert not any(action == "install" for action, _ in PeerGuest.calls)
    assert list(cloud.created) == created and not cloud.deleted


@POSIX
@pytest.mark.parametrize("case", ["mtu", "address", "dns", "vless"])
def test_UnsupportedIntentChangesFailBeforeAProviderOrSshConnection(
    deployment: tuple[SelectedVpnProject, SelectedCloud], case: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Peer enrollment cannot carry an unrelated route/runtime/listener/device-address change with it."""

    project, cloud = deployment
    updated = Desired(project)

    if case == "mtu":
        assert updated.wireguard is not None
        updated = replace(updated, wireguard=replace(updated.wireguard, mtu=1200))

    elif case == "address":
        selected = VpnProtocolSelection("wireguard", ("laptop", "phone"), (("laptop", "10.67.0.4"), ("phone", "10.67.0.9")))
        updated = replace(updated, protocolSelections=tuple(selected if item.protocol == "wireguard" else item for item in updated.protocolSelections))

    elif case == "dns":
        updated = replace(updated, vpn=replace(updated.vpn, routes=replace(updated.vpn.routes, dnsServers=("8.8.8.8",))))

    else:
        assert updated.vless is not None
        updated = replace(updated, vless=replace(updated.vless, serverName="www.example.com"))

    def Forbidden(*arguments: Any, **options: Any) -> Any:
        """Refuse any provider or SSH observation for an unsupported peer plan."""

        raise AssertionError("Invalid peer intent reached external access")

    monkeypatch.setattr(controller, "Connection", Forbidden)

    with pytest.raises(VpnError):
        Run(updated, cloud, "plan")


@POSIX
@pytest.mark.parametrize("changed", ["locator", "host-pin", "endpoint"])
def test_PendingRecoveryRefusesAnInternallyValidReplacementOfTheOriginalCloudOrTrustProof(
    deployment: tuple[SelectedVpnProject, SelectedCloud], monkeypatch: pytest.MonkeyPatch, changed: str,
) -> None:
    """Exact scope and restored guest receipts do not authorize replaying recovery against a different target graph."""

    project, cloud = deployment
    updated = Desired(project)
    PeerGuest.fail = "response"

    with pytest.raises(VpnError):
        Apply(updated, cloud)

    status = Run(updated, cloud, "status")

    if changed == "locator":
        state = LoadState(project.root / "state.json", project.vpn.identity)
        assert state is not None
        resource = cloud.resources["instance"]
        cloud.resources["instance"] = replace(resource, reference=replace(resource.reference, resourceId="replacement-instance"))
        SaveState(project.root / "state.json", replace(state, resources=tuple(
            replace(item, resourceId="replacement-instance") if item.logicalId == "instance" else item for item in state.resources)), project.vpn.identity)

    else:
        key = PUBLIC_KEY
        endpoint = "203.0.113.20"

        if changed == "host-pin":
            key = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"r" * 32).decode()
            monkeypatch.setattr(cloud, "ReadHostKey", lambda instance, fingerprint: key)

        else:
            endpoint = cloud.publicAddress = "203.0.113.21"

            for logicalId in ("instance", "address"):
                cloud.resources[logicalId] = replace(cloud.resources[logicalId], publicAddresses=(endpoint,))

        name = project.vpn.identity.stack + "-trust"
        assert RemoveArtifactBundle(project.Artifacts, project.vpn.identity, kind="server", name=name)
        WriteArtifactBundle(project.Artifacts, ArtifactBundle(project.vpn.identity, "server", name, (
            Artifact("known-hosts.txt", f"{endpoint} {key}\n".encode(), False),)))
        # Connection still validates the actual owned graph/IAM pin; this test model accepts its changed endpoint/key.
        monkeypatch.setattr(PeerGuest, "__init__", lambda self, *arguments: None)

    before = len(PeerGuest.peerCalls)

    with pytest.raises(VpnError, match="original plan"):
        Run(updated, cloud, "recover", allowMutation=True, scopeConfirm="example-folder", expectedBaseline=status.baselineSha256)

    assert not any(action == "recover" for action, _, _ in PeerGuest.peerCalls[before:])
    assert revisions.Pending(updated) is not None


@POSIX
def test_InstallGuardRejectsAuditChangedAfterTheReadOnlyPreflight(
    deployment: tuple[SelectedVpnProject, SelectedCloud], monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The expected history must reach the mutating installer, not expire when the observation RPC unlocks."""

    project, cloud = deployment
    PeerGuest.server = None
    PeerGuest.history = revisions.InitialHistory(project)
    operation = PeerGuest.WireGuardPeerOperation

    def ObserveThenChange(self: PeerGuest, bundle: ArtifactBundle, action: str, change: str, deviceId: str, **options: Any) -> dict[str, object]:
        """Model another controller completing revocation/removal in the inter-RPC gap."""

        facts = operation(self, bundle, action, change, deviceId, **options)

        if action == "history-status":
            PeerGuest.history = "e" * 64

        return facts

    monkeypatch.setattr(PeerGuest, "WireGuardPeerOperation", ObserveThenChange)
    PeerGuest.calls.clear()

    with pytest.raises(VpnError, match="install lock"):
        RunVpnProject(project, "deploy", allowMutation=True, scopeConfirm="example-folder", provider=cloud, guestFactory=PeerGuest)

    assert PeerGuest.server is None and not any(action == "install" for action, _ in PeerGuest.calls)
