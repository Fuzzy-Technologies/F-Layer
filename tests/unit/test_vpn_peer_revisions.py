"""Prove private controller revision publication without cloud, SSH or desktop network operations."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project_selection import PUBLIC_KEY, Configuration
from test_vpn_project_v2 import Project, Snapshot

from flayer import _vpn_revisions as revisions
from flayer._vpn_creation import BundleDigest, ProtocolPin, _Json
from flayer.core.contracts import _WireDict
from flayer.guest import ReadPrivate
from flayer.profiles.artifacts import Artifact, ArtifactBundle, WriteArtifactBundle
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError
from flayer.profiles.wireguard import (
    DecodeWireGuardMaterial,
    EncodeWireGuardMaterial,
    PrepareWireGuard,
    PrepareWireGuardPeerEnrollment,
    PrepareWireGuardPeerRevocation,
    WireGuardPeer,
    _PrivateKey,
)
from flayer.vpn_project import SelectedVpnProject
from flayer.vpn_project_v2 import ParseSelectedProject, PrepareSelectedProject
from flayer.vpn_selection import VpnProtocolSelection

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private revision files require POSIX; no WSL or desktop networking is started")


def test_InitialAndCommittedHistoryMatchTheGuestCanonicalDomainAndAreOwnerBound() -> None:
    """Hash only complete public ownership and exact canonical audit fields, including the parent history."""

    project = ParseSelectedProject(Path("fixture-project"), Configuration(), PUBLIC_KEY)
    owner = revisions.Digest(json.dumps(_WireDict(project.vpn.identity), sort_keys=True, separators=(",", ":")).encode())
    initial = revisions.InitialHistory(project)

    assert initial == revisions.Digest(_Json({"domain": "f-layer/wireguard/peer-history/v1", "owner": owner}))
    expected = {"schema_version": 1, "owner": owner, "action": "enroll", "device_id": "phone", "previous_receipt_sha256": "a" * 64,
                "receipt_sha256": "b" * 64, "deployment_sha256": "c" * 64, "previous_history_sha256": initial}

    assert revisions.CommittedHistory(project, "enroll", "phone", "a" * 64, "b" * 64, "c" * 64, initial) == revisions.Digest(_Json(expected))
    changed = replace(project, vpn=replace(project.vpn, identity=replace(project.vpn.identity, ownerId="another-owner")))

    assert revisions.InitialHistory(changed) != initial
    assert revisions.CommittedHistory(project, "enroll", "phone", "a" * 64, "b" * 64, "c" * 64, "d" * 64) != revisions.Digest(_Json(expected))


def Change(
    project: SelectedVpnProject, state: revisions.RevisionState, operationId: str = "0" * 16, *, change: str = "enroll",
) -> tuple[SelectedVpnProject, dict[str, Any], ArtifactBundle, ArtifactBundle, ProtocolPin, dict[str, object]]:
    """Prepare synthetic one-peer bytes and model only independently hashed guest receipt/history facts."""

    oldPin = next(pin for pin in state.pins if pin.protocol == "wireguard")
    oldServer = revisions.ReadEffectiveBundle(project, state, oldPin)
    oldMaterial = revisions.ReadEffectiveBundle(project, state, oldPin, material=True)
    material = DecodeWireGuardMaterial(next(item.content for item in oldMaterial.files if item.name == "material.json"))
    profile = project.ProtocolProfile("wireguard")
    assert project.wireguard is not None

    if change == "enroll":
        profile, material = PrepareWireGuardPeerEnrollment(profile, project.wireguard, material, VpnDevice("phone", "10.67.0.9"),
            WireGuardPeer("phone", _PrivateKey(), base64.b64encode(secrets.token_bytes(32)).decode()))

    else:
        profile, material = PrepareWireGuardPeerRevocation(profile, project.wireguard, material, "phone")

    devices = project.vpn.devices

    if not any(device.deviceId == "phone" for device in devices):
        devices += (VpnDevice("phone"),)

    membership = VpnProtocolSelection("wireguard", tuple(device.deviceId for device in profile.devices),
                                      tuple((device.deviceId, str(device.ipv4Address)) for device in profile.devices))
    updated = replace(project, vpn=replace(project.vpn, devices=devices), protocolSelections=tuple(
        membership if item.protocol == "wireguard" else item for item in project.protocolSelections))
    server = PrepareWireGuard(profile, VpnEndpoint("203.0.113.20", 51821), project.wireguard, material).serverBundle
    credentials = ArtifactBundle(project.vpn.identity, "server", oldMaterial.name, (
        Artifact("material.json", EncodeWireGuardMaterial(material)), Artifact("intent.sha256", (updated.TransportFingerprint("wireguard") + "\n").encode(), False)))
    pin = ProtocolPin("wireguard", updated.TransportFingerprint("wireguard"), BundleDigest(credentials), BundleDigest(server))
    previous = state.receipt or revisions.Digest(b"fixture-runtime" + next(item.content for item in oldServer.files if item.name == "deployment.json"))
    pending = {"schema_version": 1, "identity": _WireDict(project.vpn.identity), "creation_sha256": BundleDigest(state.baseline.bundle),
               "parent": state.head, "previous_head_sha256": state.headDigest, "previous_pin": _WireDict(oldPin),
               "desired_fingerprint": pin.intentFingerprint, "request_name": project.vpn.identity.stack + "-wp-" + operationId,
               "request_sha256": "", "change": change, "device_id": "phone", "previous_receipt_sha256": previous,
               "previous_history_sha256": state.history, "baseline_sha256": revisions.Digest(operationId.encode()), "plan_expires_at": 100000}
    descriptor = next(item.content for item in server.files if item.name == "deployment.json")
    receipt, deployment = revisions.Digest(b"fixture-runtime" + descriptor), revisions.Digest(descriptor)
    facts = {"status": "active", "is_desired": True, "receipt_sha256": receipt, "deployment_sha256": deployment,
             "history_sha256": revisions.CommittedHistory(project, change, "phone", previous, receipt, deployment, state.history)}

    return updated, pending, credentials, server, pin, facts


def Stage(project: SelectedVpnProject, pending: dict[str, Any], material: ArtifactBundle, server: ArtifactBundle) -> dict[str, Any]:
    """Persist the pre-remote journal before complete request bytes and their final pinned digest."""

    revisions.AtomicRecord(project, "wireguard-pending.json", pending)
    digest = revisions.PublishRequest(project, pending, material, server)
    pending = {**pending, "request_sha256": digest}
    revisions.AtomicRecord(project, "wireguard-pending.json", pending)

    return pending


@POSIX
def test_CommitResolvesOnlyTheNewWireGuardProjectionAndPreservesEveryOriginalBundle(tmp_path: Path) -> None:
    """The original six specs/bootstrap, unrelated keys and all prepared bundles remain byte-identical."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    original = Snapshot(project.Artifacts)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)

    with revisions.ProjectLock(project, readOnly=False):
        pending = Stage(project, pending, material, server)
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")

    active = revisions.LoadRevisions(updated)
    active.ValidateCurrent(updated)

    assert active.baseline == state.baseline and active.receipt == facts["receipt_sha256"] and active.history == facts["history_sha256"]
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in original.items())
    assert revisions.Pending(updated) is None and active.headDigest != state.headDigest
    assert revisions.ReadEffectiveBundle(updated, active, pin) == server
    assert revisions.ReadEffectiveBundle(updated, active, pin, material=True) == material
    assert tuple(item for item in active.pins if item.protocol != "wireguard") == tuple(item for item in state.pins if item.protocol != "wireguard")

    with pytest.raises(VpnError, match="explicit peer/protocol"):
        active.ValidateCurrent(project)


@POSIX
def test_RepeatedEnrollmentRevocationCyclesKeepBothHistoryChainsDistinct(tmp_path: Path) -> None:
    """Identical restored configuration bytes cannot restore a previous controller or guest history head."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    originalPin = next(pin for pin in revisions.LoadRevisions(project).pins if pin.protocol == "wireguard")
    heads: list[str] = []
    histories: list[str] = []

    for index, change in enumerate(("enroll", "revoke", "enroll", "revoke")):
        state = revisions.LoadRevisions(project)
        updated, pending, material, server, pin, facts = Change(project, state, f"{index:016x}", change=change)
        pending = Stage(project, pending, material, server)
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
        project = updated
        state = revisions.LoadRevisions(project)
        heads.append(state.headDigest)
        histories.append(state.history)

    assert len(set(heads)) == len(set(histories)) == 4
    assert next(pin for pin in state.pins if pin.protocol == "wireguard") == originalPin


@POSIX
@pytest.mark.parametrize("boundary", ["before-head", "after-head", "after-unlink"])
def test_ExplicitCommitRetryReconcilesEachDurablePublicationBoundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str) -> None:
    """An exact staged commit can finish after its record, pointer or journal removal was already persisted."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)
    publish = revisions.AtomicRecord
    failed = False

    def Interrupt(current: SelectedVpnProject, filename: str, data: dict[str, Any] | None) -> None:
        """Inject one failure around a real durable record operation."""

        nonlocal failed

        if not failed and ((boundary == "before-head" and filename == "wireguard-head.json")
                           or (boundary == "after-head" and filename == "wireguard-pending.json")):
            failed = True

            raise OSError("Synthetic controller publication failure")

        publish(current, filename, data)

        if not failed and boundary == "after-unlink" and filename == "wireguard-pending.json":
            failed = True

            raise OSError("Synthetic directory sync failure")

    monkeypatch.setattr(revisions, "AtomicRecord", Interrupt)

    with pytest.raises(OSError):
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")

    monkeypatch.setattr(revisions, "AtomicRecord", publish)
    recovered = revisions.LoadRevisions(updated)
    revisions.Commit(updated, recovered, pending, pin, facts, outcome="committed")
    assert revisions.Pending(updated) is None and revisions.LoadRevisions(updated).receipt == facts["receipt_sha256"]


@POSIX
@pytest.mark.parametrize("prepared", [True, False])
def test_NotAppliedRecoveryRetainsOldActivePinsAndArchivesAnyPreparedCredentials(tmp_path: Path, prepared: bool) -> None:
    """A submitted cancellation consumes guest authority while retaining the receipt, active projection and old keys."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    _, pending, material, server, pin, _ = Change(project, state)
    original = revisions.ReadEffectiveBundle(project, state, state.pins[-1], material=True)

    if prepared:
        pending = Stage(project, pending, material, server)

    else:
        revisions.AtomicRecord(project, "wireguard-pending.json", pending)
        pin = state.pins[-1]

    oldServer = revisions.ReadEffectiveBundle(project, state, state.pins[-1])
    facts = {"status": "active", "is_desired": False, "receipt_sha256": pending["previous_receipt_sha256"],
             "history_sha256": pending["previous_history_sha256"], "deployment_sha256": revisions.Digest(
                 next(item.content for item in oldServer.files if item.name == "deployment.json"))}

    if prepared:
        before = Snapshot(project.root)

        with pytest.raises(VpnError, match="exact peer completion"):
            revisions.Commit(project, state, pending, pin, facts, outcome="not-applied")

        assert Snapshot(project.root) == before, "Unfenced completion cannot publish any local evidence"
        facts["history_sha256"] = revisions.CommittedHistory(project, pending["change"], pending["device_id"], pending["previous_receipt_sha256"],
            pending["previous_receipt_sha256"], str(facts["deployment_sha256"]), pending["previous_history_sha256"])

    revisions.Commit(project, state, pending, pin, facts, outcome="not-applied")
    active = revisions.LoadRevisions(project)

    assert active.pins == state.pins and active.history == facts["history_sha256"] and active.headDigest != state.headDigest
    assert (active.history != state.history) is prepared
    assert revisions.ReadEffectiveBundle(project, active, active.pins[-1], material=True) == original
    assert active.lastRecord is not None and active.lastRecord["outcome"] == "not-applied" and active.activeRecord is None
    assert active.lastRecord["schema_version"] == 2
    revisions.Commit(project, active, pending, pin, facts, outcome="not-applied")
    assert revisions.LoadRevisions(project).head == active.head


@POSIX
@pytest.mark.parametrize("outcome,prepared", [("committed", True), ("not-applied", True), ("not-applied", False)])
@pytest.mark.parametrize("boundary", ["record", "head", "retired"])
def test_CompletedVersionOneEvidenceRemainsReadableWithoutRewritingItsHistory(
    tmp_path: Path, outcome: str, prepared: bool, boundary: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retained historical records keep their original immutable format; new cancellations require the new proof contract."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)

    if prepared:
        pending = Stage(project, pending, material, server)

    else:
        revisions.AtomicRecord(project, "wireguard-pending.json", pending)
        pin = state.pins[-1]

    record = {**pending, "desired_pin": _WireDict(pin), "receipt_sha256": facts["receipt_sha256"],
              "history_sha256": facts["history_sha256"], "deployment_sha256": facts["deployment_sha256"], "outcome": outcome}

    if outcome == "not-applied":
        old = revisions.ReadEffectiveBundle(project, state, state.pins[-1])
        record.update(receipt_sha256=pending["previous_receipt_sha256"], history_sha256=pending["previous_history_sha256"],
                      deployment_sha256=revisions.Digest(next(item.content for item in old.files if item.name == "deployment.json")))
        facts.update(receipt_sha256=record["receipt_sha256"], history_sha256=record["history_sha256"], deployment_sha256=record["deployment_sha256"])

    name = project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1]
    bundle = ArtifactBundle(project.vpn.identity, "server", name, (Artifact("record.json", _Json(record), False),))
    WriteArtifactBundle(project.Artifacts, bundle)
    pointer = {"name": name, "sha256": BundleDigest(bundle)}

    if boundary != "record":
        revisions.AtomicRecord(project, "wireguard-head.json", pointer)

    if boundary == "retired":
        revisions.AtomicRecord(project, "wireguard-pending.json", None)

    before = Snapshot(project.root)
    active = revisions.LoadRevisions(project)

    assert active.history == (record["history_sha256"] if boundary != "record" else state.history)
    assert active.lastRecord == (record if boundary != "record" else None)
    assert active.pins[-1] == (pin if outcome == "committed" and boundary != "record" else state.pins[-1])
    assert Snapshot(project.root) == before

    if boundary != "retired" and (outcome == "committed" or not prepared):
        monkeypatch.setattr(revisions, "MAX_PEER_REVISIONS", active.recordCount + int(boundary == "record"))
        revisions.Commit(project, active, pending, pin, facts, outcome=outcome)
        assert revisions.Pending(project) is None and revisions.LoadRevisions(project).head == pointer
        assert revisions.LoadRevisions(project).lastRecord == record

    elif boundary != "retired":
        from flayer import _vpn_peer_controller as controller

        def Forbidden(*args: Any, **options: Any) -> Any:
            """The ambiguous legacy upgrade must be rejected before any provider or guest connection."""

            raise AssertionError("Legacy unfenced completion reached external observation")

        monkeypatch.setattr(controller, "Connection", Forbidden)

        with pytest.raises(VpnError, match="partially retired legacy"):
            controller._Recover(updated, active, pending, "recover", "enroll", "phone", revisions.Digest(_Json(pending)), None, Forbidden, server)

        assert Snapshot(project.root) == before and revisions.Pending(project) == pending


@POSIX
@pytest.mark.parametrize("fault", ["device", "owner", "extra-file"])
def test_UnheadedCompletionCannotAdoptUnrelatedOrUnboundedEvidence(tmp_path: Path, fault: str) -> None:
    """A matching immutable directory name alone cannot influence upgrade preflight or idempotent recovery."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    _, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)
    record = {**pending, "desired_pin": _WireDict(pin), "receipt_sha256": facts["receipt_sha256"],
              "history_sha256": facts["history_sha256"], "deployment_sha256": facts["deployment_sha256"], "outcome": "committed"}

    if fault == "device":
        record["device_id"] = "other"
        record["history_sha256"] = revisions.CommittedHistory(project, "enroll", "other", pending["previous_receipt_sha256"],
            str(facts["receipt_sha256"]), str(facts["deployment_sha256"]), pending["previous_history_sha256"])

    elif fault == "owner":
        record["identity"] = {**record["identity"], "owner_id": "another-owner"}

    name = project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1]
    bundle = ArtifactBundle(project.vpn.identity, "server", name, (Artifact("record.json", _Json(record), False),))
    directory = WriteArtifactBundle(project.Artifacts, bundle)

    if fault == "extra-file":
        (directory / "unexpected").write_bytes(b"unrelated")

    before = Snapshot(project.root)

    with pytest.raises(VpnError):
        revisions.ExistingCompletion(project, pending)

    assert Snapshot(project.root) == before and revisions.Pending(project) == pending


@POSIX
def test_FullStagingIsReusedAfterDigestPublicationFailureWithoutGeneratingAnotherPeer(tmp_path: Path) -> None:
    """The original pre-remote journal and immutable manifest prove the one existing candidate's bytes."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    _, pending, material, server, _, _ = Change(project, state)
    revisions.AtomicRecord(project, "wireguard-pending.json", pending)
    digest = revisions.PublishRequest(project, pending, material, server)
    before = Snapshot(project.Artifacts)

    assert revisions.RecoverStaging(project, pending) == digest
    assert Snapshot(project.Artifacts) == before


@POSIX
@pytest.mark.parametrize("case", ["missing-head", "missing-parent", "request-drift", "unknown-revision", "extra-file", "head-symlink", "head-hardlink", "pending-foreign", "pending-parent", "pending-history"])
def test_MissingForeignOrDriftedRevisionProofFailsClosed(tmp_path: Path, case: str) -> None:
    """No local overlay or unexplained request can be silently adopted or used as active credentials."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)

    if case.startswith("pending-"):
        key = {"pending-foreign": "identity", "pending-parent": "previous_head_sha256", "pending-history": "previous_history_sha256"}[case]
        pending[key] = {} if key == "identity" else "f" * 64
        revisions.AtomicRecord(project, "wireguard-pending.json", pending)

    else:
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
        head = project.root / "wireguard-head.json"

        if case == "missing-head":
            head.unlink()

        elif case == "head-symlink":
            head.rename(project.root / "retained-head.json")
            head.symlink_to(project.root / "retained-head.json")

        elif case == "head-hardlink":
            os.link(head, project.root / "retained-head.json")

        elif case == "request-drift":
            (project.Artifacts / ("server-" + pending["request_name"]) / "material.json").write_bytes(b"changed-private-fixture")

        elif case == "unknown-revision":
            (project.Artifacts / "server-gateway-wp-ffffffffffffffff").mkdir(mode=0o700)

        elif case == "extra-file":
            commit = next(project.Artifacts.glob("server-gateway-wc-*"))
            (commit / "unexplained.txt").write_text("fixture", encoding="utf-8")

        elif case == "missing-parent":
            next(project.Artifacts.glob("server-gateway-wc-*"), Path()).rename(project.Artifacts / "retained-commit")

    with pytest.raises(ValueError):
        active = revisions.LoadRevisions(updated)
        revisions.ReadEffectiveBundle(updated, active, next(pin for pin in active.pins if pin.protocol == "wireguard"), material=True)


@POSIX
def test_NonsecretCommitChainRemainsReadableWhenPrivateClientMaterialIsLost(tmp_path: Path) -> None:
    """Whole-cloud cleanup can verify original specs and recorded overlays without recovering device keys."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)
    revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
    (project.Artifacts / ("server-" + pending["request_name"]) / "material.json").unlink()
    active = revisions.LoadRevisions(updated)

    assert active.baseline.plan == state.baseline.plan and active.pins[-1] == pin

    with pytest.raises(ValueError):
        revisions.ReadEffectiveBundle(updated, active, pin, material=True)


@POSIX
def test_ProjectLockSerializesAllHandlesAndReadOnlyObservationCreatesNoFile(tmp_path: Path) -> None:
    """A shared observation and an exclusive mutation cannot pass one another across complete workflows."""

    project = Project(tmp_path)

    with revisions.ProjectLock(project, readOnly=True):
        assert not (project.root / ".vpn-project.lock").exists()

    with revisions.ProjectLock(project, readOnly=False):
        with pytest.raises(VpnError, match="busy"):
            with revisions.ProjectLock(project, readOnly=False):
                pytest.fail("A second mutator acquired the project lock")

        with pytest.raises(VpnError, match="busy"):
            with revisions.ProjectLock(project, readOnly=True):
                pytest.fail("Observation raced past an exclusive project lock")

    with revisions.ProjectLock(project, readOnly=True):
        with revisions.ProjectLock(project, readOnly=True):
            assert ReadPrivate(project.root / ".vpn-project.lock") == b""


@POSIX
@pytest.mark.parametrize("case", ["mode", "content", "symlink", "hardlink", "during-read"])
def test_ProjectLockRejectsUnsafeFilesAndAbsenceRaces(tmp_path: Path, case: str) -> None:
    """Missing-lock fallback discards observations if a concurrent mutator establishes coordination."""

    project = Project(tmp_path)
    path = project.root / ".vpn-project.lock"

    if case == "during-read":
        with pytest.raises(VpnError, match="during observation"):
            with revisions.ProjectLock(project, readOnly=True):
                path.touch(mode=0o600)

        return

    path.touch(mode=0o600)

    if case == "mode":
        path.chmod(0o644)

    elif case == "content":
        path.write_bytes(b"unexpected")

    elif case == "symlink":
        path.rename(project.root / "other-lock")
        path.symlink_to(project.root / "other-lock")

    elif case == "hardlink":
        os.link(path, project.root / "other-lock")

    with pytest.raises(VpnError):
        with revisions.ProjectLock(project, readOnly=False):
            pytest.fail("Unsafe coordination file was accepted")


@POSIX
@pytest.mark.parametrize("field,value", [("status", "peer-recovery-required"), ("is_desired", False),
                                       ("history_sha256", "f" * 64), ("receipt_sha256", "unchanged"), ("deployment_sha256", "f" * 64),
                                       ("receipt_sha256", "not-a-sha"), ("receipt_sha256", {}), ("receipt_sha256", None),
                                       ("history_sha256", "G" * 64), ("history_sha256", []), ("history_sha256", None),
                                       ("deployment_sha256", "bad"), ("deployment_sha256", {}), ("deployment_sha256", None)])
def test_InvalidGuestCompletionNeverAdvancesTheControllerHead(tmp_path: Path, field: str, value: object) -> None:
    """Do not accept a transport acknowledgment or unrelated history as proof of a healthy desired commit."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)
    facts[field] = pending["previous_receipt_sha256"] if value == "unchanged" else value

    if field == "receipt_sha256" and value == "not-a-sha":
        facts["history_sha256"] = revisions.CommittedHistory(project, pending["change"], pending["device_id"], pending["previous_receipt_sha256"],
                                                             "not-a-sha", str(facts["deployment_sha256"]), pending["previous_history_sha256"])
    before = Snapshot(project.root)

    with pytest.raises(VpnError):
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")

    assert Snapshot(project.root) == before and revisions.Pending(project) == pending


@POSIX
def test_RevisionCapacityBlocksNewStagingAndPublicationButAllowsExactCompletedRetry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The writer enforces the loader's bound before a remote attempt or a new immutable head can be committed."""

    monkeypatch.setattr(revisions, "MAX_PEER_REVISIONS", 1)
    project = Project(tmp_path)
    PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, state)
    pending = Stage(project, pending, material, server)
    revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
    state = revisions.LoadRevisions(updated)

    assert state.recordCount == 1
    revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
    _, pending, material, server, _, _ = Change(updated, state, "1" * 16, change="revoke")
    revisions.AtomicRecord(updated, "wireguard-pending.json", pending)
    before = Snapshot(updated.root)

    with pytest.raises(VpnError, match="capacity"):
        revisions.PublishRequest(updated, pending, material, server)

    oldServer = revisions.ReadEffectiveBundle(updated, state, state.pins[-1])
    facts = {"status": "active", "is_desired": True, "receipt_sha256": state.receipt, "history_sha256": state.history,
             "deployment_sha256": revisions.Digest(next(item.content for item in oldServer.files if item.name == "deployment.json"))}

    with pytest.raises(VpnError, match="capacity"):
        revisions.Commit(updated, state, pending, state.pins[-1], facts, outcome="not-applied")

    assert Snapshot(updated.root) == before and revisions.LoadRevisions(updated).recordCount == 1


@POSIX
def test_ReusedTemporaryRecordIsFileSyncedBeforeRenameAfterAnActualSyncFailure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A durable directory entry cannot substitute for retrying the unflushed temporary file's own fsync."""

    project = Project(tmp_path)
    sync, rename = revisions.os.fsync, revisions.os.replace
    events: list[str] = []
    failed = False

    def Sync(descriptor: int) -> None:
        """Fail the first actual regular-file sync after complete bytes have been written."""

        nonlocal failed
        regular = stat.S_ISREG(os.fstat(descriptor).st_mode)
        events.append("file-sync" if regular else "directory-sync")

        if regular and not failed:
            failed = True

            raise OSError("Synthetic temporary file fsync failure")

        sync(descriptor)

    def Rename(source: Path, destination: Path) -> None:
        """Observe publication order while using the actual isolated filesystem rename."""

        events.append("replace")
        rename(source, destination)

    monkeypatch.setattr(revisions.os, "fsync", Sync)
    monkeypatch.setattr(revisions.os, "replace", Rename)
    data = {"fixture": "nonsecret-journal"}

    with pytest.raises(VpnError):
        revisions.AtomicRecord(project, "wireguard-pending.json", data)

    assert ReadPrivate(project.root / ".wireguard-pending.json.new") == _Json(data)
    assert not (project.root / "wireguard-pending.json").exists()
    events.clear()
    revisions.AtomicRecord(project, "wireguard-pending.json", data)

    assert events == ["file-sync", "replace", "directory-sync"]
    assert ReadPrivate(project.root / "wireguard-pending.json") == _Json(data)


@POSIX
def test_ProjectLockPreservesBodyIoFailureInsteadOfReportingLockContention(tmp_path: Path) -> None:
    """An operation's failed durable write must remain distinguishable from failure acquiring coordination."""

    project = Project(tmp_path)

    with pytest.raises(OSError, match="Synthetic operation write failure"):
        with revisions.ProjectLock(project, readOnly=False):
            raise OSError("Synthetic operation write failure")

    with revisions.ProjectLock(project, readOnly=False):
        assert ReadPrivate(project.root / ".vpn-project.lock") == b""
