"""Keep epoch-specific peer heads separate while retaining original cloud identity and immutable request bytes."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_peer_revisions import Change, Stage
from test_vpn_project_selection import PUBLIC_KEY, Configuration
from test_vpn_project_v2 import Project, Snapshot

from flayer import _vpn_revisions as revisions
from flayer._vpn_creation import (
    BundleDigest,
    LoadCreationBaseline,
    ProtocolPin,
    StaticFingerprint,
    _Json,
)
from flayer._vpn_protocol_sources import ProtocolSource
from flayer.guest import ReadPrivate, WritePrivate
from flayer.profiles.artifacts import ArtifactError
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject
from flayer.vpn_project_v2 import ParseSelectedProject, PrepareSelectedProject

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private segments require POSIX; no WSL or desktop network is started")


def Context(project: SelectedVpnProject, genesis: str = "a" * 64) -> revisions.PeerSegment:
    """Build a public synthetic starting projection without creating any private project file."""

    sources = tuple(ProtocolSource(project.vpn.identity, ProtocolPin(item.protocol, "b" * 64, "c" * 64, "d" * 64))
                    for item in project.protocolSelections)

    return revisions.PeerSegment(genesis, sources, tuple(source.pin.protocol for source in sources),
                                 StaticFingerprint(project), "e" * 64, revisions.InitialHistory(project))


@pytest.mark.parametrize("fault", ["genesis", "hash-type", "duplicate", "source-type", "source-owner", "active-type", "unknown-active", "reordered", "missing-receipt", "receipt-type"])
def test_SegmentContextRejectsAmbiguousAuthorityBeforeAnyFileAccess(tmp_path: Path, fault: str) -> None:
    """No caller path, mixed owner, extended model or contradictory active receipt can enter a segment context."""

    project = ParseSelectedProject(tmp_path / "absent", Configuration(), PUBLIC_KEY)
    context = Context(project)
    changes: dict[str, Any] = {}

    if fault == "genesis":
        changes["genesis"] = "../elsewhere"

    elif fault == "hash-type":
        changes["history"] = {"private_key": "suppressed-fixture"}

    elif fault == "duplicate":
        changes["sources"] = (context.sources[0], context.sources[0])

    elif fault == "source-type":
        changes["sources"] = list(context.sources)

    elif fault == "source-owner":
        changes["sources"] = (replace(context.sources[0], identity=replace(project.vpn.identity, ownerId="different-owner")), *context.sources[1:])

    elif fault == "active-type":
        changes["activeProtocols"] = list(context.activeProtocols)

    elif fault == "unknown-active":
        changes["activeProtocols"] = (*context.activeProtocols, "unknown")

    elif fault == "reordered":
        changes["activeProtocols"] = tuple(reversed(context.activeProtocols))

    elif fault == "missing-receipt":
        changes["receipt"] = ""

    else:
        changes["receipt"] = ["e" * 64]

    with pytest.raises(VpnError):
        replace(context, **changes)

    assert not project.root.exists()


def test_SegmentCanRetainConfiguredSourcesWhenEveryTransportIsInactive(tmp_path: Path) -> None:
    """An empty active subset preserves retained material references and a nonempty history fence."""

    project = ParseSelectedProject(tmp_path / "absent", Configuration(), PUBLIC_KEY)
    context = replace(Context(project), activeProtocols=(), receipt="")

    assert context.sources and not context.activeProtocols and context.history == revisions.InitialHistory(project)
    assert not project.root.exists()


def test_ExtendedSegmentAndCredentialBearingHashAreRejected(tmp_path: Path) -> None:
    """Closed authority records cannot accidentally serialize data added by inherited models or scalar dataclasses."""

    project = ParseSelectedProject(tmp_path / "absent", Configuration(), PUBLIC_KEY)
    context = Context(project)

    @dataclass(frozen=True, slots=True)
    class ExtendedSegment(revisions.PeerSegment):
        """Model an unsafe extension without ever persisting its synthetic credential."""

        privateKey: str = "suppressed-fixture"

    @dataclass(frozen=True, eq=False)
    class ExtendedHash(str):
        """Model a string that generic recursive dataclass serialization could mistake for credential metadata."""

        privateKey: str = "suppressed-fixture"

    with pytest.raises(VpnError):
        ExtendedSegment(context.genesis, context.sources, context.activeProtocols, context.staticFingerprint, context.receipt, context.history)

    with pytest.raises(VpnError):
        replace(context, genesis=ExtendedHash("a" * 64))

    assert not project.root.exists()


def Segment(project: SelectedVpnProject, prior: revisions.RevisionState, genesis: str = "a" * 64) -> revisions.PeerSegment:
    """Create only test-private epoch metadata directories, using retained source references for the prior projection."""

    sources = tuple(ProtocolSource(project.vpn.identity, pin, "peer", prior.activeRecord["request_name"], prior.activeRecord["request_sha256"])
                    if pin.protocol == "wireguard" and prior.activeRecord is not None else ProtocolSource(project.vpn.identity, pin)
                    for pin in prior.pins)
    directory = project.root / "protocol-epochs" / genesis
    directory.parent.mkdir(mode=0o700, exist_ok=True)
    directory.mkdir(mode=0o700)

    return revisions.PeerSegment(genesis, sources, tuple(source.pin.protocol for source in sources), StaticFingerprint(project),
                                 prior.receipt or "e" * 64, prior.history)


@POSIX
def test_SeparateSegmentContinuesTheRetainedProjectionWithoutRewritingTheOldHead(tmp_path: Path) -> None:
    """A closed initial segment and a new segment share global immutable bundles but have different head genesis values."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    initial = revisions.LoadRevisions(project)
    project, pending, material, server, pin, facts = Change(project, initial)
    pending = Stage(project, pending, material, server)
    revisions.Commit(project, initial, pending, pin, facts, outcome="committed")
    closed = revisions.LoadRevisions(project)
    oldHead = ReadPrivate(project.root / "wireguard-head.json")
    original = Snapshot(project.Artifacts)
    context = Segment(project, closed)
    state = revisions.LoadPeerSegment(project, closed.baseline, context)

    assert state.head is None and state.headDigest == context.genesis and state.recordCount == 0
    assert state.receipt == closed.receipt and state.history == closed.history
    assert revisions.ReadEffectiveBundle(project, state, pin) == server
    assert revisions.ReadEffectiveBundle(project, state, pin, material=True) == material

    updated, pending, material, server, pin, facts = Change(project, state, "1" * 16, change="revoke")
    revisions.AtomicRecord(updated, "wireguard-pending.json", pending, segment=context)
    digest = revisions.PublishRequest(updated, pending, material, server, segment=context)
    pending = {**pending, "request_sha256": digest}
    revisions.AtomicRecord(updated, "wireguard-pending.json", pending, segment=context)
    revisions.Commit(updated, state, pending, pin, facts, outcome="committed")
    active = revisions.LoadPeerSegment(updated, closed.baseline, context)
    active.ValidateCurrent(updated)
    revisions.Commit(updated, active, pending, pin, facts, outcome="committed")

    assert active.recordCount == 1 and active.headDigest not in {closed.headDigest, context.genesis}
    assert active.lastRecord is not None and active.lastRecord["creation_sha256"] == BundleDigest(initial.baseline.bundle)
    assert active.lastRecord["previous_head_sha256"] == context.genesis
    assert revisions.Pending(updated, segment=context) is None
    assert revisions.ReadEffectiveBundle(updated, active, pin) == server
    assert revisions.ReadEffectiveBundle(updated, active, pin, material=True) == material
    assert ReadPrivate(project.root / "wireguard-head.json") == oldHead
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in original.items())
    assert closed.artifactNames.isdisjoint(active.artifactNames)
    assert revisions.LoadPeerSegment(updated, closed.baseline).head == closed.head

    with pytest.raises(VpnError, match="integrated protocol workflow"):
        revisions.LoadRevisions(updated)


@POSIX
@pytest.mark.parametrize("boundary", ["record", "head", "journal"])
def test_SegmentCommitRecoveryUsesTheSameOriginalJournalAtEveryPublicationBoundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """An immutable record or published head does not cause a second epoch-local operation on retry."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    initial = revisions.LoadRevisions(project)
    context = Segment(project, initial)
    state = revisions.LoadPeerSegment(project, initial.baseline, context)
    updated, pending, material, server, pin, facts = Change(project, state)
    revisions.AtomicRecord(project, "wireguard-pending.json", pending, segment=context)
    pending = {**pending, "request_sha256": revisions.PublishRequest(project, pending, material, server, segment=context)}
    revisions.AtomicRecord(project, "wireguard-pending.json", pending, segment=context)
    publish = revisions.AtomicRecord

    def Interrupt(project: SelectedVpnProject, filename: str, data: dict[str, Any] | None, *, segment: revisions.PeerSegment | None = None) -> None:
        """Interrupt before head publication, after its rename, or after journal removal."""

        if boundary == "record" and filename == "wireguard-head.json":
            raise OSError("Synthetic interruption before head publication")

        publish(project, filename, data, segment=segment)

        if boundary == "head" and filename == "wireguard-head.json" or boundary == "journal" and filename == "wireguard-pending.json":
            raise OSError("Synthetic interruption after metadata publication")

    monkeypatch.setattr(revisions, "AtomicRecord", Interrupt)

    with pytest.raises(OSError, match="Synthetic interruption"):
        revisions.Commit(updated, state, pending, pin, facts, outcome="committed")

    monkeypatch.setattr(revisions, "AtomicRecord", publish)
    recovered = revisions.LoadPeerSegment(updated, initial.baseline, context)
    revisions.Commit(updated, recovered, pending, pin, facts, outcome="committed")
    complete = revisions.LoadPeerSegment(updated, initial.baseline, context)

    assert complete.recordCount == 1 and complete.receipt == facts["receipt_sha256"]
    assert revisions.Pending(updated, segment=context) is None and revisions.Pending(updated) is None
    assert not (project.root / "wireguard-head.json").exists()


@POSIX
@pytest.mark.parametrize("fault", ["creation-genesis", "foreign-owner", "copied-head", "inactive", "symlink-parent", "symlink-directory", "unknown-file", "missing-source"])
def test_SegmentsRefuseForeignPathsStaleHeadsInactivePeersAndMissingPrivateSources(tmp_path: Path, fault: str) -> None:
    """The original creation pointer cannot substitute for an epoch genesis, and a new head cannot revive old authority."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    initial = revisions.LoadRevisions(project)
    updated, pending, material, server, pin, facts = Change(project, initial)
    pending = Stage(project, pending, material, server)
    revisions.Commit(updated, initial, pending, pin, facts, outcome="committed")
    closed = revisions.LoadRevisions(updated)
    context = Segment(updated, closed)
    directory = project.root / "protocol-epochs" / context.genesis

    if fault == "creation-genesis":
        context = replace(context, genesis=BundleDigest(initial.baseline.bundle))

    elif fault == "foreign-owner":
        context = replace(context, sources=tuple(replace(source, identity=replace(source.identity, ownerId="different-owner")) for source in context.sources))

    elif fault == "copied-head":
        WritePrivate(directory / "wireguard-head.json", ReadPrivate(project.root / "wireguard-head.json"))

    elif fault == "inactive":
        context = replace(context, activeProtocols=(), receipt="")
        WritePrivate(directory / "wireguard-pending.json", _Json(pending))

    elif fault.startswith("symlink"):
        target = directory if fault == "symlink-directory" else directory.parent
        target.rename(target.with_name(target.name + "-retained"))
        target.symlink_to(target.with_name(target.name + "-retained"), target_is_directory=True)

    elif fault == "unknown-file":
        WritePrivate(directory / "untracked.json", b"{}\n")

    else:
        source = next(source for source in context.sources if source.pin.protocol == "wireguard")
        (project.Artifacts / ("server-" + source.requestName) / "material.json").unlink()

    before = Snapshot(project.root)

    with pytest.raises((VpnError, ArtifactError, OSError)):
        state = revisions.LoadPeerSegment(updated, initial.baseline, context)
        revisions.ReadEffectiveBundle(updated, state, pin, material=True)

    assert Snapshot(project.root) == before


@POSIX
@pytest.mark.parametrize("prepared", [False, True])
def test_UnappliedSegmentAttemptRetainsItsSourceAndTheExactCancellationHistory(tmp_path: Path, prepared: bool) -> None:
    """A prepared request consumes history on rollback while an undispatched attempt keeps its original fence."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    initial = revisions.LoadRevisions(project)
    context = Segment(project, initial)
    state = revisions.LoadPeerSegment(project, initial.baseline, context)
    _, pending, material, server, desired, _ = Change(project, state)
    originalPin = next(pin for pin in state.pins if pin.protocol == "wireguard")
    originalServer = revisions.ReadEffectiveBundle(project, state, originalPin)
    revisions.AtomicRecord(project, "wireguard-pending.json", pending, segment=context)

    if prepared:
        pending = {**pending, "request_sha256": revisions.PublishRequest(project, pending, material, server, segment=context)}
        revisions.AtomicRecord(project, "wireguard-pending.json", pending, segment=context)

    deployment = revisions.Digest(next(item.content for item in originalServer.files if item.name == "deployment.json"))
    history = (revisions.CommittedHistory(project, "enroll", "phone", state.receipt, state.receipt, deployment, state.history)
               if prepared else state.history)
    facts = {"status": "active", "is_desired": False, "receipt_sha256": state.receipt, "deployment_sha256": deployment, "history_sha256": history}
    revisions.Commit(project, state, pending, desired if prepared else originalPin, facts, outcome="not-applied")
    complete = revisions.LoadPeerSegment(project, initial.baseline, context)
    revisions.Commit(project, complete, pending, desired if prepared else originalPin, facts, outcome="not-applied")

    assert complete.pins == initial.pins and complete.receipt == state.receipt and complete.history == history
    assert complete.activeRecord is None and revisions.ReadEffectiveBundle(project, complete, originalPin) == originalServer
    assert complete.recordCount == 1 and revisions.Pending(project, segment=context) is None
    assert not (project.root / "wireguard-head.json").exists()


@POSIX
def test_SegmentMetadataTraversalSurvivesLostPrivateSourceBytes(tmp_path: Path) -> None:
    """Scoped cloud cleanup may verify the nonsecret closed segment without reading any client credential."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    initial = revisions.LoadRevisions(project)
    context = Segment(project, initial)
    (project.Artifacts / ("server-" + project.vpn.identity.stack + "-wireguard-credentials") / "material.json").unlink()
    before = Snapshot(project.root)
    state = revisions.LoadPeerSegment(project, LoadCreationBaseline(project), context)

    assert state.pins == initial.pins and state.baseline == initial.baseline and not state.artifactNames
    assert Snapshot(project.root) == before


@POSIX
@pytest.mark.parametrize("name", ["protocol-head.json", ".protocol-head.json.new", "protocol-pending.json", ".protocol-pending.json.new"])
def test_UnintegratedProtocolMetadataBlocksTheOldEntryPoint(tmp_path: Path, name: str) -> None:
    """Until the epoch coordinator is connected, ordinary peer/lifecycle readers must not adopt a legacy root."""

    project = Project(tmp_path)
    PrepareSelectedProject(project)
    WritePrivate(project.root / name, b"{}\n")
    before = Snapshot(project.root)

    with pytest.raises(VpnError, match="integrated protocol workflow"):
        revisions.LoadRevisions(project)

    assert Snapshot(project.root) == before
