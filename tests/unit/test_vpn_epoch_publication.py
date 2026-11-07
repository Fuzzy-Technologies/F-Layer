"""Recover real private epoch-publication prefixes while all cloud, guest and service facts remain synthetic."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
import test_vpn_native_graph as nativeFixtures
import test_vpn_protocol_graph as graphFixtures
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer import _vpn_epoch_publication as publication
from flayer import _vpn_protocol_epochs as epochs
from flayer import _vpn_revisions as revisions
from flayer._vpn_creation import _Json
from flayer._vpn_ingress_journal import IngressJournal
from flayer.guest import WritePrivate
from flayer.vpn_project import SelectedVpnProject

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private publication needs POSIX metadata/locks; no guest, cloud, WSL or desktop network is used")


def DispatchJournal(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> IngressJournal:
    """Retain a separately known terminal adapter reference without submitting or polling an actual provider operation."""

    metadata = json.loads(epoch.metadata)
    operation = epoch.cloud.operation
    assert operation is not None
    journal = IngressJournal(epoch.cloud.plan, metadata["creation_sha256"], metadata["previous_state_sha256"],
                             metadata["reservation"]["plan_expires_at"], "recorded", operation.reference)
    WritePrivate(project.root / "protocol-ingress-pending.json", _Json(journal.Record()))

    return journal


def Environment(tmpPath: Path) -> tuple[SelectedVpnProject, epochs.EpochCommit]:
    """Bind a complete synthetic native terminal result to real retained creation, source and ingress manifests."""

    project = graphFixtures.Initial(tmpPath)
    epoch = nativeFixtures.Commit(project, epochs.LoadCommittedGraph(project), "enable", "0" * 32)
    DispatchJournal(project, epoch)

    return project, epoch


def Prepare(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> publication.EpochPublication:
    """Use the same project coordination required of the future authenticated controller."""

    with revisions.ProjectLock(project, readOnly=False):
        return publication.PreparePublication(project, epoch, allowMutation=True)


def Commit(project: SelectedVpnProject, expected: publication.EpochPublication) -> epochs.ProtocolGraph:
    """Supply the fixture's separately observed exact completion; the local backend cannot observe a real guest."""

    with revisions.ProjectLock(project, readOnly=False):
        return publication.CommitPublication(project, expected, expected.epoch.completion, allowMutation=True)


def test_PreparedCandidateBlocksOrdinaryTraversalUntilItsSeparateAcknowledgmentPublishesOneEpoch(tmp_path: Path) -> None:
    """No predicted completion is a committed graph; publication retains all source bytes and original ownership."""

    project, epoch = Environment(tmp_path)
    creation = Snapshot(project.Artifacts)
    expected = Prepare(project, epoch)
    assert expected.phase == "prepared" and publication.LoadPublication(project) == expected
    assert not (project.root / "protocol-head.json").exists()

    with pytest.raises(ValueError, match="recovery"):
        epochs.LoadCommittedGraph(project)

    repeated = Prepare(project, epoch)
    assert repeated == expected
    result = Commit(project, expected)
    assert result.epochs == (epoch,) and result.head == {"name": epoch.Bundle().name, "sha256": epoch.Digest()}
    assert result.revision.segment is not None and result.revision.segment.genesis == epoch.Digest()
    assert result.revision.history == json.loads(epoch.metadata)["wireguard_history_sha256"]
    assert not (project.root / "protocol-pending.json").exists()
    assert not (project.root / "protocol-ingress-pending.json").exists()
    after = Snapshot(project.root)
    assert Commit(project, expected) == result and Snapshot(project.root) == after
    assert all(Snapshot(project.Artifacts)[name] == record for name, record in creation.items())


@pytest.mark.parametrize("boundary", ["pending", "epoch.json", "cloud.json", "input.json", "services.json", "manifest.json"])
def test_PreparationRecoversEachManifestLastPublicationBoundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str) -> None:
    """The canonical journal precedes every public bundle file, so retry finishes only its exact ordered prefix."""

    project, epoch = Environment(tmp_path)
    publish, exact = publication._Publish, publication._ExactFile

    def Publish(*args: Any) -> None:
        """Interrupt immediately after durable initial candidate publication."""

        publish(*args)
        raise Interrupted

    def Exact(directory: int, name: str, content: bytes, **kwargs: Any) -> None:
        """Interrupt after one exact durable public file, leaving all private material untouched."""

        exact(directory, name, content, **kwargs)

        if name == boundary:
            raise Interrupted

    with monkeypatch.context() as fault:
        fault.setattr(publication, "_Publish" if boundary == "pending" else "_ExactFile", Publish if boundary == "pending" else Exact)

        with pytest.raises(Interrupted):
            Prepare(project, epoch)

    assert publication.LoadPublication(project) == publication.EpochPublication(epoch)
    assert Commit(project, Prepare(project, epoch)).epochs == (epoch,)


@pytest.mark.parametrize("boundary", ["observed", "segment", "head", "ingress", "pending"])
def test_RecordedAcknowledgmentRecoversEveryLocalPublicationAndJournalRetirementBoundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """A retry uses the same completion and next peer genesis; no new provider request or guest authority exists here."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    publish, segment, retire = publication._Publish, publication._Segment, publication._Retire

    def Publish(current: SelectedVpnProject, name: str, content: bytes, previous: bytes | None) -> None:
        """Interrupt after acknowledgment or head publication has crossed its directory barrier."""

        publish(current, name, content, previous)

        if boundary == "observed" and name == "protocol-pending.json" or boundary == "head" and name == "protocol-head.json":
            raise Interrupted

    def Segment(*args: Any) -> None:
        """Interrupt after all exact next peer-directory barriers."""

        segment(*args)
        raise Interrupted

    def Retire(current: SelectedVpnProject, name: str, content: bytes) -> None:
        """Interrupt after one exact known journal is durably removed."""

        retire(current, name, content)

        if boundary == "ingress" and name == "protocol-ingress-pending.json" or boundary == "pending" and name == "protocol-pending.json":
            raise Interrupted

    with monkeypatch.context() as fault:
        fault.setattr(publication, "_Publish", Publish)
        fault.setattr(publication, "_Retire", Retire)

        if boundary == "segment":
            fault.setattr(publication, "_Segment", Segment)

        with pytest.raises(Interrupted):
            Commit(project, expected)

    result = Commit(project, expected)
    assert result.epochs == (epoch,) and result.revision.segment is not None
    assert result.revision.segment.genesis == epoch.Digest()
    assert {path.name for path in (project.root / "protocol-epochs").iterdir()} == {epoch.Digest()}
    assert not (project.root / "protocol-pending.json").exists()


@pytest.mark.parametrize("length", [0, 17, 300])
def test_OnlyExactInitialJournalBytePrefixesCanContinuePreparation(tmp_path: Path, length: int) -> None:
    """Partial journal bytes grant no committed graph and are finished only from the validated unchanged candidate."""

    project, epoch = Environment(tmp_path)
    record = publication.EpochPublication(epoch)
    WritePrivate(project.root / ".protocol-pending.json.new", _Json(record.Record())[:length])

    with pytest.raises(ValueError):
        epochs.LoadCommittedGraph(project)

    assert Commit(project, Prepare(project, epoch)).epochs == (epoch,)


@pytest.mark.parametrize("filename", ["epoch.json", "cloud.json", "input.json", "services.json", "manifest.json"])
def test_ExactPartialLastBundleFileContinuesWithoutReplacingEarlierInodes(tmp_path: Path, filename: str) -> None:
    """A closed durable candidate permits append-only recovery of its last known incomplete public file."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    root = project.Artifacts / ("server-" + epoch.Bundle().name)
    names = [*_FILES_FOR_TEST, "manifest.json"]
    index = names.index(filename)
    earlier = {name: (root / name).stat().st_ino for name in names[:index]}

    for name in names[index + 1:]:
        (root / name).unlink()

    path = root / filename
    path.write_bytes(path.read_bytes()[:17])
    inode = path.stat().st_ino
    assert Commit(project, expected).epochs == (epoch,)
    assert path.stat().st_ino == inode and all((root / name).stat().st_ino == value for name, value in earlier.items())


_FILES_FOR_TEST = ("epoch.json", "cloud.json", "input.json", "services.json")


@pytest.mark.parametrize("fault", ["journal-lost", "wrong-response", "unknown-file", "file-gap", "bad-file", "head-temp", "ingress-unknown", "peer-drift"])
def test_LostOrUnknownPublicationStateIsPreservedWithoutAdvancingTheHead(tmp_path: Path, fault: str) -> None:
    """Complete predicted bytes cannot reconstruct lost authority, explain unknown dispatch or replace a different publication."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    bundle = project.Artifacts / ("server-" + epoch.Bundle().name)

    if fault == "journal-lost":
        (project.root / "protocol-pending.json").unlink()

    elif fault == "unknown-file":
        WritePrivate(bundle / "foreign.json", b"preserve unrelated bytes")

    elif fault == "file-gap":
        (bundle / "cloud.json").unlink()

    elif fault == "bad-file":
        (bundle / "epoch.json").write_bytes(b"preserve changed bytes")

    elif fault == "head-temp":
        WritePrivate(project.root / ".protocol-head.json.new", b"preserve unknown pointer")

    elif fault == "ingress-unknown":
        journal = json.loads((project.root / "protocol-ingress-pending.json").read_bytes())
        journal.update(phase="dispatching", operation=None)
        (project.root / "protocol-ingress-pending.json").write_bytes(_Json(journal))

    elif fault == "peer-drift":
        directory = project.root / "protocol-epochs"
        directory.mkdir(mode=0o700)
        child = directory / epoch.Digest()
        child.mkdir(mode=0o700)
        WritePrivate(child / "wireguard-head.json", b"preserve unexplained peer authority")

    before = Snapshot(project.root)

    with revisions.ProjectLock(project, readOnly=False):
        with pytest.raises(ValueError):
            publication.CommitPublication(project, expected, b"wrong" if fault == "wrong-response" else epoch.completion, allowMutation=True)

    assert Snapshot(project.root) == before and not (project.root / "protocol-head.json").exists()

    if fault == "journal-lost":
        with pytest.raises(ValueError, match="orphan"):
            Prepare(project, epoch)

        assert Snapshot(project.root) == before


def test_RepeatedNativeEpochPublicationRetainsClosedSegmentsAndOriginalPrivateFiles(tmp_path: Path) -> None:
    """Several enable/disable generations can complete without adopting past ingress intents or changing original credentials."""

    project = graphFixtures.Initial(tmp_path)
    original = Snapshot(project.Artifacts)
    graph = epochs.LoadCommittedGraph(project)

    for index, change in enumerate(("enable", "disable", "enable", "disable")):
        epoch = nativeFixtures.Commit(project, graph, change, format(index, "032x"))
        DispatchJournal(project, epoch)
        graph = Commit(project, Prepare(project, epoch))
        assert len(graph.epochs) == index + 1
        assert graph.revision.history == json.loads(epoch.metadata)["wireguard_history_sha256"]
        assert len(list((project.root / "protocol-epochs").iterdir())) == index + 1

    after = Snapshot(project.Artifacts)
    assert all(after[name] == record for name, record in original.items())


def test_PublicMetadataPublicationDoesNotRequireOrReconstructLostPrivateSourceBodies(tmp_path: Path) -> None:
    """The prepared candidate, retained manifests and complete receipt pins suffice for historical metadata recovery."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)

    for directory in project.Artifacts.iterdir():
        if not directory.is_dir():
            continue

        manifest = json.loads((directory / "manifest.json").read_bytes())

        for item in manifest["files"]:
            if item["sensitive"]:
                (directory / item["name"]).unlink()

    before = Snapshot(project.Artifacts)
    assert Commit(project, expected).epochs == (epoch,)
    assert all(Snapshot(project.Artifacts)[name] == record for name, record in before.items())


def test_FailedFinalUnlinkBarrierBlocksPeerSegmentMutationButKeepsReadOnlyTraversalAvailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Persist root namespace absence before any later segment write, so reboot cannot resurrect an unfinishable old publication."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    root = project.root.stat()
    fsync = os.fsync
    events = []

    def Fail(descriptor: int) -> None:
        """Fail the final project-root removal barrier and the same barrier at subsequent mutating admission."""

        info = os.fstat(descriptor)

        if (stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (root.st_dev, root.st_ino)
                and not (project.root / "protocol-pending.json").exists()):
            raise OSError("Synthetic project publication directory barrier failure")

        fsync(descriptor)

    with monkeypatch.context() as fault:
        fault.setattr(os, "fsync", Fail)

        with pytest.raises(OSError):
            Commit(project, expected)

        assert not (project.root / "protocol-pending.json").exists()

        with revisions.ProjectLock(project, readOnly=True):
            graph = epochs.LoadCommittedGraph(project)
            assert graph.epochs == (epoch,)

        before = Snapshot(project.root)

        with pytest.raises(OSError):
            with revisions.ProjectLock(project, readOnly=False):
                events.append("peer mutation must remain unreachable")

        assert not events and Snapshot(project.root) == before

    def Sync(descriptor: int) -> None:
        """Observe the completed root barrier before the real synthetic segment metadata write."""

        info = os.fstat(descriptor)
        fsync(descriptor)

        if (info.st_dev, info.st_ino) == (root.st_dev, root.st_ino):
            events.append("durable root")

    monkeypatch.setattr(os, "fsync", Sync)

    with revisions.ProjectLock(project, readOnly=False):
        assert events == ["durable root"]
        revisions.AtomicRecord(project, "wireguard-pending.json", {"schema_version": 1, "synthetic": True}, segment=graph.revision.segment)
        events.append("peer write")

    assert events == ["durable root", "peer write"]


@pytest.mark.parametrize("fault", ["file", "directory", "bundle-aba", "segment-aba"])
def test_BundleAndPeerNamespaceReplacementOrMembershipAbaCannotPublishAHead(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Equal bytes do not substitute for a previously verified inode; directory add/remove races also retain the protective journal."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch) if fault == "segment-aba" else None
    root = project.Artifacts / ("server-" + epoch.Bundle().name)
    fsync = os.fsync
    fired = []
    calls = []

    def Sync(descriptor: int) -> None:
        """Replace earlier public files or mutate empty directory membership at a later durability barrier."""

        info = os.fstat(descriptor)
        target = project.root / "protocol-epochs" / epoch.Digest() if fault == "segment-aba" else root

        if stat.S_ISDIR(info.st_mode) and target.exists() and (info.st_dev, info.st_ino) == (target.stat().st_dev, target.stat().st_ino):
            calls.append(True)

            if not fired and (fault == "segment-aba" or len(calls) == 2):
                fired.append(True)

                if fault == "file":
                    replacement = project.root / "synthetic-replacement.json"
                    WritePrivate(replacement, (root / "epoch.json").read_bytes())
                    os.replace(replacement, root / "epoch.json")

                elif fault == "directory":
                    retained = project.Artifacts / "synthetic-retained-epoch"
                    root.rename(retained)
                    root.mkdir(mode=0o700)

                    for path in retained.iterdir():
                        WritePrivate(root / path.name, path.read_bytes())

                else:
                    WritePrivate(target / "synthetic-membership.json", b"preserve no foreign payload")
                    (target / "synthetic-membership.json").unlink()

        fsync(descriptor)

    with monkeypatch.context() as injected:
        injected.setattr(os, "fsync", Sync)

        with pytest.raises(ValueError):
            if expected is None:
                Prepare(project, epoch)

            else:
                Commit(project, expected)

    assert fired and (project.root / "protocol-pending.json").exists()
    assert not (project.root / "protocol-head.json").exists()


@pytest.mark.parametrize("entry", ["pending", "head"])
@pytest.mark.parametrize("valid", [False, True])
def test_UnexpectedLateMutableAuthorityCannotBecomeThePublishersExpectedPreviousBytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str, valid: bool,
) -> None:
    """Preserve a replaced pointer/journal even when its replacement has a structurally valid closed format."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    before = publication._Before
    changed = []
    path = project.root / ("protocol-pending.json" if entry == "pending" else "protocol-head.json")
    raw = (_Json({"name": project.vpn.identity.stack + "-ep-" + "f" * 16, "sha256": "f" * 64}) if entry == "head"
           else _Json(publication.EpochPublication(epoch, "observed").Record())) if valid else b"preserve unexplained authority"

    def Before(current: SelectedVpnProject, value: publication.EpochPublication) -> epochs.ProtocolGraph:
        """Replace validated authority after traversal but before the caller attempts its mutable publication."""

        graph = before(current, value)

        if not changed and (entry == "pending" or value.phase == "observed"):
            changed.append(True)

            if path.exists():
                path.write_bytes(raw)

            else:
                WritePrivate(path, raw)

        return graph

    with monkeypatch.context() as fault:
        fault.setattr(publication, "_Before", Before)

        with pytest.raises(ValueError):
            if entry == "pending":
                Prepare(project, epoch)

            else:
                Commit(project, expected)

    assert changed and path.read_bytes() == raw and (project.root / "protocol-pending.json").exists()


def test_RecreatedTerminalIngressJournalPreventsFinalPublicationJournalRetirement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A familiar canonical name does not explain reappearance after its verified deletion."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    retire = publication._Retire
    path = project.root / "protocol-ingress-pending.json"

    def Retire(current: SelectedVpnProject, name: str, content: bytes) -> None:
        """Recreate the exact acknowledged ingress journal after the cleanup wrapper returns."""

        retire(current, name, content)

        if name == "protocol-ingress-pending.json":
            WritePrivate(path, content)

    with monkeypatch.context() as fault:
        fault.setattr(publication, "_Retire", Retire)

        with pytest.raises(ValueError, match="before retirement"):
            Commit(project, expected)

    assert path.exists() and (project.root / "protocol-pending.json").exists()
    assert Commit(project, expected).epochs == (epoch,)


@pytest.mark.parametrize("boundary", ["segment", "head", "ingress", "pending"])
@pytest.mark.parametrize("replacement", ["payload", "bundle-directory"])
def test_ImmutableBundlePinsSpanEveryLaterPublicationAndCleanupBarrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, replacement: str,
) -> None:
    """A same-byte replacement after bundle synchronization cannot escape detection or leave final publication protection removed."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    bundle = project.Artifacts / ("server-" + epoch.Bundle().name)
    fsync = os.fsync
    fired = []

    def Sync(descriptor: int) -> None:
        """Replace immutable payload identity during a selected later directory barrier."""

        info = os.fstat(descriptor)
        target = project.root / "protocol-epochs" / epoch.Digest() if boundary == "segment" else project.root
        pending = (project.root / "protocol-pending.json").exists()
        ingress = (project.root / "protocol-ingress-pending.json").exists()
        head = (project.root / "protocol-head.json").exists()
        selected = boundary == "segment" or head and (
            boundary == "head" and pending and ingress or boundary == "ingress" and pending and not ingress or boundary == "pending" and not pending)

        if (not fired and selected and stat.S_ISDIR(info.st_mode) and target.exists()
                and (info.st_dev, info.st_ino) == (target.stat().st_dev, target.stat().st_ino)):
            fired.append(True)

            if replacement == "payload":
                path = project.root / "synthetic-late-replacement.json"
                WritePrivate(path, (bundle / "epoch.json").read_bytes())
                os.replace(path, bundle / "epoch.json")

            else:
                retained = project.Artifacts / "synthetic-late-retained-epoch"
                bundle.rename(retained)
                bundle.mkdir(mode=0o700)

                for path in retained.iterdir():
                    WritePrivate(bundle / path.name, path.read_bytes())

        fsync(descriptor)

    with monkeypatch.context() as fault:
        fault.setattr(os, "fsync", Sync)

        with pytest.raises(ValueError):
            Commit(project, expected)

    assert fired and (project.root / "protocol-pending.json").exists()
    assert publication.LoadPublication(project) is not None

    with pytest.raises(ValueError, match="recovery"):
        epochs.LoadCommittedGraph(project)


def test_FinalGraphTraversalDriftStillRestoresTheSameObservedProtection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The restoration guard spans return-value construction and the pinned context's final verification."""

    project, epoch = Environment(tmp_path)
    expected = Prepare(project, epoch)
    load = epochs.LoadCommittedGraph
    replaced = []

    def Load(current: SelectedVpnProject) -> epochs.ProtocolGraph:
        """Replace an immutable inode only after final journal unlink while returning otherwise identical graph facts."""

        result = load(current)
        path = current.Artifacts / ("server-" + epoch.Bundle().name) / "epoch.json"
        replacement = current.root / "synthetic-return-replacement.json"
        WritePrivate(replacement, path.read_bytes())
        os.replace(replacement, path)
        replaced.append(True)

        return result

    with monkeypatch.context() as fault:
        fault.setattr(epochs, "LoadCommittedGraph", Load)

        with pytest.raises(ValueError, match="Pinned epoch bundle"):
            Commit(project, expected)

    assert replaced and publication.LoadPublication(project) == publication.EpochPublication(epoch, "observed")

    with pytest.raises(ValueError, match="recovery"):
        load(project)
