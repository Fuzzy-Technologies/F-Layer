"""Require all intent publication barriers before authorizing even one separately consented cloud dispatch."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_vpn_ingress_journal import Setup
from test_vpn_project_v2 import Snapshot

from flayer import _vpn_ingress_journal as journal
from flayer.profiles import artifacts
from flayer.vpn_project import SelectedVpnProject

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private durability barriers require POSIX; no WSL or desktop network is started")


def Handles(project: SelectedVpnProject, pending: journal.IngressJournal) -> dict[tuple[int, int], str]:
    """Identify real private fixture descriptors by inode without reading paths from another process or filesystem."""

    directory = project.Artifacts / ("server-" + pending.Bundle().name)
    paths = {"intent": directory / "intent.json", "manifest": directory / "manifest.json", "bundle": directory, "parent": project.Artifacts}

    return {(path.stat().st_dev, path.stat().st_ino): name for name, path in paths.items()}


@pytest.mark.parametrize("action", ["republish", "dispatch"])
def test_ExistingVisibleIntentIsFullySyncedBeforeReuseOrDispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str,
) -> None:
    """A fully readable bundle models the prefix left by an abrupt stop before directory barriers became durable."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    before = Snapshot(project.Artifacts)
    handles = Handles(project, prepared)
    synced: list[str] = []
    originalSync = artifacts.os.fsync
    originalRecord = journal.AtomicRecord

    def Sync(descriptor: int) -> None:
        """Record actual file, manifest and parent barriers while preserving the real filesystem behavior."""

        info = os.fstat(descriptor)
        name = handles.get((info.st_dev, info.st_ino))

        if name is not None:
            synced.append(name)

        originalSync(descriptor)

    def Publish(current: SelectedVpnProject, filename: str, data: dict[str, Any] | None) -> None:
        """Dispatching must not be published before the verified intent's complete durability order."""

        if data is not None and data.get("phase") == "dispatching":
            assert synced.index("intent") < synced.index("bundle") < synced.index("parent")
            assert synced.index("manifest") < synced.index("bundle")

        originalRecord(current, filename, data)

    monkeypatch.setattr(artifacts.os, "fsync", Sync)
    monkeypatch.setattr(journal, "AtomicRecord", Publish)

    if action == "republish":
        journal.PublishIntent(project, prepared)

    else:
        assert journal.BeginDispatch(project, prepared).phase == "dispatching"

    assert set(synced) == {"intent", "manifest", "bundle", "parent"}
    assert Snapshot(project.Artifacts) == before


@pytest.mark.parametrize("barrier", ["intent", "manifest", "bundle", "parent"])
def test_AnyIntentDurabilityFailureLeavesTheJournalPreparedAndReturnsNoDispatchAuthority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, barrier: str,
) -> None:
    """Readability alone cannot bypass a failed file or directory synchronization, and no payload is rewritten/deleted."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    handles = Handles(project, prepared)
    original = artifacts.os.fsync
    before = Snapshot(project.root)

    def Fail(descriptor: int) -> None:
        """Fail one real durability barrier before the cloud-dispatch marker may advance."""

        info = os.fstat(descriptor)

        if handles.get((info.st_dev, info.st_ino)) == barrier:
            raise OSError("Synthetic intent durability interruption")

        original(descriptor)

    monkeypatch.setattr(artifacts.os, "fsync", Fail)

    with pytest.raises(artifacts.ArtifactError, match="durably synchronize"):
        journal.BeginDispatch(project, prepared)

    assert journal.LoadJournal(project) == prepared and Snapshot(project.root) == before


@pytest.mark.parametrize("fault", ["replacement", "manifest", "crash-lock"])
def test_RecoverySynchronizationRejectsChangedOrBusyIntentAndRetainsEveryDetectedReplacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """The durability helper cannot bless a new inode, altered manifest or an existing unknown publication lock."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    bundle = prepared.Bundle()
    directory = project.Artifacts / ("server-" + bundle.name)
    payload = directory / "intent.json"
    original = artifacts.os.fsync
    payloadId = (payload.stat().st_dev, payload.stat().st_ino)
    replaced = False

    def ReplaceDuringSync(descriptor: int) -> None:
        """Replace one synthetic payload after its handle was opened, preserving the replacement for inspection."""

        nonlocal replaced
        info = os.fstat(descriptor)

        if not replaced and (info.st_dev, info.st_ino) == payloadId:
            replacement = directory / "replacement.json"
            replacement.write_bytes(payload.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(payload)
            replaced = True

        original(descriptor)

    if fault == "replacement":
        monkeypatch.setattr(artifacts.os, "fsync", ReplaceDuringSync)

    elif fault == "manifest":
        path = directory / "manifest.json"
        path.write_bytes(path.read_bytes().replace(b'"sensitive": false', b'"sensitive": true'))

    else:
        lock = project.Artifacts / (".server-" + bundle.name + ".lock")
        lock.write_bytes(b"")
        lock.chmod(0o600)

    before = Snapshot(project.root)

    with pytest.raises(artifacts.ArtifactError):
        artifacts._SyncArtifactBundle(project.Artifacts, bundle)

    assert Snapshot(project.root) == before and payload.exists()

    if fault == "replacement":
        assert replaced and (payload.stat().st_dev, payload.stat().st_ino) != payloadId
