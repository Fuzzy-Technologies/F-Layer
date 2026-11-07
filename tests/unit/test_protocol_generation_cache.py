"""Exercise actual reserved cache journals and interrupted private writes with synthetic POSIX networking only."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_host_input_transaction import Delta
from test_protocol_reservation import Active
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer import _vpn_host_input as host
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as generations
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _wireguard_generation as cachedGenerations
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Reserved cache files require POSIX; no WSL/client or real networking is used")


def Prepared(
    tmpPath: Path, monkeypatch: pytest.MonkeyPatch, change: str = "disable", version: int = 1,
) -> tuple[Any, dict[str, Any], dict[str, Any], Path, Path | None]:
    """Expose one exact generation plan while retaining independent old runtime and source snapshots."""

    model, _, intent = Active(tmpPath, monkeypatch)
    receipt = json.loads((model.root / "receipt.json").read_bytes())
    cached = model.root
    candidate = None
    desired = None
    transition = Delta()

    if change == "enable" or version >= 2:
        candidate = tmpPath / "candidate"
        candidate.mkdir(mode=0o700)
        helper = (model.root / "install.py").read_bytes()
        desired = cachedGenerations.PrepareCached(guest, cached, candidate, guest._Digest(guest._Encode(receipt)),
                                                  intent["operation_id"], helper, guest._Digest(helper))

    if change == "enable":
        with monkeypatch.context() as stop:
            stop.setattr(guest, "_Run", model.Run)
            guest._Stop(model.root, model.unit, model.originalRequest)
        model.Run(["systemctl", "disable", model.unit.name])
        model.unit.unlink()
        model.active = False
        cached = tmpPath / "source-cache"
        model.root.rename(cached)
        before = host.InputPolicy(transition.before.identity, transition.before.creationSha256, transition.before.originalBootSha256,
                                  transition.before.managementCidrs, transition.before.listeners[:-1], "d" * 32)
        transition = host.InputTransition(before, transition.listener, "enable", transition.operationId)
        intent.update(wireguard_state="absent", wireguard_receipt_sha256="", wireguard_absence_sha256=guest._AbsenceDigest(model.owner))

    value = {"schema_version": 2, "cloud_plan_sha256": "a" * 64, "input": transition.Record(),
             "generation": {"schema_version": version, "change": change, "source_sha256": "f" * 64,
                            "source_files": {name: receipt["files"][name] for name in generations._SOURCE_FILES},
                            "cached_receipt": receipt, "candidate_receipt": desired}}

    if version == 3:
        value["generation"]["callback_abi"] = guest.PROTOCOL_RUNTIME_ABI
    intent["plan_sha256"] = policy.Digest(policy.Json(value))
    reserved = authority.Reserve(guest, peers, intent, allowMutation=True)
    authority.Expose(guest, peers, intent, reserved["reservation_sha256"], allowMutation=True)

    return model, value, intent, cached, candidate


def Prepare(value: dict[str, Any], intent: dict[str, Any], cached: Path | None, candidate: Path | None) -> dict[str, str]:
    """Use the actual backend and actual common/WG coordination with fully intercepted native effects."""

    return generations.Prepare(guest, peers, authority, policy, value, intent, cached, candidate, allowMutation=True)


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_CachePreparationRetainsAllBytesAndAuthorityWithoutActivatingAGeneration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Only a private cache/journal changes; keys, live policy and consumed history remain exact."""

    model, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch, change)
    original = Snapshot(cached)
    state = (model.active, model.interface, model.policy, model.kernelConfig, peers._History(guest, model.owner))
    result = Prepare(value, intent, cached, candidate)
    assert result["phase"] == "prepared" and result["status"] == "generation-cache"
    assert Snapshot(cached) == original
    assert state == (model.active, model.interface, model.policy, model.kernelConfig, peers._History(guest, model.owner))

    for receipt in (value["generation"]["cached_receipt"], value["generation"]["candidate_receipt"]):
        if receipt is not None:
            path = generations._CachePath(guest, receipt)
            assert guest._Receipt(path, path / ".unpublished-unit", model.owner, staged=True) == receipt
            assert len(generations._Prefix(guest, receipt, partial=False)) == len(receipt["files"]) + 1

    before = Snapshot(tmp_path)
    assert generations.Status(guest, peers, authority, policy, value, intent) == result
    assert Snapshot(tmp_path) == before
    assert Prepare(value, intent, None, None) == result
    assert authority.Status(guest, peers, intent)["phase"] == "exposed"
    assert not guest._Paths(model.owner)[2].exists()


def test_PreparedEnableRetrySurvivesLossOfItsTransientOriginalSources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once the complete cache is durable, exact retry needs no discarded transport payload or regeneration."""

    model, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch, "enable")
    result = Prepare(value, intent, cached, candidate)
    assert candidate is not None

    for path in (cached, candidate):
        assert path.is_relative_to(tmp_path)

        for entry in path.iterdir():
            entry.unlink()

        path.rmdir()

    assert Prepare(value, intent, None, None) == result
    assert not model.root.exists() and not model.active


@pytest.mark.parametrize("filename", ["wg", "server.conf", "receipt.json"])
@pytest.mark.parametrize("empty", [True, False])
def test_PreparingJournalCompletesOnlyExactKnownSourcePrefixesAfterProcessDeath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, empty: bool,
) -> None:
    """A torn private write resumes its known suffix; no old history, active root or differing bytes are restored."""

    model, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    original = generations._File
    fired = False

    def File(backend: Any, path: Path, content: bytes, mode: int, *, resume: bool) -> None:
        nonlocal fired

        if path.name == filename and not fired:
            fired = True
            path.write_bytes(b"" if empty else content[:max(1, len(content) // 2)])
            path.chmod(mode)

            raise Interrupted

        original(backend, path, content, mode, resume=resume)

    monkeypatch.setattr(generations, "_File", File)

    with pytest.raises(Interrupted):
        Prepare(value, intent, cached, candidate)

    record = authority._Decode(guest, authority._Root(guest) / "generation.json")
    assert record["phase"] == "preparing" and fired and model.active
    before = Snapshot(tmp_path)

    with pytest.raises(generations.GenerationError):
        generations.Status(guest, peers, authority, policy, value, intent)

    assert Snapshot(tmp_path) == before
    result = Prepare(value, intent, cached, candidate)
    assert result["phase"] == "prepared" and model.active


@pytest.mark.parametrize("fault", ["foreign", "symlink", "hardlink", "mode", "unknown", "missing"])
def test_PreparedCacheDriftCannotBeRepairedOrAdoptedByRetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Completed source pins are immutable; retain damaged data and require explicit recovery rather than copying over it."""

    model, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    Prepare(value, intent, cached, candidate)
    path = generations._CachePath(guest, value["generation"]["cached_receipt"]) / "COPYING"

    if fault == "foreign":
        path.write_bytes(b"foreign cache data")

    elif fault == "mode":
        path.chmod(0o644)

    elif fault == "unknown":
        (path.parent / "unknown").write_bytes(b"retained")

    else:
        path.unlink()

        if fault == "symlink":
            path.symlink_to(cached / "COPYING")

        elif fault == "hardlink":
            os.link(cached / "COPYING", path)

    before = Snapshot(tmp_path) if fault != "symlink" else None

    with pytest.raises((ValueError, OSError)):
        Prepare(value, intent, cached, candidate)

    if before is not None:
        assert Snapshot(tmp_path) == before

    assert model.active and authority.Status(guest, peers, intent)["phase"] == "exposed"


def test_CompletePreparedTemporaryPublicationIsObservedWithoutRepairAndResyncedOnRetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A complete forward journal prefix survives a lost rename; status never turns it into a repair."""

    _, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    replace = authority.os.replace

    def Replace(source: Any, destination: Any) -> None:
        path = Path(source)

        if path.name == ".generation.json.new" and json.loads(path.read_bytes())["phase"] == "prepared":
            raise Interrupted

        replace(source, destination)

    monkeypatch.setattr(authority.os, "replace", Replace)

    with pytest.raises(Interrupted):
        Prepare(value, intent, cached, candidate)

    before = Snapshot(tmp_path)
    result = generations.Status(guest, peers, authority, policy, value, intent)
    assert result["phase"] == "prepared" and Snapshot(tmp_path) == before
    monkeypatch.setattr(authority.os, "replace", replace)
    assert Prepare(value, intent, None, None) == result
    assert not (authority._Root(guest) / ".generation.json.new").exists()


@pytest.mark.parametrize("fault", ["consent", "unexposed", "plan", "source", "history", "foreign-journal", "reverse-journal"])
def test_UnmatchedAuthorityOrJournalCannotWriteCacheData(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """A copied request, changed source or unrecognized recovery prefix never grants a private generation write."""

    model, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)

    if fault == "unexposed":
        pending = authority._Pending(guest, intent)
        assert pending is not None
        authority._Publish(guest, "pending.json", {**pending, "phase": "reserved"})

    elif fault == "plan":
        intent["plan_sha256"] = "0" * 64

    elif fault == "source":
        value["generation"]["source_files"]["install.py"] = "0" * 64
        intent["plan_sha256"] = policy.Digest(policy.Json(value))

    elif fault == "history":
        receipt = json.loads((model.root / "receipt.json").read_bytes())
        peers._Cancel(guest, receipt, "revoke", "other-device", peers._History(guest, model.owner))

    elif fault in {"foreign-journal", "reverse-journal"}:
        expected = generations._Expected(guest, intent, value, peers._History(guest, model.owner))
        record = {**expected, "phase": "prepared" if fault == "reverse-journal" else "preparing"}

        if fault == "foreign-journal":
            record["history_sha256"] = "0" * 64

        authority._Publish(guest, "generation.json", record)

        if fault == "reverse-journal":
            guest._Atomic(authority._Root(guest) / ".generation.json.new", guest._Encode({**expected, "phase": "preparing"}))

    before = Snapshot(tmp_path)

    with pytest.raises((ValueError, OSError)):
        generations.Prepare(guest, peers, authority, policy, value, intent, cached, candidate, allowMutation=fault != "consent")

    assert Snapshot(tmp_path) == before and model.active


def test_LostGenerationJournalDoesNotAdoptTornCacheFiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A private byte prefix alone is not permission to reconstruct missing operation metadata."""

    _, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    original = generations._File

    def File(backend: Any, path: Path, content: bytes, mode: int, *, resume: bool) -> None:
        if path.name == "wg":
            path.write_bytes(content[:1])
            path.chmod(mode)

            raise Interrupted

        original(backend, path, content, mode, resume=resume)

    monkeypatch.setattr(generations, "_File", File)

    with pytest.raises(Interrupted):
        Prepare(value, intent, cached, candidate)

    (authority._Root(guest) / "generation.json").unlink()
    monkeypatch.setattr(generations, "_File", original)
    before = Snapshot(tmp_path)

    with pytest.raises(generations.GenerationError):
        Prepare(value, intent, cached, candidate)

    assert Snapshot(tmp_path) == before


@pytest.mark.parametrize("sparse", [False, True])
def test_PreparingCacheResyncsVisibleFilesAndCompletesRecordedSparsePublication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sparse: bool,
) -> None:
    """A crash before directory durability can leave a receipt entry without every earlier file entry; the retained journal stays authoritative."""

    _, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    directories = generations._Directories
    fired = False

    def Directories(backend: Any, path: Path, *, create: bool) -> None:
        nonlocal fired

        directories(backend, path, create=create)

        if create and (path / "receipt.json").exists() and not fired:
            fired = True

            if sparse:
                (path / "COPYING").unlink()

            raise Interrupted

    monkeypatch.setattr(generations, "_Directories", Directories)

    with pytest.raises(Interrupted):
        Prepare(value, intent, cached, candidate)

    record = authority._Decode(guest, authority._Root(guest) / "generation.json")
    assert record["phase"] == "preparing" and fired
    monkeypatch.setattr(generations, "_Directories", directories)
    assert Prepare(value, intent, cached, candidate)["phase"] == "prepared"


@pytest.mark.parametrize("replacement", ["file", "directory"])
def test_SameByteReplacementDuringFinalDirectoryBarriersCannotCommitPreparation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replacement: str,
) -> None:
    """Identical hashes do not prove replacement inodes durable; retain replacements and the preparing journal."""

    _, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    receipt = value["generation"]["cached_receipt"]
    root = generations._CachePath(guest, receipt)
    synchronize = generations._SyncPinned
    fired = False

    def Sync(descriptor: int) -> None:
        nonlocal fired

        synchronize(descriptor)
        info = os.fstat(descriptor)
        linked = root.stat()

        if (info.st_dev, info.st_ino) == (linked.st_dev, linked.st_ino) and not fired:
            fired = True

            if replacement == "file":
                path = root / "COPYING"
                temporary = root / ".identical-test"
                temporary.write_bytes(path.read_bytes())
                temporary.chmod(0o600)
                temporary.replace(path)

            else:
                old = root.with_name("old-test-cache")
                root.rename(old)
                root.mkdir(mode=0o700)

                for entry in old.iterdir():
                    path = root / entry.name
                    path.write_bytes(entry.read_bytes())
                    path.chmod(0o755 if entry.name == "wg" else 0o600)

    monkeypatch.setattr(generations, "_SyncPinned", Sync)

    with pytest.raises(generations.GenerationError, match="snapshot"):
        Prepare(value, intent, cached, candidate)

    assert fired and (root / "COPYING").exists()
    assert (root / "COPYING").read_bytes() == (cached / "COPYING").read_bytes()
    assert authority._Decode(guest, authority._Root(guest) / "generation.json")["phase"] == "preparing"


def test_DirectoryMembershipAbaAcrossFsyncCannotAcknowledgeAStableCache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Create-sync-unlink leaves visible names unchanged but must not acknowledge an older durable namespace."""

    _, value, intent, cached, candidate = Prepared(tmp_path, monkeypatch)
    root = generations._CachePath(guest, value["generation"]["cached_receipt"])
    synchronize = generations._SyncPinned
    fired = False

    def Sync(descriptor: int) -> None:
        nonlocal fired

        info = os.fstat(descriptor)
        linked = root.stat()

        if (info.st_dev, info.st_ino) == (linked.st_dev, linked.st_ino) and not fired:
            fired = True
            path = root / "unexpected-during-sync"
            path.write_bytes(b"retained only across the directory barrier")
            path.chmod(0o600)
            synchronize(descriptor)
            path.unlink()

            return

        synchronize(descriptor)

    monkeypatch.setattr(generations, "_SyncPinned", Sync)

    with pytest.raises(generations.GenerationError, match="snapshot"):
        Prepare(value, intent, cached, candidate)

    assert fired and not (root / "unexpected-during-sync").exists()
    assert (root / "COPYING").read_bytes() == (cached / "COPYING").read_bytes()
    assert authority._Decode(guest, authority._Root(guest) / "generation.json")["phase"] == "preparing"
