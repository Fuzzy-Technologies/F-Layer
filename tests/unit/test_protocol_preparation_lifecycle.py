"""Retain private pre-plan snapshots in isolated POSIX files with every guest/kernel/build/network command intercepted."""

from __future__ import annotations

import copy
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from test_protocol_generation import Composite
from test_protocol_preparation import Request
from test_protocol_reservation import Active
from test_vpn_project_v2 import Snapshot
from test_wireguard_lifecycle import Interrupted, Seed

from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_preparation as preparations
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_generation as tools
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private snapshot durability requires POSIX; no WSL or desktop VPN is started")


def Setup(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, kind: str = "fresh") -> tuple[Any, dict[str, Any], dict[str, bytes]]:
    """Prepare a synthetic source and actual model state independently from the public preparation metadata."""

    if kind == "disable":
        model, _, origin = Active(tmpPath, monkeypatch)
        source = model.root
        cached = json.loads((source / "receipt.json").read_bytes())

    else:
        source, _, model = Seed(tmpPath, monkeypatch)
        cached = None
        origin = None

    files = {name: (source / name).read_bytes() for name in ("server.conf", "deployment.json", "install.py")}
    request, _ = Request(kind, files, cached)

    if origin is not None:
        request["origin"] = {key: value for key, value in origin.items() if key != "plan_sha256"}

    else:
        request["origin"]["wireguard_history_sha256"] = peers._History(guest, request["origin"]["owner"])

    directory = tmpPath / "varlib"
    directory.mkdir(mode=0o700)
    monkeypatch.setattr(preparations, "BASE", directory / "flayer/preparations")

    return model, request, files


def Prepare(request: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
    """The production backend runs only inside the test's intercepted guest and owned temporary paths."""

    return preparations.Prepare(guest, peers, authority, completion, tools, cache, request, files,
                                allowMutation=True, scopeConfirm=request["identity"]["scope_id"])


def Root(request: dict[str, Any]) -> Path:
    """Derive the same fixed namespace, without granting a caller-selected path."""

    return preparations.BASE / request["origin"]["owner"] / request["origin"]["operation_id"]


@pytest.mark.parametrize("kind", ["fresh", "disable"])
def test_PreparationPreservesKeysOriginalRuntimeHistoryAndServiceWhilePublishingOnlyPrivateSnapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """No service activation/removal, input/cloud operation, peer fence or original source write may occur."""

    model, request, files = Setup(tmp_path, monkeypatch, kind)
    oldRoot = Snapshot(model.root) if model.root.exists() else None
    state = (model.active, model.interface, model.network, peers._History(guest, model.owner))
    result = Prepare(request, files)
    root = Root(request)
    assert result["preparation_sha256"] == guest._Digest((root / "manifest.json").read_bytes())
    assert result["generation"]["candidate_receipt"]["nonce"] == request["origin"]["operation_id"]
    assert (model.active, model.interface, model.network, peers._History(guest, model.owner)) == state
    assert (Snapshot(model.root) if model.root.exists() else None) == oldRoot
    assert not authority._Root(guest).exists() and not guest._Paths(model.owner)[2].exists()

    for name, data in files.items():
        assert (root / "source" / name).read_bytes() == data
        assert (root / "cached" / name).read_bytes() == data
        assert (root / "candidate" / name).read_bytes() == data

    before = Snapshot(tmp_path)
    assert preparations.Status(guest, peers, authority, completion, cache, request) == result
    assert Snapshot(tmp_path) == before
    monkeypatch.setattr(tools, "PrepareFresh", lambda *args, **kwargs: pytest.fail("Known retry cannot rebuild tools"))
    monkeypatch.setattr(tools, "PrepareCached", lambda *args, **kwargs: pytest.fail("Known retry cannot replace a candidate"))
    assert Prepare(request, files) == result and Snapshot(tmp_path) == before


def test_ReenableUsesRetainedPrivateCacheWithoutFetchingBuildingOrRotatingCredentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An absent service with an exact old cache prepares only a new nonce-bound activation snapshot."""

    _, request, files = Setup(tmp_path, monkeypatch)
    first = Prepare(request, files)
    original = first["generation"]["cached_receipt"]
    root = Root(request) / "cached"
    payload = {path.name: path.read_bytes() for path in root.iterdir()}
    cache._Copy(guest, original, payload, resume=False)
    request = copy.deepcopy(request)
    request["cached_receipt"] = original
    request["origin"]["operation_id"] = "d" * 32
    monkeypatch.setattr(guest, "_Fetch", lambda *args: pytest.fail("Retained runtime cannot fetch or rebuild tools"))
    monkeypatch.setattr(guest, "_BuildTools", lambda *args: pytest.fail("Retained runtime cannot rebuild tools"))
    result = Prepare(request, files)
    assert result["generation"]["cached_receipt"] == original
    assert result["generation"]["candidate_receipt"]["files"]["wg"] == original["files"]["wg"]


@pytest.mark.parametrize("kind", ["fresh", "disable"])
def test_SelectedSnapshotsFeedTheActualExposedCachePreparationOnlyAfterFullIntentAndGenerationMatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """A pre-plan manifest alone cannot invoke the cache backend: the exact full composite still needs Reserve and Expose."""

    _, request, files = Setup(tmp_path, monkeypatch, kind)
    prepared = Prepare(request, files)
    composite, _ = Composite("disable" if kind == "disable" else "enable", version=3)
    composite["generation"] = prepared["generation"]
    intent = {**request["origin"], "plan_sha256": guest._Digest(guest._Encode(composite))}
    selected, cached, candidate = preparations.Read(guest, authority, completion, cache, request, intent, prepared["generation"])
    assert selected == prepared

    with pytest.raises(ValueError):
        cache.Prepare(guest, peers, authority, policy, composite, intent, cached, candidate, allowMutation=True, runtimeBackend=runtime)

    reserved = authority.Reserve(guest, peers, intent, allowMutation=True)
    authority.Expose(guest, peers, intent, reserved["reservation_sha256"], allowMutation=True)
    result = cache.Prepare(guest, peers, authority, policy, composite, intent, cached, candidate, allowMutation=True, runtimeBackend=runtime)
    assert result["phase"] == "prepared"
    assert preparations.Status(guest, peers, authority, completion, cache, request) == prepared


@pytest.mark.parametrize("fault", ["file", "missing", "extra", "manifest", "source-link", "candidate-link", "mode"])
def test_CompleteSnapshotDriftNeverGetsRebuiltRepairedOrAdoptedByRetry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """All private data remains in the test namespace; refusal retains the exact altered files for diagnosis."""

    _, request, files = Setup(tmp_path, monkeypatch)
    Prepare(request, files)
    root = Root(request)

    if fault == "file":
        (root / "cached/server.conf").write_bytes(b"different private bytes")
    elif fault == "missing":
        (root / "candidate/wg").unlink()
    elif fault == "extra":
        (root / "unexpected").write_bytes(b"foreign")
    elif fault == "manifest":
        value = json.loads((root / "manifest.json").read_bytes())
        value["request"]["origin"]["previous_state_sha256"] = "0" * 64
        (root / "manifest.json").write_bytes(guest._Encode(value))
    elif fault in {"source-link", "candidate-link"}:
        name = "source" if fault == "source-link" else "candidate"
        outside = root.parent / "outside"
        (root / name).rename(outside)
        (root / name).symlink_to(outside, target_is_directory=True)
    else:
        (root / "cached/wg").chmod(0o600)

    before = Snapshot(root)
    monkeypatch.setattr(tools, "PrepareFresh", lambda *args, **kwargs: pytest.fail("Unknown bytes cannot trigger a replacement build"))

    with pytest.raises((ValueError, OSError)):
        Prepare(request, files)

    assert Snapshot(root) == before


def test_InterruptedFinalDirectoryBarrierKeepsOneCompleteSnapshotAndExactRetryAfterExpiryOnlyResynchronizes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Historical retrieval is distinct from fresh mutation authority; a lost response cannot silently create another receipt."""

    _, request, files = Setup(tmp_path, monkeypatch)
    sync = guest._SyncDirectory
    root = Root(request)

    def Sync(path: Path) -> None:
        if path == root.parent and root.exists():
            raise Interrupted

        sync(path)

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)

    with pytest.raises(Interrupted):
        Prepare(request, files)

    monkeypatch.setattr(guest, "_SyncDirectory", sync)
    before = Snapshot(root)
    monkeypatch.setattr(preparations, "_Guard", lambda *args: pytest.fail("Exact historical retrieval cannot require fresh authority"))
    monkeypatch.setattr(preparations.time, "time", lambda: request["origin"]["plan_expires_at"] + 1000)
    monkeypatch.setattr(tools, "PrepareFresh", lambda *args, **kwargs: pytest.fail("Complete retry must not rebuild runtime"))
    result = preparations.Status(guest, peers, authority, completion, cache, request)
    assert Prepare(request, files) == result and Snapshot(root) == before


@pytest.mark.parametrize("fault", ["same-byte-file", "same-byte-manifest", "membership-aba"])
def test_DescriptorLeaseSurvivesRenameAndRefusesLateReplacementThroughParentFsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """The exact pre-rename descriptors remain pinned until after the final publication barrier and response checks."""

    _, request, files = Setup(tmp_path, monkeypatch)
    root = Root(request)
    sync = guest._SyncDirectory
    changed = False

    def Sync(path: Path) -> None:
        nonlocal changed

        if path == root.parent and root.exists() and not changed:
            changed = True

            if fault == "membership-aba":
                extra = root / "foreign"
                extra.write_bytes(b"unknown")
                extra.unlink()

            else:
                target = root / ("cached/server.conf" if fault == "same-byte-file" else "manifest.json")
                temporary = target.with_name("replacement")
                temporary.write_bytes(target.read_bytes())
                temporary.chmod(0o600)
                os.replace(temporary, target)

        sync(path)

    monkeypatch.setattr(guest, "_SyncDirectory", Sync)

    with pytest.raises(preparations.PreparationError):
        Prepare(request, files)

    assert changed and root.exists()


def test_AtomicPublicationCannotReplaceEvenAnEmptyForeignDestination(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No-replace rename closes the final check/rename gap independently of advisory coordination."""

    _, request, files = Setup(tmp_path, monkeypatch)
    publish = preparations._Publish
    root = Root(request)

    def Publish(guest: Any, stage: Path, destination: Path, verify: Any) -> None:
        destination.mkdir(mode=0o700)
        publish(guest, stage, destination, verify)

    monkeypatch.setattr(preparations, "_Publish", Publish)

    with pytest.raises(preparations.PreparationError):
        Prepare(request, files)

    assert root.is_dir() and not tuple(root.iterdir())


@pytest.mark.parametrize("kind", ["sealed", "scratch", "unknown"])
def test_PreparationCapacityAndUnknownNamespacesRefuseBeforeAnyBuild(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    """Abandoned scratch never becomes prepared authority, and automatic cleanup never guesses which bytes may be deleted."""

    _, request, files = Setup(tmp_path, monkeypatch)
    root = preparations._Root(guest, request, create=True)
    count = preparations.MAX_PREPARATIONS if kind == "sealed" else preparations.MAX_SCRATCH if kind == "scratch" else 1

    for index in range(count):
        name = format(index, "032x") if kind == "sealed" else ".prep-" + format(index, "032x") + "-abcdefgh" if kind == "scratch" else "foreign"
        (root.parent / name).mkdir(mode=0o700)

    before = Snapshot(preparations.BASE)
    monkeypatch.setattr(tools, "PrepareFresh", lambda *args, **kwargs: pytest.fail("Invalid namespace cannot start a build"))

    with pytest.raises(preparations.PreparationError):
        Prepare(request, files)

    assert Snapshot(preparations.BASE) == before


@pytest.mark.parametrize("fault", ["origin", "generation"])
def test_LaterCacheSelectionRequiresBothTheCompleteOriginAndTheExactPreparedGeneration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A valid placeholder or another self-consistent receipt cannot select a different private snapshot."""

    _, request, files = Setup(tmp_path, monkeypatch)
    prepared = Prepare(request, files)
    generation = copy.deepcopy(prepared["generation"])
    intent = {**request["origin"], "plan_sha256": "a" * 64}

    if fault == "origin":
        intent["previous_state_sha256"] = "0" * 64
    else:
        generation["cached_receipt"]["nonce"] = "9" * 32

    before = Snapshot(Root(request))

    with pytest.raises(ValueError):
        preparations.Read(guest, authority, completion, cache, request, intent, generation)

    assert Snapshot(Root(request)) == before


@pytest.mark.parametrize("fault", ["expiry", "history", "pending", "completed-nonce"])
def test_NewPreparationCannotBypassExpiredConsumedReservedOrCompletedOrigin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Only historical exact snapshot retrieval bypasses these guards; fresh work cannot create even its private namespace."""

    _, request, files = Setup(tmp_path, monkeypatch)

    if fault == "expiry":
        request["origin"]["plan_expires_at"] = 1
    elif fault == "history":
        monkeypatch.setattr(peers, "_History", lambda *args: "0" * 64)
    elif fault == "pending":
        monkeypatch.setattr(authority, "_Pending", lambda *args: {"phase": "reserved"})
        monkeypatch.setattr(authority, "_Authority", lambda *args: (None, request["origin"]["previous_authority_sha256"], None, 0))
    else:
        root = authority._Root(guest)
        root.mkdir(mode=0o700, parents=True)
        (root / ("done-" + request["origin"]["operation_id"] + ".json")).write_bytes(b"preserve completed operation")
        monkeypatch.setattr(authority, "_Authority", lambda *args: (None, request["origin"]["previous_authority_sha256"], None, 0))

    monkeypatch.setattr(tools, "PrepareFresh", lambda *args, **kwargs: pytest.fail("Unadmitted origin cannot build runtime tools"))

    with pytest.raises(ValueError):
        Prepare(request, files)

    assert not preparations.BASE.exists()


@pytest.mark.parametrize("fault", ["extra", "same-byte-replacement"])
def test_DriftBeforeRenameRetainsUnknownOrReplacementScratchAndLaterWorkNeverAdoptsOrDeletesIt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A failed preparation is not an ownership grant to recursively delete whatever now occupies its scratch namespace."""

    _, request, files = Setup(tmp_path, monkeypatch)
    original, fsync = preparations._Durable, os.fsync
    active: list[Path] = []
    changed = False

    @contextmanager
    def Durable(guest: Any, root: Path, payloads: dict[Path, bytes]) -> Any:
        active.append(root)

        with original(guest, root, payloads) as verify:
            yield verify

    def Fsync(descriptor: int) -> None:
        nonlocal changed

        if active and not changed:
            changed = True
            stage = active[-1]

            if fault == "extra":
                (stage / "source/foreign").write_bytes(b"preserve unknown private bytes")
            else:
                target = stage / "source/server.conf"
                replacement = target.with_name("replacement")
                replacement.write_bytes(target.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, target)

        fsync(descriptor)

    monkeypatch.setattr(preparations, "_Durable", Durable)
    monkeypatch.setattr(os, "fsync", Fsync)

    with pytest.raises(preparations.PreparationError):
        Prepare(request, files)

    assert changed and not Root(request).exists()
    stage = active[0]
    assert stage.is_dir()
    before = Snapshot(stage)
    monkeypatch.setattr(preparations, "_Durable", original)
    monkeypatch.setattr(os, "fsync", fsync)
    later = copy.deepcopy(request)
    later["origin"]["operation_id"] = "d" * 32
    assert Prepare(later, files)["generation"]["candidate_receipt"]["nonce"] == "d" * 32
    assert Snapshot(stage) == before


@pytest.mark.parametrize("action", ["status", "retry", "selection"])
def test_UnexpectedSourceFileIsPreservedAndNeverOpenedBeforeRefusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    """A closed role set must be checked before any unknown private filename is read, even inside a formerly valid snapshot."""

    _, request, files = Setup(tmp_path, monkeypatch)
    prepared = Prepare(request, files)
    root = Root(request)
    unknown = root / "source/foreign-private-file"
    unknown.write_bytes(b"preserve unknown private bytes")
    unknown.chmod(0o600)
    read = guest._Read

    def Read(path: Path, **kwargs: Any) -> bytes:
        assert path != unknown, "Unknown source roles must be refused before reading their bytes"

        return read(path, **kwargs)

    monkeypatch.setattr(guest, "_Read", Read)
    before = Snapshot(root)

    with pytest.raises(preparations.PreparationError):
        if action == "status":
            preparations.Status(guest, peers, authority, completion, cache, request)
        elif action == "retry":
            Prepare(request, files)
        else:
            preparations.Read(guest, authority, completion, cache, request, {**request["origin"], "plan_sha256": "a" * 64}, prepared["generation"])

    assert unknown.read_bytes() == b"preserve unknown private bytes" and Snapshot(root) == before


@pytest.mark.parametrize("field", ["schema", "origin-schema", "cached-schema"])
@pytest.mark.parametrize("action", ["status", "retry", "selection"])
def test_StoredRequestBooleanAndFloatAliasesCannotMasqueradeAsItsOriginalCanonicalBytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, action: str) -> None:
    """Python's True == 1 == 1.0 is not a wire-contract equality or a license to report a digest for different stored bytes."""

    _, request, files = Setup(tmp_path, monkeypatch, "disable")
    prepared = Prepare(request, files)
    root = Root(request)
    manifest = root / "manifest.json"
    value = json.loads(manifest.read_bytes())

    if field == "schema":
        value["request"]["schema_version"] = True
    elif field == "origin-schema":
        value["request"]["origin"]["schema_version"] = True
    else:
        value["request"]["cached_receipt"]["schema_version"] = 1.0

    manifest.write_bytes(guest._Encode(value))
    assert prepared["preparation_sha256"] != guest._Digest(manifest.read_bytes())
    before = Snapshot(root)

    with pytest.raises(preparations.PreparationError):
        if action == "status":
            preparations.Status(guest, peers, authority, completion, cache, request)
        elif action == "retry":
            Prepare(request, files)
        else:
            preparations.Read(guest, authority, completion, cache, request, {**request["origin"], "plan_sha256": "a" * 64}, prepared["generation"])

    assert Snapshot(root) == before


def test_RenameMetadataRefreshCannotHideMembershipAbaInThePublishedSnapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the renamed directory's ctime may change; its content size/mtime are not part of the expected rename mutation."""

    _, request, files = Setup(tmp_path, monkeypatch)
    publish = preparations._Publish
    changed = False

    def Publish(guest: Any, stage: Path, destination: Path, verify: Any) -> None:
        def Verify(published: Path | None = None) -> None:
            nonlocal changed

            if published is not None:
                extra = published / "foreign"
                extra.write_bytes(b"unknown")
                extra.unlink()
                changed = True

            verify(published)

        publish(guest, stage, destination, Verify)

    monkeypatch.setattr(preparations, "_Publish", Publish)

    with pytest.raises(preparations.PreparationError):
        Prepare(request, files)

    assert changed and Root(request).exists()
