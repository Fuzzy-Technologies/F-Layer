"""Bind actual POSIX input journals to complete versioned recovery caches using intercepted native effects."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
from test_host_input_transaction import Delta, InputModel
from test_protocol_generation_cache import Prepare, Prepared
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer import _vpn_host_input as host
from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as generations
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Pinned recovery/input fixtures require POSIX; no WSL, VPN client or real network is used")


def Environment(
    tmpPath: Path, monkeypatch: pytest.MonkeyPatch, change: str = "disable", version: int = 2,
) -> tuple[Any, InputModel, dict[str, Any], dict[str, Any], Path, Path | None]:
    """Expose one real common reservation while modeling boot/live input separately from WG forwarding."""

    model, request, intent, cached, candidate = Prepared(tmpPath, monkeypatch, change, version)
    transition = Delta()

    if change == "enable":
        before = host.InputPolicy(transition.before.identity, transition.before.creationSha256, transition.before.originalBootSha256,
                                  transition.before.managementCidrs, transition.before.listeners[:-1], "d" * 32)
        transition = host.InputTransition(before, transition.listener, "enable", transition.operationId)

    assert transition.Record() == request["input"]
    boot = tmpPath / "etc/nftables.conf"
    boot.parent.mkdir(mode=0o755, exist_ok=True)
    boot.write_bytes(transition.before.BootFile())
    boot.chmod(0o644)
    monkeypatch.setattr(inputs, "BOOT", boot)
    network = InputModel(guest._Run, transition)
    monkeypatch.setattr(guest, "_Run", network.Run)

    return model, network, request, intent, cached, candidate


def InputPrepare(request: dict[str, Any], intent: dict[str, Any]) -> dict[str, str]:
    """Use explicit trusted cache coordination; no JSON field can select or skip that backend."""

    return inputs.Prepare(guest, peers, authority, policy, request, intent, allowMutation=True, generationCache=generations)


def InputApply(request: dict[str, Any], intent: dict[str, Any], *, rollback: bool = False) -> dict[str, str]:
    """Keep both caches pinned throughout boot publication, native input replacement and final journal publication."""

    return inputs.Apply(guest, peers, authority, policy, request, intent, allowMutation=True, rollback=rollback, generationCache=generations)


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_InputCannotPrepareUntilBothExactRecoveryCachesAreDurable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Preparing a port change never precedes preserving its activation/restoration keys and compiled runtime."""

    model, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch, change)
    before = Snapshot(tmp_path)

    with pytest.raises(generations.GenerationError):
        InputPrepare(request, intent)

    assert Snapshot(tmp_path) == before and network.mutations == 0
    Prepare(request, intent, cached, candidate)
    prepared = InputPrepare(request, intent)
    assert prepared["phase"] == "prepared" and network.mutations == 0
    assert InputPrepare(request, intent) == prepared
    root = Snapshot(model.root) if model.root.exists() else {}
    history = peers._History(guest, model.owner)
    assert InputApply(request, intent)["phase"] == "applied" and network.current == 1
    assert InputApply(request, intent)["phase"] == "applied" and network.mutations == 1
    assert InputApply(request, intent, rollback=True)["phase"] == "rolled-back" and network.current == 2
    assert peers._History(guest, model.owner) == history
    assert (Snapshot(model.root) if model.root.exists() else {}) == root
    snapshot = Snapshot(tmp_path)
    assert inputs.Status(guest, peers, authority, policy, request, intent, generationCache=generations)["phase"] == "rolled-back"
    assert Snapshot(tmp_path) == snapshot


@pytest.mark.parametrize("change", ["enable", "disable"])
@pytest.mark.parametrize("boundary", ["cache-write", "cache-before-prepared"])
def test_InterruptedRecoveryPreparationCannotAuthorizeTheHostInputJournal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, boundary: str,
) -> None:
    """Known complete files alone do not replace the exact durable prepared-generation publication."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch, change)
    publish = authority._Publish
    write = generations._File

    def Publish(backend: Any, filename: str, record: dict[str, Any], **options: Any) -> None:
        if boundary == "cache-before-prepared" and filename == "generation.json" and record["phase"] == "prepared":
            raise Interrupted

        publish(backend, filename, record, **options)

    def File(backend: Any, path: Path, content: bytes, mode: int, *, resume: bool) -> None:
        write(backend, path, content, mode, resume=resume)

        if boundary == "cache-write":
            raise Interrupted

    monkeypatch.setattr(authority, "_Publish", Publish)
    monkeypatch.setattr(generations, "_File", File)

    with pytest.raises(Interrupted):
        Prepare(request, intent, cached, candidate)

    before = Snapshot(tmp_path)

    with pytest.raises(generations.GenerationError):
        InputPrepare(request, intent)

    assert Snapshot(tmp_path) == before and network.mutations == 0


@pytest.mark.parametrize("change", ["enable", "disable"])
@pytest.mark.parametrize("rollback", [True, False])
@pytest.mark.parametrize("fault", ["cached-body", "candidate-body", "journal-request", "journal-history", "journal-missing", "backend-missing"])
def test_ChangedRecoveryAuthorityRefusesBeforeAnyFurtherInputPublication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, rollback: bool, fault: str,
) -> None:
    """An existing prepared input journal never grants a bypass around missing, copied or changed recovery state."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch, change)
    Prepare(request, intent, cached, candidate)
    InputPrepare(request, intent)

    if rollback:
        InputApply(request, intent)

    journal = authority._Root(guest) / "generation.json"

    if fault.endswith("-body"):
        receipt = request["generation"]["cached_receipt" if fault == "cached-body" else "candidate_receipt"]
        (generations._CachePath(guest, receipt) / "server.conf").write_bytes(b"changed-private-canary")

    elif fault == "journal-missing":
        journal.unlink()

    elif fault.startswith("journal-"):
        record = authority._Decode(guest, journal)

        if fault == "journal-history":
            record["history_sha256"] = "9" * 64

        else:
            record["request"]["cloud_plan_sha256"] = "9" * 64

        journal.write_bytes(guest._Encode(record))

    before = Snapshot(tmp_path)
    mutations = network.mutations

    with pytest.raises(ValueError):
        inputs.Apply(guest, peers, authority, policy, request, intent, allowMutation=True, rollback=rollback,
                     generationCache=None if fault == "backend-missing" else generations)

    assert Snapshot(tmp_path) == before and network.mutations == mutations


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_OldCacheOnlyRequestsStayReadableButCannotGainInputMutationAuthority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Migration is explicit: a new recovery candidate cannot be attached beneath a previously exposed old plan hash."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch, change, 1)
    assert Prepare(request, intent, cached, candidate)["phase"] == "prepared"
    before = Snapshot(tmp_path)

    with pytest.raises(inputs.InputError):
        InputPrepare(request, intent)

    assert Snapshot(tmp_path) == before and network.mutations == 0


@pytest.mark.parametrize("fault", ["prepared-temporary", "journal-fsync", "journal-directory-fsync"])
def test_VisiblePreparedJournalRequiresDurabilityBeforeAnyInputPublication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """A complete visible crash prefix is not mutation authority until explicit cache recovery makes it durable."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Prepare(request, intent, cached, candidate)
    root = authority._Root(guest)
    journal = root / "generation.json"
    record = authority._Decode(guest, journal)

    if fault == "prepared-temporary":
        temporary = root / ".generation.json.new"
        temporary.write_bytes(guest._Encode(record))
        temporary.chmod(0o600)
        journal.write_bytes(guest._Encode({**record, "phase": "preparing"}))

    sync = authority._SyncFile
    syncDirectory = guest._SyncDirectory
    journalSynced = False

    def Sync(backend: Any, path: Path, content: bytes) -> None:
        nonlocal journalSynced

        if fault == "journal-fsync" and path == journal:
            raise Interrupted

        sync(backend, path, content)

        if path == journal:
            journalSynced = True

    def SyncDirectory(path: Path) -> None:
        if fault == "journal-directory-fsync" and path == root and journalSynced:
            raise Interrupted

        syncDirectory(path)

    monkeypatch.setattr(authority, "_SyncFile", Sync)
    monkeypatch.setattr(guest, "_SyncDirectory", SyncDirectory)
    before = Snapshot(tmp_path)

    with pytest.raises((generations.GenerationError, Interrupted)):
        InputPrepare(request, intent)

    assert Snapshot(tmp_path) == before and network.mutations == 0
    assert not (root / "input.json").exists() and not (root / ".input.json.new").exists()

    if fault == "prepared-temporary":
        assert Prepare(request, intent, None, None)["phase"] == "prepared"
        assert InputPrepare(request, intent)["phase"] == "prepared"


@pytest.mark.parametrize("fault", ["removed", "changed", "same-bytes-replacement", "temporary"])
def test_JournalDriftDuringNativeInputWriteCannotPublishATerminalAcknowledgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Prepared authority stays bound throughout the actual write, not just when Ready is first entered."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Prepare(request, intent, cached, candidate)
    InputPrepare(request, intent)
    run = guest._Run
    root = authority._Root(guest)
    journal = root / "generation.json"
    original = journal.read_bytes()

    def Run(command: list[str], **options: Any) -> tuple[int, bytes]:
        result = run(command, **options)

        if command == ["nft", "-f", "-"]:
            if fault == "removed":
                journal.unlink()

            elif fault == "changed":
                journal.write_bytes(guest._Encode({**authority._Decode(guest, journal), "history_sha256": "9" * 64}))

            else:
                temporary = root / (".generation.json.new" if fault == "temporary" else "replacement")
                temporary.write_bytes(original)
                temporary.chmod(0o600)

                if fault == "same-bytes-replacement":
                    os.replace(temporary, journal)

        return result

    monkeypatch.setattr(guest, "_Run", Run)

    with pytest.raises((generations.GenerationError, OSError)):
        InputApply(request, intent)

    record = authority._Decode(guest, root / "input.json")
    assert record["phase"] == "applying" and network.current == 1 and network.mutations == 1


def test_CacheReplacementDuringNativeInputWriteDoesNotPublishATerminalJournal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pinned inode checks cover the actual mutation interval, leaving its known applying prefix for explicit recovery."""

    _, network, request, intent, cached, candidate = Environment(tmp_path, monkeypatch)
    Prepare(request, intent, cached, candidate)
    InputPrepare(request, intent)
    run = guest._Run
    receipt = request["generation"]["candidate_receipt"]
    path = generations._CachePath(guest, receipt) / "server.conf"
    original = path.read_bytes()

    def Run(command: list[str], **options: Any) -> tuple[int, bytes]:
        result = run(command, **options)

        if command == ["nft", "-f", "-"]:
            replacement = path.with_name("replacement")
            replacement.write_bytes(original)
            replacement.chmod(0o600)
            os.replace(replacement, path)

        return result

    monkeypatch.setattr(guest, "_Run", Run)

    with pytest.raises(generations.GenerationError):
        InputApply(request, intent)

    record = authority._Decode(guest, authority._Root(guest) / "input.json")
    assert record["phase"] == "applying" and network.current == 1 and network.mutations == 1
