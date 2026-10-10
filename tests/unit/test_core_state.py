"""Owned-state round trips and persistence failure paths without cloud operations."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, replace
from pathlib import Path
from typing import IO

import pytest

from flayer.core.contracts import ContractError, StackIdentity
from flayer.core.state import (
    LoadState,
    ParseState,
    RemoveState,
    ResourceState,
    SaveState,
    StackState,
    StateError,
)


def ExampleState() -> StackState:
    """Create an inventory of synthetic locators that cannot address real infrastructure."""

    return StackState(
        identity=StackIdentity("example", "demo", "example-cloud", "example-scope", "owner"),
        resources=(ResourceState("gateway", "instance", "example-instance"),),
    )


def test_AtomicRoundTripAndOwnedRemoval(tmp_path: Path) -> None:
    """State can be replaced and removed only using its complete explicit identity."""

    state = ExampleState()
    path = tmp_path / "nested" / "state.json"

    assert LoadState(path, state.identity) is None, "Missing state unexpectedly became a default"

    SaveState(path, state, state.identity)
    loaded = LoadState(path, state.identity)

    assert loaded == state, "State round trip changed resource ownership or locators"
    assert json.loads(path.read_text(encoding="utf-8")) == asdict(state) | {
        "resources": [asdict(resource) for resource in state.resources]
    }, "Persisted state contains unexpected payloads"

    replacement = replace(state, resources=())
    SaveState(path, replacement, state.identity)

    assert LoadState(path, state.identity) == replacement, "Atomic replacement kept stale resources"
    assert RemoveState(path, state.identity), "Owned state was not removed"
    assert not RemoveState(path, state.identity), "Missing state should be an idempotent no-op"
    assert list(path.parent.iterdir()) == [], "Persistence left temporary or lock files behind"


def test_MissingParentRemovalCreatesNoStorage(tmp_path: Path) -> None:
    """Removing absent state does not create directories or artifacts."""

    path = tmp_path / "missing" / "state.json"

    assert not RemoveState(path, ExampleState().identity), "Missing parent should be a no-op"
    assert not path.parent.exists(), "Removal created a directory for absent state"


@pytest.mark.parametrize(
    ("field", "value"),
    [("project", "other"), ("stack", "other"), ("provider", "other"),
     ("scope_id", "other-scope"), ("owner_id", "other-owner")],
)
def test_EveryIdentityDimensionGuardsReadSaveAndRemove(
    tmp_path: Path, field: str, value: str
) -> None:
    """No ownership dimension can be ignored during local state operations."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()
    foreign_identity = replace(state.identity, **{field: value})

    with pytest.raises(StateError, match="ownership"):
        LoadState(path, foreign_identity)

    with pytest.raises(StateError, match="ownership"):
        SaveState(path, replace(state, identity=foreign_identity), foreign_identity)

    with pytest.raises(StateError, match="ownership"):
        SaveState(path, state, foreign_identity)

    with pytest.raises(StateError, match="ownership"):
        RemoveState(path, foreign_identity)

    assert path.read_bytes() == original, "An identity mismatch modified foreign state"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], "Lock cleanup failed"


@pytest.mark.parametrize(
    "content",
    [b"", b"{", b"\xff", b"[]", b"null", b'{"schema_version":1,"schema_version":1}',
     b'{"schema_version":1,"identity":{},"resources":[]}',
     b'{"schema_version":' + b"9" * 5000 + b'}',
     b'{' + b'"nested":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}'],
)
def test_CorruptExistingStateNeverBecomesEmptyOrOverwritten(tmp_path: Path, content: bytes) -> None:
    """Unreadable state blocks load, save, and remove without losing recovery evidence."""

    path = tmp_path / "state.json"
    path.write_bytes(content)
    state = ExampleState()

    with pytest.raises(StateError):
        LoadState(path, state.identity)

    with pytest.raises(StateError):
        SaveState(path, state, state.identity)

    with pytest.raises(StateError):
        RemoveState(path, state.identity)

    assert path.read_bytes() == content, "Corrupt state was discarded or overwritten"


@pytest.mark.parametrize("schema_version", [True, 0, 2, "1"])
def test_StateSchemaIsStrict(schema_version: object) -> None:
    """Unknown state versions require explicit migration rather than silent coercion."""

    state = ExampleState()
    data = json.loads(json.dumps(asdict(state)))
    data["schema_version"] = schema_version

    with pytest.raises(StateError, match="schema_version"):
        ParseState(data, state.identity)


@pytest.mark.parametrize("section", ["state", "identity", "resources"])
def test_UnexpectedStatePayloadsAreRejected(section: str) -> None:
    """State has a closed minimum schema excluding secrets and provider payloads."""

    state = ExampleState()
    data = json.loads(json.dumps(asdict(state)))
    table = data if section == "state" else data[section]

    if section == "resources":
        table = table[0]

    table["token"] = "synthetic-secret"

    with pytest.raises(StateError, match="unknown") as captured:
        ParseState(data, state.identity)

    assert "synthetic-secret" not in str(captured.value), "State error echoed a secret payload"


@pytest.mark.parametrize("resources", [None, "wrong", [None], [{"logical_id": "gateway"}]])
def test_MalformedResourceInventoryFailsClosed(resources: object) -> None:
    """Malformed inventories are never interpreted as having no owned resources."""

    state = ExampleState()
    data = json.loads(json.dumps(asdict(state)))
    data["resources"] = resources

    with pytest.raises(StateError):
        ParseState(data, state.identity)


def test_StateModelRejectsDuplicateLogicalIdsAndProviderLocators() -> None:
    """One resource locator must never be managed twice through an ambiguous inventory."""

    state = ExampleState()
    resource = state.resources[0]

    with pytest.raises(ContractError, match="logical_id"):
        replace(state, resources=(resource, replace(resource, resource_id="another-instance")))

    with pytest.raises(ContractError, match="provider locators"):
        replace(state, resources=(resource, replace(resource, logical_id="another")))

    with pytest.raises(ContractError, match="StackIdentity"):
        StackState(identity="wrong")  # type: ignore[arg-type]

    with pytest.raises(ContractError, match="tuple"):
        replace(state, resources=("wrong",))

    with pytest.raises(ContractError, match="resource_id"):
        replace(resource, resource_id="")


@pytest.mark.parametrize("operation", [LoadState, SaveState, RemoveState])
def test_SymlinkTargetsCannotRedirectState(tmp_path: Path, operation: object) -> None:
    """Even a matching state snapshot cannot authorize following a storage symlink."""

    state = ExampleState()
    target = tmp_path / "target.json"
    link = tmp_path / "state.json"
    SaveState(target, state, state.identity)
    original = target.read_bytes()
    link.symlink_to(target)

    with pytest.raises(StateError, match="symlinks"):
        if operation is SaveState:
            SaveState(link, state, state.identity)

        elif operation is LoadState:
            LoadState(link, state.identity)

        else:
            RemoveState(link, state.identity)

    assert target.read_bytes() == original, "A symlink redirected state mutation"


def test_SymlinkParentAndTraversalPathsAreRejected(tmp_path: Path) -> None:
    """State storage cannot escape through a linked directory or parent traversal."""

    state = ExampleState()
    directory = tmp_path / "owned"
    directory.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(directory, target_is_directory=True)

    with pytest.raises(StateError, match="symlinks"):
        SaveState(link / "state.json", state, state.identity)

    with pytest.raises(StateError, match="traversal"):
        SaveState(directory / ".." / "state.json", state, state.identity)

    with pytest.raises(StateError, match="regular file"):
        LoadState(directory, state.identity)

    with pytest.raises(StateError, match="must name a file"):
        LoadState(Path("."), state.identity)

    with pytest.raises(StateError, match="must name a file"):
        SaveState(Path("."), state, state.identity)

    with pytest.raises(StateError, match="must name a file"):
        RemoveState(Path("."), state.identity)


def test_ExistingWriterLockBlocksMutation(tmp_path: Path) -> None:
    """Concurrent writers and stale crash locks fail closed without forced lock deletion."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()
    lock_path = tmp_path / ".state.json.lock"
    lock_path.write_text("", encoding="utf-8")

    with pytest.raises(StateError, match="lock"):
        SaveState(path, replace(state, resources=()), state.identity)

    with pytest.raises(StateError, match="lock"):
        RemoveState(path, state.identity)

    assert lock_path.exists(), "A concurrent writer lock was forcibly removed"
    assert path.read_bytes() == original, "A locked state snapshot was changed"


def test_ReplaceFailurePreservesPreviousStateAndCleansArtifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure before commit preserves the old snapshot and removes local temporary files."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()

    def RejectReplace(source: object, destination: object) -> None:
        """Inject a deterministic filesystem failure before the atomic commit point."""

        raise OSError("synthetic replacement failure")

    monkeypatch.setattr("flayer.core.state.os.replace", RejectReplace)

    with pytest.raises(StateError, match="persist"):
        SaveState(path, replace(state, resources=()), state.identity)

    assert path.read_bytes() == original, "Failed replacement lost the previous snapshot"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], (
        "Temporary file leaked"
    )


def test_FileSyncFailurePreservesOldState(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A durability failure before replace cannot corrupt an already persisted state file."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()

    def RejectSync(descriptor: int) -> None:
        """Inject a deterministic failure when flushing the new snapshot."""

        raise OSError("synthetic file sync failure")

    monkeypatch.setattr("flayer.core.state.os.fsync", RejectSync)

    with pytest.raises(StateError, match="persist"):
        SaveState(path, replace(state, resources=()), state.identity)

    assert path.read_bytes() == original, "Failed file sync committed a new snapshot"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], (
        "Temporary file leaked"
    )


@pytest.mark.skipif(os.name != "posix", reason="Directory fsync is a POSIX persistence contract")
def test_DirectorySyncFailureReportsPossiblyCommittedState(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after replace is reported as uncertain while preserving a readable new snapshot."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    replacement = replace(state, resources=())
    original_sync = os.fsync
    calls = 0

    def RejectDirectorySync(descriptor: int) -> None:
        """Let file flush succeed and fail the subsequent directory durability flush."""

        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError("synthetic directory sync failure")

        original_sync(descriptor)

    monkeypatch.setattr("flayer.core.state.os.fsync", RejectDirectorySync)

    with pytest.raises(StateError, match="completed replacement may be visible"):
        SaveState(path, replacement, state.identity)

    assert LoadState(path, state.identity) == replacement, (
        "Post-commit failure lost the new snapshot"
    )
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], "Writer lock leaked"


def test_ReadAndLockErrorsAreReportedWithoutDefaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Filesystem access failures are distinct from a missing state snapshot."""

    state = ExampleState()
    path = tmp_path / "state.json"

    def RejectOpen(*args: object, **kwargs: object) -> int:
        """Inject access-denied behavior without relying on host user permissions."""

        raise PermissionError("synthetic permission failure")

    monkeypatch.setattr("flayer.core.state.os.open", RejectOpen)

    with pytest.raises(StateError, match="read"):
        LoadState(path, state.identity)

    with pytest.raises(StateError, match="storage"):
        SaveState(path, state, state.identity)


@pytest.mark.parametrize("operation", ["read", "save"])
@pytest.mark.parametrize("failure_type", [OSError, FileNotFoundError])
def test_StreamCreationFailureClosesDescriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    failure_type: type[OSError],
) -> None:
    """Failed descriptor-to-stream ownership transfer closes the resource on both paths."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()
    descriptors: list[int] = []
    original_fdopen = os.fdopen

    def RejectStream(descriptor: int, mode: str, encoding: str) -> IO[str]:
        """Record a descriptor and inject failure before a stream takes ownership of it."""

        if operation == "save" and mode == "r":
            return original_fdopen(descriptor, mode, encoding=encoding)

        descriptors.append(descriptor)

        raise failure_type("synthetic stream creation failure")

    monkeypatch.setattr("flayer.core.state.os.fdopen", RejectStream)

    with pytest.raises(StateError, match="read" if operation == "read" else "persist"):
        if operation == "read":
            LoadState(path, state.identity)

        else:
            SaveState(path, replace(state, resources=()), state.identity)

    assert descriptors, "Injected stream creation failure was not exercised"

    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)

    assert path.read_bytes() == original, "Stream creation failure replaced previous state"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], (
        "Cleanup leaked artifacts"
    )


def test_TemporaryAllocationFailureReleasesWriterLock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Storage allocation failure cannot leave a cooperating writer permanently locked out."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()

    def RejectTemporary(*args: object, **kwargs: object) -> tuple[int, str]:
        """Fail before a temporary descriptor or path exists."""

        raise OSError("synthetic temporary allocation failure")

    monkeypatch.setattr("flayer.core.state.tempfile.mkstemp", RejectTemporary)

    with pytest.raises(StateError, match="persist"):
        SaveState(path, replace(state, resources=()), state.identity)

    assert path.read_bytes() == original, "Allocation failure changed previous state"
    assert sorted(item.name for item in tmp_path.iterdir()) == ["state.json"], "Writer lock leaked"


def test_TemporaryCleanupFailureRaisesStateErrorWithRecoveryEvidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A denied cleanup reports an explicit domain error and leaves the prior snapshot intact."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original = path.read_bytes()
    original_unlink = Path.unlink

    def RejectReplace(source: object, destination: object) -> None:
        """Force a pre-commit failure requiring pending snapshot cleanup."""

        raise OSError("synthetic replacement failure")

    def RejectTemporaryCleanup(self: Path, missing_ok: bool = False) -> None:
        """Allow lock release while denying deletion of the temporary snapshot."""

        if self.suffix == ".tmp":
            raise OSError("synthetic temporary cleanup failure")

        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr("flayer.core.state.os.replace", RejectReplace)
    monkeypatch.setattr(Path, "unlink", RejectTemporaryCleanup)

    with pytest.raises(StateError, match="incomplete local cleanup requires recovery") as captured:
        SaveState(path, replace(state, resources=()), state.identity)

    assert isinstance(captured.value.__cause__, OSError), "Cleanup failure cause was lost"
    assert path.read_bytes() == original, "Failed cleanup discarded the previous state"
    assert any(item.suffix == ".tmp" for item in tmp_path.iterdir()), "Recovery artifact was lost"
    assert not (tmp_path / ".state.json.lock").exists(), "Temporary cleanup failure leaked the lock"


def test_LockCleanupFailureIsReportedAfterSuccessfulCommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed snapshot remains readable when failed lock cleanup requires recovery."""

    state = ExampleState()
    path = tmp_path / "state.json"
    original_unlink = Path.unlink

    def RejectLockCleanup(self: Path, missing_ok: bool = False) -> None:
        """Deny writer lock removal while allowing other storage cleanup."""

        if self.name == ".state.json.lock":
            raise OSError("synthetic lock cleanup failure")

        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", RejectLockCleanup)

    with pytest.raises(StateError, match="release the state writer lock"):
        SaveState(path, state, state.identity)

    assert LoadState(path, state.identity) == state, (
        "Lock cleanup failure lost a committed snapshot"
    )
    assert (tmp_path / ".state.json.lock").exists(), (
        "Failed cleanup silently removed recovery evidence"
    )


def test_RemoveFailurePreservesSnapshotAndReleasesLock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unlink failure reports the domain error without deleting ownership evidence."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)
    original_unlink = Path.unlink

    def RejectSnapshotRemoval(self: Path, missing_ok: bool = False) -> None:
        """Allow lock cleanup while failing the owned snapshot removal."""

        if self == path:
            raise OSError("synthetic snapshot removal failure")

        original_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", RejectSnapshotRemoval)

    with pytest.raises(StateError, match="remove the owned state snapshot"):
        RemoveState(path, state.identity)

    assert LoadState(path, state.identity) == state, "Removal failure lost the owned snapshot"
    assert not (tmp_path / ".state.json.lock").exists(), "Removal failure leaked a writer lock"


def test_MissingExpectedIdentityAndWrongModelsFailBeforeWriting(tmp_path: Path) -> None:
    """State operations require typed expectations even when no snapshot exists yet."""

    state = ExampleState()
    path = tmp_path / "state.json"

    with pytest.raises(StateError, match="expected_identity"):
        LoadState(path, None)  # type: ignore[arg-type]

    with pytest.raises(StateError, match="expected_identity"):
        RemoveState(path, None)  # type: ignore[arg-type]

    with pytest.raises(StateError, match="StackState"):
        SaveState(path, "wrong", state.identity)  # type: ignore[arg-type]

    with pytest.raises(StateError, match="ownership"):
        SaveState(path, state, None)  # type: ignore[arg-type]

    assert not path.exists(), "Invalid model or ownership expectation created state"


@pytest.mark.skipif(
    os.name != "posix", reason="POSIX mode bits do not express Windows ACL behavior"
)
def test_StateFilesHaveOwnerOnlyPermissions(tmp_path: Path) -> None:
    """Atomic replacements keep provider locators private to the local operating-system owner."""

    state = ExampleState()
    path = tmp_path / "state.json"
    SaveState(path, state, state.identity)

    assert path.stat().st_mode & 0o777 == 0o600, "Persisted state is readable by other local users"
