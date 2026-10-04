"""Minimal owned-resource snapshots with strict reads and atomic local persistence."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import IO

from .contracts import (
    SCHEMA_VERSION,
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateIdentifier,
    ValidateName,
    ValidateSchemaVersion,
)

MAX_JSON_BYTES = 1024 * 1024


class StateError(ContractError):
    """Owned state is malformed, mismatched, busy, or cannot be persisted safely."""


@dataclass(frozen=True)
class ResourceState:
    """Minimum provider locator for a resource recorded by one managed stack."""

    logical_id: str
    kind: str
    resource_id: str

    def __post_init__(self) -> None:
        """Keep persisted locators explicit and free of arbitrary provider payloads."""

        ValidateName(self.logical_id, "resources.logical_id")
        ValidateName(self.kind, "resources.kind")
        ValidateIdentifier(self.resource_id, "resources.resource_id")


@dataclass(frozen=True)
class StackState:
    """Immutable resource inventory scoped to a complete ownership identity."""

    identity: StackIdentity
    resources: tuple[ResourceState, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Reject duplicate locators and invalid direct model construction."""

        ValidateSchemaVersion(self.schema_version)

        if not isinstance(self.identity, StackIdentity):
            raise ContractError("identity must be a StackIdentity")

        if not isinstance(self.resources, tuple) or any(
            not isinstance(resource, ResourceState) for resource in self.resources
        ):
            raise ContractError("resources must be a tuple of ResourceState values")

        if len({resource.logical_id for resource in self.resources}) != len(self.resources):
            raise ContractError("resources.logical_id values must be unique")

        if len({(resource.kind, resource.resource_id) for resource in self.resources}) != len(
            self.resources
        ):
            raise ContractError("resources must not contain duplicate provider locators")


def _RequireIdentity(actual: StackIdentity, expected: StackIdentity) -> None:
    """Block all state operations when any ownership or provider-scope field differs."""

    if not isinstance(expected, StackIdentity) or actual != expected:
        raise StateError("State identity does not match the expected ownership boundary")


def ParseState(data: Mapping[str, object], expected_identity: StackIdentity) -> StackState:
    """Decode a versioned snapshot and require explicit caller ownership expectations."""

    try:
        ValidateFields(
            data, frozenset({"schema_version", "identity", "resources"}), frozenset(), "state"
        )
        ValidateSchemaVersion(data["schema_version"])
        identity = ParseIdentity(data["identity"])
        _RequireIdentity(identity, expected_identity)
        raw_resources = data["resources"]

        if not isinstance(raw_resources, list):
            raise ContractError("resources must be an array of tables")

        resources: list[ResourceState] = []

        for item in raw_resources:
            table = RequireTable(item, "resources")
            ValidateFields(
                table,
                frozenset({"logical_id", "kind", "resource_id"}),
                frozenset(),
                "resources",
            )
            resources.append(
                ResourceState(
                    logical_id=ValidateName(table["logical_id"], "resources.logical_id"),
                    kind=ValidateName(table["kind"], "resources.kind"),
                    resource_id=ValidateIdentifier(table["resource_id"], "resources.resource_id"),
                )
            )

        return StackState(identity=identity, resources=tuple(resources))

    except ContractError as error:
        raise StateError(str(error)) from error


def _UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON fields instead of silently accepting the last value."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise StateError("State JSON contains duplicate fields")

        result[key] = value

    return result


def _ValidatePath(path: Path) -> None:
    """Reject traversal, symlinks, and nonregular targets within caller-owned storage."""

    if not path.name or ".." in path.parts:
        raise StateError("State path must name a file without parent traversal")

    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise StateError("State path must not contain symlinks")

    if path.exists() and not path.is_file():
        raise StateError("State path must refer to a regular file")


def _OpenTextStream(descriptor: int, mode: str) -> IO[str]:
    """Transfer descriptor ownership to a stream or close it when the transfer fails."""

    try:
        return os.fdopen(descriptor, mode, encoding="utf-8")

    except BaseException:
        os.close(descriptor)

        raise


def _ReadOwnedJson(path: Path) -> object:
    """Read bounded regular JSON without blocking on a post-validation FIFO substitution."""

    opened_descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = opened_descriptor

    try:
        opened = os.fstat(opened_descriptor)

        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_JSON_BYTES:
            raise StateError("Owned JSON must be a bounded regular file")

        stream_descriptor = opened_descriptor
        descriptor = None

        with _OpenTextStream(stream_descriptor, "r") as stream:
            text = stream.read(MAX_JSON_BYTES + 1)

        if len(text.encode("utf-8")) > MAX_JSON_BYTES:
            raise StateError("Owned JSON exceeds its bounded read limit")

        return json.loads(text, object_pairs_hook=_UniqueObject)

    except FileNotFoundError as error:
        raise StateError("Unable to read an opened owned JSON file") from error

    finally:
        if descriptor is not None:
            os.close(descriptor)


def LoadState(path: str | Path, expected_identity: StackIdentity) -> StackState | None:
    """Return a strictly owned snapshot, or None only when the file is absent."""

    state_path = Path(path)

    if not isinstance(expected_identity, StackIdentity):
        raise StateError("expected_identity must be a StackIdentity")

    try:
        _ValidatePath(state_path)
        data = _ReadOwnedJson(state_path)

    except FileNotFoundError:
        return None

    except StateError:
        raise

    except (OSError, ValueError, RecursionError) as error:
        raise StateError("Unable to read a valid state snapshot") from error

    try:
        return ParseState(RequireTable(data, "state"), expected_identity)

    except ContractError as error:
        raise StateError(str(error)) from error


@contextmanager
def _StateLock(path: Path) -> Iterator[None]:
    """Serialize cooperating writers and leave crash locks for explicit operator recovery."""

    descriptor: int | None = None

    try:
        _ValidatePath(path)
        lock_path = path.with_name(f".{path.name}.lock")
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        descriptor = None

    except OSError as error:
        if descriptor is not None:
            try:
                os.close(descriptor)

            except OSError:
                pass

        raise StateError("State storage is unavailable or another writer holds its lock") from error

    try:
        yield

    finally:
        try:
            lock_path.unlink()

        except OSError as error:
            raise StateError("Unable to release the state writer lock") from error


def _SyncDirectory(path: Path) -> None:
    """Persist directory updates on platforms with a usable directory fsync operation."""

    if os.name != "posix":
        return

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def SaveState(path: str | Path, state: StackState, expected_identity: StackIdentity) -> None:
    """Atomically save owned state; never replace a foreign or malformed existing snapshot."""

    if not isinstance(state, StackState):
        raise StateError("state must be a StackState")

    _RequireIdentity(state.identity, expected_identity)
    serialized = json.dumps(asdict(state), indent=2, sort_keys=True) + "\n"

    if len(serialized.encode("utf-8")) > MAX_JSON_BYTES:
        raise StateError("Owned state snapshot exceeds its bounded JSON storage limit")

    state_path = Path(path)
    temporary_path: Path | None = None

    with _StateLock(state_path):
        LoadState(state_path, expected_identity)

        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{state_path.name}.", suffix=".tmp", dir=state_path.parent
            )
            temporary_path = Path(temporary_name)

            with _OpenTextStream(descriptor, "w") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temporary_path, state_path)
            temporary_path = None
            _SyncDirectory(state_path.parent)

        except OSError as error:
            raise StateError(
                "Unable to persist state; a completed replacement may be visible"
            ) from error

        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink(missing_ok=True)

                except OSError as error:
                    raise StateError(
                        "Unable to clean temporary state; "
                        "incomplete local cleanup requires recovery"
                    ) from error


def RemoveState(path: str | Path, expected_identity: StackIdentity) -> bool:
    """Remove only a matching local snapshot; never delete infrastructure resources."""

    state_path = Path(path)

    if not isinstance(expected_identity, StackIdentity):
        raise StateError("expected_identity must be a StackIdentity")

    try:
        _ValidatePath(state_path)

        if not state_path.parent.exists():
            return False

        with _StateLock(state_path):
            if LoadState(state_path, expected_identity) is None:
                return False

            state_path.unlink()
            _SyncDirectory(state_path.parent)

    except OSError as error:
        raise StateError("Unable to remove the owned state snapshot") from error

    return True
