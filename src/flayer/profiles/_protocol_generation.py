"""Freeze exact WG cache/generation bytes beneath one exposed composite protocol reservation."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

MAX_REQUEST_BYTES = 32768
MAX_CACHE_BYTES = 12 * 1024 * 1024
_SOURCE_FILES = frozenset({"server.conf", "deployment.json", "install.py"})


class GenerationError(ValueError):
    """A fixed transaction diagnostic without private cache bodies or native output."""


def Request(guest: Any, policy: Any, value: object, intent: dict[str, Any]) -> dict[str, Any]:
    """Bind complete generation metadata, cloud plan and exact input delta before any guest or filesystem access."""

    fields = {"schema_version", "cloud_plan_sha256", "input", "generation"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 2
            or type(value["cloud_plan_sha256"]) is not str or guest._HASH.fullmatch(value["cloud_plan_sha256"]) is None):
        raise GenerationError("Generation requires its closed composite protocol plan")

    before, after, _ = policy.Transition(value["input"])
    generation = guest._GenerationRecord(value["generation"], intent)

    if (value["input"]["listener"]["transport"] != "wireguard" or value["input"]["change"] != generation["change"]
            or policy.Owner(before) != intent["owner"] or before["creation_sha256"] != intent["creation_sha256"]
            or after["operation_id"] != intent["operation_id"] or policy.Digest(policy.Json(value)) != intent["plan_sha256"]
            or len(policy.Json(value)) > MAX_REQUEST_BYTES):
        raise GenerationError("Generation plan differs from its exact owner, source, operation or reserved composite hash")

    return cast(dict[str, Any], policy.Decode(policy.Json(value)))


def _Reservation(guest: Any, peer: Any, authority: Any, intent: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Require the exposed exact common authority and original actual WG state under common then WG locks."""

    pending = authority._Pending(guest, intent)
    head, digest, _, _ = authority._Authority(guest, intent, pending)

    if pending is None or pending["phase"] != "exposed" or pending["parent"] != head or digest != intent["previous_authority_sha256"]:
        raise GenerationError("Generation preparation requires its exact current exposed reservation")

    _, history = authority._Observe(guest, peer, intent)

    if history != authority._FencedHistory(guest, intent, pending["deployment_sha256"]):
        raise GenerationError("Generation preparation has stale WG authority")

    return pending, history


def _Expected(guest: Any, intent: dict[str, Any], request: dict[str, Any], history: str) -> dict[str, Any]:
    """Retain only bounded public hashes and the full exact recovery request in a fixed common journal."""

    return {"schema_version": 1, "intent_sha256": guest._Digest(guest._Encode(intent)), "request": request, "history_sha256": history}


def _Load(guest: Any, authority: Any, expected: dict[str, Any]) -> dict[str, Any] | None:
    """Recognize only exact preparing-to-prepared publication, preserving foreign or partial journal bytes."""

    values = []

    for filename in ("generation.json", ".generation.json.new"):
        path = authority._Root(guest) / filename

        if path.exists() or path.is_symlink():
            value = authority._Decode(guest, path)

            if (set(value) != {*expected, "phase"} or guest._Encode({key: item for key, item in value.items() if key != "phase"}) != guest._Encode(expected)
                    or type(value["phase"]) is not str or value["phase"] not in {"preparing", "prepared"}):
                raise GenerationError("Generation journal is foreign, partial or differs from its reserved request")

            values.append(value)

    if len(values) == 2 and values[0] != values[1] and (values[0]["phase"], values[1]["phase"]) != ("preparing", "prepared"):
        raise GenerationError("Generation publication is outside its exact forward prefix")

    return values[-1] if values else None


def _Source(guest: Any, path: Path, receipt: dict[str, Any], listener: dict[str, Any]) -> dict[str, bytes]:
    """Read complete pinned private source bytes without executing the retained installer or accepting path aliases."""

    if not path.is_absolute() or path != path.resolve(strict=True):
        raise GenerationError("Generation source requires its canonical private path")

    guest._Directory(path, private=True)
    observed = guest._Receipt(path, path / ".unpublished-unit", receipt["owner"], staged=True)
    request = guest._Request(path)[0]

    if (guest._Read(path / "receipt.json") != guest._Encode(receipt) or observed != receipt
            or request["port"] != listener["port"]):
        raise GenerationError("Private generation source differs from its exact receipt or listener")

    guest._KernelMatches(receipt)
    payload = {name: guest._Read(path / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                               mode=0o755 if name == "wg" else 0o600) for name in receipt["files"]}

    if (any(guest._Digest(content) != receipt["files"][name] for name, content in payload.items())
            or sum(map(len, payload.values())) + len(guest._Encode(receipt)) > MAX_CACHE_BYTES):
        raise GenerationError("Private generation source changed or exceeds its bounded cache size")

    payload["receipt.json"] = guest._Encode(receipt)

    return payload


def _CachePath(guest: Any, receipt: dict[str, Any]) -> Path:
    """Derive only one owner-bound complete-receipt content address; a cache never grants protocol authority."""

    return cast(Path, guest.BASE.parent / "wireguard-cache" / receipt["owner"] / guest._Digest(guest._Encode(receipt)))


def _Directories(guest: Any, path: Path, *, create: bool) -> None:
    """Validate every private cache ancestor and re-sync visible creation boundaries before prepared authority."""

    for directory in (guest.BASE.parent.parent, guest.BASE.parent, path.parent.parent, path.parent, path):
        if create or directory.exists() or directory.is_symlink():
            guest._Directory(directory, create=create, private=directory not in {guest.BASE.parent.parent, guest.BASE.parent})

    if create:
        for directory in (path, path.parent, path.parent.parent, guest.BASE.parent, guest.BASE.parent.parent, guest.BASE.parent.parent.parent):
            guest._SyncDirectory(directory)


def _Prefix(guest: Any, receipt: dict[str, Any], *, partial: bool, payload: dict[str, bytes] | None = None) -> set[str]:
    """Verify every retained private prefix file; a published receipt requires all complete file pins."""

    path = _CachePath(guest, receipt)
    _Directories(guest, path, create=False)

    if not path.exists():
        if partial:
            return set()

        raise GenerationError("Prepared generation cache is absent")

    names = {item.name for item in path.iterdir()}

    if not names <= set(receipt["files"]) | {"receipt.json"}:
        raise GenerationError("Generation cache contains unknown entries")

    for name in names:
        content = _ReadPrefix(guest, path / name, 8 * 1024 * 1024 if name == "wg" else 1048576, 0o755 if name == "wg" else 0o600)

        exact = content == guest._Encode(receipt) if name == "receipt.json" else guest._Digest(content) == receipt["files"][name]

        if not exact and not (partial and payload is not None and len(content) < len(payload[name]) and payload[name].startswith(content)):
            raise GenerationError("Generation cache prefix has foreign or changed bytes")

    if (not partial or "receipt.json" in names and payload is None) and names != set(receipt["files"]) | {"receipt.json"}:
        raise GenerationError("Published generation cache is incomplete")

    return names


def _ReadPrefix(guest: Any, path: Path, limit: int, mode: int) -> bytes:
    """Read even an empty crash prefix only through one bounded owned inode; this grants no completed file proof."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
                or not 0 <= info.st_size <= limit):
            raise GenerationError("Generation cache prefix has unsafe ownership or size")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)

        current = os.fstat(descriptor)

        if (len(content) > limit or (info.st_dev, info.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)
                or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
            raise GenerationError("Generation cache prefix changed during observation")

        return content

    finally:
        os.close(descriptor)


def _File(guest: Any, path: Path, content: bytes, mode: int, *, resume: bool) -> None:
    """Append only the proved missing suffix of an exact journaled source prefix, never overwrite differing private bytes."""

    creating = not path.exists() and not path.is_symlink()
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT | os.O_EXCL if creating else 0), mode)

    try:
        if creating:
            os.fchmod(descriptor, mode)

        info = os.fstat(descriptor)

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode
                or (info.st_dev, info.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)):
            raise GenerationError("Generation cache file has unsafe ownership or changed identity")

        with os.fdopen(descriptor, "r+b", closefd=False) as stream:
            existing = stream.read(len(content) + 1)

            if existing != content and not ((creating or resume) and len(existing) < len(content) and content.startswith(existing)):
                raise GenerationError("Generation cache file differs from its exact private source")

            if existing != content:
                stream.seek(len(existing))
                stream.write(content[len(existing):])
                stream.flush()

            expected = os.fstat(descriptor)
            os.fsync(descriptor)
            current = os.fstat(descriptor)

        if ((info.st_dev, info.st_ino) != (path.lstat().st_dev, path.lstat().st_ino)
                or (expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                or current.st_size != len(content) or current.st_nlink != 1 or current.st_uid != guest._ROOT_UID or stat.S_IMODE(current.st_mode) != mode):
            raise GenerationError("Generation cache file changed during synchronization")

    finally:
        os.close(descriptor)


def _Copy(guest: Any, receipt: dict[str, Any], payload: dict[str, bytes], *, resume: bool) -> None:
    """Durably complete only exact source-bound cache prefixes, publishing the receipt last."""

    path = _CachePath(guest, receipt)
    _Prefix(guest, receipt, partial=resume, payload=payload if resume else None)
    _Directories(guest, path, create=True)

    for name in (*sorted(receipt["files"]), "receipt.json"):
        _File(guest, path / name, payload[name], 0o755 if name == "wg" else 0o600, resume=resume)

    _Directories(guest, path, create=True)
    _Prefix(guest, receipt, partial=False)


def _SyncPinned(descriptor: int) -> None:
    """Sync the exact retained inode rather than reopening a possibly replaced cache path."""

    os.fsync(descriptor)


@contextmanager
def _DurableCaches(guest: Any, receipts: list[dict[str, Any]]) -> Iterator[Callable[[], None]]:
    """Pin complete file and directory snapshots through final barriers, authority rechecks and prepared publication."""

    directories: dict[Path, tuple[int, os.stat_result]] = {}
    files: dict[Path, tuple[int, os.stat_result]] = {}
    members: dict[Path, set[str]] = {}

    def Verify() -> None:
        """Reject same-byte replacement, metadata drift and changed membership without deleting the replacement."""

        for path, (descriptor, expected) in (*directories.items(), *files.items()):
            current = os.fstat(descriptor)
            linked = path.lstat()

            if ((expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino)
                    or (expected.st_dev, expected.st_ino) != (linked.st_dev, linked.st_ino)
                    or (expected.st_mode, expected.st_uid, expected.st_nlink) != (current.st_mode, current.st_uid, current.st_nlink)
                    or (expected.st_mode, expected.st_uid, expected.st_nlink) != (linked.st_mode, linked.st_uid, linked.st_nlink)
                    or (expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)
                    != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
                raise GenerationError("Generation cache snapshot changed during durable publication")

        for path, names in members.items():
            if set(os.listdir(directories[path][0])) != names:
                raise GenerationError("Generation cache membership changed during durable publication")

    try:
        for receipt in receipts:
            path = _CachePath(guest, receipt)
            _Directories(guest, path, create=False)
            paths = (guest.BASE.parent.parent.parent, guest.BASE.parent.parent, guest.BASE.parent, path.parent.parent, path.parent, path)

            for directory in paths:
                if directory not in directories:
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    directories[directory] = descriptor, os.fstat(descriptor)
                    info = directories[directory][1]

                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_mode & 0o022
                            or directory.is_relative_to(guest.BASE.parent / "wireguard-cache") and stat.S_IMODE(info.st_mode) != 0o700):
                        raise GenerationError("Generation cache ancestor changed before synchronization")

            members[path] = set(receipt["files"]) | {"receipt.json"}

            for name in sorted(members[path]):
                filePath = path / name
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directories[path][0])
                files[filePath] = descriptor, os.fstat(descriptor)
                info = files[filePath][1]
                limit = 8 * 1024 * 1024 if name == "wg" else 1048576

                if (not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != (0o755 if name == "wg" else 0o600) or not 0 < info.st_size <= limit):
                    raise GenerationError("Generation cache file changed before synchronization")

                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    content = stream.read(limit + 1)

                exact = content == guest._Encode(receipt) if name == "receipt.json" else guest._Digest(content) == receipt["files"][name]

                if len(content) > limit or not exact:
                    raise GenerationError("Generation cache pinned bytes differ from their exact receipt")

        Verify()

        for descriptor, _ in files.values():
            _SyncPinned(descriptor)

        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            _SyncPinned(directories[path][0])

        Verify()

        yield Verify
        Verify()

    finally:
        for descriptor, _ in (*files.values(), *reversed(directories.values())):
            os.close(descriptor)


def Prepared(
    guest: Any, authority: Any, policy: Any, value: object, intent: dict[str, Any], history: str,
) -> list[dict[str, Any]]:
    """Observe complete exact recovery caches; an old cache-only request cannot authorize a host-input change."""

    request = Request(guest, policy, value, intent)
    record = _Load(guest, authority, _Expected(guest, intent, request, history))

    temporary = authority._Root(guest) / ".generation.json.new"

    if (request["generation"]["schema_version"] != 2 or record is None or record["phase"] != "prepared"
            or temporary.exists() or temporary.is_symlink()):
        raise GenerationError("Host input requires its prepared versioned activation/restoration cache")

    receipts = [request["generation"]["cached_receipt"], request["generation"]["candidate_receipt"]]

    for receipt in receipts:
        _Source(guest, _CachePath(guest, receipt), receipt, request["input"]["listener"])

    return receipts


@contextmanager
def Ready(
    guest: Any, authority: Any, policy: Any, value: object, intent: dict[str, Any], history: str,
) -> Iterator[Callable[[], None]]:
    """Keep both complete recovery caches pinned and durable across the caller's locked host-input mutation."""

    receipts = Prepared(guest, authority, policy, value, intent, history)
    expected = {**_Expected(guest, intent, Request(guest, policy, value, intent), history), "phase": "prepared"}

    with _DurableCaches(guest, receipts) as verifyCaches:
        root = authority._DurableRoot(guest)
        path = root / "generation.json"
        temporary = root / ".generation.json.new"
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

            try:
                initial = os.fstat(descriptor)
                rootInfo = os.fstat(directory)

                def Verify() -> None:
                    """Recheck the same durable recovery authority as well as both immutable cache snapshots."""

                    verifyCaches()
                    current = os.fstat(descriptor)
                    linked = path.lstat()
                    linkedRoot = root.lstat()

                    if (not stat.S_ISREG(current.st_mode) or current.st_uid != guest._ROOT_UID or current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600
                            or (initial.st_dev, initial.st_ino) != (linked.st_dev, linked.st_ino)
                            or (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                            or not stat.S_ISDIR(linkedRoot.st_mode) or linkedRoot.st_uid != guest._ROOT_UID or stat.S_IMODE(linkedRoot.st_mode) != 0o700
                            or (rootInfo.st_dev, rootInfo.st_ino) != (linkedRoot.st_dev, linkedRoot.st_ino)
                            or temporary.exists() or temporary.is_symlink()
                            or guest._Read(path, limit=65536) != guest._Encode(expected)):
                        raise GenerationError("Prepared recovery authority changed during host-input admission")

                Verify()
                authority._SyncFile(guest, path, guest._Encode(expected))
                guest._SyncDirectory(root)
                Verify()

                yield Verify
                Verify()

            finally:
                os.close(descriptor)

        finally:
            os.close(directory)


def Prepare(
    guest: Any, peer: Any, authority: Any, policy: Any, value: object, rawIntent: object,
    cached: Path | None = None, candidate: Path | None = None, *, allowMutation: bool = False,
) -> dict[str, str]:
    """Journal and freeze complete private rollback/runtime bytes without changing a root, service, input rule or cloud resource."""

    intent = authority.Intent(rawIntent)
    request = Request(guest, policy, value, intent)

    if allowMutation is not True:
        raise GenerationError("Generation preparation requires explicit mutation consent")

    with authority._Locks(guest, readOnly=False):
        pending, history = _Reservation(guest, peer, authority, intent)
        expected = _Expected(guest, intent, request, history)
        record = _Load(guest, authority, expected)
        generation = request["generation"]
        receipts = [generation["cached_receipt"], *([generation["candidate_receipt"]] if generation["candidate_receipt"] is not None else [])]

        if record is not None and record["phase"] == "prepared":
            sources = [(_CachePath(guest, receipt), receipt) for receipt in receipts]

        else:
            if cached is None or (candidate is None) != (generation["candidate_receipt"] is None):
                raise GenerationError("Unprepared generation requires its exact complete private sources")

            sources = [(cached, generation["cached_receipt"])]

            if candidate is not None:
                sources.append((candidate, generation["candidate_receipt"]))

        payloads = [_Source(guest, path, receipt, request["input"]["listener"]) for path, receipt in sources]

        for (_, receipt), payload in zip(sources, payloads):
            _Prefix(guest, receipt, partial=record is None or record["phase"] == "preparing",
                    payload=payload if record is not None and record["phase"] == "preparing" else None)

        authority._Publish(guest, "pending.json", pending)
        record = record if record is not None else {**expected, "phase": "preparing"}
        authority._Publish(guest, "generation.json", record)

        for (_, receipt), payload in zip(sources, payloads):
            _Copy(guest, receipt, payload, resume=record["phase"] == "preparing")

        with _DurableCaches(guest, receipts) as verify:
            for (path, receipt), payload in zip(sources, payloads):
                if _Source(guest, path, receipt, request["input"]["listener"]) != payload:
                    raise GenerationError("Private generation source changed before cache commitment")

            if _Reservation(guest, peer, authority, intent) != (pending, history):
                raise GenerationError("Protocol authority changed during generation cache preparation")

            verify()
            record = {**expected, "phase": "prepared"}
            authority._Publish(guest, "generation.json", record)

        return {"status": "generation-cache", "phase": "prepared", "journal_sha256": guest._Digest(guest._Encode(record)), "history_sha256": history}


def Status(guest: Any, peer: Any, authority: Any, policy: Any, value: object, rawIntent: object) -> dict[str, str]:
    """Observe only verified reservation/cache prefixes without repairs or a claim that a generation is active."""

    intent = authority.Intent(rawIntent)
    request = Request(guest, policy, value, intent)

    with authority._Locks(guest, readOnly=True):
        _, history = _Reservation(guest, peer, authority, intent)
        record = _Load(guest, authority, _Expected(guest, intent, request, history))

        if record is None:
            raise GenerationError("No exact generation cache transaction is recorded")

        for receipt in (request["generation"]["cached_receipt"], request["generation"]["candidate_receipt"]):
            if receipt is not None:
                _Prefix(guest, receipt, partial=record["phase"] == "preparing")

        return {"status": "generation-cache", "phase": record["phase"], "journal_sha256": guest._Digest(guest._Encode(record)), "history_sha256": history}
