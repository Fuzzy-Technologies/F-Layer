"""Reserve one protocol intent and consume WireGuard peer authority before any later network mutation."""

from __future__ import annotations

import json
import os
import re
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
MAX_COMPLETIONS = 4096


class ReservationError(ValueError):
    """A fixed protocol-authority failure without private guest state or command output."""


def _Json(value: object) -> bytes:
    """Keep each public authority record canonical and independent from private runtime/configuration payloads."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _Hash(value: object) -> bool:
    """Require complete plain hash scalars at every authority boundary."""

    return type(value) is str and _HASH.fullmatch(value) is not None


def Intent(value: object) -> dict[str, Any]:
    """Validate only nonsecret immutable intent; full cloud/input attestation remains the protocol coordinator's responsibility."""

    fields = {"schema_version", "owner", "creation_sha256", "previous_authority_sha256", "previous_state_sha256", "operation_id",
              "plan_sha256", "plan_expires_at", "wireguard_state", "wireguard_receipt_sha256", "wireguard_absence_sha256", "wireguard_history_sha256"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or any(not _Hash(value[key]) for key in ("owner", "creation_sha256", "previous_authority_sha256", "previous_state_sha256", "plan_sha256", "wireguard_history_sha256"))
            or type(value["operation_id"]) is not str or _NONCE.fullmatch(value["operation_id"]) is None
            or type(value["plan_expires_at"]) is not int or value["plan_expires_at"] <= 0
            or type(value["wireguard_state"]) is not str or value["wireguard_state"] not in {"active", "absent"}
            or type(value["wireguard_receipt_sha256"]) is not str or type(value["wireguard_absence_sha256"]) is not str
            or value["wireguard_state"] == "active" and (not _Hash(value["wireguard_receipt_sha256"]) or value["wireguard_absence_sha256"] != "")
            or value["wireguard_state"] == "absent" and (not _Hash(value["wireguard_absence_sha256"]) or value["wireguard_receipt_sha256"] != "")):
        raise ReservationError("Protocol reservation intent is malformed or contains unsupported authority fields")

    return dict(value)


def _Decode(guest: Any, path: Path) -> dict[str, Any]:
    """Read bounded canonical records without copying raw parser diagnostics into an exception chain."""

    value = None

    try:
        content = guest._Read(path, limit=65536)
        parsed = guest._Json(content)

        if not isinstance(parsed, dict) or content != _Json(parsed):
            raise ValueError

        value = parsed

    except (ValueError, TypeError, RecursionError):
        pass

    if value is None:
        raise ReservationError("Protocol reservation metadata is invalid or noncanonical")

    return value


def _Root(guest: Any) -> Path:
    """Keep common authority separate from every retained WireGuard installation and peer transaction."""

    root = guest.BASE.parent / "ingress"

    if root.exists() or root.is_symlink():
        guest._Directory(root, private=True)

    return cast(Path, root)


@contextmanager
def _Locks(guest: Any, *, readOnly: bool) -> Iterator[tuple[int, ...]]:
    """Acquire common ingress then existing WireGuard coordination; never reinterpret a body I/O failure as lock contention."""

    import fcntl

    path = guest.LOCK.with_name("flayer-ingress.lock")
    common: int | None = None
    wireguard: int | None = None

    try:
        try:
            guest._Directory(path.parent)

            try:
                common = os.open(path, (os.O_RDONLY if readOnly else os.O_RDWR | os.O_CREAT) | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)

            except FileNotFoundError:
                if not readOnly or path.exists() or path.is_symlink():
                    raise

            if common is not None:
                info = os.fstat(common)

                if (not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
                    raise ReservationError("Common ingress coordination file has unsafe ownership or content")

                fcntl.flock(common, (fcntl.LOCK_SH if readOnly else fcntl.LOCK_EX) | fcntl.LOCK_NB)

            try:
                wireguard = guest._OpenLock(readOnly=readOnly)

            except FileNotFoundError:
                if not readOnly or guest.LOCK.exists() or guest.LOCK.is_symlink():
                    raise

            if wireguard is not None:
                fcntl.flock(wireguard, (fcntl.LOCK_SH if readOnly else fcntl.LOCK_EX) | fcntl.LOCK_NB)

        except OSError:
            raise ReservationError("Protocol coordination is busy or unavailable") from None

        yield tuple(descriptor for descriptor in (common, wireguard) if descriptor is not None)

        if (common is None and (path.exists() or path.is_symlink())
                or wireguard is None and (guest.LOCK.exists() or guest.LOCK.is_symlink())):
            raise ReservationError("Protocol coordination appeared during observation; repeat the read")

    finally:
        for descriptor in (wireguard, common):
            if descriptor is not None:
                os.close(descriptor)


def _SyncFile(guest: Any, path: Path, expected: bytes) -> None:
    """Re-sync exact private bytes through a pinned descriptor before relying on a recovered publication."""

    if guest._Read(path, limit=65536) != expected:
        raise ReservationError("Protocol metadata differs from the exact expected publication")

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)
        linked = path.lstat()

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)):
            raise ReservationError("Protocol metadata ownership changed before synchronization")

        os.fsync(descriptor)
        current = os.fstat(descriptor)
        linked = path.lstat()

        if ((info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
                or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                or guest._Read(path, limit=65536) != expected):
            raise ReservationError("Protocol metadata changed during synchronization")

    finally:
        os.close(descriptor)


def _DurableRoot(guest: Any) -> Path:
    """Reestablish existing or newly created namespace publication through every owned ancestor before granting authority."""

    root = _Root(guest)
    directories = (guest.BASE.parent.parent, guest.BASE.parent, root)

    for path in directories:
        guest._Directory(path, create=True, private=path == root)

    paths = (directories[0].parent, *directories)
    descriptors: list[tuple[Path, int, os.stat_result]] = []

    try:
        for path in paths:
            guest._Directory(path, private=path == root)
            descriptor = (os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1][1])
                          if descriptors else os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            info = os.fstat(descriptor)
            descriptors.append((path, descriptor, info))

            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_mode & 0o022
                    or path == root and stat.S_IMODE(info.st_mode) != 0o700):
                raise ReservationError("Protocol namespace directory ownership changed before durable publication")

        for _, descriptor, _ in reversed(descriptors):
            os.fsync(descriptor)

        for path, descriptor, expected in descriptors:
            current = os.fstat(descriptor)
            linked = path.lstat()

            if (not stat.S_ISDIR(linked.st_mode) or current.st_uid != guest._ROOT_UID or linked.st_uid != guest._ROOT_UID
                    or (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino)
                    or (expected.st_dev, expected.st_ino) != (linked.st_dev, linked.st_ino)
                    or current.st_mode & 0o022 or linked.st_mode & 0o022
                    or path == root and (stat.S_IMODE(current.st_mode) != 0o700 or stat.S_IMODE(linked.st_mode) != 0o700)):
                raise ReservationError("Protocol namespace changed during durable publication")

    finally:
        for _, descriptor, _ in reversed(descriptors):
            os.close(descriptor)

    return root


def _Publish(guest: Any, filename: str, record: dict[str, Any], *, immutable: bool = False) -> None:
    """Publish only fixed canonical authority paths, retaining interrupted bytes and never replacing an immutable completion."""

    if filename not in {"pending.json", "head.json", "input.json"} and re.fullmatch(r"done-[0-9a-f]{32}\.json", filename) is None:
        raise ReservationError("Unsupported protocol authority path")

    root = _DurableRoot(guest)
    path = root / filename
    content = _Json(record)

    if len(content) > 65536:
        raise ReservationError("Protocol authority metadata exceeds its bound")

    if immutable:
        if not path.exists() and not path.is_symlink():
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(descriptor)

            finally:
                os.close(descriptor)

        _SyncFile(guest, path, content)

    else:
        temporary = root / ("." + filename + ".new")

        if not temporary.exists() and not temporary.is_symlink():
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

            try:
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(descriptor)

            finally:
                os.close(descriptor)

        _SyncFile(guest, temporary, content)
        os.replace(temporary, path)

    guest._SyncDirectory(root)


def _Pointer(value: object) -> dict[str, str] | None:
    """Accept only confined full-digest completion pointers, with null denoting the explicit initial authority."""

    if value is None:
        return None

    if (type(value) is not dict or set(value) != {"name", "sha256"} or type(value["name"]) is not str
            or re.fullmatch(r"done-[0-9a-f]{32}\.json", value["name"]) is None or not _Hash(value["sha256"])):
        raise ReservationError("Protocol authority head is invalid")

    return dict(value)


def _Initial(guest: Any, intent: dict[str, Any]) -> str:
    """Bind absent common history to one exact owner and permanent creation, independently from guest peer history."""

    return cast(str, guest._Digest(_Json({"domain": "f-layer/ingress/authority/v1", "owner": intent["owner"], "creation_sha256": intent["creation_sha256"]})))


def _Pending(guest: Any, intent: dict[str, Any]) -> dict[str, Any] | None:
    """Recognize only complete exact forward journal publication; an exposed temporary record already consumes dispatch authority."""

    root = _Root(guest)
    values = []

    for name in ("pending.json", ".pending.json.new"):
        path = root / name

        if path.exists() or path.is_symlink():
            value = _Decode(guest, path)

            if (set(value) != {"schema_version", "intent", "parent", "deployment_sha256", "phase", "fenced"}
                    or type(value["schema_version"]) is not int or value["schema_version"] != 1
                    or Intent(value["intent"]) != intent or type(value["phase"]) is not str
                    or value["phase"] not in {"preparing", "reserved", "exposed", "cancelling"} or type(value["fenced"]) is not bool
                    or (not _Hash(value["deployment_sha256"]) if intent["wireguard_state"] == "active" else value["deployment_sha256"] != "")
                    or intent["wireguard_state"] == "absent" and value["fenced"]
                    or value["phase"] == "preparing" and value["fenced"]
                    or value["phase"] in {"reserved", "exposed"} and value["fenced"] != (intent["wireguard_state"] == "active")):
                raise ReservationError("Protocol reservation is incomplete, foreign or in an unsupported phase")

            _Pointer(value["parent"])
            values.append(value)

    if not values:
        return None

    if len(values) == 2 and values[0] != values[1]:
        before, after = values

        if ({key: value for key, value in before.items() if key not in {"phase", "fenced"}}
                != {key: value for key, value in after.items() if key not in {"phase", "fenced"}}
                or (before["phase"], after["phase"]) not in {("preparing", "reserved"), ("preparing", "cancelling"),
                                                           ("reserved", "exposed"), ("reserved", "cancelling")}
                or before["fenced"] and not after["fenced"]):
            raise ReservationError("Interrupted protocol journal is not its exact next phase")

    return values[-1]


def _Authority(guest: Any, intent: dict[str, Any], pending: dict[str, Any] | None) -> tuple[dict[str, str] | None, str, dict[str, Any] | None, int]:
    """Verify every immutable completed parent and reject orphan records rather than reconstructing a lost mutable head."""

    root = _Root(guest)
    names = {path.name for path in root.iterdir()} if root.exists() else set()
    allowed = {"head.json", ".head.json.new", "pending.json", ".pending.json.new", "input.json", ".input.json.new"}

    if len(names) > MAX_COMPLETIONS + len(allowed) or any(name not in allowed and re.fullmatch(r"done-[0-9a-f]{32}\.json", name) is None for name in names):
        raise ReservationError("Common protocol namespace contains unknown or unbounded metadata")

    if names & {"input.json", ".input.json.new"} and (pending is None or pending["phase"] != "exposed"):
        raise ReservationError("Host input transaction requires its exact exposed protocol reservation")

    head = _Pointer(_Decode(guest, root / "head.json")) if "head.json" in names else None
    current = head
    visited: set[str] = set()
    latest = None
    initial = _Initial(guest, intent)

    while current is not None:
        if current["name"] in visited or len(visited) >= MAX_COMPLETIONS:
            raise ReservationError("Protocol completion history is cyclic or exceeds its bound")

        visited.add(current["name"])
        record = _Decode(guest, root / current["name"])

        if (set(record) != {"schema_version", "owner", "creation_sha256", "operation_id", "intent_sha256", "parent", "previous_authority_sha256", "history_sha256", "outcome"}
                or type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["owner"] != intent["owner"]
                or record["creation_sha256"] != intent["creation_sha256"] or record["outcome"] != "cancelled"
                or type(record["operation_id"]) is not str or _NONCE.fullmatch(record["operation_id"]) is None
                or current["name"] != "done-" + record["operation_id"] + ".json" or guest._Digest(_Json(record)) != current["sha256"]
                or any(not _Hash(record[key]) for key in ("intent_sha256", "previous_authority_sha256", "history_sha256"))):
            raise ReservationError("Protocol completion record has invalid ownership or history proof")

        parent = _Pointer(record["parent"])

        if record["previous_authority_sha256"] != (parent["sha256"] if parent is not None else initial):
            raise ReservationError("Protocol completion does not bind its exact previous authority")

        if latest is None:
            latest = record

        current = parent

    expected = set(visited)

    if pending is not None:
        expected.add("done-" + intent["operation_id"] + ".json")

    unheaded = {name for name in names if name.startswith("done-")} - visited

    if ({name for name in names if name.startswith("done-")} - expected
            or (unheaded or ".head.json.new" in names) and (pending is None or pending["phase"] != "cancelling")):
        raise ReservationError("Unrecorded protocol completion or interrupted head requires recovery; missing authority is never adopted")

    return head, head["sha256"] if head is not None else initial, latest, len(visited)


def _Observe(guest: Any, peer: Any, intent: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Prove the complete actual active or absent WG namespace, refusing every unresolved peer/install transaction."""

    owner = intent["owner"]
    root, unit, transaction = guest._Paths(owner)

    if transaction.exists() or transaction.is_symlink():
        raise ReservationError("Pending WireGuard transaction requires recovery before protocol reservation")

    if intent["wireguard_state"] == "active":
        request = guest._Request(root)[0]
        receipt = guest._Check(root, unit, request)

        if guest._Digest(guest._Encode(receipt)) != intent["wireguard_receipt_sha256"]:
            raise ReservationError("WireGuard receipt differs from the protocol intent")

        audit = peer._Audit(guest, owner)

        if audit is not None and (audit["receipt_sha256"] != intent["wireguard_receipt_sha256"] or audit["deployment_sha256"] != receipt["deployment_sha256"]):
            raise ReservationError("WireGuard audit does not describe its current active root")

    else:
        guest._RequireAbsent(owner)

        if guest._AbsenceDigest(owner) != intent["wireguard_absence_sha256"]:
            raise ReservationError("WireGuard absence differs from the protocol intent")

        receipt = None

    return receipt, peer._History(guest, owner)


def _FencedHistory(guest: Any, intent: dict[str, Any], deployment: str) -> str:
    """Use exactly the existing v1 equal-receipt cancellation shape understood by already queued peer driver bytes."""

    if intent["wireguard_state"] == "absent":
        return str(intent["wireguard_history_sha256"])

    return cast(str, guest._Digest(_Json({"schema_version": 1, "owner": intent["owner"], "action": "revoke", "device_id": "protocol-" + intent["operation_id"],
        "previous_receipt_sha256": intent["wireguard_receipt_sha256"], "receipt_sha256": intent["wireguard_receipt_sha256"],
        "deployment_sha256": deployment, "previous_history_sha256": intent["wireguard_history_sha256"]})))


def Reserve(guest: Any, peer: Any, value: object, *, allowMutation: bool = False) -> dict[str, Any]:
    """Under common→WG locks, persist exact intent before durably consuming only active WG history; no runtime/key/network mutation."""

    intent = Intent(value)

    if allowMutation is not True:
        raise ReservationError("Protocol reservation requires explicit mutation consent")

    with _Locks(guest, readOnly=False):
        pending = _Pending(guest, intent)
        head, authority, _, count = _Authority(guest, intent, pending)

        if authority != intent["previous_authority_sha256"] or pending is not None and pending["parent"] != head:
            raise ReservationError("Protocol intent has stale or changed common authority")

        if pending is None:
            completed = _Root(guest) / ("done-" + intent["operation_id"] + ".json")

            if completed.exists() or completed.is_symlink():
                raise ReservationError("A completed protocol operation nonce cannot be reused")

            if count >= MAX_COMPLETIONS or not int(time.time()) < intent["plan_expires_at"] <= int(time.time()) + 600:
                raise ReservationError("Protocol history is at capacity or the new reservation plan expired")

            receipt, history = _Observe(guest, peer, intent)

            if history != intent["wireguard_history_sha256"]:
                raise ReservationError("WireGuard history differs from the exact reservation plan")

            pending = {"schema_version": 1, "intent": intent, "parent": head, "deployment_sha256": receipt["deployment_sha256"] if receipt is not None else "",
                       "phase": "preparing", "fenced": False}
            _Publish(guest, "pending.json", pending)

        if pending["phase"] not in {"preparing", "reserved"}:
            raise ReservationError("Exposed or cancelling protocol authority cannot grant another reservation")

        receipt, history = _Observe(guest, peer, intent)
        expected = _FencedHistory(guest, intent, pending["deployment_sha256"])

        if history not in {intent["wireguard_history_sha256"], expected} or pending["fenced"] and history != expected:
            raise ReservationError("Protocol reservation found unexplained WireGuard history")

        _Publish(guest, "pending.json", pending)

        if receipt is not None:
            if history == intent["wireguard_history_sha256"] and pending["phase"] == "preparing" and intent["plan_expires_at"] <= int(time.time()):
                raise ReservationError("Protocol reservation expired before fencing; cancel its retained preparation")

            peer._Cancel(guest, receipt, "revoke", "protocol-" + intent["operation_id"], intent["wireguard_history_sha256"])

        if peer._History(guest, intent["owner"]) != expected:
            raise ReservationError("Protocol history fence could not be verified")

        pending = {**pending, "phase": "reserved", "fenced": receipt is not None}
        _Publish(guest, "pending.json", pending)

        return {"status": "reserved", "reservation_sha256": guest._Digest(_Json(pending)), "history_sha256": expected, "authority_sha256": authority}


def Expose(guest: Any, peer: Any, value: object, expectedReservation: str, *, allowMutation: bool = False) -> dict[str, str]:
    """Consume the sole cloud/guest dispatch grant before the external write; repeated/lost acknowledgments remain uncertain."""

    intent = Intent(value)

    if allowMutation is not True or not _Hash(expectedReservation):
        raise ReservationError("Protocol dispatch requires explicit consent and the exact reserved journal")

    with _Locks(guest, readOnly=False):
        pending = _Pending(guest, intent)
        head, authority, _, _ = _Authority(guest, intent, pending)

        if (pending is None or pending["phase"] != "reserved" or pending["parent"] != head
                or authority != intent["previous_authority_sha256"] or guest._Digest(_Json(pending)) != expectedReservation
                or not int(time.time()) < intent["plan_expires_at"] <= int(time.time()) + 600):
            raise ReservationError("Protocol dispatch is stale, already exposed or lacks its exact reservation")

        _, history = _Observe(guest, peer, intent)

        if history != _FencedHistory(guest, intent, pending["deployment_sha256"]):
            raise ReservationError("Protocol dispatch has different WireGuard fence history")

        _Publish(guest, "pending.json", pending)
        pending = {**pending, "phase": "exposed"}
        _Publish(guest, "pending.json", pending)

        return {"status": "exposed", "reservation_sha256": guest._Digest(_Json(pending)), "history_sha256": history}


def Cancel(guest: Any, peer: Any, value: object, *, allowMutation: bool = False) -> dict[str, str]:
    """Retire only an unexposed reservation, preserving consumed WG history and publishing a new immutable common authority."""

    intent = Intent(value)

    if allowMutation is not True:
        raise ReservationError("Protocol reservation cancellation requires explicit mutation consent")

    with _Locks(guest, readOnly=False):
        pending = _Pending(guest, intent)
        head, authority, latest, count = _Authority(guest, intent, pending)
        intentSha = guest._Digest(_Json(intent))

        if pending is None:
            if latest is None or latest["intent_sha256"] != intentSha or head is None:
                raise ReservationError("No exact latest unexposed protocol cancellation is recorded")

            _Publish(guest, head["name"], latest, immutable=True)
            _Publish(guest, "head.json", head)

            return {"status": "cancelled", "authority_sha256": authority, "history_sha256": latest["history_sha256"]}

        if pending["phase"] == "exposed":
            raise ReservationError("Exposed protocol outcome is unknown; it cannot be cancelled or reset by an old-looking state")

        receipt, history = _Observe(guest, peer, intent)
        expected = _FencedHistory(guest, intent, pending["deployment_sha256"])

        if history not in {intent["wireguard_history_sha256"], expected} or pending["fenced"] and history != expected:
            raise ReservationError("Protocol cancellation found unexplained WireGuard history")

        record = {"schema_version": 1, "owner": intent["owner"], "creation_sha256": intent["creation_sha256"], "operation_id": intent["operation_id"],
                  "intent_sha256": intentSha, "parent": pending["parent"], "previous_authority_sha256": intent["previous_authority_sha256"],
                  "history_sha256": history, "outcome": "cancelled"}
        pointer = {"name": "done-" + intent["operation_id"] + ".json", "sha256": guest._Digest(_Json(record))}

        if (head != pending["parent"] and (head != pointer or latest != record)
                or head == pending["parent"] and (authority != intent["previous_authority_sha256"] or count >= MAX_COMPLETIONS)):
            raise ReservationError("Protocol cancellation authority changed or reached capacity")

        cancelling = {**pending, "phase": "cancelling", "fenced": receipt is not None and history == expected}
        _Publish(guest, "pending.json", pending)
        _Publish(guest, "pending.json", cancelling)
        _Publish(guest, pointer["name"], record, immutable=True)
        _Publish(guest, "head.json", pointer)
        path = _Root(guest) / "pending.json"

        if _Pending(guest, intent) != cancelling:
            raise ReservationError("Protocol cancellation journal changed before retirement")

        path.unlink()
        guest._SyncDirectory(path.parent)

        return {"status": "cancelled", "authority_sha256": pointer["sha256"], "history_sha256": history}


def Status(guest: Any, peer: Any, value: object) -> dict[str, Any]:
    """Report only verified common authority and pending metadata; this is not a runtime, ingress or traffic health claim."""

    intent = Intent(value)

    with _Locks(guest, readOnly=True):
        pending = _Pending(guest, intent)
        _, authority, latest, count = _Authority(guest, intent, pending)

        return {"status": "protocol-authority", "authority_sha256": authority, "history_sha256": peer.HistoryStatus(guest, intent["owner"])["history_sha256"],
                "phase": pending["phase"] if pending is not None else "cancelled" if latest is not None else "initial",
                "reservation_sha256": guest._Digest(_Json(pending)) if pending is not None else "", "completion_count": count}
