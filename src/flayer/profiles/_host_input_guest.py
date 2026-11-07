"""Journal one reserved owned-input table/boot transition without touching transport services or cloud resources."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

BOOT = Path("/etc/nftables.conf")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NEXT = {("prepared", "applying"), ("applying", "applied"), ("prepared", "rolling-back"),
         ("applying", "rolling-back"), ("applied", "rolling-back"), ("rolling-back", "rolled-back")}


class InputError(ValueError):
    """A fixed transaction diagnostic without native output or private transport material."""


def Request(guest: Any, policy: Any, value: object, intent: dict[str, Any]) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Bind one closed input delta and cloud-plan digest to the reservation's complete immutable plan hash."""

    if (type(value) is not dict or type(value.get("schema_version")) is not int or value["schema_version"] not in {1, 2}
            or set(value) != ({"schema_version", "cloud_plan_sha256", "input"} | ({"generation"} if value["schema_version"] == 2 else set()))
            or type(value["cloud_plan_sha256"]) is not str or _HASH.fullmatch(value["cloud_plan_sha256"]) is None):
        raise InputError("Host input request requires its closed composite protocol plan")

    policies = policy.Transition(value["input"])
    before, after, _ = policies

    if value["schema_version"] == 2:
        generation = guest._GenerationRecord(value["generation"], intent)

        if (generation["schema_version"] not in {2, 3} or value["input"]["listener"]["transport"] != "wireguard"
                or value["input"]["change"] != generation["change"]):
            raise InputError("Host input requires the exact versioned WG activation/restoration contract")

    if (policy.Owner(before) != intent["owner"] or before["creation_sha256"] != intent["creation_sha256"]
            or after["operation_id"] != intent["operation_id"] or policy.Digest(policy.Json(value)) != intent["plan_sha256"]
            or len(policy.Json(value)) > 32768):
        raise InputError("Host input request differs from its owner, creation, operation or exact reserved plan")

    return policy.Decode(policy.Json(value)), policies


def _Reservation(
    guest: Any, peer: Any, authority: Any, policy: Any, request: dict[str, Any], intent: dict[str, Any], generationCache: Any, runtimeBackend: Any,
    *, rollback: bool | None = None,
) -> dict[str, Any]:
    """Require the same exposed reservation and actual retained WG fence under common then WG coordination."""

    pending = authority._Pending(guest, intent)
    head, digest, _, _ = authority._Authority(guest, intent, pending)

    if (pending is None or pending["phase"] != "exposed" or pending["parent"] != head or digest != intent["previous_authority_sha256"]):
        raise InputError("Host input mutation requires the exact current exposed reservation")

    root = authority._Root(guest)

    if any((root / name).exists() or (root / name).is_symlink() for name in ("runtime.json", ".runtime.json.new")):
        if request["schema_version"] != 2 or generationCache is None or runtimeBackend is None:
            raise InputError("Native generation input recovery requires its exact trusted runtime and cache backends")

        observed = runtimeBackend.Observe(guest, peer, authority, policy, generationCache, request, intent)

        if (rollback is True and request["generation"]["change"] == "disable" and observed["phase"] not in {"restored", "unchanged"}
                or rollback is False and request["generation"]["change"] == "enable" and observed["phase"] != "active"):
            raise InputError("Native generation must reach its planned healthy state before opening host input")

    else:
        if (request["schema_version"] == 2 and request["generation"]["schema_version"] == 3
                and (rollback is False and request["generation"]["change"] == "enable"
                     or rollback is True and request["generation"]["change"] == "disable")):
            raise InputError("Opening host input requires its matching healthy native generation record")

        _, history = authority._Observe(guest, peer, intent)

        if history != authority._FencedHistory(guest, intent, pending["deployment_sha256"]):
            raise InputError("Host input operation has stale WireGuard history")

    return cast(dict[str, Any], pending)


@contextmanager
def _Caches(
    guest: Any, authority: Any, policy: Any, request: dict[str, Any], intent: dict[str, Any], pending: dict[str, Any],
    generationCache: Any, *, readOnly: bool = False,
) -> Iterator[Callable[[], None]]:
    """Require prepared exact private recovery bytes before admitting a generation-bearing input plan."""

    if request["schema_version"] == 1:
        yield lambda: None

        return

    if generationCache is None:
        raise InputError("Generation-bearing input requires its trusted cache backend")

    history = authority._FencedHistory(guest, intent, pending["deployment_sha256"])

    if readOnly:
        generationCache.Prepared(guest, authority, policy, request, intent, history)

        yield lambda: None

    else:
        with generationCache.Ready(guest, authority, policy, request, intent, history) as verify:
            yield verify


def _Compiled(guest: Any, policy: Any, values: tuple[dict[str, Any], ...]) -> list[str]:
    """Compile expected tables in fresh guest network namespaces, never by changing the running input chain."""

    result = []

    guest._Directory(guest.LOCK.parent)

    with tempfile.TemporaryDirectory(prefix=".flayer-input-", dir=guest.LOCK.parent) as directory:
        for index, value in enumerate(values):
            path = Path(directory) / ("policy-" + str(index) + ".nft")
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

            with os.fdopen(descriptor, "wb") as stream:
                stream.write(policy.Table(value))

            _, content = guest._Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", str(path)])
            result.append(policy.NativeFingerprint(value, content))

    return result


def _Load(guest: Any, authority: Any, expected: dict[str, Any]) -> dict[str, Any] | None:
    """Recognize only complete exact forward phase publications; retain partial or foreign bytes for diagnosis."""

    values = []

    for filename in ("input.json", ".input.json.new"):
        path = authority._Root(guest) / filename

        if path.exists() or path.is_symlink():
            value = authority._Decode(guest, path)

            if (set(value) != {*expected, "phase"} or guest._Encode({key: item for key, item in value.items() if key != "phase"}) != guest._Encode(expected)
                    or type(value["phase"]) is not str or value["phase"] not in {"prepared", "applying", "applied", "rolling-back", "rolled-back"}):
                raise InputError("Host input journal is foreign, incomplete or differs from its exact reserved request")

            values.append(value)

    if len(values) == 2 and values[0] != values[1] and (values[0]["phase"], values[1]["phase"]) not in _NEXT:
        raise InputError("Interrupted host input journal is not its exact next phase")

    return values[-1] if values else None


def _BootBytes(guest: Any) -> tuple[bytes, bytes | None]:
    """Observe only the fixed root-owned boot file and its exact journaled publication slot."""

    guest._Directory(BOOT.parent)
    current = guest._Read(BOOT, limit=32768, mode=0o644)
    temporary = BOOT.with_name(".flayer-input.new")
    staged = guest._Read(temporary, limit=32768, mode=0o644) if temporary.exists() or temporary.is_symlink() else None

    return current, staged


def _State(guest: Any, policy: Any, values: tuple[dict[str, Any], ...], fingerprints: list[str], phase: str) -> tuple[int, int, bytes | None]:
    """Accept only the documented boot-first prefixes, including a reboot between boot publication and live replacement."""

    boot, staged = _BootBytes(guest)
    boots = [policy.Boot(value) for value in values]
    _, content = guest._Run(["nft", "-j", "list", "table", "inet", "flayer_bootstrap"])
    live = None

    for index, value in enumerate(values):
        try:
            if policy.NativeFingerprint(value, content) == fingerprints[index]:
                live = index

                break

        except ValueError:
            continue

    bootIndex = next((index for index, value in enumerate(boots) if boot == value), None)
    prefixes = ({(0, 0)} if phase == "prepared" else {(1, 1)} if phase == "applied"
                else {(2, 2)} if phase == "rolled-back" else {(0, 0), (1, 0), (1, 1)})

    if phase == "rolling-back":
        prefixes |= {(2, 0), (2, 1), (2, 2)}

    allowed = [boots[1]] if phase == "applying" else [boots[1], boots[2]] if phase == "rolling-back" else []

    if (bootIndex, live) not in prefixes or staged is not None and staged not in allowed:
        raise InputError("Host input boot/live state or publication slot is outside the exact recorded prefixes")

    assert bootIndex is not None and live is not None

    return bootIndex, live, staged


def _SyncBoot(guest: Any, path: Path, expected: bytes) -> None:
    """Re-sync complete known boot bytes through a pinned private descriptor before a recovered rename."""

    if guest._Read(path, limit=32768, mode=0o644) != expected:
        raise InputError("Host input boot publication differs from its recorded exact bytes")

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        before = os.fstat(descriptor)
        linked = path.lstat()

        if (not stat.S_ISREG(before.st_mode) or before.st_uid != guest._ROOT_UID or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o644 or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)):
            raise InputError("Host input boot ownership changed before durable publication")

        os.fsync(descriptor)
        after = os.fstat(descriptor)
        linked = path.lstat()

        if ((before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
                or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or guest._Read(path, limit=32768, mode=0o644) != expected):
            raise InputError("Host input boot changed during durable publication")

    finally:
        os.close(descriptor)


def _FinishBoot(guest: Any, staged: bytes | None) -> None:
    """Finish only a previously verified complete journaled boot prefix; never overwrite an unexplained temporary file."""

    if staged is not None:
        temporary = BOOT.with_name(".flayer-input.new")
        _SyncBoot(guest, temporary, staged)
        os.replace(temporary, BOOT)
        guest._SyncDirectory(BOOT.parent)


def _PublishBoot(guest: Any, content: bytes) -> None:
    """Persist a fixed bounded owned boot delta without replaying it in the running namespace."""

    temporary = BOOT.with_name(".flayer-input.new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)

    try:
        os.fchmod(descriptor, 0o644)

        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(descriptor)

    finally:
        os.close(descriptor)

    _FinishBoot(guest, content)


def _Expected(policy: Any, intent: dict[str, Any], request: dict[str, Any], fingerprints: list[str]) -> dict[str, Any]:
    """Retain complete public intent and compiled proofs, never arbitrary scripts or private transport configuration."""

    return {"schema_version": 1, "intent_sha256": policy.Digest(policy.Json(intent)), "request": request, "fingerprints": fingerprints}


def _Result(policy: Any, values: tuple[dict[str, Any], ...], record: dict[str, Any]) -> dict[str, str]:
    """Report the exact input outcome only; this does not claim cloud or transport-service health."""

    index = 2 if record["phase"] == "rolled-back" else 1 if record["phase"] == "applied" else 0 if record["phase"] == "prepared" else None

    return {"status": "host-input", "phase": record["phase"], "journal_sha256": policy.Digest(policy.Json(record)),
            "boot_sha256": policy.Digest(policy.Boot(values[index])) if index is not None else "",
            "native_sha256": record["fingerprints"][index] if index is not None else ""}


def Prepare(
    guest: Any, peer: Any, authority: Any, policy: Any, value: object, rawIntent: object, *,
    allowMutation: bool = False, generationCache: Any = None, runtimeBackend: Any = None,
) -> dict[str, str]:
    """Verify original/committed boot and actual native input before publishing the durable exact recovery request."""

    intent = authority.Intent(rawIntent)
    request, values = Request(guest, policy, value, intent)

    if allowMutation is not True:
        raise InputError("Host input preparation requires explicit mutation consent")

    with authority._Locks(guest, readOnly=False):
        pending = _Reservation(guest, peer, authority, policy, request, intent, generationCache, runtimeBackend)

        with _Caches(guest, authority, policy, request, intent, pending, generationCache) as verify:
            fingerprints = _Compiled(guest, policy, values)
            expected = _Expected(policy, intent, request, fingerprints)
            record = _Load(guest, authority, expected)
            _State(guest, policy, values, fingerprints, record["phase"] if record is not None else "prepared")
            verify()
            authority._Publish(guest, "pending.json", pending)
            record = record if record is not None else {**expected, "phase": "prepared"}
            authority._Publish(guest, "input.json", record)

            return _Result(policy, values, record)


def Apply(
    guest: Any, peer: Any, authority: Any, policy: Any, value: object, rawIntent: object, *,
    allowMutation: bool = False, rollback: bool = False, generationCache: Any = None, runtimeBackend: Any = None,
) -> dict[str, str]:
    """Move only verified boot-first prefixes forward or restore old listeners under the consumed new operation marker."""

    intent = authority.Intent(rawIntent)
    request, values = Request(guest, policy, value, intent)

    if allowMutation is not True or type(rollback) is not bool:
        raise InputError("Host input mutation requires explicit consent and an exact rollback selection")

    with authority._Locks(guest, readOnly=False) as locks:
        pending = _Reservation(guest, peer, authority, policy, request, intent, generationCache, runtimeBackend, rollback=rollback)

        with _Caches(guest, authority, policy, request, intent, pending, generationCache) as verify:
            fingerprints = _Compiled(guest, policy, values)
            record = _Load(guest, authority, _Expected(policy, intent, request, fingerprints))

            if record is None or not rollback and record["phase"] in {"rolling-back", "rolled-back"}:
                raise InputError("Host input requires its prepared journal and cannot revive a rolled-back operation")

            _State(guest, policy, values, fingerprints, record["phase"])
            verify()
            authority._Publish(guest, "pending.json", pending)
            authority._Publish(guest, "input.json", record)
            final = "rolled-back" if rollback else "applied"

            if record["phase"] == final:
                return _Result(policy, values, record)

            nextPhase = "rolling-back" if rollback else "applying"
            record = {**record, "phase": nextPhase}
            authority._Publish(guest, "input.json", record)
            _, _, staged = _State(guest, policy, values, fingerprints, nextPhase)
            _FinishBoot(guest, staged)
            boot, live, _ = _State(guest, policy, values, fingerprints, nextPhase)
            target = 2 if rollback else 1
            verify()

            if boot != target:
                _PublishBoot(guest, policy.Boot(values[target]))

            _SyncBoot(guest, BOOT, policy.Boot(values[target]))
            guest._SyncDirectory(BOOT.parent)

            if live != target:
                # Live batches delete only the proved owned table. Historical global-flush boot bytes are never executed.
                verify()
                guest._Run(["nft", "-f", "-"], payload=b"delete table inet flayer_bootstrap\n" + policy.Table(values[target]), passFds=locks)

            _State(guest, policy, values, fingerprints, final)
            verify()
            record = {**record, "phase": final}
            authority._Publish(guest, "input.json", record)

            return _Result(policy, values, record)


def Status(
    guest: Any, peer: Any, authority: Any, policy: Any, value: object, rawIntent: object, *, generationCache: Any = None, runtimeBackend: Any = None,
) -> dict[str, str]:
    """Observe only an exactly reserved known prefix without creating a durable file or repairing a temporary publication."""

    intent = authority.Intent(rawIntent)
    request, values = Request(guest, policy, value, intent)

    with authority._Locks(guest, readOnly=True):
        pending = _Reservation(guest, peer, authority, policy, request, intent, generationCache, runtimeBackend)

        with _Caches(guest, authority, policy, request, intent, pending, generationCache, readOnly=True):
            fingerprints = _Compiled(guest, policy, values)
            record = _Load(guest, authority, _Expected(policy, intent, request, fingerprints))

            if record is None:
                raise InputError("No exact prepared host input transaction is recorded")

            _State(guest, policy, values, fingerprints, record["phase"])

            return _Result(policy, values, record)
