"""Transition one reserved WG generation with retained recovery caches and explicitly drained systemd jobs."""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any, cast

CGROUPS = Path("/sys/fs/cgroup")
_NEXT = {("ready", "publishing"), ("publishing", "starting"), ("starting", "active"),
         ("ready", "removing-original"), ("removing-original", "stopping-original"), ("stopping-original", "inactive"),
         ("inactive", "publishing"), ("starting", "restored"), ("ready", "unchanged"),
         ("ready", "removing-candidate"), ("publishing", "removing-candidate"), ("starting", "removing-candidate"),
         ("active", "removing-candidate"), ("removing-candidate", "stopping-candidate"), ("stopping-candidate", "rolled-back"),
         ("active", "restarting-active"), ("restarting-active", "active"), ("restored", "restarting-restored"), ("restarting-restored", "restored"),
         ("restarting-active", "removing-candidate")}
_PROPERTIES = ("Id", "LoadState", "ActiveState", "SubState", "Job", "MainPID", "ControlPID", "ControlGroup", "FragmentPath", "DropInPaths")


class RuntimeError(ValueError):
    """A bounded native-generation diagnostic without credentials, command output or private payloads."""


def _Reservation(guest: Any, authority: Any, intent: dict[str, Any]) -> dict[str, Any]:
    """Retain exact exposed common authority throughout every native phase and lock handoff."""

    pending = authority._Pending(guest, intent)
    head, digest, _, _ = authority._Authority(guest, intent, pending)

    if pending is None or pending["phase"] != "exposed" or pending["parent"] != head or digest != intent["previous_authority_sha256"]:
        raise RuntimeError("Native generation requires its exact current exposed reservation")

    return cast(dict[str, Any], pending)


def _Load(guest: Any, authority: Any, request: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any] | None:
    """Read only complete bound forward prefixes; retain unknown, torn and conflicting publications."""

    values = []

    for name in ("runtime.json", ".runtime.json.new"):
        path = authority._Root(guest) / name

        if path.exists() or path.is_symlink():
            record = guest._RuntimeRecord(authority._Decode(guest, path), intent)

            if guest._Encode(record["request"]) != guest._Encode(request):
                raise RuntimeError("Native generation journal has a different complete request")

            values.append(record)

    if len(values) == 2 and values[0] != values[1]:
        before, after = values

        if (guest._Encode({key: item for key, item in before.items() if key not in {"phase", "rollback"}})
                != guest._Encode({key: item for key, item in after.items() if key not in {"phase", "rollback"}})
                or before["rollback"] and not after["rollback"]
                or before["rollback"] != after["rollback"] and before["phase"] != after["phase"]
                or (before["phase"] != after["phase"] and (before["phase"], after["phase"]) not in _NEXT)
                or before["phase"] == after["phase"] and before["rollback"] == after["rollback"]):
            raise RuntimeError("Native generation publication is outside its recorded forward prefix")

    return values[-1] if values else None


def _Write(guest: Any, authority: Any, record: dict[str, Any], phase: str, *, rollback: bool | None = None) -> dict[str, Any]:
    """Persist intent before the corresponding root, history, service or cleanup action."""

    updated = {**record, "phase": phase, "rollback": record["rollback"] if rollback is None else rollback}
    guest._RuntimeRecord(updated, record["intent"])
    authority._Publish(guest, "runtime.json", updated)

    return updated


def _Service(guest: Any, unit: Path, *, allowCachedError: bool = False) -> dict[str, str]:
    """Read explicit empty properties: systemd 255 renders no queued job as Job=, not Job=0."""

    _, content = guest._Run(["systemctl", "show", "--all", "--no-pager", "--property=" + ",".join(_PROPERTIES), unit.name])
    values: dict[str, str] = {}

    try:
        for line in content.decode("ascii").splitlines():
            name, value = line.split("=", 1)

            if name in values or name not in _PROPERTIES:
                raise ValueError

            values[name] = value

        cached = allowCachedError and values.get("LoadState") in {"bad-setting", "error"}

        if (set(values) != set(_PROPERTIES) or values["Id"] != unit.name or values["LoadState"] not in ({"loaded", "not-found", "bad-setting", "error"} if cached else {"loaded", "not-found"})
                or values["FragmentPath"] not in ({"", str(unit)} if cached else {str(unit)} if values["LoadState"] == "loaded" else {""}) or values["DropInPaths"]
                or values["Job"] and re.fullmatch(r"[1-9][0-9]{0,9}", values["Job"]) is None
                or any(re.fullmatch(r"0|[1-9][0-9]{0,9}", values[name]) is None for name in ("MainPID", "ControlPID"))
                or values["ControlGroup"] not in {"", "/system.slice/" + unit.name}):
            raise ValueError

    except (ValueError, UnicodeError):
        raise RuntimeError("Owned service queue/process observation is incomplete or foreign") from None

    return values


def _CgroupEmpty(guest: Any, unit: Path) -> None:
    """Require cgroup-v2 recursive emptiness, including children not represented by MainPID or ControlPID."""

    guest._Directory(CGROUPS)
    marker = os.open(CGROUPS / "cgroup.controllers", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(marker)

        if not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_mode & 0o022:
            raise RuntimeError("Native generation requires the owned cgroup-v2 hierarchy")

    finally:
        os.close(marker)

    parent = CGROUPS / "system.slice"
    path = parent / unit.name

    if parent.exists() or parent.is_symlink():
        guest._Directory(parent)

    if not path.exists() and not path.is_symlink():
        return

    guest._Directory(path)
    descriptor = os.open(path / "cgroup.events", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_mode & 0o022:
            raise RuntimeError("Owned service cgroup observation has unsafe ownership")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(2049)

        if len(content) > 2048 or content not in (b"populated 0\nfrozen 0\n", b"populated 0\n"):
            raise RuntimeError("Owned service cgroup is populated or cannot prove recursive emptiness")

    finally:
        os.close(descriptor)


def _Drained(guest: Any, unit: Path) -> None:
    """Never replace a generation while PID1 still has a job, callback process or populated service cgroup."""

    before = _Service(guest, unit)

    if (before["Job"] or before["MainPID"] != "0" or before["ControlPID"] != "0"
            or before["ActiveState"] not in {"inactive", "failed"} or before["SubState"] not in {"dead", "failed"}):
        raise RuntimeError("Owned service has not reached a drained inactive terminal state")

    _CgroupEmpty(guest, unit)

    if _Service(guest, unit) != before:
        raise RuntimeError("Owned service changed during terminal process observation")


def _Active(guest: Any, unit: Path) -> None:
    """Require the exact completed oneshot activation without a queued job or residual callback child."""

    before = _Service(guest, unit)

    if (before["Job"] or before["MainPID"] != "0" or before["ControlPID"] != "0"
            or before["ActiveState"] != "active" or before["SubState"] != "exited"):
        raise RuntimeError("Generation activation has no exact terminal native observation")

    _CgroupEmpty(guest, unit)

    if _Service(guest, unit) != before:
        raise RuntimeError("Generation activation changed during terminal observation")


def _Reconcile(guest: Any, unit: Path, locks: tuple[int, ...]) -> None:
    """Reload only after a quiescent observation so a stale cached definition cannot supply a retired unit's stop command."""

    before = _Service(guest, unit, allowCachedError=True)

    if before["Job"] or before["MainPID"] != "0" or before["ControlPID"] != "0":
        raise RuntimeError("Owned unit has an unresolved job before definition reconciliation")

    _CgroupEmpty(guest, unit)
    guest._Run(["systemctl", "daemon-reload"], passFds=locks)
    after = _Service(guest, unit)

    if after["Job"] or after["MainPID"] != "0" or after["ControlPID"] != "0":
        raise RuntimeError("Owned unit changed during definition reconciliation")

    _CgroupEmpty(guest, unit)


@contextmanager
def _Published(guest: Any, root: Path, unit: Path, receipt: dict[str, Any]) -> Iterator[None]:
    """Pin/resync the actual root, unit and link across publication or acknowledgment; receipt replacement uses a separate scope."""

    if guest._Receipt(root, unit, receipt["owner"], staged=True) != receipt:
        raise RuntimeError("Published native generation differs from its complete reserved receipt")

    expectedNames = set(receipt["files"]) | {"receipt.json"}
    descriptors: dict[Path, tuple[int, os.stat_result]] = {}
    directories: dict[Path, tuple[int, os.stat_result]] = {}
    link = guest.SYSTEMD / "multi-user.target.wants" / unit.name

    def Verify() -> None:
        """Reject same-byte inode replacement and changed namespace membership without adopting or deleting it."""

        for path, (descriptor, expected) in (*directories.items(), *descriptors.items()):
            current = os.fstat(descriptor)
            linked = path.lstat()

            if ((expected.st_dev, expected.st_ino, expected.st_mode, expected.st_uid, expected.st_nlink)
                    != (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink)
                    or (expected.st_dev, expected.st_ino) != (linked.st_dev, linked.st_ino)
                    or (expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)
                    != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
                raise RuntimeError("Published native generation changed during durable activation")

        if ({path.name for path in root.iterdir()} != expectedNames
                or guest._Receipt(root, unit, receipt["owner"], staged=True) != receipt):
            raise RuntimeError("Published native generation has changed payload or membership")

        guest._EnabledLink(unit)

        if not link.is_symlink():
            raise RuntimeError("Published native generation has no exact enablement link")

    try:
        for path in (root.parent, root, guest.SYSTEMD, link.parent):
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directories[path] = descriptor, os.fstat(descriptor)

        for path in (*(root / name for name in sorted(expectedNames)), unit):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors[path] = descriptor, os.fstat(descriptor)

        descriptor = os.open(link, os.O_PATH | os.O_NOFOLLOW)
        descriptors[link] = descriptor, os.fstat(descriptor)
        Verify()

        for path, (descriptor, _) in descriptors.items():
            if path != link:
                os.fsync(descriptor)

        for path in (root, root.parent, link.parent, guest.SYSTEMD):
            os.fsync(directories[path][0])

        Verify()

        yield
        Verify()

    finally:
        for descriptor, _ in (*descriptors.values(), *reversed(directories.values())):
            os.close(descriptor)


@contextmanager
def _Handoff(locks: tuple[int, ...]) -> Iterator[tuple[int, ...]]:
    """Keep common authority while allowing the WG leaf callback to finish; never invert lock acquisition."""

    import fcntl

    if len(locks) != 2:
        raise RuntimeError("Native job handoff requires both existing coordination descriptors")

    fcntl.flock(locks[1], fcntl.LOCK_UN)

    try:
        yield (locks[0],)

    finally:
        fcntl.flock(locks[1], fcntl.LOCK_EX | fcntl.LOCK_NB)


@contextmanager
def _Native(guest: Any, locks: tuple[int, ...]) -> Iterator[None]:
    """Direct native children retain both parent locks through process death before any systemd handoff."""

    if guest._callbackFds:
        raise RuntimeError("Nested native generation authority is unsupported")

    guest._callbackFds = locks

    try:
        yield

    finally:
        guest._callbackFds = ()


def _Input(guest: Any, authority: Any, policy: Any, inputs: Any, request: dict[str, Any], intent: dict[str, Any]) -> str:
    """Verify actual boot and live input under the same locks, without replaying historical bootstrap bytes."""

    values = policy.Transition(request["input"])
    fingerprints = inputs._Compiled(guest, policy, values)
    record = inputs._Load(guest, authority, inputs._Expected(policy, intent, request, fingerprints))

    if record is None:
        raise RuntimeError("Native generation requires its prepared exact host-input transaction")

    inputs._State(guest, policy, values, fingerprints, record["phase"])

    return str(record["phase"])


def _Quiet(guest: Any, owner: str) -> None:
    """Prove the owned forwarding/interface namespace absent without resetting shared forwarding or other transports."""

    if guest._InterfaceState(owner) is not None or guest._NftState(owner, "0" * 32) is not None:
        raise RuntimeError("Native generation namespace is not completely stopped")


def _Units(guest: Any, owner: str, unit: Path, content: bytes, *, absent: bool = False) -> None:
    """Validate only the exact known unit and enablement link; never sweep other owner entries or aliases."""

    allowed = {unit, guest.SYSTEMD / "multi-user.target.wants" / unit.name}

    if guest._OwnedUnits(owner) - allowed:
        raise RuntimeError("Native generation unit namespace contains foreign or other-generation entries")

    guest._EnabledLink(unit)

    if unit.exists() or unit.is_symlink():
        if absent or guest._Read(unit, mode=0o644) != content:
            raise RuntimeError("Native generation unit differs from its exact cached bytes")


def _PartialRoot(guest: Any, root: Path, receipt: dict[str, Any]) -> None:
    """Recognize only a complete known file subset during journaled flat deletion, never repair foreign state."""

    if not root.exists() and not root.is_symlink():
        return

    guest._Directory(root, private=True)
    names = {path.name for path in root.iterdir()}

    if not names <= set(receipt["files"]) | {"receipt.json"}:
        raise RuntimeError("Native generation root contains unknown files")

    for name in names:
        content = guest._Read(root / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576, mode=0o755 if name == "wg" else 0o600)

        if (content != guest._Encode(receipt) if name == "receipt.json" else guest._Digest(content) != receipt["files"][name]):
            raise RuntimeError("Native generation deletion prefix has changed bytes")


def _CandidatePrefix(guest: Any, cache: Any, root: Path, receipt: dict[str, Any]) -> set[str]:
    """Recognize source-proved torn publication bytes only while the native journal owns this exact candidate."""

    if not root.exists() and not root.is_symlink():
        return set()

    guest._Directory(root, private=True)
    names = {path.name for path in root.iterdir()}
    source = cache._CachePath(guest, receipt)

    if not names <= set(receipt["files"]) | {"receipt.json"}:
        raise RuntimeError("Candidate publication contains unknown files")

    for name in names:
        content = cache._ReadPrefix(guest, root / name, 8 * 1024 * 1024 if name == "wg" else 1048576, 0o755 if name == "wg" else 0o600)
        expected = guest._Encode(receipt) if name == "receipt.json" else guest._Read(source / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                                                                                 mode=0o755 if name == "wg" else 0o600)

        if not expected.startswith(content) and not (name == "receipt.json" and content == guest._Encode({**receipt, "status": "installed"})):
            raise RuntimeError("Candidate publication has foreign or changed private bytes")

    return names


def _CandidateUnit(guest: Any, cache: Any, owner: str, unit: Path, receipt: dict[str, Any]) -> None:
    """Accept only the exact staged unit prefix before activation or during candidate-only cleanup."""

    allowed = {unit, guest.SYSTEMD / "multi-user.target.wants" / unit.name}

    if guest._OwnedUnits(owner) - allowed:
        raise RuntimeError("Candidate publication has other or unknown owner units")

    if unit.exists() or unit.is_symlink():
        content = cache._ReadPrefix(guest, unit, 1048576, 0o644)
        expected = guest._Read(cache._CachePath(guest, receipt) / "service.service")

        if not expected.startswith(content):
            raise RuntimeError("Candidate unit is outside its exact publication prefix")

    guest._EnabledLink(unit)


def _Guard(guest: Any, authority: Any, record: dict[str, Any], verify: Callable[[], None]) -> None:
    """Keep complete cache, generation, reservation and native-intent binding through each mutation boundary."""

    verify()
    _Reservation(guest, authority, record["intent"])

    if _Load(guest, authority, record["request"], record["intent"]) != record:
        raise RuntimeError("Native generation intent changed during its mutation")


def _FreshHistory(guest: Any, request: dict[str, Any], intent: dict[str, Any]) -> str:
    """Return the preplanned fresh fence; this is not evidence that a service ever activated."""

    return str(guest._Digest(guest._Encode(guest._GenerationAudit(intent, request))))


def _Fence(guest: Any, peer: Any, request: dict[str, Any], intent: dict[str, Any]) -> None:
    """Consume new generation authority before root publication, retaining the prior consumed fence on rollback."""

    original = guest._ProtocolHistory(intent, request)
    expected = guest._GenerationAudit(intent, request)

    if peer._History(guest, intent["owner"]) not in {original, guest._Digest(guest._Encode(expected))}:
        raise RuntimeError("Native generation has stale or unrecorded peer history")

    peer._Cancel(guest, {**request["generation"]["candidate_receipt"], "status": "installed"}, "revoke", "protocol-" + intent["operation_id"], original)


def _Observe(
    guest: Any, peer: Any, authority: Any, cache: Any, request: dict[str, Any], intent: dict[str, Any], record: dict[str, Any],
) -> str:
    """Validate known real prefixes; intermediate phases report no active-health claim or permission to guess recovery."""

    owner = intent["owner"]
    root, _, transaction = guest._Paths(owner)
    generation = request["generation"]
    old = generation["cached_receipt"]
    candidate = generation["candidate_receipt"]
    phase = record["phase"]
    oldUnit = guest._Paths(owner, nonce=old["nonce"] if old["schema_version"] == 2 else "")[1]
    newUnit = guest._Paths(owner, nonce=candidate["nonce"])[1]
    history = peer._History(guest, owner)
    original = guest._ProtocolHistory(intent, request)
    fresh = _FreshHistory(guest, request, intent)

    if transaction.exists() or transaction.is_symlink():
        raise RuntimeError("A legacy WG/peer transaction cannot overlap native protocol recovery")

    if phase in {"ready", "unchanged"}:
        _, history = authority._Observe(guest, peer, intent)

        if history != original:
            raise RuntimeError("Native generation original history differs")

        return str(history)

    expected = ({original} if phase in {"removing-original", "stopping-original", "inactive"} else {original, fresh}
                if phase in {"publishing", "removing-candidate"} else {fresh})

    if history not in expected or history == fresh and peer._Audit(guest, owner) != guest._GenerationAudit(intent, request):
        raise RuntimeError("Native generation receipt/history prefix is stale or foreign")

    if phase in {"active", "restored"}:
        observed = guest._Check(root, newUnit, guest._Request(root)[0])

        if observed != {**candidate, "status": "installed"}:
            raise RuntimeError("Native generation active receipt differs from the reserved candidate")

        _Active(guest, newUnit)

    elif phase in {"inactive", "rolled-back"}:
        guest._RequireAbsent(owner)
        _Drained(guest, oldUnit if phase == "inactive" else newUnit)

    elif phase in {"removing-original", "stopping-original", "removing-candidate", "stopping-candidate"}:
        receipt = old if phase.endswith("original") else candidate
        unit = oldUnit if phase.endswith("original") else newUnit
        content = guest._Read(cache._CachePath(guest, receipt) / "service.service")
        quiet = guest._InterfaceState(owner) is None and guest._NftState(owner, receipt["nonce"]) is None

        if phase == "removing-candidate" and quiet:
            _CandidateUnit(guest, cache, owner, unit, receipt)

        else:
            _Units(guest, owner, unit, content)

        if root.exists() or root.is_symlink():
            actual = receipt

            if (root / "receipt.json").exists():
                raw = cache._ReadPrefix(guest, root / "receipt.json", 1048576, 0o600)

                if raw in {guest._Encode(receipt), guest._Encode({**receipt, "status": "installed"})}:
                    actual = guest._Json(raw)

                elif not quiet or not phase.endswith("candidate"):
                    raise RuntimeError("Native generation has an incomplete unexpected receipt")

            if phase.endswith("candidate") and actual == {**candidate, "status": "installed"}:
                receipt = actual

            if guest._InterfaceState(owner) is not None or guest._NftState(owner, receipt["nonce"]) is not None:
                observed = guest._Receipt(root, unit, owner, staged=True)

                if observed != receipt:
                    raise RuntimeError("Native generation cleanup found an unplanned root")

                state = guest._InterfaceState(owner)

                if state is not None:
                    if state.get("ifalias") != guest._Alias(owner, receipt["nonce"]):
                        raise RuntimeError("Native generation cleanup has foreign interface ownership")

                    prepared = guest._Request(root)[0]
                    guest._WireGuardState(root, prepared, partial=receipt["status"] == "staged")
                    guest._AddressState(owner, prepared, partial=receipt["status"] == "staged")

                if guest._NftState(owner, receipt["nonce"]) not in {None, receipt["network_sha256"]}:
                    raise RuntimeError("Native generation cleanup has foreign forwarding state")

            else:
                if candidate == receipt or {**candidate, "status": "installed"} == receipt:
                    _CandidatePrefix(guest, cache, root, candidate)

                else:
                    _PartialRoot(guest, root, receipt)

        else:
            _Quiet(guest, owner)

        if phase.startswith("stopping-") and (root.exists() or root.is_symlink()):
            raise RuntimeError("Dispatched stop still has an armed root")

    else:
        if phase in {"starting", "restarting-active", "restarting-restored"}:
            _Units(guest, owner, newUnit, guest._Read(cache._CachePath(guest, candidate) / "service.service"))
            observed = guest._Receipt(root, newUnit, owner, staged=True)

            if observed not in (candidate, {**candidate, "status": "installed"}):
                raise RuntimeError("Starting generation has a different complete receipt")

        else:
            _Quiet(guest, owner)
            _CandidatePrefix(guest, cache, root, candidate)
            _CandidateUnit(guest, cache, owner, newUnit, candidate)

            if (newUnit.exists() or newUnit.is_symlink()) and not root.exists():
                raise RuntimeError("Candidate unit exists before its journaled root publication")

    return str(history)


def _TerminalAbsent(guest: Any, peer: Any, request: dict[str, Any], intent: dict[str, Any], record: dict[str, Any]) -> bool:
    """Prove a completed generation's full kernel absence after reboot, never treat partial installed state as recoverable reset peers."""

    if record["phase"] not in {"active", "restored"}:
        return False

    owner = intent["owner"]

    if guest._InterfaceState(owner) is not None or guest._NftState(owner, "0" * 32) is not None:
        return False

    receipt = {**request["generation"]["candidate_receipt"], "status": "installed"}
    root, unit, transaction = guest._Paths(owner, nonce=receipt["nonce"])

    if (transaction.exists() or transaction.is_symlink() or guest._Receipt(root, unit, owner) != receipt
            or peer._Audit(guest, owner) != guest._GenerationAudit(intent, request)):
        raise RuntimeError("Absent completed generation has foreign receipt, transaction or history")

    _Units(guest, owner, unit, guest._Read(root / "service.service"))
    link = guest.SYSTEMD / "multi-user.target.wants" / unit.name

    if not link.is_symlink():
        raise RuntimeError("Absent completed generation has lost its exact enablement link")

    _Drained(guest, unit)

    return True


def Observe(
    guest: Any, peer: Any, authority: Any, policy: Any, cache: Any, value: object, rawIntent: object,
) -> dict[str, str]:
    """Observe a runtime prefix beneath caller-held common/WG locks for exact input recovery; never acquire locks in reverse."""

    intent = authority.Intent(rawIntent)
    request = cache.Request(guest, policy, value, intent)
    _Reservation(guest, authority, intent)
    record = _Load(guest, authority, request, intent)

    if record is None:
        raise RuntimeError("No exact native generation transaction is recorded")

    cache.Prepared(guest, authority, policy, request, intent, guest._ProtocolHistory(intent, request))
    absent = _TerminalAbsent(guest, peer, request, intent, record)
    history = _FreshHistory(guest, request, intent) if absent else _Observe(guest, peer, authority, cache, request, intent, record)

    return {"status": "native-generation", "phase": "recovery-required" if absent else record["phase"], "history_sha256": history}


def _Remove(
    guest: Any, peer: Any, authority: Any, cache: Any, record: dict[str, Any], locks: tuple[int, ...], verify: Callable[[], None], *, candidate: bool,
) -> dict[str, Any]:
    """Disarm under WG before handoff, then drain PID1 and erase only this generation's exact unit/link."""

    request, intent = record["request"], record["intent"]
    owner = intent["owner"]
    receipt = request["generation"]["candidate_receipt" if candidate else "cached_receipt"]
    root = guest._Paths(owner)[0]
    unit = guest._Paths(owner, nonce=receipt["nonce"] if receipt["schema_version"] == 2 else "")[1]
    content = guest._Read(cache._CachePath(guest, receipt) / "service.service")
    removing = "removing-candidate" if candidate else "removing-original"
    stopping = "stopping-candidate" if candidate else "stopping-original"

    if record["phase"] == removing:
        _Guard(guest, authority, record, verify)
        if candidate:
            _Fence(guest, peer, request, intent)

        _Observe(guest, peer, authority, cache, request, intent, record)
        if candidate and guest._InterfaceState(owner) is None and guest._NftState(owner, receipt["nonce"]) is None:
            _CandidateUnit(guest, cache, owner, unit, receipt)

            if unit.exists():
                cache._File(guest, unit, content, 0o644, resume=True)
                guest._SyncDirectory(guest.SYSTEMD)

        _Units(guest, owner, unit, content)
        _Reconcile(guest, unit, locks)
        link = guest.SYSTEMD / "multi-user.target.wants" / unit.name

        if link.is_symlink():
            link.unlink()
            guest._SyncDirectory(link.parent)

        if root.exists() or root.is_symlink():
            if guest._InterfaceState(owner) is not None or guest._NftState(owner, receipt["nonce"]) is not None:
                receipt = guest._Receipt(root, unit, owner, staged=True)

                with _Native(guest, locks):
                    guest._Stop(root, unit, guest._Request(root)[0], partial=receipt["status"] == "staged", recovering=True)

            _Quiet(guest, owner)

            _Guard(guest, authority, record, verify)

            if candidate:
                names = _CandidatePrefix(guest, cache, root, request["generation"]["candidate_receipt"])

                for name in (*sorted(names - {"receipt.json"}), "receipt.json"):
                    path = root / name

                    if name in names:
                        _CandidatePrefix(guest, cache, root, request["generation"]["candidate_receipt"])
                        path.unlink()

                guest._SyncDirectory(root)
                root.rmdir()
                guest._SyncDirectory(root.parent)

            else:
                guest._EraseRoot(root, receipt)

        _Quiet(guest, owner)
        _Guard(guest, authority, record, verify)
        record = _Write(guest, authority, record, stopping)

        # The root is absent before WG unlock, so a legacy WG-only driver cannot
        # obtain fresh healthy old-root authority during this handoff.
        with _Handoff(locks) as common:
            guest._Run(["systemctl", "stop", unit.name], required=False, passFds=common)

    if record["phase"] == stopping:
        _Guard(guest, authority, record, verify)
        _Observe(guest, peer, authority, cache, request, intent, record)
        state = _Service(guest, unit)

        if (state["Job"] or state["MainPID"] != "0" or state["ControlPID"] != "0"
                or state["ActiveState"] not in {"inactive", "failed"} or state["SubState"] not in {"dead", "failed"}):
            # Death may occur after durable stop intent but before submission.
            # This exact unit is permanently retired, so repeating its stop
            # cannot target the fresh restoration unit or revive old authority.
            with _Handoff(locks) as common:
                guest._Run(["systemctl", "stop", unit.name], required=False, passFds=common)

            _Guard(guest, authority, record, verify)

        _Drained(guest, unit)
        _Units(guest, owner, unit, content)
        link = guest.SYSTEMD / "multi-user.target.wants" / unit.name

        if link.exists() or link.is_symlink():
            raise RuntimeError("Stopped native generation retains an unexpected enablement link")

        if unit.exists():
            unit.unlink()

        guest._SyncDirectory(guest.SYSTEMD)
        guest._Run(["systemctl", "daemon-reload"], passFds=locks)
        _Drained(guest, unit)
        guest._RequireAbsent(owner)
        _Guard(guest, authority, record, verify)
        record = _Write(guest, authority, record, "rolled-back" if candidate else "inactive")

    return record


def _Activate(
    guest: Any, peer: Any, authority: Any, policy: Any, cache: Any, record: dict[str, Any], locks: tuple[int, ...], verify: Callable[[], None],
) -> dict[str, Any]:
    """Publish only the preplanned fresh generation, then admit its exact callback without restoring old unit identity."""

    request, intent = record["request"], record["intent"]
    owner = intent["owner"]
    receipt = request["generation"]["candidate_receipt"]
    root, unit, _ = guest._Paths(owner, nonce=receipt["nonce"])

    if record["phase"] == "publishing":
        _Guard(guest, authority, record, verify)
        _Quiet(guest, owner)
        _Fence(guest, peer, request, intent)
        payload = cache._Source(guest, cache._CachePath(guest, receipt), receipt, request["input"]["listener"])
        guest._Directory(root, create=True, private=True)

        if {path.name for path in root.iterdir()} - set(payload):
            raise RuntimeError("Candidate root has unrecorded private entries")

        for name in (*sorted(set(payload) - {"receipt.json"}), "receipt.json"):
            cache._File(guest, root / name, payload[name], 0o755 if name == "wg" else 0o600, resume=True)

        guest._SyncDirectory(root)
        guest._SyncDirectory(root.parent)
        cache._File(guest, unit, payload["service.service"], 0o644, resume=True)
        guest._SyncDirectory(guest.SYSTEMD)
        guest._Receipt(root, unit, owner, staged=True)
        guest._EnabledLink(unit)
        link = guest.SYSTEMD / "multi-user.target.wants" / unit.name
        guest._Directory(link.parent, create=True)

        if not link.exists() and not link.is_symlink():
            link.symlink_to(unit)

        guest._EnabledLink(unit)
        guest._SyncDirectory(link.parent)
        guest._SyncDirectory(guest.SYSTEMD)
        _Guard(guest, authority, record, verify)

        with _Published(guest, root, unit, receipt):
            record = _Write(guest, authority, record, "starting")

    if record["phase"] in {"restarting-active", "restarting-restored"}:
        current = guest._Receipt(root, unit, owner, staged=True)

        if current["status"] == "installed":
            _Quiet(guest, owner)
            _Drained(guest, unit)

            with _Published(guest, root, unit, current):
                _Guard(guest, authority, record, verify)

            guest._Atomic(root / "receipt.json", guest._Encode(receipt))

    if record["phase"] in {"starting", "restarting-active", "restarting-restored"}:
        _Guard(guest, authority, record, verify)
        _Observe(guest, peer, authority, cache, request, intent, record)
        current = guest._Receipt(root, unit, owner, staged=True)

        with _Published(guest, root, unit, current):
            _Reconcile(guest, unit, locks)
            state = _Service(guest, unit)

            if state["ActiveState"] in {"inactive", "failed"}:
                _Drained(guest, unit)

                # Failed staged starts may have known partial native state.
                # Direct cleanup retains both locks and creates no delayed stop
                # of a restoration identity that must subsequently remain live.
                with _Native(guest, locks):
                    guest._Stop(root, unit, guest._Request(root)[0], partial=current["status"] == "staged", recovering=True)

                with _Handoff(locks) as common:
                    guest._Run(["systemctl", "start", unit.name], required=False, passFds=common)

            elif state["ActiveState"] != "active":
                raise RuntimeError("Generation activation has an unknown native service state")

            staged = guest._Check(root, unit, guest._Request(root)[0], staged=True)

            if staged not in (receipt, {**receipt, "status": "installed"}):
                raise RuntimeError("Activated generation differs from its exact candidate")

            _Active(guest, unit)
            _Guard(guest, authority, record, verify)

        guest._Atomic(root / "receipt.json", guest._Encode({**receipt, "status": "installed"}))

        with _Published(guest, root, unit, {**receipt, "status": "installed"}):
            guest._Check(root, unit, guest._Request(root)[0])
            _Guard(guest, authority, record, verify)
            record = _Write(guest, authority, record, "restored" if request["generation"]["change"] == "disable" else "active")

    return record


def Execute(
    guest: Any, peer: Any, authority: Any, policy: Any, inputs: Any, cache: Any, value: object, rawIntent: object, *,
    allowMutation: bool = False, rollback: bool = False,
    expectedProgramSha256: str = "",
) -> dict[str, str]:
    """Advance or recover one exact native WG generation; cloud ordering and common completion remain controller responsibilities."""

    intent = authority.Intent(rawIntent)
    request = cache.Request(guest, policy, value, intent)

    if allowMutation is not True or type(rollback) is not bool or request["generation"]["schema_version"] != 3:
        raise RuntimeError("Native generation requires explicit consent and a versioned restoration plan")

    guest._RequireDigest(expectedProgramSha256)

    if guest._Digest(guest._Read(Path(guest.__file__), limit=1048576)) != expectedProgramSha256:
        raise RuntimeError("Native receiver program differs from its explicit approved source pin")

    with authority._Locks(guest, readOnly=False) as locks:
        pending = _Reservation(guest, authority, intent)
        record = _Load(guest, authority, request, intent)
        history = guest._ProtocolHistory(intent, request)
        change = request["generation"]["change"]
        inputPhase = _Input(guest, authority, policy, inputs, request, intent)
        expectedInput = ({"rolled-back"} if change == "enable" and rollback else {"prepared"} if change == "enable" else {"applied"})

        if record is not None:
            if change == "enable" and not rollback and record["phase"] in {"active", "restarting-active"}:
                expectedInput.add("applied")

            elif change == "disable" and rollback and record["phase"] in {"restored", "restarting-restored", "unchanged"}:
                expectedInput.add("rolled-back")

        if inputPhase not in expectedInput or record is not None and record["rollback"] and not rollback:
            raise RuntimeError("Native generation input phase or recovery direction differs from its recorded order")

        if record is None:
            if request["generation"]["candidate_receipt"]["files"]["lifecycle.py"] != expectedProgramSha256:
                raise RuntimeError("Native admission requires the exact approved sealed callback program")

            _, actual = authority._Observe(guest, peer, intent)

            if actual != history:
                raise RuntimeError("Native generation begins with stale actual WG history")

        else:
            if not _TerminalAbsent(guest, peer, request, intent, record):
                _Observe(guest, peer, authority, cache, request, intent, record)

        # Create only the shared empty WG container before pinning its ancestors;
        # the owner root and service remain absent until journaled publication.
        guest._Directory(guest.BASE, create=True)

        with cache.Ready(guest, authority, policy, request, intent, history) as verify:
            authority._Publish(guest, "pending.json", pending)
            record = record if record is not None else {"schema_version": 1, "intent": intent, "request": request,
                                                       "history_sha256": history, "admitted_program_sha256": expectedProgramSha256,
                                                       "phase": "ready", "rollback": False}
            authority._Publish(guest, "runtime.json", record)

            if rollback and not record["rollback"]:
                record = _Write(guest, authority, record, record["phase"], rollback=True)

            if change == "disable":
                if record["phase"] == "ready":
                    record = _Write(guest, authority, record, "unchanged" if rollback else "removing-original")

                if record["phase"] in {"removing-original", "stopping-original"}:
                    verify()
                    record = _Remove(guest, peer, authority, cache, record, locks, verify, candidate=False)

                if record["phase"] == "inactive" and rollback:
                    record = _Write(guest, authority, record, "publishing")

            elif rollback:
                if record["phase"] not in {"removing-candidate", "stopping-candidate", "rolled-back"}:
                    record = _Write(guest, authority, record, "removing-candidate")

                if record["phase"] != "rolled-back":
                    verify()
                    record = _Remove(guest, peer, authority, cache, record, locks, verify, candidate=True)

            elif record["phase"] == "ready":
                record = _Write(guest, authority, record, "publishing")

            if _TerminalAbsent(guest, peer, request, intent, record):
                _Guard(guest, authority, record, verify)
                record = _Write(guest, authority, record, "restarting-" + record["phase"])

            if record["phase"] in {"publishing", "starting", "restarting-active", "restarting-restored"}:
                verify()
                record = _Activate(guest, peer, authority, policy, cache, record, locks, verify)

            verify()
            _Reservation(guest, authority, intent)
            candidate = {**request["generation"]["candidate_receipt"], "status": "installed"}
            root, unit, _ = guest._Paths(intent["owner"], nonce=candidate["nonce"])

            with _Published(guest, root, unit, candidate) if record["phase"] in {"active", "restored"} else nullcontext():
                _Guard(guest, authority, record, verify)
                actual = _Observe(guest, peer, authority, cache, request, intent, record)

                return {"status": "native-generation", "phase": record["phase"], "history_sha256": actual,
                        "journal_sha256": guest._Digest(guest._Encode(record))}


def Status(guest: Any, peer: Any, authority: Any, policy: Any, cache: Any, value: object, rawIntent: object) -> dict[str, str]:
    """Observe exact known prefixes with no service command, repair, cache resync or publication."""

    with authority._Locks(guest, readOnly=True):
        return Observe(guest, peer, authority, policy, cache, value, rawIntent)
