"""Apply one receipt-bound peer change without restarting a shared WireGuard interface."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

HELPER_SHA256 = "__FLAYER_WIREGUARD_HELPER_SHA256__"


def Programs() -> tuple[bytes, bytes]:
    """Pack the exact stdlib-only driver and checksum-bound helper for private controller-to-guest staging."""

    from importlib.resources import files

    source = files("flayer.profiles").joinpath("_wireguard_peer.py").read_bytes().replace(b"\r\n", b"\n")
    helper = files("flayer.profiles").joinpath("_wireguard_guest.py").read_bytes().replace(b"\r\n", b"\n")
    marker = HELPER_SHA256.encode("ascii")

    if source.count(marker) != 1:
        raise ValueError("WireGuard peer driver template has an unexpected helper pin")

    return source.replace(marker, hashlib.sha256(helper).hexdigest().encode("ascii")), helper


def _Guest() -> Any:
    """Load only the package helper or a checksum-bound private standalone copy, never a supplied module path."""

    if __package__:
        from flayer.profiles import _wireguard_guest as wireguardGuest

        return wireguardGuest

    path = Path(__file__).absolute().parent / "maintenance.py"

    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError("WireGuard maintenance source has unsafe ancestry")

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

    try:
        info = os.fstat(descriptor)

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 1 <= info.st_size <= 1048576):
            raise ValueError("WireGuard maintenance source is not a private root-owned file")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(1048577)

        if hashlib.sha256(content).hexdigest() != HELPER_SHA256:
            raise ValueError("WireGuard maintenance source does not match its exact package pin")

    finally:
        os.close(descriptor)

    spec = importlib.util.spec_from_loader("flayer_wireguard_maintenance", loader=None)

    if spec is None:
        raise ValueError("WireGuard maintenance module is unavailable")

    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    exec(compile(content, str(path), "exec"), module.__dict__)

    return module


def _Delta(guest: Any, old: Path, new: Path, action: str, deviceId: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Prove a sole named addition/removal while retaining every other credential, address and runtime pin."""

    _Change(guest, action, deviceId)

    previous, oldConfig, _ = guest._Request(old)
    desired, newConfig, _ = guest._Request(new)

    if {key: value for key, value in previous.items() if key not in {"peers", "config_sha256"}} != {
        key: value for key, value in desired.items() if key not in {"peers", "config_sha256"}
    }:
        raise guest.GuestError("Peer change cannot modify identity, listener, subnet, policy or runtime")

    before = {peer["device_id"]: peer for peer in previous["peers"]}
    after = {peer["device_id"]: peer for peer in desired["peers"]}
    expected = set(before) | {deviceId} if action == "enroll" else set(before) - {deviceId}

    if (set(after) != expected or (deviceId in before) != (action == "revoke")
            or any(before[name] != after[name] for name in set(before) & set(after))):
        raise guest.GuestError("WireGuard peer change differs from the single named membership delta")

    oldPrivate, oldPublic, oldPeers = guest._Config(oldConfig, previous, old / "wg")
    newPrivate, newPublic, newPeers = guest._Config(newConfig, desired, old / "wg")

    if (oldPrivate != newPrivate or oldPublic != newPublic
            or any(oldPeers[key] != newPeers[key] for key in set(oldPeers) & set(newPeers))):
        raise guest.GuestError("Peer change cannot rotate the server or unrelated peer credentials")

    return previous, desired


def _Change(guest: Any, action: str, deviceId: str) -> None:
    """Reject unsupported actions and ambiguous device names before inspecting any managed state."""

    if not isinstance(action, str) or action not in {"enroll", "revoke"} or not isinstance(deviceId, str) or guest._NAME.fullmatch(deviceId) is None:
        raise guest.GuestError("WireGuard peer change requires one supported action and device identity")


def _Exchange(guest: Any, left: Path, right: Path) -> None:
    """Atomically exchange complete private directories without exposing missing or mixed configuration."""

    for path in (left, right):
        guest._Directory(path, private=True)

    if left.stat().st_dev != right.stat().st_dev:
        raise guest.GuestError("Atomic peer publication requires one owned filesystem")

    library = ctypes.CDLL(None, use_errno=True)

    try:
        rename = library.renameat2

    except AttributeError:
        raise guest.GuestError("Atomic directory exchange is unavailable on this guest") from None

    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int

    if rename(-100, os.fsencode(left), -100, os.fsencode(right), 2) != 0:
        raise guest.GuestError("Atomic directory exchange failed; retain the peer recovery journal")

    guest._SyncDirectory(left.parent)
    guest._SyncDirectory(right.parent)


def _Runtime(guest: Any, root: Path, unit: Path, request: dict[str, Any], receipt: dict[str, Any]) -> None:
    """Verify stable service/interface/address/kernel facts independently of the transitioning peer and nft policy."""

    owner = request["owner"]
    guest._KernelMatches(receipt)
    guest._Run(["systemctl", "is-active", "--quiet", unit.name])
    guest._Run(["systemctl", "is-enabled", "--quiet", unit.name])
    state = guest._InterfaceState(owner)

    if (state is None or state.get("ifalias") != guest._Alias(owner, receipt["nonce"])
            or state.get("mtu") != request["mtu"] or not isinstance(state.get("flags"), list) or "UP" not in state["flags"]):
        raise guest.GuestError("WireGuard peer operation found a changed interface")

    guest._AddressState(owner, request)
    guest._LoadedSource(receipt["kernel"]["module_srcversion"], required=True)
    _, forwarding = guest._Run(["sysctl", "-n", "net.ipv4.ip_forward"])

    if forwarding.strip() != b"1":
        raise guest.GuestError("WireGuard peer operation requires active forwarding")


def _Journal(guest: Any, owner: str) -> tuple[dict[str, Any], Path]:
    """Accept only a complete published single-peer transaction with compatible old/new runtime receipts."""

    _, _, transaction = guest._Paths(owner)
    guest._Directory(transaction, private=True)

    if {path.name for path in transaction.iterdir()} not in ({"transaction.json", "new"}, {"transaction.json"}):
        raise guest.GuestError("WireGuard peer transaction has unknown or incomplete metadata")

    content = guest._Read(transaction / "transaction.json")
    record = guest._Json(content)

    if (not isinstance(record, dict) or set(record) != {"schema_version", "owner", "phase", "action", "device_id", "previous", "desired", "previous_history_sha256"}
            or type(record["schema_version"]) is not int or record["schema_version"] != 2 or record["owner"] != owner
            or record["phase"] != "peer-prepared" or record["action"] not in {"enroll", "revoke"}
            or not isinstance(record["device_id"], str) or guest._NAME.fullmatch(record["device_id"]) is None):
        raise guest.GuestError("WireGuard peer journal is invalid")

    if content != guest._Encode(record):
        raise guest.GuestError("WireGuard peer journal has noncanonical changed bytes")

    guest._RequireDigest(record["previous_history_sha256"])
    before = guest._ReceiptData(record["previous"], owner)
    after = guest._ReceiptData(record["desired"], owner)

    if ({key: value for key, value in before.items() if key not in {"files", "network_sha256", "deployment_sha256"}}
            != {key: value for key, value in after.items() if key not in {"files", "network_sha256", "deployment_sha256"}}
            or any(before["files"][name] != after["files"][name] for name in set(before["files"]) - {"server.conf", "deployment.json", "firewall.nft"})
            or before["files"]["server.conf"] == after["files"]["server.conf"]
            or before["network_sha256"] == after["network_sha256"]
            or before["deployment_sha256"] == after["deployment_sha256"]):
        raise guest.GuestError("Peer journal cannot authorize runtime, unit or owner changes")

    return record, transaction


def _Publish(guest: Any, desired: Path, action: str, deviceId: str, expected: str, expectedHistory: str) -> tuple[dict[str, Any], Path]:
    """Durably stage complete candidate files and nonsecret receipt-bound recovery intent before live mutation."""

    request, _, _ = guest._Request(desired)
    owner = request["owner"]
    root, unit, transaction = guest._ActivePaths(owner)

    if transaction.exists() or transaction.is_symlink():
        raise guest.GuestError("An unresolved WireGuard operation requires explicit recovery")

    previous = guest._Check(root, unit, guest._Request(root)[0])

    if guest._Read(root / "receipt.json") != guest._Encode(previous):
        raise guest.GuestError("WireGuard peer operation requires the unchanged canonical root receipt")

    if guest._Digest(guest._Read(root / "receipt.json")) != expected:
        raise guest.GuestError("WireGuard peer change requires the exact current receipt")

    if _History(guest, owner) != expectedHistory:
        raise guest.GuestError("WireGuard peer history changed after the plan was observed")

    _, request = _Delta(guest, root, desired, action, deviceId)

    with tempfile.TemporaryDirectory(prefix=".peer-stage-", dir=guest.BASE) as temporary:
        work = Path(temporary)
        os.chmod(work, 0o700)
        # Test required publication support on this filesystem before any live peer/table change.
        probeLeft, probeRight = work / "probe-left", work / "probe-right"
        probeLeft.mkdir(mode=0o700)
        probeRight.mkdir(mode=0o700)
        _Exchange(guest, probeLeft, probeRight)
        probeLeft.rmdir()
        probeRight.rmdir()
        guest._SyncDirectory(work)
        container = work / "transaction"
        container.mkdir(mode=0o700)
        candidate = container / "new"
        candidate.mkdir(mode=0o700)
        payload = {name: guest._Read(root / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                                     mode=0o755 if name == "wg" else 0o600) for name in previous["files"]}
        payload.update({name: guest._Read(desired / name) for name in ("server.conf", "deployment.json")})
        payload["firewall.nft"] = guest._Firewall(request, previous["nonce"])

        for name, content in payload.items():
            guest._Atomic(candidate / name, content, 0o755 if name == "wg" else 0o600)

        network = guest._ExpectedNetwork(candidate / "firewall.nft", owner, previous["nonce"])

        if network == previous["network_sha256"]:
            raise guest.GuestError("WireGuard peer membership did not produce a distinct scoped source policy")

        receipt = {**previous, "files": {name: guest._Digest(content) for name, content in payload.items()},
                   "network_sha256": network, "deployment_sha256": guest._Digest(payload["deployment.json"])}
        guest._Atomic(candidate / "receipt.json", guest._Encode(receipt))
        guest._Receipt(candidate, unit, owner)
        record = {"schema_version": 2, "owner": owner, "phase": "peer-prepared", "action": action,
                  "device_id": deviceId, "previous": previous, "desired": receipt, "previous_history_sha256": expectedHistory}
        guest._Atomic(container / "transaction.json", guest._Encode(record))
        # The exact current root/runtime must still match before the recovery journal becomes authoritative.
        guest._Check(root, unit, guest._Request(root)[0])

        if guest._Digest(guest._Read(root / "receipt.json")) != expected:
            raise guest.GuestError("WireGuard receipt changed during peer staging")

        if _History(guest, owner) != expectedHistory:
            raise guest.GuestError("WireGuard peer history changed during staging")

        guest._Publish(container, transaction)

    return record, transaction


def _KernelChoice(guest: Any, options: tuple[tuple[Path, dict[str, Any]], ...]) -> Path:
    """Accept only exact old/new peer state; learned endpoints and counters remain outside managed policy."""

    for directory, request in options:
        try:
            guest._WireGuardState(directory, request)

            return directory

        except guest.GuestError:
            continue

    raise guest.GuestError("WireGuard peer state is outside both recorded configurations")


def _ReplacePolicy(guest: Any, directory: Path, request: dict[str, Any], receipt: dict[str, Any], accepted: set[str]) -> None:
    """Replace only the fully proved owned nft table in one kernel batch, preserving all unrelated tables."""

    owner, nonce = request["owner"], receipt["nonce"]

    observed = guest._NftState(owner, nonce)

    if observed not in accepted:
        raise guest.GuestError("WireGuard peer policy has drifted before replacement")

    if observed == receipt["network_sha256"]:
        return

    policy = b"delete table ip " + guest._Table(owner).encode() + b"\n" + guest._Read(directory / "firewall.nft")
    guest._Run(["nft", "-f", "-"], payload=policy)

    if guest._NftState(owner, nonce) != receipt["network_sha256"]:
        raise guest.GuestError("WireGuard peer firewall readback is uncertain; retain the journal")


def _Converge(
    guest: Any, target: Path, other: Path, request: dict[str, Any], otherRequest: dict[str, Any],
    receipt: dict[str, Any], otherReceipt: dict[str, Any], *, adding: bool,
) -> None:
    """Change a sole peer without service restart; revoked sources are denied before kernel removal."""

    root, unit, _ = guest._ActivePaths(request["owner"])
    _Runtime(guest, root, unit, request, receipt)
    current = _KernelChoice(guest, ((target, request), (other, otherRequest)))
    accepted = {receipt["network_sha256"], otherReceipt["network_sha256"]}

    policy = guest._NftState(request["owner"], receipt["nonce"])

    if policy not in accepted:
        raise guest.GuestError("WireGuard peer operation found an unknown firewall")

    if (adding and current != target and policy == receipt["network_sha256"]
            or not adding and current == target and policy == otherReceipt["network_sha256"]):
        raise guest.GuestError("WireGuard peer operation found an unrecorded kernel/firewall transition prefix")

    if not adding:
        _ReplacePolicy(guest, target, request, receipt, accepted)

    # syncconf updates only differences, preserving every unchanged peer's active session.
    if current != target:
        guest._Run([str(root / "wg"), "syncconf", guest._Interface(request["owner"]), str(target / "server.conf")])

    guest._WireGuardState(target, request)

    if adding:
        _ReplacePolicy(guest, target, request, receipt, accepted)

    _Runtime(guest, root, unit, request, receipt)


def _Audit(guest: Any, owner: str) -> dict[str, Any] | None:
    """Read the last committed operation proof without treating a changed root as a normal retry."""

    return cast(dict[str, Any] | None, guest._PeerAudit(owner))


def _History(guest: Any, owner: str) -> str:
    """Chain each completion to its exact parent so unchanged configuration cannot authorize stale replay."""

    return cast(str, guest._PeerHistory(owner))


def _CommitRecord(guest: Any, record: dict[str, Any]) -> dict[str, Any]:
    """Bind the completed sole-peer action to the exact old and new ownership receipts."""

    return {"schema_version": 1, "owner": record["owner"], "action": record["action"], "device_id": record["device_id"],
            "previous_receipt_sha256": guest._Digest(guest._Encode(record["previous"])),
            "receipt_sha256": guest._Digest(guest._Encode(record["desired"])),
            "deployment_sha256": record["desired"]["deployment_sha256"], "previous_history_sha256": record["previous_history_sha256"]}


def _CancellationRecord(guest: Any, previous: dict[str, Any], action: str, deviceId: str, history: str) -> dict[str, Any]:
    """Consume the original authority without changing the installed receipt or any peer key."""

    receipt = guest._Digest(guest._Encode(previous))

    return {"schema_version": 1, "owner": previous["owner"], "action": action, "device_id": deviceId,
            "previous_receipt_sha256": receipt, "receipt_sha256": receipt,
            "deployment_sha256": previous["deployment_sha256"], "previous_history_sha256": history}


def _Cancel(guest: Any, previous: dict[str, Any], action: str, deviceId: str, history: str) -> None:
    """Durably fence delayed apply requests before acknowledging recovery or discarding its journal."""

    expected = _CancellationRecord(guest, previous, action, deviceId, history)
    owner = previous["owner"]

    if _Audit(guest, owner) != expected and _History(guest, owner) != history:
        raise guest.GuestError("WireGuard peer cancellation has a different original history head")

    # Repeat the file and directory durability boundary even after a lost publication acknowledgment.
    guest._Atomic(guest.BASE / ("peer-" + owner + ".json"), guest._Encode(expected))

    if _Audit(guest, owner) != expected:
        raise guest.GuestError("WireGuard peer cancellation proof could not be verified")


def _AuditMatches(guest: Any, record: dict[str, Any], *, committed: bool) -> None:
    """Allow only the preceding history or this transaction's exact published completion proof."""

    audit = _Audit(guest, record["owner"])

    if committed and audit == _CommitRecord(guest, record):
        return

    if not committed and audit == _CancellationRecord(guest, record["previous"], record["action"], record["device_id"], record["previous_history_sha256"]):
        return

    if (_History(guest, record["owner"]) != record["previous_history_sha256"]
            or audit is not None and audit["receipt_sha256"] != guest._Digest(guest._Encode(record["previous"]))):
        raise guest.GuestError("WireGuard peer commit history does not match the current transaction")


def _Clear(guest: Any, record: dict[str, Any], *, committed: bool) -> None:
    """Retire only hash-proved backups after the complete selected root/runtime and commit boundary are durable."""

    owner = record["owner"]
    root, unit, transaction = guest._ActivePaths(owner)
    selected = record["desired" if committed else "previous"]
    discarded = record["previous" if committed else "desired"]
    current = guest._Check(root, unit, guest._Request(root)[0])

    if current != selected:
        raise guest.GuestError("WireGuard peer cleanup found a different committed root")

    _AuditMatches(guest, record, committed=committed)
    candidate = transaction / "new"

    if candidate.exists() or candidate.is_symlink():
        guest._Directory(candidate, private=True)
        names = {path.name for path in candidate.iterdir()}

        if not names <= set(discarded["files"]) | {"receipt.json"}:
            raise guest.GuestError("WireGuard peer backup contains unknown files")

        for name in names:
            content = guest._Read(candidate / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                                  mode=0o755 if name == "wg" else 0o600)

            if (content != guest._Encode(discarded) if name == "receipt.json" else guest._Digest(content) != discarded["files"][name]):
                raise guest.GuestError("WireGuard peer backup changed before cleanup")

    # Re-establish both exchange-parent boundaries before erasing any exchanged backup.
    guest._SyncDirectory(guest.BASE)
    guest._SyncDirectory(transaction)

    if committed:
        expected = _CommitRecord(guest, record)
        guest._Atomic(guest.BASE / ("peer-" + owner + ".json"), guest._Encode(expected))

        if _Audit(guest, owner) != expected:
            raise guest.GuestError("WireGuard peer commit proof could not be verified")

    else:
        _Cancel(guest, record["previous"], record["action"], record["device_id"], record["previous_history_sha256"])

    if candidate.exists() or candidate.is_symlink():
        guest._EraseRoot(candidate, discarded)

    if {path.name for path in transaction.iterdir()} != {"transaction.json"}:
        raise guest.GuestError("WireGuard peer cleanup has unknown remaining files")

    # Persist root exchange and every previous removal before discarding the recovery record.
    guest._SyncDirectory(guest.BASE)
    guest._SyncDirectory(guest.SYSTEMD)
    guest._SyncDirectory(transaction)
    (transaction / "transaction.json").unlink()
    guest._SyncDirectory(transaction)
    transaction.rmdir()
    guest._SyncDirectory(guest.BASE)


def Apply(guest: Any, desired: Path, action: str, deviceId: str, expected: str, expectedHistory: str) -> str:
    """Apply one explicitly consented, receipt-bound change; preserve a published commit on cleanup failure."""

    _Change(guest, action, deviceId)
    guest._RequireDigest(expected)
    guest._RequireDigest(expectedHistory)
    request, _, raw = guest._Request(desired)
    root, unit, transaction = guest._ActivePaths(request["owner"])
    audit = _Audit(guest, request["owner"])

    if not transaction.exists() and not transaction.is_symlink():
        actual = guest._Check(root, unit, guest._Request(root)[0])

        if guest._Read(root / "receipt.json") != guest._Encode(actual):
            raise guest.GuestError("WireGuard peer operation found changed root receipt bytes")

        if audit is not None and audit["previous_receipt_sha256"] != audit["receipt_sha256"] and (
            audit["action"], audit["device_id"], audit["previous_receipt_sha256"], audit["deployment_sha256"], audit["previous_history_sha256"],
        ) == (
            action, deviceId, expected, guest._Digest(raw), expectedHistory,
        ):
            if audit["receipt_sha256"] != guest._Digest(guest._Encode(actual)):
                raise guest.GuestError("WireGuard peer committed root has changed")

            return "committed"

        if audit is not None and audit["receipt_sha256"] != guest._Digest(guest._Encode(actual)):
            raise guest.GuestError("WireGuard peer root differs from its previous commit proof")

    record, transaction = _Publish(guest, desired, action, deviceId, expected, expectedHistory)
    candidate = transaction / "new"
    previous, desiredRequest = _Delta(guest, root, candidate, action, deviceId)

    try:
        _Converge(guest, candidate, root, desiredRequest, previous, record["desired"], record["previous"], adding=action == "enroll")
        _Exchange(guest, root, candidate)
        guest._Check(root, unit, desiredRequest)

    except Exception:
        # The root receipt, not a possibly failed post-publication fsync, decides whether commit occurred.
        # Explicit recovery still validates current state and never guesses through unrelated drift.
        raise guest.GuestError("WireGuard peer operation interrupted; retain its exact receipt-bound recovery state") from None

    _Clear(guest, record, committed=True)

    return "committed"


def Recover(
    guest: Any, desired: Path, action: str, deviceId: str, expected: str, expectedPrevious: str, expectedHistory: str,
) -> str:
    """Restore only the recorded peer prefix or finalize its complete published root, never roll back a healthy commit."""

    _Change(guest, action, deviceId)
    guest._RequireDigest(expected)
    guest._RequireDigest(expectedPrevious)
    guest._RequireDigest(expectedHistory)
    requested, _, raw = guest._Request(desired)
    owner = requested["owner"]
    root, unit, transaction = guest._ActivePaths(owner)
    actualRequest = guest._Request(root)[0]
    actual = guest._Receipt(root, unit, owner)

    if guest._Read(root / "receipt.json") != guest._Encode(actual) or guest._Digest(guest._Read(root / "receipt.json")) != expected:
        raise guest.GuestError("WireGuard peer recovery requires the exact current root receipt")

    if not transaction.exists() and not transaction.is_symlink():
        guest._Check(root, unit, actualRequest)
        audit = _Audit(guest, owner)

        if audit is not None and audit["receipt_sha256"] != expected:
            raise guest.GuestError("WireGuard peer root differs from its last completed operation proof")

        if expected != expectedPrevious and audit is not None and audit == {"schema_version": 1, "owner": owner, "action": action, "device_id": deviceId,
                                          "previous_receipt_sha256": expectedPrevious, "receipt_sha256": expected,
                                          "deployment_sha256": guest._Digest(raw), "previous_history_sha256": expectedHistory}:
            return "committed"

        if expected == expectedPrevious:
            _Cancel(guest, actual, action, deviceId, expectedHistory)

            return "not-applied"

        raise guest.GuestError("No matching WireGuard peer recovery or committed operation is recorded")

    guest._Directory(transaction, private=True)

    if not tuple(transaction.iterdir()):
        guest._Check(root, unit, actualRequest)
        audit = _Audit(guest, owner)

        if audit is not None and audit["receipt_sha256"] != expected:
            raise guest.GuestError("Empty peer journal has changed commit history")

        if expected != expectedPrevious and (audit is None or audit["receipt_sha256"] != expected
                                             or audit["previous_receipt_sha256"] != expectedPrevious
                                             or audit["deployment_sha256"] != guest._Digest(raw)
                                             or audit["previous_history_sha256"] != expectedHistory
                                             or (audit["action"], audit["device_id"]) != (action, deviceId)):
            raise guest.GuestError("Empty peer journal has no matching completed commit proof")

        if expected == expectedPrevious:
            _Cancel(guest, actual, action, deviceId, expectedHistory)

        guest._SyncDirectory(guest.BASE)
        guest._SyncDirectory(transaction)
        transaction.rmdir()
        guest._SyncDirectory(guest.BASE)

        return "not-applied" if expected == expectedPrevious else "committed"

    record, transaction = _Journal(guest, owner)

    if ((record["action"], record["device_id"]) != (action, deviceId)
            or guest._Digest(guest._Encode(record["previous"])) != expectedPrevious
            or record["previous_history_sha256"] != expectedHistory
            or record["desired"]["deployment_sha256"] != guest._Digest(raw)
            or record["desired"]["files"]["server.conf"] != requested["config_sha256"]
            or record["desired"]["files"]["install.py"] != requested["program_sha256"]):
        raise guest.GuestError("WireGuard peer recovery differs from the requested original transaction")

    _AuditMatches(guest, record, committed=actual == record["desired"])

    if actual == record["desired"]:
        guest._Check(root, unit, actualRequest)
        _Clear(guest, record, committed=True)

        return "committed"

    if actual != record["previous"]:
        raise guest.GuestError("WireGuard peer recovery root is outside both recorded receipts")

    try:
        guest._Check(root, unit, actualRequest)

    except guest.GuestError:
        candidate = transaction / "new"

        if guest._Receipt(candidate, unit, owner) != record["desired"]:
            raise guest.GuestError("WireGuard peer rollback lacks its complete recorded candidate")

        previous, desiredRequest = _Delta(guest, root, candidate, action, deviceId)
        _Converge(guest, root, candidate, previous, desiredRequest, record["previous"], record["desired"], adding=action == "revoke")

    _Clear(guest, record, committed=False)

    return "not-applied"


def Status(guest: Any, desired: Path, action: str, deviceId: str) -> dict[str, object]:
    """Expose only current receipt and transaction facts after proving complete active or recorded transition state."""

    _Change(guest, action, deviceId)
    requested, _, raw = guest._Request(desired)
    owner = requested["owner"]
    root, unit, transaction = guest._ActivePaths(owner)
    actualRequest = guest._Request(root)[0]
    actual = guest._Receipt(root, unit, owner)

    if guest._Read(root / "receipt.json") != guest._Encode(actual):
        raise guest.GuestError("WireGuard peer status found changed receipt bytes")

    digest = guest._Digest(guest._Encode(actual))
    history = _History(guest, owner)
    pending = transaction.exists() or transaction.is_symlink()
    previous = ""
    previousHistory = ""

    if pending:
        guest._Directory(transaction, private=True)

        if not tuple(transaction.iterdir()):
            guest._Check(root, unit, actualRequest)
            audit = _Audit(guest, owner)

            if audit is not None and (audit["receipt_sha256"] != digest or audit["deployment_sha256"] != actual["deployment_sha256"]):
                raise guest.GuestError("Empty peer journal has unexplained commit history")

            matching = (audit is not None and (audit["action"], audit["device_id"]) == (action, deviceId)
                        and (audit["deployment_sha256"] == guest._Digest(raw) or audit["previous_receipt_sha256"] == digest))
            previous = audit["previous_receipt_sha256"] if matching and audit is not None else digest
            previousHistory = audit["previous_history_sha256"] if matching and audit is not None else history

        else:
            record, _ = _Journal(guest, owner)

            if ((record["action"], record["device_id"]) != (action, deviceId)
                    or record["desired"]["deployment_sha256"] != guest._Digest(raw)
                    or record["desired"]["files"]["server.conf"] != requested["config_sha256"]
                    or record["desired"]["files"]["install.py"] != requested["program_sha256"]
                    or actual not in (record["previous"], record["desired"])):
                raise guest.GuestError("WireGuard peer status differs from the supplied transaction intent")

            _AuditMatches(guest, record, committed=actual == record["desired"])
            previous = guest._Digest(guest._Encode(record["previous"]))
            previousHistory = record["previous_history_sha256"]

            if actual == record["desired"]:
                guest._Check(root, unit, actualRequest)

            else:
                try:
                    guest._Check(root, unit, actualRequest)

                except guest.GuestError:
                    candidate = transaction / "new"

                    if guest._Receipt(candidate, unit, owner) != record["desired"]:
                        raise guest.GuestError("WireGuard peer status has no complete candidate for the transitioning runtime")

                    _, desiredRequest = _Delta(guest, root, candidate, action, deviceId)
                    _Runtime(guest, root, unit, actualRequest, actual)
                    current = _KernelChoice(guest, ((root, actualRequest), (candidate, desiredRequest)))
                    policy = guest._NftState(owner, actual["nonce"])

                    if policy not in {record["previous"]["network_sha256"], record["desired"]["network_sha256"]}:
                        raise guest.GuestError("WireGuard peer status found an unexplained firewall")

                    if (action == "enroll" and current == root and policy == record["desired"]["network_sha256"]
                            or action == "revoke" and current == candidate and policy == record["previous"]["network_sha256"]):
                        raise guest.GuestError("WireGuard peer status found an unrecorded transition prefix")

    else:
        guest._Check(root, unit, actualRequest)
        audit = _Audit(guest, owner)

        if audit is not None:
            if audit["receipt_sha256"] != digest or audit["deployment_sha256"] != actual["deployment_sha256"]:
                raise guest.GuestError("WireGuard peer root differs from its completed operation proof")

            previous = audit["previous_receipt_sha256"]
            previousHistory = audit["previous_history_sha256"]

        if actual["deployment_sha256"] != guest._Digest(raw):
            _Delta(guest, root, desired, action, deviceId)

    return {"status": "peer-recovery-required" if pending else "active", "receipt_sha256": digest,
            "previous_receipt_sha256": previous, "deployment_sha256": actual["deployment_sha256"],
            "history_sha256": history, "previous_history_sha256": previousHistory,
            "desired_deployment_sha256": guest._Digest(raw), "is_desired": actual["deployment_sha256"] == guest._Digest(raw),
            "action": action, "device_id": deviceId, "tools_version": guest.TOOLS_VERSION,
            "kernel_policy": "cached-named-cve-baseline"}


def HistoryStatus(guest: Any, owner: str) -> dict[str, str]:
    """Read owner-bound audit history even without an installed root, creating no files or managed state."""

    guest._Paths(owner)

    for path in (guest.BASE, *guest.BASE.parents):
        if path.exists() or path.is_symlink():
            guest._Directory(path)

            break

    return {"status": "peer-history", "owner": owner, "history_sha256": _History(guest, owner), "tools_version": guest.TOOLS_VERSION}


def _OriginalGuest(guest: Any, stage: Path, expected: str) -> Any:
    """Load the exact retained installer bytes already authorized by the original private server bundle."""

    guest._RequireDigest(expected)
    path = stage / "original.py"
    content = guest._Read(path)

    if guest._Digest(content) != expected:
        raise guest.GuestError("Original installer differs from its retained program pin")

    spec = importlib.util.spec_from_loader("flayer_wireguard_original", loader=None)

    if spec is None:
        raise guest.GuestError("Original installer module is unavailable")

    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    exec(compile(content, str(path), "exec"), module.__dict__)

    return module


def _StageFile(guest: Any, path: Path, content: bytes) -> None:
    """Write one private transient input without requiring a managed installation or crossing filesystems."""

    guest._Directory(path.parent, private=True)

    if not isinstance(content, bytes) or not 1 <= len(content) <= 1048576:
        raise guest.GuestError("Transient peer input exceeds its bound")

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)


def _ProtocolGate(guest: Any) -> None:
    """Under the existing WG lock, refuse unresolved common protocol authority before normal peer/install actions."""

    guest._ProtocolGate()


def Main(argv: list[str] | None = None) -> int:
    """Run only an explicit owned peer action with root, fixed staging, consent and exact receipt guards."""

    parser = argparse.ArgumentParser(description="Manage one owned WireGuard peer transaction")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true")
    group.add_argument("--history-status", action="store_true", dest="historyStatus")
    group.add_argument("--install", action="store_true")
    group.add_argument("--check-install", action="store_true", dest="checkInstall")
    group.add_argument("--apply", action="store_true")
    group.add_argument("--recover", action="store_true")
    parser.add_argument("--change", choices=("enroll", "revoke"), required=True)
    parser.add_argument("--device-id", required=True, dest="deviceId")
    parser.add_argument("--allow-mutation", action="store_true", dest="allowMutation")
    parser.add_argument("--expected-receipt-sha256", default="", dest="expectedReceipt")
    parser.add_argument("--expected-previous-receipt-sha256", default="", dest="expectedPrevious")
    parser.add_argument("--expected-history-sha256", default="", dest="expectedHistory")
    options = parser.parse_args(argv)

    try:
        guest = _Guest()

        if os.name != "posix" or os.geteuid() != guest._ROOT_UID:
            raise ValueError

        import fcntl

        _Change(guest, options.change, options.deviceId)

        installing = options.install or options.checkInstall
        readOnly = options.status or options.historyStatus or options.checkInstall

        if installing:
            if bool(options.allowMutation) != bool(options.install) or options.expectedReceipt or options.expectedPrevious:
                raise guest.GuestError("Installation requires exact mutation consent; its check is read-only")

            guest._RequireDigest(options.expectedHistory)

        elif readOnly:
            if options.allowMutation or options.expectedReceipt or options.expectedPrevious or options.expectedHistory:
                raise guest.GuestError("WireGuard peer status accepts no mutation consent or receipt options")

        else:
            if not options.allowMutation:
                raise guest.GuestError("WireGuard peer mutation requires explicit consent")

            guest._RequireDigest(options.expectedReceipt)
            guest._RequireDigest(options.expectedHistory)

            if options.recover:
                guest._RequireDigest(options.expectedPrevious)

            elif options.expectedPrevious:
                raise guest.GuestError("Previous-receipt recovery consent is not an apply option")

        stage = Path(__file__).absolute().parent
        guest._Directory(stage, private=True)

        if {path.name for path in stage.iterdir()} != {"install.py", "maintenance.py", "server.conf", "deployment.json", *({"original.py"} if installing else set())}:
            raise guest.GuestError("WireGuard peer staging has unknown or missing files")

        supplied = guest._Json(guest._Read(stage / "deployment.json"))

        if not isinstance(supplied, dict):
            raise ValueError

        owner = supplied.get("owner")

        if not isinstance(owner, str):
            raise ValueError

        root, unit, _ = guest._Paths(owner) if options.historyStatus else guest._ActivePaths(owner)
        descriptor: int | None

        try:
            descriptor = guest._OpenLock(readOnly=readOnly)

        except FileNotFoundError:
            if not readOnly or guest.LOCK.exists() or guest.LOCK.is_symlink():
                raise

            descriptor = None

        try:
            if descriptor is not None:
                fcntl.flock(descriptor, (fcntl.LOCK_SH if readOnly else fcntl.LOCK_EX) | fcntl.LOCK_NB)

            if not options.historyStatus:
                _ProtocolGate(guest)

            if installing:
                if HistoryStatus(guest, owner)["history_sha256"] != options.expectedHistory:
                    raise guest.GuestError("Peer history changed before installation; no installer was started")

                if not root.exists() and not root.is_symlink() and _Audit(guest, owner) is not None:
                    raise guest.GuestError("Retained peer history requires explicit protocol recovery; an absent root cannot be reinstalled")

                program = supplied.get("program_sha256")

                if not isinstance(program, str):
                    raise ValueError

                original = _OriginalGuest(guest, stage, program)

                with tempfile.TemporaryDirectory(prefix=".original-", dir=stage) as temporary:
                    desired = Path(temporary)
                    os.chmod(desired, 0o700)

                    for name in ("server.conf", "deployment.json", "install.py"):
                        _StageFile(guest, desired / name, guest._Read(stage / ("original.py" if name == "install.py" else name)))

                    request = original._Request(desired)[0]

                    if options.install:
                        original._Install(desired, request)

                    original._Check(root, unit, request)

                result: dict[str, object] = {"status": "install-complete" if options.install else "install-checked"}

            elif options.historyStatus:
                result = dict(HistoryStatus(guest, owner))

            else:
                guest._Receipt(root, unit, owner)

                with tempfile.TemporaryDirectory(prefix=".desired-", dir=stage) as temporary:
                    desired = Path(temporary)
                    os.chmod(desired, 0o700)

                    for name in ("server.conf", "deployment.json", "install.py"):
                        _StageFile(guest, desired / name, guest._Read((root if name == "install.py" else stage) / name))

                    if options.status:
                        result = Status(guest, desired, options.change, options.deviceId)

                    else:
                        outcome = (Recover(guest, desired, options.change, options.deviceId, options.expectedReceipt, options.expectedPrevious, options.expectedHistory)
                                   if options.recover else Apply(guest, desired, options.change, options.deviceId, options.expectedReceipt, options.expectedHistory))
                        result = {"status": "complete", "outcome": outcome}

            if descriptor is None and (guest.LOCK.exists() or guest.LOCK.is_symlink()):
                raise guest.GuestError("WireGuard operation started during observation; retry status")

        finally:
            if descriptor is not None:
                os.close(descriptor)

    except Exception:
        print("WireGuard peer operation failed; retain private material and inspect exact receipt-bound recovery state.", file=sys.stderr)

        return 1

    print(json.dumps(result, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
