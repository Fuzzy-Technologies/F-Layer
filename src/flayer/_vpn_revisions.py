"""Retain immutable WireGuard peer revisions beside the original cloud creation baseline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from flayer._vpn_creation import (
    BundleDigest,
    CreationBaseline,
    LoadCreationBaseline,
    ProtocolPin,
    ReadPinnedBundle,
    StaticFingerprint,
    _Decode,
    _Json,
)
from flayer._vpn_peer_transport import ValidateBundle
from flayer.core.contracts import _WireDict
from flayer.guest import PrivatePath, ReadPrivate, WritePrivate
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_FILES = ("material.json", "intent.sha256", "server.conf", "deployment.json", "install.py", "request.json")
MAX_PEER_REVISIONS = 4096


def Digest(content: bytes) -> str:
    """Identify exact private bytes without placing their contents in diagnostics."""

    return hashlib.sha256(content).hexdigest()


def InitialHistory(project: SelectedVpnProject) -> str:
    """Bind the explicit absence of guest peer history to the complete owner identity."""

    owner = Digest(json.dumps(_WireDict(project.vpn.identity), sort_keys=True, separators=(",", ":")).encode())

    return Digest(_Json({"domain": "f-layer/wireguard/peer-history/v1", "owner": owner}))


def CommittedHistory(project: SelectedVpnProject, change: str, deviceId: str, previous: str, current: str, deployment: str, history: str) -> str:
    """Reproduce the exact guest commit-chain hash from bounded operation facts."""

    owner = Digest(json.dumps(_WireDict(project.vpn.identity), sort_keys=True, separators=(",", ":")).encode())

    return Digest(_Json({"schema_version": 1, "owner": owner, "action": change, "device_id": deviceId,
                         "previous_receipt_sha256": previous, "receipt_sha256": current,
                         "deployment_sha256": deployment, "previous_history_sha256": history}))


@contextmanager
def ProjectLock(project: SelectedVpnProject, *, readOnly: bool) -> Iterator[None]:
    """Serialize the complete selected-project workflow across cloud, guest and local publication."""

    PrivatePath(project.root, directory=True)

    import fcntl

    path = project.root / ".vpn-project.lock"
    descriptor: int | None = None

    try:
        try:
            descriptor = os.open(path, (os.O_RDONLY if readOnly else os.O_RDWR | os.O_CREAT) | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)

        except FileNotFoundError:
            if not readOnly or path.exists() or path.is_symlink():
                raise

        if descriptor is not None:
            info = os.fstat(descriptor)

            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0):
                raise VpnError("Project coordination file has unsafe ownership or content")

            fcntl.flock(descriptor, (fcntl.LOCK_SH if readOnly else fcntl.LOCK_EX) | fcntl.LOCK_NB)

        yield

        if descriptor is None and (path.exists() or path.is_symlink()):
            raise VpnError("Project mutation started during observation; repeat status or plan")

    except OSError:
        raise VpnError("Selected project is busy or its coordination file is unavailable") from None

    finally:
        if descriptor is not None:
            os.close(descriptor)


def AtomicRecord(project: SelectedVpnProject, filename: str, data: dict[str, Any] | None) -> None:
    """Publish one fixed private metadata file durably while the complete project lock is held."""

    if filename not in {"wireguard-head.json", "wireguard-pending.json"}:
        raise VpnError("Unsupported peer metadata path")

    path = project.root / filename
    temporary = project.root / ("." + filename + ".new")

    if path.exists() or path.is_symlink():
        ReadPrivate(path)

    if data is None:
        if temporary.exists() or temporary.is_symlink():
            raise VpnError("Interrupted metadata bytes must be reconciled before journal removal")

        path.unlink()

    else:
        if temporary.exists() or temporary.is_symlink():
            if ReadPrivate(temporary) != _Json(data):
                raise VpnError("Interrupted metadata bytes differ; no file was overwritten")

        else:
            WritePrivate(temporary, _Json(data))

        descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

        try:
            opened = os.fstat(descriptor)
            linked = temporary.lstat()

            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600 or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
                    or ReadPrivate(temporary) != _Json(data)):
                raise VpnError("Peer metadata changed before durable publication")

            os.fsync(descriptor)
            synced = os.fstat(descriptor)
            linked = temporary.lstat()

            if ((opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
                    or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (synced.st_size, synced.st_mtime_ns, synced.st_ctime_ns)):
                raise VpnError("Peer metadata changed during durable publication")

        finally:
            os.close(descriptor)

        os.replace(temporary, path)

    descriptor = os.open(project.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def _ReadBundle(project: SelectedVpnProject, name: str, digest: str, filenames: tuple[str, ...]) -> ArtifactBundle:
    """Require exact confined immutable revision files and the externally pinned complete bundle hash."""

    if (re.fullmatch(re.escape(project.vpn.identity.stack) + r"-w[pc]-[0-9a-f]{16}", name) is None
            or not isinstance(digest, str) or _HASH.fullmatch(digest) is None):
        raise VpnError("Peer revision locator is invalid")

    directory = project.Artifacts / ("server-" + name)
    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", *filenames}:
        raise VpnError("Peer revision has missing or unknown files; retain recovery material")

    bundle = ArtifactBundle(project.vpn.identity, "server", name, tuple(Artifact(filename,
        ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=name),
        filename not in {"request.json", "record.json", "intent.sha256"}) for filename in filenames))

    if BundleDigest(bundle) != digest:
        raise VpnError("Peer revision differs from its pinned immutable bytes")

    return bundle


def _Pin(value: object) -> ProtocolPin:
    """Decode one exact nonsecret WireGuard projection/material/server pin."""

    if (not isinstance(value, dict) or set(value) != {"protocol", "intent_fingerprint", "material_digest", "server_digest"}
            or value["protocol"] != "wireguard"):
        raise VpnError("Peer revision protocol pin is invalid")

    pin = ProtocolPin(value["protocol"], value["intent_fingerprint"], value["material_digest"], value["server_digest"])

    if pin.protocol != "wireguard":
        raise VpnError("Peer revisions cannot change another protocol")

    return pin


def _Pointer(value: object, project: SelectedVpnProject) -> dict[str, str] | None:
    """Accept only a full-digest owned commit pointer, with null denoting the immutable creation baseline."""

    if value is None:
        return None

    if (not isinstance(value, dict) or set(value) != {"name", "sha256"}
            or not isinstance(value["name"], str) or re.fullmatch(re.escape(project.vpn.identity.stack) + r"-wc-[0-9a-f]{16}", value["name"]) is None
            or not isinstance(value["sha256"], str) or _HASH.fullmatch(value["sha256"]) is None):
        raise VpnError("Peer revision head is invalid")

    return {key: str(item) for key, item in value.items()}


@dataclass(frozen=True, slots=True)
class RevisionState:
    """Resolved nonsecret effective pins and the complete unchanged cloud creation snapshot."""

    baseline: CreationBaseline
    pins: tuple[ProtocolPin, ...]
    head: dict[str, str] | None
    headDigest: str
    receipt: str
    history: str
    lastRecord: dict[str, Any] | None = field(repr=False)
    activeRecord: dict[str, Any] | None = field(repr=False)
    recordCount: int

    def ValidateCurrent(self, project: SelectedVpnProject, *, peerChange: bool = False) -> None:
        """Allow only an explicitly planned WireGuard peer projection delta, preserving every other intent field."""

        if (StaticFingerprint(project) != self.baseline.staticFingerprint
                or tuple(item.protocol for item in project.protocolSelections) != tuple(item.protocol for item in self.pins)
                or any(project.TransportFingerprint(pin.protocol) != pin.intentFingerprint
                       for pin in self.pins if not peerChange or pin.protocol != "wireguard")):
            raise VpnError("Selected intent differs from its effective revision; use an explicit peer/protocol transition")


def LoadRevisions(project: SelectedVpnProject) -> RevisionState:
    """Verify the complete nonsecret commit chain without depending on private client key availability."""

    baseline = LoadCreationBaseline(project)
    origin = BundleDigest(baseline.bundle)
    path = project.root / "wireguard-head.json"
    rawHead = ReadPrivate(path) if path.exists() or path.is_symlink() else None
    head = _Pointer(_Decode(rawHead), project) if rawHead is not None else None

    if rawHead is not None and rawHead != _Json(head):
        raise VpnError("Peer head metadata must use exact canonical bytes")

    current = head
    records: list[dict[str, Any]] = []
    visited: set[str] = set()

    while current is not None:
        if current["name"] in visited or len(visited) >= MAX_PEER_REVISIONS:
            raise VpnError("Peer commit chain is cyclic or exceeds its bound")

        visited.add(current["name"])
        bundle = _ReadBundle(project, current["name"], current["sha256"], ("record.json",))
        raw = bundle.files[0].content
        record = _Decode(raw)
        fields = {"schema_version", "identity", "creation_sha256", "parent", "previous_head_sha256", "previous_pin", "desired_pin",
                  "request_name", "request_sha256", "change", "device_id", "previous_receipt_sha256", "receipt_sha256",
                  "previous_history_sha256", "history_sha256", "deployment_sha256", "baseline_sha256", "plan_expires_at", "outcome", "desired_fingerprint"}

        if (set(record) != fields or raw != _Json(record) or type(record["schema_version"]) is not int or record["schema_version"] != 1
                or record["identity"] != _WireDict(project.vpn.identity) or record["creation_sha256"] != origin
                or not isinstance(record["change"], str) or record["change"] not in {"enroll", "revoke"} or not isinstance(record["device_id"], str)
                or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", record["device_id"]) is None
                or not isinstance(record["request_name"], str)
                or re.fullmatch(re.escape(project.vpn.identity.stack) + r"-wp-[0-9a-f]{16}", record["request_name"]) is None
                or type(record["plan_expires_at"]) is not int or record["plan_expires_at"] <= 0
                or not isinstance(record["outcome"], str) or record["outcome"] not in {"committed", "not-applied"}
                or not isinstance(record["request_sha256"], str)
                or record["request_sha256"] != "" and _HASH.fullmatch(record["request_sha256"]) is None
                or record["outcome"] == "committed" and not record["request_sha256"]
                or any(not isinstance(record[key], str) or _HASH.fullmatch(record[key]) is None
                       for key in ("previous_head_sha256", "previous_receipt_sha256", "receipt_sha256", "previous_history_sha256",
                                   "history_sha256", "deployment_sha256", "baseline_sha256", "desired_fingerprint"))
                or (record["outcome"] == "committed" and (
                    record["receipt_sha256"] == record["previous_receipt_sha256"]
                    or record["history_sha256"] != CommittedHistory(project, record["change"], record["device_id"], record["previous_receipt_sha256"],
                                                                    record["receipt_sha256"], record["deployment_sha256"], record["previous_history_sha256"])))
                or (record["outcome"] == "not-applied" and (record["receipt_sha256"] != record["previous_receipt_sha256"]
                                                            or record["history_sha256"] != record["previous_history_sha256"]))):
            raise VpnError("Peer commit ownership, history or proof fields are invalid")

        _Pin(record["previous_pin"])
        _Pin(record["desired_pin"])
        current = _Pointer(record["parent"], project)

        if record["previous_head_sha256"] != (Digest(_Json(current)) if current is not None else origin):
            raise VpnError("Peer commit parent differs from its original head")

        records.append(record)

    pin = next((item for item in baseline.protocols if item.protocol == "wireguard"), None)
    receipt, history = "", InitialHistory(project)
    activeRecord = None

    for record in reversed(records):
        if (pin != _Pin(record["previous_pin"]) or record["previous_history_sha256"] != history
                or receipt and record["previous_receipt_sha256"] != receipt):
            raise VpnError("Peer commit chain does not continue its exact previous projection or guest history")

        desiredPin = _Pin(record["desired_pin"])

        if record["outcome"] == "committed":
            if desiredPin.intentFingerprint != record["desired_fingerprint"] or desiredPin == pin:
                raise VpnError("Committed peer projection is not the recorded desired change")

            pin, activeRecord = desiredPin, record

        elif not record["request_sha256"] and desiredPin != pin:
            raise VpnError("An unstaged peer attempt cannot claim prepared material")

        receipt, history = record["receipt_sha256"], record["history_sha256"]

    expectedNames = {item["request_name"] for item in records} | visited
    pending = Pending(project)

    if pending is not None:
        expectedNames.add(pending["request_name"])
        expectedNames.add(project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1])

        if (pending["creation_sha256"] != origin
                or pending["previous_head_sha256"] != (Digest(_Json(pending["parent"])) if pending["parent"] is not None else origin)
                or head != pending["parent"] and (not records or records[0]["request_name"] != pending["request_name"]
                                                  or {key: records[0][key] for key in pending} != pending)
                or head == pending["parent"] and (_Pin(pending["previous_pin"]) != pin or pending["previous_history_sha256"] != history
                                                   or receipt and pending["previous_receipt_sha256"] != receipt)):
            raise VpnError("Pending peer operation does not continue its exact original controller and guest state")

    actualNames = {path.name.removeprefix("server-") for path in project.Artifacts.iterdir()
                   if path.name.startswith(("server-" + project.vpn.identity.stack + "-wp-", "server-" + project.vpn.identity.stack + "-wc-"))}

    if actualNames - expectedNames:
        raise VpnError("Unrecorded peer revision artifacts require explicit inspection; a missing head is never adopted")

    pins = tuple(pin if item.protocol == "wireguard" and pin is not None else item for item in baseline.protocols)

    return RevisionState(baseline, pins, head, Digest(_Json(head)) if head is not None else origin, receipt, history,
                         records[0] if records else None, activeRecord, len(records))


def RequireCapacity(state: RevisionState) -> None:
    """Refuse a new attempt before activation rather than publishing an unreadable oversized history chain."""

    if state.recordCount >= MAX_PEER_REVISIONS:
        raise VpnError("Peer revision history is at capacity; retain the current project and do not activate another peer change")


def Pending(project: SelectedVpnProject) -> dict[str, Any] | None:
    """Read only a complete owner-bound metadata journal, with original material kept in immutable bundles."""

    path = project.root / "wireguard-pending.json"

    if not path.exists() and not path.is_symlink():
        temporary = project.root / ".wireguard-pending.json.new"

        if not temporary.exists() and not temporary.is_symlink():
            return None

        path = temporary

    raw = ReadPrivate(path)
    data = _Decode(raw)
    fields = {"schema_version", "identity", "creation_sha256", "parent", "previous_head_sha256", "previous_pin", "desired_fingerprint",
              "request_name", "request_sha256", "change", "device_id", "previous_receipt_sha256", "previous_history_sha256", "baseline_sha256", "plan_expires_at"}

    if (set(data) != fields or raw != _Json(data) or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["identity"] != _WireDict(project.vpn.identity) or not isinstance(data["change"], str) or data["change"] not in {"enroll", "revoke"}
            or not isinstance(data["device_id"], str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", data["device_id"]) is None
            or not isinstance(data["request_name"], str)
            or re.fullmatch(re.escape(project.vpn.identity.stack) + r"-wp-[0-9a-f]{16}", data["request_name"]) is None
            or type(data["plan_expires_at"]) is not int or data["plan_expires_at"] <= 0
            or any(not isinstance(data[key], str) or _HASH.fullmatch(data[key]) is None
                   for key in ("creation_sha256", "previous_head_sha256", "desired_fingerprint", "previous_receipt_sha256", "previous_history_sha256", "baseline_sha256"))
            or not isinstance(data["request_sha256"], str) or data["request_sha256"] != "" and _HASH.fullmatch(data["request_sha256"]) is None):
        raise VpnError("Peer recovery journal is invalid; retain all private artifacts")

    _Pointer(data["parent"], project)
    _Pin(data["previous_pin"])

    return data


def RequestBundles(project: SelectedVpnProject, name: str, digest: str) -> tuple[ArtifactBundle, ArtifactBundle]:
    """Rehydrate standard material/server roles from one exact retained request without rotating its program."""

    request = _ReadBundle(project, name, digest, _REQUEST_FILES)
    contents = {item.name: item.content for item in request.files}
    base = project.vpn.identity.stack + "-wireguard"

    return (ArtifactBundle(project.vpn.identity, "server", base + "-credentials", tuple(
        Artifact(filename, contents[filename], filename != "intent.sha256") for filename in ("material.json", "intent.sha256"))),
        ArtifactBundle(project.vpn.identity, "server", base, tuple(Artifact(filename, contents[filename])
            for filename in ("server.conf", "deployment.json", "install.py"))))


def ValidateRequest(project: SelectedVpnProject, pending: dict[str, Any], pin: ProtocolPin) -> tuple[ArtifactBundle, ArtifactBundle]:
    """Bind a prepared request to the complete original journal and exact new material/server projection."""

    request = _ReadBundle(project, pending["request_name"], pending["request_sha256"], _REQUEST_FILES)

    if next(item.content for item in request.files if item.name == "request.json") != _Json({**pending, "request_sha256": ""}):
        raise VpnError("Peer request metadata differs from its original operation journal")

    material, server = RequestBundles(project, pending["request_name"], pending["request_sha256"])
    ValidateBundle(server)

    if (pin.protocol != "wireguard" or pin.intentFingerprint != pending["desired_fingerprint"]
            or BundleDigest(material) != pin.materialDigest or BundleDigest(server) != pin.serverDigest
            or next(item.content for item in material.files if item.name == "intent.sha256") != (pin.intentFingerprint + "\n").encode()):
        raise VpnError("Peer request bytes differ from the exact desired protocol projection")

    return material, server


def ReadEffectiveBundle(project: SelectedVpnProject, state: RevisionState, pin: ProtocolPin, *, material: bool = False) -> ArtifactBundle:
    """Resolve only the last committed transport revision while preserving all unrelated original pins."""

    if pin.protocol != "wireguard" or state.activeRecord is None:
        return ReadPinnedBundle(project, pin, material=material)

    credentials, server = RequestBundles(project, state.activeRecord["request_name"], state.activeRecord["request_sha256"])
    result = credentials if material else server

    if BundleDigest(result) != (pin.materialDigest if material else pin.serverDigest):
        raise VpnError("Effective peer material/server bundle differs from its committed projection")

    return result


def PublishRequest(project: SelectedVpnProject, pending: dict[str, Any], material: ArtifactBundle, server: ArtifactBundle) -> str:
    """Persist all newly retained peer bytes before any remote action, keeping original bundles unchanged."""

    if (Pending(project) != pending or pending["request_sha256"] != ""
            or material.identity != project.vpn.identity or material.kind != "server"
            or material.name != project.vpn.identity.stack + "-wireguard-credentials"
            or {item.name for item in material.files} != {"material.json", "intent.sha256"}
            or any(item.sensitive != (item.name != "intent.sha256") for item in material.files)
            or next(item.content for item in material.files if item.name == "intent.sha256") != (pending["desired_fingerprint"] + "\n").encode()):
        raise VpnError("Peer preparation requires its exact persisted pre-remote journal and private material role")

    ValidateBundle(server)

    if server.identity != project.vpn.identity:
        raise VpnError("Peer server belongs to a different stack")

    RequireCapacity(LoadRevisions(project))
    metadata = {**pending, "request_sha256": ""}
    bundle = ArtifactBundle(project.vpn.identity, "server", pending["request_name"],
                            material.files + server.files + (Artifact("request.json", _Json(metadata), False),))
    WriteArtifactBundle(project.Artifacts, bundle)

    return BundleDigest(bundle)


def RecoverStaging(project: SelectedVpnProject, pending: dict[str, Any]) -> str:
    """Reuse a complete pre-remote staged request; never regenerate partially retained device credentials."""

    directory = project.Artifacts / ("server-" + pending["request_name"])
    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", *_REQUEST_FILES}:
        raise VpnError("Peer material preparation was interrupted before remote activation; retain partial private files for inspection")

    bundle = ArtifactBundle(project.vpn.identity, "server", pending["request_name"], tuple(Artifact(filename,
        ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=pending["request_name"]),
        filename not in {"request.json", "intent.sha256"}) for filename in _REQUEST_FILES))
    raw = next(item.content for item in bundle.files if item.name == "request.json")

    if raw != _Json({**pending, "request_sha256": ""}):
        raise VpnError("Staged peer request differs from the original pre-remote journal")

    return BundleDigest(bundle)


def Commit(
    project: SelectedVpnProject, state: RevisionState, pending: dict[str, Any], pin: ProtocolPin, facts: dict[str, object], *, outcome: str,
) -> None:
    """Publish immutable verified commit evidence before atomically advancing the controller head."""

    if (outcome not in {"committed", "not-applied"} or facts.get("status") != "active"
            or any(not isinstance(facts.get(key), str) or _HASH.fullmatch(str(facts[key])) is None
                   for key in ("receipt_sha256", "deployment_sha256", "history_sha256"))):
        raise VpnError("Peer completion requires a verified active result and exact outcome")

    if (outcome == "committed" and (not pending["request_sha256"] or pin.intentFingerprint != pending["desired_fingerprint"]
                                    or facts.get("is_desired") is not True or facts["receipt_sha256"] == pending["previous_receipt_sha256"]
                                    or facts["history_sha256"] != CommittedHistory(project, pending["change"], pending["device_id"], pending["previous_receipt_sha256"],
                                                                                str(facts["receipt_sha256"]), str(facts["deployment_sha256"]), pending["previous_history_sha256"]))
            or outcome == "not-applied" and (facts["receipt_sha256"] != pending["previous_receipt_sha256"]
                                             or facts["history_sha256"] != pending["previous_history_sha256"])):
        raise VpnError("Guest facts do not prove the exact peer completion outcome")

    if pending["request_sha256"]:
        _, server = ValidateRequest(project, pending, pin)

        if (outcome == "committed" and facts["deployment_sha256"] != Digest(
                next(item.content for item in server.files if item.name == "deployment.json"))):
            raise VpnError("Guest receipt describes a different desired peer deployment")

    elif outcome != "not-applied" or pin != _Pin(pending["previous_pin"]):
        raise VpnError("An unstaged peer attempt can only retain its previous projection")

    record = dict(pending)
    record.update(desired_pin=_WireDict(pin), receipt_sha256=facts["receipt_sha256"], history_sha256=facts["history_sha256"],
                  deployment_sha256=facts["deployment_sha256"], outcome=outcome)
    name = project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1]
    bundle = ArtifactBundle(project.vpn.identity, "server", name, (Artifact("record.json", _Json(record), False),))
    directory = project.Artifacts / ("server-" + name)
    pointer = {"name": name, "sha256": BundleDigest(bundle)}
    actual = LoadRevisions(project)

    if (actual.head != state.head or state.head not in (pending["parent"], pointer)
            or Pending(project) != pending and (Pending(project) is not None or actual.head != pointer or actual.lastRecord != record)):
        raise VpnError("Peer commit head or journal changed; retain the pending operation")

    if actual.head != pointer:
        RequireCapacity(actual)

    if directory.exists() or directory.is_symlink():
        _ReadBundle(project, name, BundleDigest(bundle), ("record.json",))

    else:
        WriteArtifactBundle(project.Artifacts, bundle)

    AtomicRecord(project, "wireguard-head.json", pointer)

    if Pending(project) is not None:
        AtomicRecord(project, "wireguard-pending.json", None)
