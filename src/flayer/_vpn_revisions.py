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
from pathlib import Path
from typing import Any

from flayer._vpn_creation import (
    BundleDigest,
    CreationBaseline,
    LoadCreationBaseline,
    ProtocolPin,
    StaticFingerprint,
    _Decode,
    _Json,
)
from flayer._vpn_peer_transport import ValidateBundle
from flayer._vpn_protocol_sources import ProtocolSource, ReadSource
from flayer.core.contracts import _WireDict
from flayer.guest import PrivatePath, ReadPrivate, WritePrivate
from flayer.profiles.artifacts import (
    MAX_ARTIFACT_BYTES,
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


@dataclass(frozen=True, slots=True)
class PeerSegment:
    """An epoch's retained starting projection; its full digest confines the separate mutable peer head."""

    genesis: str
    sources: tuple[ProtocolSource, ...]
    activeProtocols: tuple[str, ...]
    staticFingerprint: str
    receipt: str
    history: str

    def __post_init__(self) -> None:
        """Keep segment metadata closed, bounded and independent from private payloads or caller paths."""

        if (type(self) is not PeerSegment or type(self.sources) is not tuple or not 1 <= len(self.sources) <= 3
                or any(type(source) is not ProtocolSource for source in self.sources)
                or type(self.activeProtocols) is not tuple or any(type(value) is not str for value in self.activeProtocols)
                or any(type(value) is not str or _HASH.fullmatch(value) is None
                       for value in (self.genesis, self.staticFingerprint, self.history))
                or type(self.receipt) is not str or self.receipt != "" and _HASH.fullmatch(self.receipt) is None):
            raise VpnError("Peer segment requires exact bounded projection and authority hashes")

        for source in self.sources:
            source.Record()

        protocols = tuple(source.pin.protocol for source in self.sources)

        if (len(set(protocols)) != len(protocols) or len(set(self.activeProtocols)) != len(self.activeProtocols)
                or self.activeProtocols != tuple(protocol for protocol in protocols if protocol in self.activeProtocols)
                or any(source.identity != self.sources[0].identity for source in self.sources)
                or bool(self.receipt) != ("wireguard" in self.activeProtocols)):
            raise VpnError("Peer segment selection, ownership or active WireGuard receipt is inconsistent")


def _Directory(project: SelectedVpnProject, segment: PeerSegment | None) -> Path:
    """Resolve only the original metadata root or a complete epoch digest below its fixed private directory."""

    if segment is None:
        return project.root

    if type(segment) is not PeerSegment or any(source.identity != project.vpn.identity for source in segment.sources):
        raise VpnError("Peer segment cannot select another project's metadata")

    PrivatePath(project.root, directory=True)
    parent = project.root / "protocol-epochs"
    PrivatePath(parent, directory=True)
    directory = parent / segment.genesis
    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} - {"wireguard-head.json", "wireguard-pending.json", ".wireguard-head.json.new", ".wireguard-pending.json.new"}:
        raise VpnError("Peer segment contains unknown metadata files")

    return directory


def Digest(content: bytes) -> str:
    """Identify exact private bytes without placing their contents in diagnostics."""

    return hashlib.sha256(content).hexdigest()


def InitialHistory(project: SelectedVpnProject) -> str:
    """Bind the explicit absence of guest peer history to the complete owner identity."""

    owner = Digest(json.dumps(_WireDict(project.vpn.identity), sort_keys=True, separators=(",", ":")).encode())

    return Digest(_Json({"domain": "f-layer/wireguard/peer-history/v1", "owner": owner}))


def CommittedHistory(project: SelectedVpnProject, change: str, deviceId: str, previous: str, current: str, deployment: str, history: str) -> str:
    """Reproduce the exact guest audit-chain hash for a commit or cancellation from bounded facts."""

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

        except OSError:
            raise VpnError("Selected project is busy or its coordination file is unavailable") from None

        yield

        if descriptor is None and (path.exists() or path.is_symlink()):
            raise VpnError("Project mutation started during observation; repeat status or plan")

    finally:
        if descriptor is not None:
            os.close(descriptor)


def AtomicRecord(project: SelectedVpnProject, filename: str, data: dict[str, Any] | None, *, segment: PeerSegment | None = None) -> None:
    """Publish one fixed private metadata file durably while the complete project lock is held."""

    if (filename not in {"wireguard-head.json", "wireguard-pending.json", "protocol-ingress-pending.json"}
            or filename == "protocol-ingress-pending.json" and (segment is not None or data is None)):
        raise VpnError("Unsupported peer metadata path")

    limit = MAX_ARTIFACT_BYTES if filename == "protocol-ingress-pending.json" else 65536
    directory = _Directory(project, segment)
    path = directory / filename
    temporary = directory / ("." + filename + ".new")

    if path.exists() or path.is_symlink():
        ReadPrivate(path, limit=limit)

    if data is None:
        if temporary.exists() or temporary.is_symlink():
            raise VpnError("Interrupted metadata bytes must be reconciled before journal removal")

        path.unlink()

    else:
        if len(_Json(data)) > limit:
            raise VpnError("Private metadata exceeds its bounded publication size")

        if temporary.exists() or temporary.is_symlink():
            if ReadPrivate(temporary, limit=limit) != _Json(data):
                raise VpnError("Interrupted metadata bytes differ; no file was overwritten")

        else:
            WritePrivate(temporary, _Json(data))

        descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

        try:
            opened = os.fstat(descriptor)
            linked = temporary.lstat()

            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid() or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600 or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
                    or ReadPrivate(temporary, limit=limit) != _Json(data)):
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

    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

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
    segment: PeerSegment | None = None
    artifactNames: frozenset[str] = field(default_factory=frozenset, repr=False)

    def ValidateCurrent(self, project: SelectedVpnProject, *, peerChange: bool = False) -> None:
        """Allow only an explicitly planned WireGuard peer projection delta, preserving every other intent field."""

        static = self.segment.staticFingerprint if self.segment is not None else self.baseline.staticFingerprint

        if (StaticFingerprint(project) != static
                or tuple(item.protocol for item in project.protocolSelections) != tuple(item.protocol for item in self.pins)
                or any(project.TransportFingerprint(pin.protocol) != pin.intentFingerprint
                       for pin in self.pins if not peerChange or pin.protocol != "wireguard")):
            raise VpnError("Selected intent differs from its effective revision; use an explicit peer/protocol transition")


def _CompletionRecord(project: SelectedVpnProject, raw: bytes, origin: str, *, genesis: str | None = None) -> dict[str, Any]:
    """Validate one complete immutable completion independently of whether its head was published."""

    record = _Decode(raw)
    fields = {"schema_version", "identity", "creation_sha256", "parent", "previous_head_sha256", "previous_pin", "desired_pin",
              "request_name", "request_sha256", "change", "device_id", "previous_receipt_sha256", "receipt_sha256",
              "previous_history_sha256", "history_sha256", "deployment_sha256", "baseline_sha256", "plan_expires_at", "outcome", "desired_fingerprint"}

    if (set(record) != fields or raw != _Json(record) or type(record["schema_version"]) is not int or record["schema_version"] not in {1, 2}
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
                or record["history_sha256"] != (
                    CommittedHistory(project, record["change"], record["device_id"], record["previous_receipt_sha256"], record["receipt_sha256"],
                                     record["deployment_sha256"], record["previous_history_sha256"])
                    if record["schema_version"] == 2 and record["request_sha256"] else record["previous_history_sha256"])))):
        raise VpnError("Peer commit ownership, history or proof fields are invalid")

    _Pin(record["previous_pin"])
    _Pin(record["desired_pin"])
    current = _Pointer(record["parent"], project)

    if record["previous_head_sha256"] != (Digest(_Json(current)) if current is not None else genesis or origin):
        raise VpnError("Peer commit parent differs from its original head")

    return record


def ExistingCompletion(project: SelectedVpnProject, pending: dict[str, Any], *, segment: PeerSegment | None = None) -> dict[str, Any] | None:
    """Read an exact manifest-owned pending completion even before its head pointer was published."""

    if (not isinstance(pending.get("request_name"), str)
            or re.fullmatch(re.escape(project.vpn.identity.stack) + r"-wp-[0-9a-f]{16}", pending["request_name"]) is None):
        raise VpnError("Pending peer completion requires an exact confined request name")

    name = project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1]
    directory = project.Artifacts / ("server-" + name)

    if not directory.exists() and not directory.is_symlink():
        return None

    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", "record.json"}:
        raise VpnError("Pending peer completion has unknown or missing immutable files")

    raw = ReadOwnedArtifactFile(directory / "record.json", project.vpn.identity, kind="server", name=name)
    record = _CompletionRecord(project, raw, pending["creation_sha256"], genesis=segment.genesis if segment is not None else None)

    if ({key: record[key] for key in pending if key != "schema_version"}
            != {key: value for key, value in pending.items() if key != "schema_version"}):
        raise VpnError("Existing peer completion differs from its exact pending operation")

    return record


def LoadRevisions(project: SelectedVpnProject) -> RevisionState:
    """Verify the complete nonsecret commit chain without depending on private client key availability."""

    for filename in ("protocol-head.json", ".protocol-head.json.new", "protocol-pending.json", ".protocol-pending.json.new", "protocol-epochs",
                     "protocol-ingress-pending.json", ".protocol-ingress-pending.json.new"):
        path = project.root / filename

        if path.exists() or path.is_symlink():
            raise VpnError("Protocol epoch metadata requires the integrated protocol workflow; no legacy peer head was adopted")

    baseline = LoadCreationBaseline(project)

    if any(path.name.startswith("server-" + project.vpn.identity.stack + "-ip-") for path in project.Artifacts.iterdir()):
        raise VpnError("Retained ingress intent requires the integrated protocol workflow; a missing journal is never adopted")

    state = LoadPeerSegment(project, baseline)
    actualNames = {path.name.removeprefix("server-") for path in project.Artifacts.iterdir()
                   if path.name.startswith(("server-" + project.vpn.identity.stack + "-wp-", "server-" + project.vpn.identity.stack + "-wc-"))}

    if actualNames - state.artifactNames:
        raise VpnError("Unrecorded peer revision artifacts require explicit inspection; a missing head is never adopted")

    return state


def LoadPeerSegment(project: SelectedVpnProject, baseline: CreationBaseline, segment: PeerSegment | None = None) -> RevisionState:
    """Verify one bounded peer segment against its explicit genesis, retaining its global immutable artifact names."""

    origin = BundleDigest(baseline.bundle)
    genesis = segment.genesis if segment is not None else origin

    if (baseline.plan.identity != project.vpn.identity or segment is not None and genesis == origin):
        raise VpnError("Peer segment must preserve its original creation owner and use a distinct epoch genesis")

    directory = _Directory(project, segment)
    path = directory / "wireguard-head.json"
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
        record = _CompletionRecord(project, raw, origin, genesis=genesis)
        current = _Pointer(record["parent"], project)

        records.append(record)

    originalPins = tuple(source.pin for source in segment.sources) if segment is not None else baseline.protocols
    pin = next((item for item in originalPins if item.protocol == "wireguard"), None)
    receipt, history = (segment.receipt, segment.history) if segment is not None else ("", InitialHistory(project))
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
    pending = Pending(project, segment=segment)

    if pending is not None:
        expectedNames.add(pending["request_name"])
        expectedNames.add(project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1])

        if (pending["creation_sha256"] != origin
                or pending["previous_head_sha256"] != (Digest(_Json(pending["parent"])) if pending["parent"] is not None else genesis)
                or head != pending["parent"] and (not records or records[0]["request_name"] != pending["request_name"]
                                                  or {key: records[0][key] for key in pending if key != "schema_version"}
                                                  != {key: value for key, value in pending.items() if key != "schema_version"})
                or head == pending["parent"] and (_Pin(pending["previous_pin"]) != pin or pending["previous_history_sha256"] != history
                                                   or receipt and pending["previous_receipt_sha256"] != receipt)):
            raise VpnError("Pending peer operation does not continue its exact original controller and guest state")

    if segment is not None and "wireguard" not in segment.activeProtocols and (records or pending is not None):
        raise VpnError("An inactive WireGuard segment cannot contain a peer operation")

    pins = tuple(pin if item.protocol == "wireguard" and pin is not None else item for item in originalPins)

    return RevisionState(baseline, pins, head, Digest(_Json(head)) if head is not None else genesis, receipt, history,
                         records[0] if records else None, activeRecord, len(records), segment, frozenset(expectedNames))


def RequireCapacity(state: RevisionState) -> None:
    """Refuse a new attempt before activation rather than publishing an unreadable oversized history chain."""

    if state.recordCount >= MAX_PEER_REVISIONS:
        raise VpnError("Peer revision history is at capacity; retain the current project and do not activate another peer change")


def Pending(project: SelectedVpnProject, *, segment: PeerSegment | None = None) -> dict[str, Any] | None:
    """Read only a complete owner-bound metadata journal, with original material kept in immutable bundles."""

    directory = _Directory(project, segment)
    path = directory / "wireguard-pending.json"

    if not path.exists() and not path.is_symlink():
        temporary = directory / ".wireguard-pending.json.new"

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
        source = (next((source for source in state.segment.sources if source.pin == pin), None) if state.segment is not None
                  else ProtocolSource(project.vpn.identity, pin))

        if source is None:
            raise VpnError("Effective protocol pin has no retained source in its epoch")

    else:
        source = ProtocolSource(project.vpn.identity, pin, "peer", state.activeRecord["request_name"], state.activeRecord["request_sha256"])

    return ReadSource(project, source, material=material)


def PublishRequest(
    project: SelectedVpnProject, pending: dict[str, Any], material: ArtifactBundle, server: ArtifactBundle, *, segment: PeerSegment | None = None,
) -> str:
    """Persist all newly retained peer bytes before any remote action, keeping original bundles unchanged."""

    if (Pending(project, segment=segment) != pending or pending["request_sha256"] != ""
            or material.identity != project.vpn.identity or material.kind != "server"
            or material.name != project.vpn.identity.stack + "-wireguard-credentials"
            or {item.name for item in material.files} != {"material.json", "intent.sha256"}
            or any(item.sensitive != (item.name != "intent.sha256") for item in material.files)
            or next(item.content for item in material.files if item.name == "intent.sha256") != (pending["desired_fingerprint"] + "\n").encode()):
        raise VpnError("Peer preparation requires its exact persisted pre-remote journal and private material role")

    ValidateBundle(server)

    if server.identity != project.vpn.identity:
        raise VpnError("Peer server belongs to a different stack")

    state = LoadRevisions(project) if segment is None else LoadPeerSegment(project, LoadCreationBaseline(project), segment)
    RequireCapacity(state)

    if segment is not None and "wireguard" not in segment.activeProtocols:
        raise VpnError("An inactive WireGuard segment cannot stage a peer change")

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
                or facts["history_sha256"] != (
                    CommittedHistory(project, pending["change"], pending["device_id"], pending["previous_receipt_sha256"], str(facts["receipt_sha256"]),
                                     str(facts["deployment_sha256"]), pending["previous_history_sha256"])
                    if pending["request_sha256"] else pending["previous_history_sha256"]))):
        raise VpnError("Guest facts do not prove the exact peer completion outcome")

    if pending["request_sha256"]:
        _, server = ValidateRequest(project, pending, pin)

        if (outcome == "committed" and facts["deployment_sha256"] != Digest(
                next(item.content for item in server.files if item.name == "deployment.json"))):
            raise VpnError("Guest receipt describes a different desired peer deployment")

    elif outcome != "not-applied" or pin != _Pin(pending["previous_pin"]):
        raise VpnError("An unstaged peer attempt can only retain its previous projection")

    record = dict(pending)
    record.update(schema_version=2, desired_pin=_WireDict(pin), receipt_sha256=facts["receipt_sha256"], history_sha256=facts["history_sha256"],
                  deployment_sha256=facts["deployment_sha256"], outcome=outcome)

    existing = ExistingCompletion(project, pending, segment=state.segment)

    if (existing is not None and existing["schema_version"] == 1 and (outcome == "committed" or not pending["request_sha256"])
            and existing == {**record, "schema_version": 1}):
        record = existing

    name = project.vpn.identity.stack + "-wc-" + pending["request_name"].rsplit("-", 1)[1]
    bundle = ArtifactBundle(project.vpn.identity, "server", name, (Artifact("record.json", _Json(record), False),))
    directory = project.Artifacts / ("server-" + name)
    pointer = {"name": name, "sha256": BundleDigest(bundle)}
    actual = LoadRevisions(project) if state.segment is None else LoadPeerSegment(project, state.baseline, state.segment)
    currentPending = Pending(project, segment=state.segment)

    if (actual.head != state.head or state.head not in (pending["parent"], pointer)
            or currentPending != pending and (currentPending is not None or actual.head != pointer or actual.lastRecord != record)):
        raise VpnError("Peer commit head or journal changed; retain the pending operation")

    if actual.head != pointer:
        RequireCapacity(actual)

    if directory.exists() or directory.is_symlink():
        _ReadBundle(project, name, BundleDigest(bundle), ("record.json",))

    else:
        WriteArtifactBundle(project.Artifacts, bundle)

    options = {"segment": state.segment} if state.segment is not None else {}
    AtomicRecord(project, "wireguard-head.json", pointer, **options)

    if Pending(project, segment=state.segment) is not None:
        AtomicRecord(project, "wireguard-pending.json", None, **options)
