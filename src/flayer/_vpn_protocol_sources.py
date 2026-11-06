"""Resolve immutable per-protocol sources without replacing original bundles or generating credentials."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from flayer._vpn_creation import (
    _SERVER_FILES,
    BundleDigest,
    ProtocolPin,
    ReadPinnedBundle,
    _Decode,
    _Json,
)
from flayer.core.contracts import ParseIdentity, StackIdentity, _WireDict
from flayer.guest import PrivatePath
from flayer.profiles.artifacts import Artifact, ArtifactBundle, ReadOwnedArtifactFile
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MATERIAL_FILES = ("material.json", "intent.sha256")


def _ProtocolRequestName(identity: StackIdentity, protocol: str, operationId: str) -> str:
    """Separate protocol snapshots from peer revisions while binding one operation's independent protocol roles."""

    suffix = hashlib.sha256((protocol + ":" + operationId).encode()).hexdigest()[:16]

    return identity.stack + "-tp-" + suffix


@dataclass(frozen=True, slots=True)
class ProtocolSource:
    """Nonsecret owner-bound source metadata for original, peer or staged protocol projection bytes."""

    identity: StackIdentity
    pin: ProtocolPin
    kind: str = "initial"
    requestName: str = ""
    requestSha256: str = ""

    def __post_init__(self) -> None:
        """Keep historical role and request locators explicit, confined and separate from their virtual protocol bundle names."""

        if (not isinstance(self.identity, StackIdentity) or not isinstance(self.pin, ProtocolPin)
                or not isinstance(self.kind, str) or self.kind not in {"initial", "peer", "protocol"}
                or not isinstance(self.requestName, str) or not isinstance(self.requestSha256, str)):
            raise VpnError("Protocol source requires exact ownership, projection and supported source kind")

        if self.kind == "initial":
            if self.requestName or self.requestSha256:
                raise VpnError("Original protocol source cannot redirect its fixed role bundles")

        else:
            prefix = "wp" if self.kind == "peer" else "tp"

            if (self.kind == "peer" and self.pin.protocol != "wireguard"
                    or len(self.requestName) > 63
                    or re.fullmatch(re.escape(self.identity.stack) + "-" + prefix + r"-[0-9a-f]{16}", self.requestName) is None
                    or _HASH.fullmatch(self.requestSha256) is None):
                raise VpnError("Protocol source request cannot cross its owned protocol role or store namespace")

    def Record(self) -> dict[str, object]:
        """Serialize only hashes and bounded public ownership references for a future epoch record."""

        return {"schema_version": 1, **_WireDict(self)}


def DecodeSource(value: object, identity: StackIdentity) -> ProtocolSource:
    """Decode complete source metadata without reading private files or adopting an implicit protocol role."""

    if (not isinstance(value, dict) or set(value) != {"schema_version", "identity", "pin", "kind", "request_name", "request_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or ParseIdentity(value["identity"]) != identity or not isinstance(value["pin"], dict)
            or set(value["pin"]) != {"protocol", "intent_fingerprint", "material_digest", "server_digest"}):
        raise VpnError("Protocol source metadata is malformed or belongs to another owner")

    pin = value["pin"]

    return ProtocolSource(identity, ProtocolPin(pin["protocol"], pin["intent_fingerprint"], pin["material_digest"], pin["server_digest"]),
                          value["kind"], value["request_name"], value["request_sha256"])


def _Request(project: SelectedVpnProject, source: ProtocolSource) -> ArtifactBundle:
    """Read one complete immutable owned request, then prove its externally pinned digest before reconstructing roles."""

    directory = project.Artifacts / ("server-" + source.requestName)
    PrivatePath(directory, directory=True)
    filenames = (*_MATERIAL_FILES, *_SERVER_FILES[source.pin.protocol], "request.json")

    if {path.name for path in directory.iterdir()} != {"manifest.json", *filenames}:
        raise VpnError("Protocol source request has missing or unknown files")

    bundle = ArtifactBundle(project.vpn.identity, "server", source.requestName, tuple(Artifact(filename,
        ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=source.requestName),
        filename not in {"intent.sha256", "request.json"}) for filename in filenames))

    if BundleDigest(bundle) != source.requestSha256:
        raise VpnError("Protocol source request differs from its pinned immutable bytes")

    return bundle


def ReadSource(project: SelectedVpnProject, source: ProtocolSource, *, material: bool = False) -> ArtifactBundle:
    """Resolve exact retained projection bytes only; metadata traversal and cloud cleanup need not call this private reader."""

    if not isinstance(source, ProtocolSource) or source.identity != project.vpn.identity or type(material) is not bool:
        raise VpnError("Protocol source cannot read another owner or an ambiguous bundle role")

    if source.kind == "initial":
        return ReadPinnedBundle(project, source.pin, material=material)

    request = _Request(project, source)
    contents = {item.name: item.content for item in request.files}

    if source.kind == "protocol":
        metadata = _Decode(contents["request.json"])
        fields = {"schema_version", "identity", "protocol", "operation_id", "previous_state_sha256", "pin"}

        if (set(metadata) != fields or contents["request.json"] != _Json(metadata)
                or type(metadata["schema_version"]) is not int or metadata["schema_version"] != 1
                or metadata["identity"] != _WireDict(project.vpn.identity) or metadata["protocol"] != source.pin.protocol
                or not isinstance(metadata["operation_id"], str) or re.fullmatch(r"[0-9a-f]{32}", metadata["operation_id"]) is None
                or not isinstance(metadata["previous_state_sha256"], str) or _HASH.fullmatch(metadata["previous_state_sha256"]) is None
                or metadata["pin"] != _WireDict(source.pin)
                or source.requestName != _ProtocolRequestName(project.vpn.identity, source.pin.protocol, metadata["operation_id"])):
            raise VpnError("Protocol source request metadata differs from its exact projection")

    base = project.vpn.identity.stack + "-" + source.pin.protocol
    credentials = ArtifactBundle(project.vpn.identity, "server", base + "-credentials", tuple(
        Artifact(filename, contents[filename], filename != "intent.sha256") for filename in _MATERIAL_FILES))
    server = ArtifactBundle(project.vpn.identity, "server", base, tuple(Artifact(filename, contents[filename]) for filename in _SERVER_FILES[source.pin.protocol]))

    if (contents["intent.sha256"] != (source.pin.intentFingerprint + "\n").encode()
            or BundleDigest(credentials) != source.pin.materialDigest or BundleDigest(server) != source.pin.serverDigest):
        raise VpnError("Protocol source bytes differ from their canonical material/server projection")

    return credentials if material else server


def PrepareProtocolRequest(
    project: SelectedVpnProject, pin: ProtocolPin, material: ArtifactBundle, server: ArtifactBundle, *, operationId: str, previousState: str,
) -> tuple[ProtocolSource, ArtifactBundle]:
    """Prepare a retained protocol source in memory; publication, journaling and remote mutation remain separate operations."""

    if (not isinstance(pin, ProtocolPin) or not isinstance(operationId, str) or re.fullmatch(r"[0-9a-f]{32}", operationId) is None
            or not isinstance(previousState, str) or _HASH.fullmatch(previousState) is None
            or any(not isinstance(bundle, ArtifactBundle) or bundle.identity != project.vpn.identity or bundle.kind != "server" for bundle in (material, server))
            or (material.name, server.name) != (project.vpn.identity.stack + "-" + pin.protocol + "-credentials", project.vpn.identity.stack + "-" + pin.protocol)
            or {item.name for item in material.files} != set(_MATERIAL_FILES) or {item.name for item in server.files} != set(_SERVER_FILES[pin.protocol])
            or any(item.sensitive != (item.name != "intent.sha256") for item in material.files) or any(not item.sensitive for item in server.files)
            or BundleDigest(material) != pin.materialDigest or BundleDigest(server) != pin.serverDigest
            or next(item.content for item in material.files if item.name == "intent.sha256") != (pin.intentFingerprint + "\n").encode()):
        raise VpnError("Protocol source preparation requires complete unchanged owned material/server roles and exact operation proofs")

    name = _ProtocolRequestName(project.vpn.identity, pin.protocol, operationId)
    metadata: dict[str, Any] = {"schema_version": 1, "identity": _WireDict(project.vpn.identity), "protocol": pin.protocol,
                                "operation_id": operationId, "previous_state_sha256": previousState, "pin": _WireDict(pin)}
    request = ArtifactBundle(project.vpn.identity, "server", name, material.files + server.files + (Artifact("request.json", _Json(metadata), False),))
    source = ProtocolSource(project.vpn.identity, pin, "protocol", name, BundleDigest(request))

    return source, request
