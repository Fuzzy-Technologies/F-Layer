"""Retain an immutable six-resource creation plan independently of selected transport evolution."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from flayer.core.contracts import ParseIdentity, _WireDict
from flayer.core.lifecycle import DeploymentPlan
from flayer.guest import PrivatePath
from flayer.profiles.artifacts import Artifact, ArtifactBundle, ReadOwnedArtifactFile
from flayer.profiles.vpn import VpnError
from flayer.providers.contracts import ResourceKind
from flayer.providers.lifecycle import JsonValue, ResourceSpec
from flayer.vpn_project import SelectedVpnProject, _Bootstrap, _CompileOwnedResources

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = (("network", ResourceKind.NETWORK), ("subnet", ResourceKind.SUBNET),
          ("firewall", ResourceKind.SECURITY_GROUP), ("address", ResourceKind.ADDRESS),
          ("boot-disk", ResourceKind.DISK), ("instance", ResourceKind.INSTANCE))
_SERVER_FILES = {
    "amneziawg": ("server.conf", "install.sh", "firewall.nft", "network.sh", "service.service"),
    "vless-reality": ("server.json", "deployment.json", "install.py"),
    "wireguard": ("server.conf", "deployment.json", "install.py"),
}


def _Digest(content: bytes) -> str:
    """Compare exact nonsecret records and opaque private bundle bytes without exposing them."""

    return hashlib.sha256(content).hexdigest()


def _Json(data: object) -> bytes:
    """Encode deterministic versioned local metadata with no key material."""

    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _Decode(content: bytes) -> dict[str, Any]:
    """Reject oversized, duplicate or malformed baseline records without echoing input."""

    def Unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Require an unambiguous field interpretation at every depth."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError

            result[key] = value

        return result

    try:
        if not 1 <= len(content) <= 65536:
            raise ValueError

        data = json.loads(content, object_pairs_hook=Unique)

        if not isinstance(data, dict):
            raise ValueError

        return data

    except (ValueError, RecursionError):
        raise VpnError("Creation baseline JSON is invalid or ambiguous") from None


def _Immutable(value: object, depth: int = 0) -> JsonValue:
    """Restore exact ordered tuples instead of recompiling desired parameters from current settings."""

    if depth > 12:
        raise VpnError("Creation baseline parameters exceed their depth bound")

    if isinstance(value, list):
        return tuple(_Immutable(item, depth + 1) for item in value)

    if value is None or type(value) in {str, int, bool}:
        return cast(JsonValue, value)

    raise VpnError("Creation baseline parameters require immutable JSON values")


def BundleDigest(bundle: ArtifactBundle) -> str:
    """Bind complete file names, sensitivity, content hashes and exact bundle identity without storing secrets."""

    return _Digest(_Json({"identity": _WireDict(bundle.identity), "kind": bundle.kind, "name": bundle.name,
                          "files": [{"name": item.name, "sensitive": item.sensitive, "size": len(item.content),
                                     "sha256": _Digest(item.content)} for item in sorted(bundle.files, key=lambda item: item.name)]}))


def StaticFingerprint(project: SelectedVpnProject) -> str:
    """Identify original resource intent while allowing an unrelated device or local auth-profile alias to change."""

    return _Digest(_Json({"identity": _WireDict(project.vpn.identity),
                          "cloud": {"zone_id": project.cloud.zoneId, "image_id": project.cloud.imageId,
                                    "subnet_cidr": project.cloud.subnetCidr, "management_cidrs": project.cloud.managementCidrs},
                          "resources": _WireDict(project.resources) if project.resources is not None else None,
                          "ssh_public_key": project.sshPublicKey,
                          "listeners": [_WireDict(listener) for listener in project.vpn.listeners]}))


@dataclass(frozen=True, slots=True)
class ProtocolPin:
    """Original protocol projection and complete material/server bundle digests, without their payloads."""

    protocol: str
    intentFingerprint: str
    materialDigest: str
    serverDigest: str

    def __post_init__(self) -> None:
        """Refuse unsupported protocols or invalid proof values before trusting local ownership metadata."""

        if self.protocol not in _SERVER_FILES or any(
            not isinstance(value, str) or _HASH.fullmatch(value) is None
            for value in (self.intentFingerprint, self.materialDigest, self.serverDigest)
        ):
            raise VpnError("Creation protocol pin is invalid")


@dataclass(frozen=True, slots=True)
class CreationBaseline:
    """Exact original plan/bootstrap/SSH marker plus separate protocol pins; never a new desired plan."""

    plan: DeploymentPlan
    projectFingerprint: str
    staticFingerprint: str
    protocols: tuple[ProtocolPin, ...]
    bundle: ArtifactBundle = field(repr=False)

    def ValidateCurrent(self, project: SelectedVpnProject) -> None:
        """Refuse implicit resource/listener/protocol changes while preserving irrelevant device declarations."""

        if (project.vpn.identity != self.plan.identity or StaticFingerprint(project) != self.staticFingerprint
                or tuple(item.protocol for item in project.protocolSelections) != tuple(item.protocol for item in self.protocols)
                or any(project.TransportFingerprint(item.protocol) != item.intentFingerprint for item in self.protocols)):
            raise VpnError("Creation baseline differs from current intent; restore its settings or use an explicit peer/protocol transition or resource migration")


def _Name(project: SelectedVpnProject) -> str:
    """Resolve one stable owned creation bundle without accepting a caller-supplied metadata path."""

    return project.vpn.identity.stack + "-creation"


def _Directory(project: SelectedVpnProject) -> Path:
    """Pin an absolute bootstrap reference inside the declared private artifact root."""

    return (project.Artifacts / ("server-" + _Name(project))).absolute()


def _Record(plan: DeploymentPlan) -> list[dict[str, object]]:
    """Preserve exact resource parameter/dependency order and original creation labels."""

    return [{"logical_id": item.logicalId, "kind": item.kind.value, "name": item.name,
             "parameters": item.parameters, "dependencies": item.dependencies,
             "creation_labels": item.OwnershipLabels(plan.identity)} for item in plan.resources]


def _FreshBootstrap(project: SelectedVpnProject) -> bytes:
    """Add only fresh-guest build prerequisites to the unchanged reusable bootstrap security baseline."""

    raw = _Bootstrap(project).files[0].content
    data = json.loads(raw.removeprefix(b"#cloud-config\n"))

    if project.wireguard is not None:
        data["packages"].extend(("build-essential", "kmod", "iproute2", "util-linux"))

    return ("#cloud-config\n" + json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


def PrepareCreationBundle(project: SelectedVpnProject, transports: tuple[tuple[ArtifactBundle, ArtifactBundle], ...]) -> ArtifactBundle:
    """Capture the first verified compiler output once; reuse its bytes instead of replaying a new bootstrap."""

    name = _Name(project)
    directory = _Directory(project)

    if directory.exists() or directory.is_symlink():
        baseline = LoadCreationBaseline(project)
        baseline.ValidateCurrent(project)

        return baseline.bundle

    if (not isinstance(transports, tuple) or len(transports) != len(project.protocolSelections)
            or any(not isinstance(pair, tuple) or len(pair) != 2 for pair in transports)):
        raise VpnError("Creation baseline requires complete explicitly selected protocol bundles")

    for selection, (material, server) in zip(project.protocolSelections, transports, strict=True):
        if any(not isinstance(bundle, ArtifactBundle) or bundle.identity != project.vpn.identity or bundle.kind != "server"
               for bundle in (material, server)) or (material.name, server.name) != (
                   project.vpn.identity.stack + "-" + selection.protocol + "-credentials",
                   project.vpn.identity.stack + "-" + selection.protocol,
               ):
            raise VpnError("Creation protocol bundles do not match their exact owner and selected role")

        if ({item.name for item in material.files} != {"material.json", "intent.sha256"}
                or {item.name for item in server.files} != set(_SERVER_FILES[selection.protocol])
                or any(not item.sensitive for item in server.files)
                or any(item.sensitive != (item.name != "intent.sha256") for item in material.files)
                or next(item.content for item in material.files if item.name == "intent.sha256")
                != (project.TransportFingerprint(selection.protocol) + "\n").encode("ascii")):
            raise VpnError("Creation protocol bundles require the exact prepared file roles and intent proof")

    bootstrap = _FreshBootstrap(project)
    plan = _CompileOwnedResources(project, directory / "cloud-init.json", bootstrap)
    pins = tuple(ProtocolPin(selection.protocol, project.TransportFingerprint(selection.protocol),
                             BundleDigest(material), BundleDigest(server))
                 for selection, (material, server) in zip(project.protocolSelections, transports, strict=True))
    record = {"schema_version": 1, "identity": _WireDict(project.vpn.identity),
              "project_fingerprint": project.Fingerprint(), "static_fingerprint": StaticFingerprint(project),
              "plan_fingerprint": plan.Fingerprint(), "resources": _Record(plan),
              "protocols": [_WireDict(pin) for pin in pins]}

    return ArtifactBundle(project.vpn.identity, "server", name, (
        Artifact("creation.json", _Json(record), False), Artifact("cloud-init.json", bootstrap, False),
    ))


def LoadCreationBaseline(project: SelectedVpnProject) -> CreationBaseline:
    """Load only manifest-verified original specs and bootstrap, rejecting foreign roots and malformed snapshots."""

    name = _Name(project)
    directory = _Directory(project)

    if not directory.exists() and not directory.is_symlink():
        raise VpnError("Schema-2 creation baseline is absent; prepare the private project offline first")

    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", "creation.json", "cloud-init.json"}:
        raise VpnError("Creation baseline contains unknown or missing files")

    def Read(filename: str) -> bytes:
        """Authorize each file through the complete unchanged original bundle manifest."""

        return ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=name)

    content, bootstrap = Read("creation.json"), Read("cloud-init.json")
    data = _Decode(content)

    try:
        if (set(data) != {"schema_version", "identity", "project_fingerprint", "static_fingerprint", "plan_fingerprint", "resources", "protocols"}
                or type(data["schema_version"]) is not int or data["schema_version"] != 1
                or ParseIdentity(data["identity"]) != project.vpn.identity
                or any(not isinstance(data[key], str) or _HASH.fullmatch(data[key]) is None
                       for key in ("project_fingerprint", "static_fingerprint", "plan_fingerprint"))
                or not isinstance(data["resources"], list) or len(data["resources"]) != 6
                or not isinstance(data["protocols"], list) or not 1 <= len(data["protocols"]) <= 3):
            raise ValueError

        resources: list[ResourceSpec] = []

        for raw, (logicalId, kind) in zip(data["resources"], _KINDS, strict=True):
            if (not isinstance(raw, dict) or set(raw) != {"logical_id", "kind", "name", "parameters", "dependencies", "creation_labels"}
                    or raw["logical_id"] != logicalId or raw["kind"] != kind.value
                    or raw["name"] != project.vpn.identity.stack + "-" + logicalId
                    or not isinstance(raw["parameters"], list) or not isinstance(raw["dependencies"], list)):
                raise ValueError

            spec = ResourceSpec(raw["logical_id"], kind, raw["name"], cast(tuple[tuple[str, JsonValue], ...], _Immutable(raw["parameters"])),
                                 tuple(raw["dependencies"]))

            if raw["creation_labels"] != json.loads(json.dumps(spec.OwnershipLabels(project.vpn.identity))):
                raise ValueError

            resources.append(spec)

        plan = DeploymentPlan(project.vpn.identity, tuple(resources))
        instance = dict(plan.resources[-1].parameters)

        if (plan.Fingerprint() != data["plan_fingerprint"] or instance.get("user_data_file") != str(directory / "cloud-init.json")
                or instance.get("user_data_sha256") != _Digest(bootstrap)):
            raise ValueError

        pins: list[ProtocolPin] = []

        for raw in data["protocols"]:
            if not isinstance(raw, dict) or set(raw) != {"protocol", "intent_fingerprint", "material_digest", "server_digest"}:
                raise ValueError

            pins.append(ProtocolPin(raw["protocol"], raw["intent_fingerprint"], raw["material_digest"], raw["server_digest"]))

        expectedOrder = tuple(protocol for protocol in _SERVER_FILES if protocol in {pin.protocol for pin in pins})

        if tuple(pin.protocol for pin in pins) != expectedOrder:
            raise ValueError

        bundle = ArtifactBundle(project.vpn.identity, "server", name, (
            Artifact("creation.json", content, False), Artifact("cloud-init.json", bootstrap, False),
        ))

        return CreationBaseline(plan, data["project_fingerprint"], data["static_fingerprint"], tuple(pins), bundle)

    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise VpnError("Creation baseline ownership, resource snapshot or original bootstrap proof is invalid") from None


def ReadPinnedBundle(project: SelectedVpnProject, pin: ProtocolPin, *, material: bool = False) -> ArtifactBundle:
    """Read original private bytes against their creation pin without regenerating keys or installer programs."""

    name = project.vpn.identity.stack + "-" + pin.protocol + ("-credentials" if material else "")
    filenames = ("material.json", "intent.sha256") if material else _SERVER_FILES[pin.protocol]
    directory = project.Artifacts / ("server-" + name)
    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", *filenames}:
        raise VpnError("Pinned protocol bundle has an unknown or missing file")

    bundle = ArtifactBundle(project.vpn.identity, "server", name, tuple(Artifact(filename,
        ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=name),
        filename != "intent.sha256") for filename in filenames))

    if BundleDigest(bundle) != (pin.materialDigest if material else pin.serverDigest):
        raise VpnError("Pinned protocol bundle differs from its original creation snapshot")

    return bundle
