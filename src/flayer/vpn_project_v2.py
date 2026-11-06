"""Validate and prepare explicitly selected protocols without adopting legacy projects or cloud state."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from flayer.core.contracts import RequireTable, ValidateFields, ValidateName
from flayer.guest import PrivatePath, ValidateSshPathSyntax
from flayer.profiles.amneziawg import (
    AmneziaWgSettings,
    DecodeAmneziaWgSecrets,
    EncodeAmneziaWgSecrets,
    GenerateAmneziaWgSecrets,
    PrepareAmneziaWg,
)
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vless import (
    DecodeVlessMaterial,
    EncodeVlessMaterial,
    GenerateVlessMaterial,
    PrepareVless,
    VlessRealitySettings,
)
from flayer.profiles.vpn import (
    ParseVpnProfile,
    PreparedVpnTransport,
    VpnEndpoint,
    VpnError,
    VpnProfile,
)
from flayer.profiles.wireguard import (
    DecodeWireGuardMaterial,
    EncodeWireGuardMaterial,
    GenerateWireGuardMaterial,
    PrepareWireGuard,
    WireGuardSettings,
    _ValidateWireGuardIntent,
)
from flayer.vpn_project import (
    PROJECT_TEMPLATE,
    CloudPlacement,
    SelectedVpnProject,
    VpnProjectReport,
    VpnResources,
    _PublicKey,
    _VerifyAdministrationKey,
)
from flayer.vpn_selection import VPN_PROTOCOLS, ParseProtocolSelections, VpnProtocolSelection

_IMPLEMENTED = VPN_PROTOCOLS[:3]
_TABLES = {"amneziawg": "amneziawg", "vless-reality": "vless", "wireguard": "wireguard"}


def _Protocols(value: object) -> tuple[str, ...]:
    """Normalize explicit protocol selection without treating an empty list as the legacy default."""

    if (not isinstance(value, (list, tuple)) or not 1 <= len(value) <= len(_IMPLEMENTED)
            or any(not isinstance(item, str) or item not in _IMPLEMENTED for item in value)
            or len(set(value)) != len(value)):
        raise VpnError("Select unique supported protocols explicitly; OpenVPN project integration is not implemented yet")

    return tuple(protocol for protocol in _IMPLEMENTED if protocol in value)


def SelectedProjectTemplate(protocols: tuple[str, ...]) -> str:
    """Render an opt-in schema-2 template while preserving the default schema-1 template byte for byte."""

    if not isinstance(protocols, tuple):
        raise VpnError("Explicit project protocols must be an immutable tuple")

    selected = _Protocols(protocols)
    # Reuse the canonical common editable sections; the legacy template itself is never changed.
    common, separator, _ = PROJECT_TEMPLATE.partition("[amneziawg]\n")

    if not separator or common.count("schema_version = 1\n") != 1:
        raise VpnError("Canonical project template no longer has its expected common sections")

    common = common.replace("schema_version = 1\n", "schema_version = 2\nprotocols = " + json.dumps(selected) + "\n", 1)

    if "amneziawg" not in selected:
        common = common.replace('ipv4_address = "10.66.0.2"\n', "")

    sections = {
        "amneziawg": '[amneziawg]\ndevice_ids = ["laptop"]\nport = 51820\ntunnel_cidr = "10.66.0.0/24"\nmtu = 1280\n',
        "vless-reality": '[vless]\ndevice_ids = ["laptop"]\nport = 443\n# Choose an accessible TLS 1.3 / HTTP/2 target for the server location.\ntarget_host = "www.microsoft.com"\nserver_name = "www.microsoft.com"\n',
        "wireguard": '[wireguard]\ndevice_ids = ["laptop"]\nport = 51821\ntunnel_cidr = "10.67.0.0/24"\nmtu = 1280\n\n[wireguard.device_addresses]\nlaptop = "10.67.0.2"\n',
    }

    return common + "\n".join(sections[protocol] for protocol in selected)


def ValidateSelectedProject(project: SelectedVpnProject) -> None:
    """Reject all invalid memberships, settings, collisions and native-client limits before key generation."""

    if (not isinstance(project, SelectedVpnProject) or not isinstance(project.root, Path) or not isinstance(project.vpn, VpnProfile)
            or not isinstance(project.cloud, CloudPlacement)
            or not isinstance(project.protocolSelections, tuple) or not project.protocolSelections
            or any(not isinstance(item, VpnProtocolSelection) for item in project.protocolSelections)):
        raise VpnError("Schema-2 project requires validated immutable intent and explicit protocol membership")

    selected = _Protocols(tuple(item.protocol for item in project.protocolSelections))

    if {listener.transport for listener in project.vpn.listeners} != set(selected):
        raise VpnError("Schema-2 listeners must match exactly the selected protocols")

    if project.vpn.identity.provider != "yandex-cloud" or project.vpn.identity.scopeId.startswith("replace-with-"):
        raise VpnError("Project requires an explicit Yandex Cloud folder ID")

    if not isinstance(project.sshPublicKey, str):
        raise VpnError("Schema-2 project requires a validated administration public key")

    _PublicKey(project.sshPublicKey.encode("utf-8"))

    if len(project.vpn.routes.dnsServers) > 2:
        raise VpnError("Native client profiles support at most two DNS servers; truncation is refused")

    if project.resources is not None and not isinstance(project.resources, VpnResources):
        raise VpnError("Schema-2 resources require validated VpnResources")

    if project.resources is not None and project.cloud.zoneId.startswith("kz1-") and project.resources.platformId != "standard-v3":
        raise VpnError("Kazakhstan VPN deployments require platform_id standard-v3")

    settings = {"amneziawg": (project.amneziawg, AmneziaWgSettings),
                "vless-reality": (project.vless, VlessRealitySettings), "wireguard": (project.wireguard, WireGuardSettings)}
    networks = [ipaddress.IPv4Network(project.cloud.subnetCidr)]
    awgMembers: set[str] = set()

    for protocol in _IMPLEMENTED:
        value, expectedType = settings[protocol]

        if protocol not in selected:
            if value is not None:
                raise VpnError("Inactive protocol settings are not allowed in schema 2")

            continue

        if not isinstance(value, expectedType):
            raise VpnError("Each selected protocol requires its exact validated settings")

        profile = project.ProtocolProfile(protocol)
        listener = profile.listeners[0]

        if listener.protocol != ("tcp" if protocol == "vless-reality" else "udp") or listener.protocol == "tcp" and listener.port == 22:
            raise VpnError("Selected listener transport or port conflicts with its protocol or administration")

        for suffix in (protocol, protocol + "-credentials"):
            ValidateName(project.vpn.identity.stack + "-" + suffix, "selected project artifact name")

        if isinstance(value, WireGuardSettings):
            _ValidateWireGuardIntent(profile, value)
            networks.append(ipaddress.IPv4Network(value.tunnelCidr))

        elif isinstance(value, AmneziaWgSettings):
            network = ipaddress.IPv4Network(value.tunnelCidr)
            networks.append(network)
            awgMembers = {device.deviceId for device in profile.devices}

            for device in profile.devices:
                address = ipaddress.IPv4Address(str(device.ipv4Address))

                if address not in network or address in {network.network_address, network.network_address + 1, network.broadcast_address}:
                    raise VpnError("AWG members require explicit usable nonserver tunnel addresses")

    if any(device.ipv4Address is not None and device.deviceId not in awgMembers for device in project.vpn.devices):
        raise VpnError("Top-level device IPv4 addresses belong only to selected AWG members")

    if any(left.overlaps(right) for index, left in enumerate(networks) for right in networks[index + 1:]):
        raise VpnError("Selected tunnel networks and cloud subnet must not overlap")

    selections = {item.protocol: item for item in project.protocolSelections}
    object.__setattr__(project, "protocolSelections", tuple(selections[protocol] for protocol in selected))
    object.__setattr__(project, "vpn", VpnProfile(project.vpn.identity,
                       tuple(sorted(project.vpn.devices, key=lambda item: item.deviceId)), project.vpn.routes,
                       tuple(next(listener for listener in project.vpn.listeners if listener.transport == protocol) for protocol in selected)))


def ParseSelectedProject(root: Path, data: Mapping[str, object], publicKey: str) -> SelectedVpnProject:
    """Parse strict schema-2 public TOML without generating keys, migrating state or constructing a provider."""

    try:
        if type(data.get("schema_version")) is not int or data["schema_version"] != 2 or not isinstance(data.get("protocols"), list):
            raise VpnError("Selected projects require schema_version 2 and an explicit protocols array")

        protocols = _Protocols(data["protocols"])
        ValidateFields(data, frozenset({"schema_version", "protocols", "identity", "cloud", "routes", "devices",
                                      *(_TABLES[protocol] for protocol in protocols)}), frozenset({"resources"}), "schema-2 VPN project")
        cloud = RequireTable(data["cloud"], "cloud")
        ValidateFields(cloud, frozenset({"yc_profile", "zone_id", "image_id", "subnet_cidr", "management_cidrs"}), frozenset(), "cloud")

        if (any(not isinstance(cloud[key], str) for key in ("yc_profile", "zone_id", "image_id", "subnet_cidr"))
                or not isinstance(cloud["management_cidrs"], list)):
            raise VpnError("Cloud placement requires explicit strings and a management CIDR array")

        placement = CloudPlacement(cast(str, cloud["yc_profile"]), cast(str, cloud["zone_id"]),
                                   cast(str, cloud["image_id"]), cast(str, cloud["subnet_cidr"]), tuple(cloud["management_cidrs"]))
        tables: dict[str, object] = {}
        listeners = []

        for protocol in protocols:
            table = RequireTable(data[_TABLES[protocol]], "selected protocol")
            required = {"device_ids", "port", "target_host", "server_name"} if protocol == "vless-reality" else {"device_ids", "port", "tunnel_cidr"}

            if protocol == "wireguard":
                required.add("device_addresses")

            ValidateFields(table, frozenset(required), frozenset() if protocol == "vless-reality" else frozenset({"mtu"}), "selected protocol")
            tables[protocol] = dict(table)
            listeners.append({"transport": protocol, "protocol": "tcp" if protocol == "vless-reality" else "udp",
                              "port": table["port"], "source_cidrs": ["0.0.0.0/0"]})

        profile = ParseVpnProfile({"schema_version": 1, "identity": data["identity"], "routes": data["routes"],
                                   "devices": data["devices"], "listeners": listeners})
        selections = ParseProtocolSelections(list(protocols), tables, profile)
        awg = cast(dict[str, object], tables.get("amneziawg", {}))
        vless = cast(dict[str, object], tables.get("vless-reality", {}))
        wireguard = cast(dict[str, object], tables.get("wireguard", {}))
        resources = None

        if "resources" in data:
            sizing = RequireTable(data["resources"], "resources")
            ValidateFields(sizing, frozenset({"platform_id", "cores", "core_fraction", "memory_gib", "disk_size_gib", "disk_type"}), frozenset(), "resources")
            resources = VpnResources(cast(str, sizing["platform_id"]), cast(int, sizing["cores"]),
                                     cast(int, sizing["core_fraction"]), cast(int, sizing["memory_gib"]),
                                     cast(int, sizing["disk_size_gib"]), cast(str, sizing["disk_type"]))

        return SelectedVpnProject(
            root, profile, placement, selections, publicKey,
            AmneziaWgSettings(cast(str, awg["tunnel_cidr"]), cast(int, awg.get("mtu", 1280))) if awg else None,
            VlessRealitySettings(cast(str, vless["target_host"]), cast(str, vless["server_name"])) if vless else None,
            WireGuardSettings(cast(str, wireguard["tunnel_cidr"]), cast(int, wireguard.get("mtu", 1280))) if wireguard else None,
            resources,
        )

    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        if isinstance(error, VpnError):
            raise

        raise VpnError("Schema-2 configuration is invalid; check its documented fields and types") from None


def _Read(project: SelectedVpnProject, bundle: ArtifactBundle, filename: str) -> bytes:
    """Authorize exact retained files only through their complete owned bundle manifest."""

    return ReadOwnedArtifactFile(project.Artifacts / (bundle.kind + "-" + bundle.name) / filename,
                                 bundle.identity, kind=bundle.kind, name=bundle.name)


def _Material(project: SelectedVpnProject, protocol: str) -> ArtifactBundle:
    """Retain one protocol's credentials independently, refusing changed prepared membership or settings."""

    profile = project.ProtocolProfile(protocol)
    name = project.vpn.identity.stack + "-" + protocol + "-credentials"
    proof = (project.TransportFingerprint(protocol) + "\n").encode("ascii")
    reference = ArtifactBundle(profile.identity, "server", name, (Artifact("intent.sha256", proof, False),))
    path = project.Artifacts / ("server-" + name)

    if path.exists() or path.is_symlink():
        if _Read(project, reference, "intent.sha256") != proof:
            raise VpnError("Prepared protocol intent changed; use an explicit peer/protocol transition without rotating unrelated credentials")

        material = _Read(project, reference, "material.json")

    elif protocol == "amneziawg":
        material = EncodeAmneziaWgSecrets(GenerateAmneziaWgSecrets(profile))

    elif protocol == "vless-reality":
        material = EncodeVlessMaterial(GenerateVlessMaterial(profile))

    else:
        assert project.wireguard is not None
        material = EncodeWireGuardMaterial(GenerateWireGuardMaterial(profile, project.wireguard))

    return ArtifactBundle(profile.identity, "server", name, (Artifact("material.json", material), Artifact("intent.sha256", proof, False)))


def _Transport(project: SelectedVpnProject, protocol: str, material: ArtifactBundle, host: str = "192.0.2.1") -> PreparedVpnTransport:
    """Render only that protocol's server from retained material, using no claimed client endpoint."""

    profile = project.ProtocolProfile(protocol)
    endpoint = VpnEndpoint(host, profile.listeners[0].port)
    content = next(item.content for item in material.files if item.name == "material.json")

    if protocol == "amneziawg":
        assert project.amneziawg is not None

        return PrepareAmneziaWg(profile, endpoint, project.amneziawg, DecodeAmneziaWgSecrets(content))

    if protocol == "vless-reality":
        assert project.vless is not None

        return PrepareVless(profile, endpoint, project.vless, DecodeVlessMaterial(content))

    assert project.wireguard is not None

    return PrepareWireGuard(profile, endpoint, project.wireguard, DecodeWireGuardMaterial(content))


def _CheckExisting(project: SelectedVpnProject, bundle: ArtifactBundle) -> bool:
    """Verify the complete exact existing file set before publishing any newly prepared bundle."""

    path = project.Artifacts / (bundle.kind + "-" + bundle.name)

    if not path.exists() and not path.is_symlink():
        return False

    PrivatePath(path, directory=True)

    if {item.name for item in path.iterdir()} != {"manifest.json", *(item.name for item in bundle.files)}:
        raise VpnError("Prepared protocol bundle has an unexpected file set; recovery is required")

    if any(_Read(project, bundle, item.name) != item.content for item in bundle.files):
        raise VpnError("Prepared protocol artifacts changed; retain the previous project and use explicit maintenance")

    return True


def PrepareSelectedProject(project: SelectedVpnProject) -> VpnProjectReport:
    """Prepare selected server/material bundles offline, preserving existing protocol bytes and legacy state."""

    ValidateSelectedProject(project)
    ValidateSshPathSyntax(project.root)
    PrivatePath(project.root, directory=True)
    PrivatePath(project.Artifacts, directory=True)
    legacy = tuple(project.Artifacts / ("server-" + project.vpn.identity.stack + "-" + suffix)
                   for suffix in ("credentials", "bootstrap", "trust"))

    state = (project.root / "state.json", project.root / ".state.json.operation.json")

    if (any(path.exists() or path.is_symlink() for path in (*state, *legacy))
            or any(path.name.startswith("device-") for path in project.Artifacts.iterdir())):
        raise VpnError("Schema-2 offline preparation cannot adopt an existing deployment or legacy material; explicit migration is pending")

    from flayer._vpn_creation import LoadCreationBaseline, PrepareCreationBundle, ReadPinnedBundle

    creation = project.Artifacts / ("server-" + project.vpn.identity.stack + "-creation")

    if creation.exists() or creation.is_symlink():
        baseline = LoadCreationBaseline(project)
        baseline.ValidateCurrent(project)

        for pin in baseline.protocols:
            ReadPinnedBundle(project, pin, material=True)
            ReadPinnedBundle(project, pin)

        _VerifyAdministrationKey(project)

        return VpnProjectReport("prepare", "complete", details="Original selected protocol and creation bundles verified offline without regeneration")

    _VerifyAdministrationKey(project)
    bundles: list[ArtifactBundle] = []
    transports = []

    for selection in project.protocolSelections:
        material = _Material(project, selection.protocol)
        transport = _Transport(project, selection.protocol, material)
        bundles.extend((material, transport.serverBundle))
        transports.append((material, transport.serverBundle))

    bundles.append(PrepareCreationBundle(project, tuple(transports)))
    existing = [_CheckExisting(project, bundle) for bundle in bundles]

    for bundle, retained in zip(bundles, existing, strict=True):
        if not retained:
            WriteArtifactBundle(project.Artifacts, bundle)

    return VpnProjectReport("prepare", "complete", details="Selected material/server bundles and original creation baseline prepared offline; client exports require an observed address")
