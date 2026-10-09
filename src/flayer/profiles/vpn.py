"""Transport-neutral VPN intent, private artifact ownership, and replacement checks."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tomllib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path

from flayer.core.contracts import (
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateName,
    ValidateSchemaVersion,
)
from flayer.profiles.artifacts import Artifact, ArtifactBundle

VPN_SCHEMA_VERSION = 1
MAX_VPN_PROFILE_BYTES = 65536
MAX_VPN_DEVICES = 16
MAX_VPN_TRANSPORTS = 8
_ROUTE_MODES = frozenset({"full", "split"})
_HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


class VpnError(ContractError):
    """VPN intent or artifact ownership is invalid before any external operation."""


def _Name(value: object, label: str) -> str:
    """Keep error types stable without exposing rejected input values."""

    try:
        return ValidateName(value, label)

    except ContractError:
        raise VpnError(f"{label} must be a lowercase name of 1..63 characters") from None


def _Port(value: object) -> int:
    """Reject booleans, coercion, and ports outside the transport range."""

    if type(value) is not int or not 1 <= value <= 65535:
        raise VpnError("VPN port must be an integer within 1..65535")

    return value


def _Address(value: object, label: str) -> str:
    """Accept canonical IPv4 unicast addresses, without resolving DNS or credentials."""

    try:
        if not isinstance(value, str):
            raise ValueError

        address = ipaddress.IPv4Address(value)

        if (
            str(address) != value or address.is_unspecified or address.is_multicast
            or address.is_loopback or address.is_link_local or int(address) == 2 ** 32 - 1
        ):
            raise ValueError

    except ValueError:
        raise VpnError(f"{label} must be a canonical nonlocal unicast IPv4 address") from None

    return value


def _Cidrs(value: object, label: str) -> tuple[str, ...]:
    """Bound IPv4 expansion and reject mutable, noncanonical, or overlapping networks."""

    if not isinstance(value, tuple) or not 1 <= len(value) <= 16:
        raise VpnError(f"{label} must contain 1..16 immutable IPv4 CIDRs")

    networks: list[ipaddress.IPv4Network] = []

    for item in value:
        try:
            if not isinstance(item, str):
                raise ValueError

            network = ipaddress.IPv4Network(item, strict=True)

            if str(network) != item:
                raise ValueError

        except ValueError:
            raise VpnError(f"{label} requires canonical IPv4 CIDRs") from None

        if any(network.overlaps(previous) for previous in networks):
            raise VpnError(f"{label} must not contain overlapping or duplicate CIDRs")

        networks.append(network)

    return value


@dataclass(frozen=True, slots=True)
class VpnDevice:
    """One named client; an optional private IPv4 address belongs to an IP tunnel."""

    device_id: str
    ipv4_address: str | None = None

    def __post_init__(self) -> None:
        """Validate public device intent without accepting any credential material."""

        _Name(self.device_id, "device_id")

        if self.ipv4_address is not None:
            address = ipaddress.IPv4Address(_Address(self.ipv4_address, "device IPv4 address"))

            if not any(address in network for network in _PRIVATE_NETWORKS):
                raise VpnError("Device tunnel addresses must belong to an RFC1918 network")


@dataclass(frozen=True, slots=True)
class VpnRoutes:
    """IPv4 destination policy; clients must disable IPv6 outside this initial contract."""

    mode: str
    ipv4_cidrs: tuple[str, ...]
    dns_servers: tuple[str, ...]
    ipv6_policy: str

    def __post_init__(self) -> None:
        """Reject incomplete full routes, unbounded split routes, and unsupported IPv6."""

        if not isinstance(self.mode, str) or self.mode not in _ROUTE_MODES:
            raise VpnError("VPN route mode must be full or split")

        cidrs = _Cidrs(self.ipv4_cidrs, "VPN routes")

        if self.mode == "full" and cidrs != ("0.0.0.0/0",):
            raise VpnError("Full IPv4 routing requires exactly 0.0.0.0/0")

        collapsed = tuple(ipaddress.collapse_addresses(
            ipaddress.IPv4Network(item) for item in cidrs
        ))

        if self.mode == "split" and any(item.prefixlen == 0 for item in collapsed):
            raise VpnError("Split routing must not cover the complete IPv4 address space")

        if self.ipv6_policy != "disabled":
            raise VpnError("IPv6 routing is unsupported; explicitly select ipv6_policy=disabled")

        if not isinstance(self.dns_servers, tuple) or not 1 <= len(self.dns_servers) <= 4:
            raise VpnError("VPN DNS requires 1..4 immutable IPv4 addresses")

        addresses = tuple(_Address(item, "VPN DNS") for item in self.dns_servers)

        if len(set(addresses)) != len(addresses):
            raise VpnError("VPN DNS addresses must be unique")

        if any(not any(ipaddress.IPv4Address(item) in network for network in collapsed) for item in addresses):
            raise VpnError("VPN DNS addresses must be reachable through the declared routes")


@dataclass(frozen=True, slots=True)
class VpnEndpoint:
    """Public transport destination; a DNS name still needs adapter-side IPv4 resolution."""

    host: str
    port: int

    def __post_init__(self) -> None:
        """Reject URL syntax, IPv6 literals, shell tokens, and local-only destinations."""

        _Port(self.port)

        if not isinstance(self.host, str) or _HOST_PATTERN.fullmatch(self.host) is None:
            raise VpnError("VPN endpoint must be a canonical IPv4 address or lowercase DNS name")

        if self.host.replace(".", "").isdigit():
            _Address(self.host, "VPN endpoint")

        elif self.host == "localhost" or self.host.endswith(".localhost") or any(
            not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
            for part in self.host.split(".")
        ):
            raise VpnError("VPN endpoint requires a nonlocal lowercase DNS name")


@dataclass(frozen=True, slots=True)
class VpnListener:
    """One explicit TCP or UDP ingress allowance for a named transport implementation."""

    transport: str
    protocol: str
    port: int
    source_cidrs: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate ingress intent without claiming that the service is installed or healthy."""

        _Name(self.transport, "transport")
        _Port(self.port)

        if not isinstance(self.protocol, str) or self.protocol not in {"tcp", "udp"}:
            raise VpnError("VPN listener protocol must be tcp or udp")

        _Cidrs(self.source_cidrs, "VPN listener sources")


@dataclass(frozen=True, slots=True)
class VpnCapabilities:
    """Transport-declared traffic scope; an application proxy is not an OS-wide tunnel."""

    transport: str
    network_mode: str
    route_modes: tuple[str, ...]
    ipv4: bool = True
    ipv6: bool = False

    def __post_init__(self) -> None:
        """Keep implementation capabilities explicit and within the supported address family."""

        _Name(self.transport, "transport")

        if not isinstance(self.network_mode, str) or self.network_mode not in {"ip-tunnel", "application-proxy"}:
            raise VpnError("VPN network_mode must be ip-tunnel or application-proxy")

        if (
            not isinstance(self.route_modes, tuple) or not 1 <= len(self.route_modes) <= 2
            or any(not isinstance(item, str) or item not in _ROUTE_MODES for item in self.route_modes)
            or len(set(self.route_modes)) != len(self.route_modes)
        ):
            raise VpnError("VPN route capabilities must contain unique full or split values")

        if type(self.ipv4) is not bool or not self.ipv4 or type(self.ipv6) is not bool or self.ipv6:
            raise VpnError("Initial VPN implementations require IPv4 and must not advertise IPv6")


@dataclass(frozen=True, slots=True)
class VpnProfile:
    """Public device and routing intent owned by one exact infrastructure stack."""

    identity: StackIdentity
    devices: tuple[VpnDevice, ...]
    routes: VpnRoutes
    listeners: tuple[VpnListener, ...]
    schema_version: int = VPN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Reject duplicate identities, addresses, listeners, or mutable nested values."""

        try:
            ValidateSchemaVersion(self.schema_version)

        except ContractError:
            raise VpnError("VPN schema_version must be the supported integer 1") from None

        if not isinstance(self.identity, StackIdentity) or not isinstance(self.routes, VpnRoutes):
            raise VpnError("VPN profile requires a StackIdentity and VpnRoutes")

        if (
            not isinstance(self.devices, tuple) or not 1 <= len(self.devices) <= MAX_VPN_DEVICES
            or any(not isinstance(item, VpnDevice) for item in self.devices)
        ):
            raise VpnError("VPN profile requires 1..16 immutable VpnDevice values")

        addresses = [item.ipv4_address for item in self.devices if item.ipv4_address is not None]

        if len({item.device_id for item in self.devices}) != len(self.devices) or len(set(addresses)) != len(addresses):
            raise VpnError("VPN devices must have unique IDs and unique assigned IPv4 addresses")

        if (
            not isinstance(self.listeners, tuple) or not 1 <= len(self.listeners) <= MAX_VPN_TRANSPORTS
            or any(not isinstance(item, VpnListener) for item in self.listeners)
        ):
            raise VpnError("VPN profile requires 1..8 immutable VpnListener values")

        if (
            len({item.transport for item in self.listeners}) != len(self.listeners)
            or len({(item.protocol, item.port) for item in self.listeners}) != len(self.listeners)
        ):
            raise VpnError("VPN listeners require unique transports and protocol/port pairs")

        device_names: set[str] = set()

        for listener in self.listeners:
            _Name(f"{self.identity.stack}-{listener.transport}", "VPN server artifact name")

            for device in self.devices:
                name = _Name(f"{device.device_id}-{listener.transport}", "VPN device artifact name")

                if name in device_names:
                    raise VpnError("VPN device and transport names create an ambiguous artifact name")

                device_names.add(name)

    def Fingerprint(self) -> str:
        """Hash only public intent for binding prepared artifacts to an exact profile."""

        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ValidateVpnTransport(profile: VpnProfile, capabilities: VpnCapabilities) -> VpnListener:
    """Require the selected implementation to support this exact declared routing intent."""

    if not isinstance(profile, VpnProfile) or not isinstance(capabilities, VpnCapabilities):
        raise VpnError("VPN preparation requires a VpnProfile and VpnCapabilities")

    listener = next((item for item in profile.listeners if item.transport == capabilities.transport), None)

    if listener is None:
        raise VpnError("VPN transport must have an explicitly declared listener")

    if profile.routes.mode not in capabilities.route_modes:
        raise VpnError("VPN implementation does not support the requested routing mode")

    if capabilities.network_mode == "ip-tunnel" and any(item.ipv4_address is None for item in profile.devices):
        raise VpnError("IP tunnel devices require explicit private IPv4 addresses")

    return listener


def _Transport(profile: VpnProfile, transport: str) -> None:
    """Bind artifact naming to one transport explicitly selected by the public profile."""

    if not isinstance(profile, VpnProfile):
        raise VpnError("VPN artifacts require a VpnProfile")

    _Name(transport, "transport")

    if not any(item.transport == transport for item in profile.listeners):
        raise VpnError("VPN artifacts must belong to a declared transport")


def _SensitiveFiles(files: tuple[Artifact, ...]) -> None:
    """Require conservative sensitivity for every opaque transport payload."""

    if (
        not isinstance(files, tuple) or not 1 <= len(files) <= 8
        or any(not isinstance(item, Artifact) or not item.sensitive for item in files)
    ):
        raise VpnError("VPN payloads require 1..8 immutable sensitive Artifact values")


def BuildVpnServerBundle(
    profile: VpnProfile, transport: str, files: tuple[Artifact, ...],
) -> ArtifactBundle:
    """Prepare private server bytes for authenticated guest provisioning, never cloud metadata."""

    _Transport(profile, transport)
    _SensitiveFiles(files)

    return ArtifactBundle(profile.identity, "server", f"{profile.identity.stack}-{transport}", files)


def BuildVpnDeviceBundle(
    profile: VpnProfile, transport: str, device_id: str, files: tuple[Artifact, ...],
) -> ArtifactBundle:
    """Prepare owned client bytes without overwriting or revoking existing credentials."""

    _Transport(profile, transport)
    _Name(device_id, "device_id")
    _SensitiveFiles(files)

    if not any(item.device_id == device_id for item in profile.devices):
        raise VpnError("VPN client artifacts require an explicitly declared device")

    return ArtifactBundle(profile.identity, "device", f"{device_id}-{transport}", files)


@dataclass(frozen=True, slots=True)
class PreparedVpnTransport:
    """Sensitive server and client artifacts; preparation is not deployment or health evidence."""

    profile: VpnProfile
    capabilities: VpnCapabilities
    server_bundle: ArtifactBundle = field(repr=False)
    device_bundles: tuple[ArtifactBundle, ...] = field(repr=False)

    def __post_init__(self) -> None:
        """Require exact stack ownership, transport naming, and a complete device artifact set."""

        ValidateVpnTransport(self.profile, self.capabilities)
        transport = self.capabilities.transport

        if (
            not isinstance(self.server_bundle, ArtifactBundle)
            or self.server_bundle.identity != self.profile.identity
            or self.server_bundle.kind != "server"
            or self.server_bundle.name != f"{self.profile.identity.stack}-{transport}"
        ):
            raise VpnError("VPN server bundle must match the exact stack and transport")

        _SensitiveFiles(self.server_bundle.files)

        if not isinstance(self.device_bundles, tuple) or any(
            not isinstance(item, ArtifactBundle) for item in self.device_bundles
        ):
            raise VpnError("VPN client bundles must be immutable ArtifactBundle values")

        names = [item.name for item in self.device_bundles]
        expected = {f"{item.device_id}-{transport}" for item in self.profile.devices}

        if len(set(names)) != len(names) or set(names) != expected:
            raise VpnError("VPN client bundles must match every declared device exactly once")

        for bundle in self.device_bundles:
            if bundle.identity != self.profile.identity or bundle.kind != "device":
                raise VpnError("VPN client bundle ownership must match the exact stack")

            _SensitiveFiles(bundle.files)

    def Fingerprint(self) -> str:
        """Bind replacement approval to public intent and exact private payload digests."""

        bundles = (self.server_bundle, *self.device_bundles)
        document = {
            "profile": self.profile.Fingerprint(), "capabilities": asdict(self.capabilities),
            "artifacts": sorted((
                bundle.kind, bundle.name, artifact.name,
                hashlib.sha256(artifact.content).hexdigest(),
            ) for bundle in bundles for artifact in bundle.files),
        }
        payload = json.dumps(document, sort_keys=True, separators=(",", ":"))

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def ValidateVpnReplacement(
    previous: PreparedVpnTransport, replacement: PreparedVpnTransport, *, expected_fingerprint: str,
) -> None:
    """Require exact old artifact consent; guest revocation and local cleanup remain separate."""

    if not isinstance(previous, PreparedVpnTransport) or not isinstance(replacement, PreparedVpnTransport):
        raise VpnError("VPN replacement requires prepared previous and replacement artifacts")

    if previous.profile.identity != replacement.profile.identity or previous.capabilities.transport != replacement.capabilities.transport:
        raise VpnError("VPN replacement must preserve exact stack identity and transport")

    if not isinstance(expected_fingerprint, str) or previous.Fingerprint() != expected_fingerprint:
        raise VpnError("VPN replacement requires the exact expected previous fingerprint")


def ParseVpnProfile(data: Mapping[str, object]) -> VpnProfile:
    """Decode only public VPN intent and reject unknown fields, including inline credentials."""

    try:
        ValidateFields(data, frozenset({
            "schema_version", "identity", "devices", "routes", "listeners",
        }), frozenset(), "VPN profile")
        ValidateSchemaVersion(data["schema_version"])
        routes = RequireTable(data["routes"], "VPN routes")
        ValidateFields(routes, frozenset({
            "mode", "ipv4_cidrs", "dns_servers", "ipv6_policy",
        }), frozenset(), "VPN routes")

        if (
            not isinstance(routes["mode"], str) or not isinstance(routes["ipv6_policy"], str)
            or not isinstance(routes["ipv4_cidrs"], list) or not isinstance(routes["dns_servers"], list)
            or not isinstance(data["devices"], list) or not isinstance(data["listeners"], list)
        ):
            raise VpnError("VPN profile requires string policies and explicit array values")

        devices: list[VpnDevice] = []
        listeners: list[VpnListener] = []

        for raw_device in data["devices"]:
            device = RequireTable(raw_device, "VPN device")
            ValidateFields(device, frozenset({"device_id"}), frozenset({"ipv4_address"}), "VPN device")
            address = device.get("ipv4_address")

            if address is not None:
                address = _Address(address, "device IPv4 address")

            devices.append(VpnDevice(_Name(device["device_id"], "device_id"), address))

        for raw_listener in data["listeners"]:
            listener = RequireTable(raw_listener, "VPN listener")
            ValidateFields(listener, frozenset({
                "transport", "protocol", "port", "source_cidrs",
            }), frozenset(), "VPN listener")

            if not isinstance(listener["protocol"], str) or not isinstance(listener["source_cidrs"], list):
                raise VpnError("VPN listener requires a protocol string and a CIDR array")

            listeners.append(VpnListener(
                _Name(listener["transport"], "transport"), listener["protocol"],
                _Port(listener["port"]), tuple(listener["source_cidrs"]),
            ))

        return VpnProfile(
            ParseIdentity(data["identity"]), tuple(devices),
            VpnRoutes(routes["mode"], tuple(routes["ipv4_cidrs"]), tuple(routes["dns_servers"]), routes["ipv6_policy"]),
            tuple(listeners),
        )

    except ContractError as error:
        raise VpnError(str(error)) from None


def LoadVpnProfile(path: str | Path) -> VpnProfile:
    """Read a bounded public TOML profile without reading credentials or contacting a provider."""

    try:
        with Path(path).open("rb") as stream:
            content = stream.read(MAX_VPN_PROFILE_BYTES + 1)

        if len(content) > MAX_VPN_PROFILE_BYTES:
            raise VpnError("VPN profile exceeds its bounded input size")

        data = tomllib.loads(content.decode("utf-8"))

    except (OSError, ValueError, RecursionError):
        raise VpnError("Unable to read a valid bounded VPN profile") from None

    return ParseVpnProfile(data)
