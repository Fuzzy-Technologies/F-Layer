"""Standard WireGuard intent and private artifacts without AmneziaWG parameters."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import secrets
from dataclasses import dataclass, field
from importlib.resources import files

from flayer.core.contracts import _WireDict
from flayer.profiles.artifacts import Artifact
from flayer.profiles.vpn import (
    MAX_VPN_DEVICES,
    BuildVpnDeviceBundle,
    BuildVpnServerBundle,
    PreparedVpnTransport,
    ValidateVpnTransport,
    VpnCapabilities,
    VpnEndpoint,
    VpnError,
    VpnProfile,
    _Name,
)

WIREGUARD_CAPABILITIES = VpnCapabilities("wireguard", "ip-tunnel", ("full", "split"))
WIREGUARD_TOOLS_VERSION = "1.0.20260223"
WIREGUARD_TOOLS_REVISION = "49ce333da02056ae7b22ee2aeb6afe8aaed79b19"
WIREGUARD_TOOLS_SHA256 = "af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf"
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def _Key(value: object) -> str:
    """Validate canonical nonzero 32-byte key material without echoing its value."""

    try:
        if not isinstance(value, str):
            raise ValueError

        raw = base64.b64decode(value, validate=True)

        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode("ascii") != value:
            raise ValueError

    except (ValueError, UnicodeError):
        raise VpnError("WireGuard keys must be canonical nonzero 32-byte base64 values") from None

    return value


def _PrivateKey() -> str:
    """Generate a clamped Curve25519 scalar independently of every other protocol."""

    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64

    return base64.b64encode(raw).decode("ascii")


def _PublicKey(privateKey: str) -> str:
    """Derive the protocol public key through the optional verified crypto dependency."""

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    except ImportError:
        raise VpnError("Install the f-layer[vpn] extra before preparing WireGuard material") from None

    raw = base64.b64decode(_Key(privateKey))

    return base64.b64encode(X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes_raw()).decode("ascii")


@dataclass(frozen=True, slots=True)
class WireGuardPeer:
    """One stable device's controller-only private key and independent preshared key."""

    deviceId: str
    privateKey: str = field(repr=False)
    presharedKey: str = field(repr=False)

    def __post_init__(self) -> None:
        """Reject invalid identities and credential values before rendering or persistence."""

        _Name(self.deviceId, "device_id")
        _Key(self.privateKey)
        _Key(self.presharedKey)

    @property
    def PublicKey(self) -> str:
        """Expose only the derived public half for the owned server configuration."""

        return _PublicKey(self.privateKey)


@dataclass(frozen=True, slots=True)
class WireGuardMaterial:
    """Private retained credentials bound to unique named devices, never cloud metadata."""

    serverPrivateKey: str = field(repr=False)
    peers: tuple[WireGuardPeer, ...] = field(repr=False)

    def __post_init__(self) -> None:
        """Prevent ambiguous peers, shared credentials and equivalent Curve25519 identities."""

        _Key(self.serverPrivateKey)

        if (not isinstance(self.peers, tuple) or not 1 <= len(self.peers) <= MAX_VPN_DEVICES
                or any(not isinstance(peer, WireGuardPeer) for peer in self.peers)):
            raise VpnError("WireGuard material requires 1..16 immutable named peers")

        publicKeys = (_PublicKey(self.serverPrivateKey), *(peer.PublicKey for peer in self.peers))
        presharedKeys = tuple(peer.presharedKey for peer in self.peers)
        privateKeys = (self.serverPrivateKey, *(peer.privateKey for peer in self.peers))
        presharedIdentities = {_PublicKey(key) for key in presharedKeys}

        if (len({peer.deviceId for peer in self.peers}) != len(self.peers)
                or len(set(publicKeys)) != len(publicKeys)
                or len(set(presharedKeys)) != len(presharedKeys)
                or set(presharedKeys) & (set(privateKeys) | set(publicKeys))
                or presharedIdentities & set(publicKeys)):
            raise VpnError("WireGuard peers require unique device identities and independent credentials")


@dataclass(frozen=True, slots=True)
class WireGuardSettings:
    """A distinct private IPv4 tunnel with an explicit bounded client/server MTU."""

    tunnelCidr: str = "10.67.0.0/24"
    mtu: int = 1280

    def __post_init__(self) -> None:
        """Reject noncanonical/public subnets and MTU coercion before generating credentials."""

        try:
            if not isinstance(self.tunnelCidr, str):
                raise ValueError

            network = ipaddress.IPv4Network(self.tunnelCidr, strict=True)

            if (str(network) != self.tunnelCidr or not 16 <= network.prefixlen <= 28
                    or not any(network.subnet_of(private) for private in _PRIVATE_NETWORKS)
                    or type(self.mtu) is not int or not 576 <= self.mtu <= 1420):
                raise ValueError

        except (ValueError, TypeError):
            raise VpnError("WireGuard requires a canonical RFC1918 /16../28 subnet and integer MTU 576..1420") from None


def GenerateWireGuardMaterial(profile: VpnProfile, settings: WireGuardSettings) -> WireGuardMaterial:
    """Generate one protocol's independent credentials only for its explicitly selected devices."""

    _ValidateWireGuardIntent(profile, settings)

    return WireGuardMaterial(_PrivateKey(), tuple(
        WireGuardPeer(device.deviceId, _PrivateKey(), base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
        for device in sorted(profile.devices, key=lambda item: item.deviceId)
    ))


def EncodeWireGuardMaterial(material: WireGuardMaterial) -> bytes:
    """Encode private controller storage with stable fields and no diagnostic representation."""

    if not isinstance(material, WireGuardMaterial):
        raise VpnError("WireGuard encoding requires a validated WireGuardMaterial")

    payload = {"schema_version": 1, "server_private_key": material.serverPrivateKey, "peers": [
        {"device_id": peer.deviceId, "private_key": peer.privateKey, "preshared_key": peer.presharedKey}
        for peer in material.peers
    ]}

    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def _UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate fields rather than selecting one interpretation of private material."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError

        result[key] = value

    return result


def DecodeWireGuardMaterial(content: bytes) -> WireGuardMaterial:
    """Read bounded exact controller material without accepting ambiguous or additional fields."""

    try:
        if not isinstance(content, bytes) or not 1 <= len(content) <= 65536:
            raise ValueError

        data = json.loads(content, object_pairs_hook=_UniqueObject)

        if (not isinstance(data, dict) or set(data) != {"schema_version", "server_private_key", "peers"}
                or type(data["schema_version"]) is not int or data["schema_version"] != 1
                or not isinstance(data["peers"], list) or not 1 <= len(data["peers"]) <= MAX_VPN_DEVICES):
            raise ValueError

        peers = []

        for peer in data["peers"]:
            if not isinstance(peer, dict) or set(peer) != {"device_id", "private_key", "preshared_key"}:
                raise ValueError

            peers.append(WireGuardPeer(peer["device_id"], peer["private_key"], peer["preshared_key"]))

        return WireGuardMaterial(data["server_private_key"], tuple(peers))

    except (ValueError, TypeError, KeyError, RecursionError):
        raise VpnError("Private WireGuard material is invalid or unsupported") from None


def WireGuardServiceName(profile: VpnProfile) -> str:
    """Derive the stable service identity without including mutable peers or credentials."""

    payload = json.dumps(_WireDict(profile.identity), sort_keys=True, separators=(",", ":"))

    return "flayer-wg-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _ValidateWireGuardIntent(profile: VpnProfile, settings: WireGuardSettings) -> int:
    """Check listener and assigned addresses before any key generation or private output."""

    listener = ValidateVpnTransport(profile, WIREGUARD_CAPABILITIES)

    if not isinstance(settings, WireGuardSettings) or listener.protocol != "udp":
        raise VpnError("WireGuard requires validated tunnel settings and one UDP listener")

    network = ipaddress.IPv4Network(settings.tunnelCidr)

    for device in profile.devices:
        if device.ipv4Address is None:
            raise VpnError("Every selected WireGuard device requires an explicit private IPv4 address")

        address = ipaddress.IPv4Address(device.ipv4Address)

        if address not in network or address in {network.network_address, network.network_address + 1, network.broadcast_address}:
            raise VpnError("WireGuard device addresses must be usable nonserver hosts in its tunnel subnet")

    return listener.port


def _ValidateWireGuard(
    profile: VpnProfile, settings: WireGuardSettings, material: WireGuardMaterial,
) -> int:
    """Bind retained private material to exactly the selected protocol's safe device intent."""

    port = _ValidateWireGuardIntent(profile, settings)

    if (not isinstance(material, WireGuardMaterial)
            or {peer.deviceId for peer in material.peers} != {device.deviceId for device in profile.devices}):
        raise VpnError("WireGuard requires retained material for exactly its selected devices")

    return port


def RenderWireGuardServer(profile: VpnProfile, settings: WireGuardSettings, material: WireGuardMaterial) -> bytes:
    """Render only server credentials and selected peer public/preshared keys for wg setconf."""

    port = _ValidateWireGuard(profile, settings, material)
    addresses = {device.deviceId: device.ipv4Address for device in profile.devices}
    lines = ["[Interface]", f"PrivateKey = {material.serverPrivateKey}", f"ListenPort = {port}"]

    for peer in sorted(material.peers, key=lambda item: item.deviceId):
        lines.extend(["", "[Peer]", f"# Device: {peer.deviceId}", f"PublicKey = {peer.PublicKey}",
                      f"PresharedKey = {peer.presharedKey}", f"AllowedIPs = {addresses[peer.deviceId]}/32"])

    return ("\n".join(lines) + "\n").encode("utf-8")


def RenderWireGuardClient(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: WireGuardSettings,
    material: WireGuardMaterial, deviceId: str,
) -> bytes:
    """Render one standard client without AWG fields or other devices' private credentials."""

    if not isinstance(endpoint, VpnEndpoint):
        raise VpnError("WireGuard client requires a validated VpnEndpoint")

    _Name(deviceId, "device_id")
    port = _ValidateWireGuard(profile, settings, material)
    peers = {peer.deviceId: peer for peer in material.peers}
    devices = {device.deviceId: device for device in profile.devices}

    if deviceId not in peers or endpoint.port != port:
        raise VpnError("WireGuard client requires a selected device and the exact declared endpoint port")

    peer = peers[deviceId]
    lines = [
        "[Interface]", f"PrivateKey = {peer.privateKey}", f"Address = {devices[deviceId].ipv4Address}/32",
        f"DNS = {', '.join(profile.routes.dnsServers)}", f"MTU = {settings.mtu}", "", "[Peer]",
        f"PublicKey = {_PublicKey(material.serverPrivateKey)}", f"PresharedKey = {peer.presharedKey}",
        f"Endpoint = {endpoint.host}:{endpoint.port}", f"AllowedIPs = {', '.join(profile.routes.ipv4Cidrs)}",
        "PersistentKeepalive = 25", "",
    ]

    return "\n".join(lines).encode("utf-8")


def PrepareWireGuard(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: WireGuardSettings, material: WireGuardMaterial,
) -> PreparedVpnTransport:
    """Prepare private kernel-service and standard client bundles without persisting or deploying them."""

    server = RenderWireGuardServer(profile, settings, material)
    clients = tuple(BuildVpnDeviceBundle(profile, "wireguard", device.deviceId, (
        Artifact("wireguard.conf", RenderWireGuardClient(profile, endpoint, settings, material, device.deviceId)),
    )) for device in sorted(profile.devices, key=lambda item: item.deviceId))
    program = files("flayer.profiles").joinpath("_wireguard_guest.py").read_bytes().replace(b"\r\n", b"\n")
    owner = hashlib.sha256(json.dumps(_WireDict(profile.identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    peers = {peer.deviceId: peer for peer in material.peers}
    descriptor = (json.dumps({
        "schema_version": 1, "owner": owner, "port": endpoint.port, "tunnel_cidr": settings.tunnelCidr,
        "mtu": settings.mtu, "ipv4_routes": list(profile.routes.ipv4Cidrs),
        "peers": [{"device_id": device.deviceId, "public_key": peers[device.deviceId].PublicKey,
                   "ipv4_address": device.ipv4Address} for device in sorted(profile.devices, key=lambda item: item.deviceId)],
        "config_sha256": hashlib.sha256(server).hexdigest(), "program_sha256": hashlib.sha256(program).hexdigest(),
        "tools_version": WIREGUARD_TOOLS_VERSION, "tools_sha256": WIREGUARD_TOOLS_SHA256,
    }, sort_keys=True, separators=(",", ":")) + "\n").encode()
    bundle = BuildVpnServerBundle(profile, "wireguard", (
        Artifact("server.conf", server), Artifact("deployment.json", descriptor), Artifact("install.py", program),
    ))

    return PreparedVpnTransport(profile, WIREGUARD_CAPABILITIES, bundle, clients)
