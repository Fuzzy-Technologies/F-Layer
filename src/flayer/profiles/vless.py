"""Prepare private VLESS Reality profiles for the pinned Xray implementation."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from urllib.parse import quote, urlencode

from flayer.core.contracts import ContractError, ValidateName
from flayer.profiles.artifacts import Artifact
from flayer.profiles.vpn import (
    BuildVpnDeviceBundle,
    BuildVpnServerBundle,
    PreparedVpnTransport,
    ValidateVpnTransport,
    VpnCapabilities,
    VpnEndpoint,
    VpnProfile,
)

VLESS_TRANSPORT = "vless-reality"
VLESS_FLOW = "xtls-rprx-vision"
VLESS_CAPABILITIES = VpnCapabilities(VLESS_TRANSPORT, "application-proxy", ("full", "split"))
XRAY_VERSION = "26.3.27"
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")


class VlessError(ContractError):
    """VLESS intent or credentials cannot safely produce a supported configuration."""


def _Host(value: object) -> str:
    """Require an explicit canonical DNS hostname without transport or shell syntax."""

    if not isinstance(value, str) or _HOST.fullmatch(value) is None or "." not in value:
        raise VlessError("Reality target and server name require a canonical DNS hostname")

    if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
           for part in value.split(".")):
        raise VlessError("Reality hostname contains an invalid DNS label")

    try:
        ipaddress.ip_address(value)

    except ValueError:
        return value

    raise VlessError("Reality target and server name require DNS names, not IP addresses")


def _Port(value: object) -> int:
    """Reject booleans and require a real TCP port."""

    if type(value) is not int or not 1 <= value <= 65535:
        raise VlessError("VLESS ports must be integers within 1..65535")

    return value


@dataclass(frozen=True, slots=True)
class VlessRealitySettings:
    """Public Reality handshake target and local application-proxy listener settings."""

    target_host: str
    server_name: str
    target_port: int = 443
    fingerprint: str = "chrome"
    socks_port: int = 10808

    def __post_init__(self) -> None:
        """Require explicit TLS identities and a supported stable browser fingerprint."""

        _Host(self.target_host)
        _Host(self.server_name)
        _Port(self.target_port)
        _Port(self.socks_port)

        if not isinstance(self.fingerprint, str) or self.fingerprint not in {
            "chrome", "firefox", "safari", "ios", "android", "edge",
        }:
            raise VlessError("Reality fingerprint is not supported by this profile")


@dataclass(frozen=True, slots=True)
class VlessDeviceCredential:
    """One revocable per-device VLESS UUID, excluded from object representations."""

    device_id: str
    user_id: str = field(repr=False)

    def __post_init__(self) -> None:
        """Accept only canonical nonzero randomly generated UUID credentials."""

        ValidateName(self.device_id, "device_id")

        try:
            value = uuid.UUID(self.user_id)

        except (ValueError, TypeError, AttributeError):
            raise VlessError("VLESS device credential must be a canonical UUID version 4") from None

        if str(value) != self.user_id or value.version != 4:
            raise VlessError("VLESS device credential must be a canonical UUID version 4")


@dataclass(frozen=True, slots=True)
class VlessMaterial:
    """Explicit secret material retained in private bundles, never generic lifecycle state."""

    server_private_key: bytes = field(repr=False)
    server_public_key: bytes = field(repr=False)
    short_id: str = field(repr=False)
    devices: tuple[VlessDeviceCredential, ...] = field(repr=False)

    def __post_init__(self) -> None:
        """Validate material structure without including values in error messages."""

        if any(not isinstance(value, bytes) or len(value) != 32 or value == bytes(32)
               for value in (self.server_private_key, self.server_public_key)):
            raise VlessError("Reality keys must contain 32 nonzero raw bytes")

        if not isinstance(self.short_id, str) or re.fullmatch(r"[0-9a-f]{16}", self.short_id) is None:
            raise VlessError("Reality short ID must contain 16 lowercase hexadecimal characters")

        if not isinstance(self.devices, tuple) or not 1 <= len(self.devices) <= 16 or any(
            not isinstance(item, VlessDeviceCredential) for item in self.devices
        ):
            raise VlessError("VLESS requires 1..16 immutable per-device credentials")

        if len({item.device_id for item in self.devices}) != len(self.devices) or len({
            item.user_id for item in self.devices
        }) != len(self.devices):
            raise VlessError("VLESS device identities and UUID credentials must be unique")


def _PublicKey(private_key: bytes) -> bytes:
    """Derive a raw X25519 public key through the optional audited crypto dependency."""

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    except ImportError:
        raise VlessError("Install the f-layer[vpn] extra before preparing VPN credentials") from None

    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


def GenerateVlessMaterial(profile: VpnProfile) -> VlessMaterial:
    """Generate fresh server and device credentials only for an explicitly validated profile."""

    ValidateVpnTransport(profile, VLESS_CAPABILITIES)
    private_key = secrets.token_bytes(32)

    return VlessMaterial(
        private_key, _PublicKey(private_key), secrets.token_hex(8),
        tuple(VlessDeviceCredential(device.device_id, str(uuid.uuid4())) for device in profile.devices),
    )



def EncodeVlessMaterial(material: VlessMaterial) -> bytes:
    """Serialize credentials only for a caller-owned sensitive artifact, never general state."""

    if not isinstance(material, VlessMaterial):
        raise VlessError("Expected validated VLESS material")

    return _Json({
        "schema_version": 1,
        "server_private_key": _Encode(material.server_private_key),
        "server_public_key": _Encode(material.server_public_key),
        "short_id": material.short_id,
        "devices": [asdict(item) for item in material.devices],
    })


def DecodeVlessMaterial(content: bytes) -> VlessMaterial:
    """Read an explicitly supplied bounded private snapshot without consulting local defaults."""

    try:
        if not isinstance(content, bytes) or not 1 <= len(content) <= 16384:
            raise ValueError("Invalid input size")

        data = json.loads(content)
        expected = {"schema_version", "server_private_key", "server_public_key", "short_id", "devices"}

        if not isinstance(data, dict) or set(data) != expected or type(data["schema_version"]) is not int:
            raise ValueError("Invalid schema")

        if data["schema_version"] != 1 or not isinstance(data["devices"], list):
            raise ValueError("Invalid schema version")

        keys = []

        for name in ("server_private_key", "server_public_key"):
            value = data[name]

            if not isinstance(value, str) or re.fullmatch(r"[a-zA-Z0-9_-]{43}", value) is None:
                raise ValueError("Invalid key encoding")

            raw = base64.urlsafe_b64decode(value + "=")

            if _Encode(raw) != value:
                raise ValueError("Noncanonical key encoding")

            keys.append(raw)

        devices = []

        for device in data["devices"]:
            if not isinstance(device, dict) or set(device) != {"device_id", "user_id"}:
                raise ValueError("Invalid device credential")

            devices.append(VlessDeviceCredential(device["device_id"], device["user_id"]))

        material = VlessMaterial(keys[0], keys[1], data["short_id"], tuple(devices))

        if not secrets.compare_digest(_PublicKey(material.server_private_key), material.server_public_key):
            raise ValueError("Inconsistent keys")

        return material

    except (ValueError, TypeError, KeyError, RecursionError):
        raise VlessError("Private VLESS material does not satisfy its schema or key contract") from None


def _Validate(profile: VpnProfile, settings: VlessRealitySettings, material: VlessMaterial) -> int:
    """Bind each credential to one declared device and reject inconsistent key pairs."""

    listener = ValidateVpnTransport(profile, VLESS_CAPABILITIES)

    if listener.protocol != "tcp" or not isinstance(settings, VlessRealitySettings):
        raise VlessError("VLESS Reality requires one TCP listener and explicit Reality settings")

    if not isinstance(material, VlessMaterial):
        raise VlessError("VLESS requires separately supplied private material")

    if {item.device_id for item in material.devices} != {
        device.device_id for device in profile.devices
    }:
        raise VlessError("VLESS credentials must match the declared devices exactly")

    if not secrets.compare_digest(_PublicKey(material.server_private_key), material.server_public_key):
        raise VlessError("Reality server private and public keys do not form a pair")

    return listener.port


def _Encode(value: bytes) -> str:
    """Encode an X25519 key using Xray's unpadded URL-safe representation."""

    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _Json(value: object) -> bytes:
    """Render deterministic UTF-8 JSON with a trailing newline for private artifacts."""

    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def RenderVlessServer(
    profile: VpnProfile, settings: VlessRealitySettings, material: VlessMaterial,
) -> bytes:
    """Build a Reality-protected IPv4 proxy without device traffic or credential logging."""

    port = _Validate(profile, settings, material)
    blocked = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "::/0",
    ]

    return _Json({
        "log": {"loglevel": "none", "access": "none", "error": "none"},
        "dns": {"servers": list(profile.routes.dns_servers), "queryStrategy": "UseIPv4"},
        "inbounds": [{
            "tag": "vless-reality", "listen": "0.0.0.0", "port": port, "protocol": "vless",
            "settings": {
                "clients": [{"id": item.user_id, "flow": VLESS_FLOW} for item in material.devices],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "show": False, "target": f"{settings.target_host}:{settings.target_port}",
                    "xver": 0, "serverNames": [settings.server_name],
                    "privateKey": _Encode(material.server_private_key), "shortIds": [material.short_id],
                },
            },
        }],
        "outbounds": [
            {"tag": "internet", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPOnDemand",
            "rules": [{"type": "field", "ip": blocked, "outboundTag": "blocked"}],
        },
    })


def _Credential(material: VlessMaterial, device_id: str) -> VlessDeviceCredential:
    """Select one device without exposing other clients' authentication credentials."""

    for item in material.devices:
        if item.device_id == device_id:
            return item

    raise VlessError("Requested device has no VLESS credential")


def RenderVlessClient(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: VlessRealitySettings,
    material: VlessMaterial, device_id: str,
) -> bytes:
    """Render a loopback SOCKS client; split destinations outside the allowlist are rejected."""

    port = _Validate(profile, settings, material)

    if not isinstance(endpoint, VpnEndpoint) or endpoint.port != port:
        raise VlessError("VLESS endpoint must match the declared TCP listener port")

    credential = _Credential(material, device_id)
    routing_rules: list[dict[str, object]] = [
        {"type": "field", "ip": ["::/0"], "outboundTag": "blocked"},
        {"type": "field", "ip": list(profile.routes.dns_servers), "port": "53",
         "outboundTag": "vpn"},
        {"type": "field", "ip": list(profile.routes.ipv4_cidrs), "outboundTag": "vpn"},
        {"type": "field", "network": "tcp,udp", "outboundTag": "blocked"},
    ]

    return _Json({
        "log": {"loglevel": "none", "access": "none", "error": "none"},
        "dns": {"servers": list(profile.routes.dns_servers), "queryStrategy": "UseIPv4"},
        "inbounds": [{
            "tag": "local-socks", "listen": "127.0.0.1", "port": settings.socks_port,
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
        }],
        "outbounds": [{
            "tag": "vpn", "protocol": "vless",
            "settings": {"vnext": [{
                "address": endpoint.host, "port": endpoint.port,
                "users": [{"id": credential.user_id, "encryption": "none", "flow": VLESS_FLOW}],
            }]},
            "streamSettings": {
                "network": "tcp", "security": "reality",
                "realitySettings": {
                    "fingerprint": settings.fingerprint, "serverName": settings.server_name,
                    "publicKey": _Encode(material.server_public_key), "shortId": material.short_id,
                    "spiderX": "/",
                },
            },
        }, {"tag": "blocked", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": routing_rules},
    })


def BuildVlessUri(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: VlessRealitySettings,
    material: VlessMaterial, device_id: str,
) -> str:
    """Produce a transport import URI; client route and DNS policy need separate configuration."""

    RenderVlessClient(profile, endpoint, settings, material, device_id)
    credential = _Credential(material, device_id)
    parameters = urlencode({
        "encryption": "none", "flow": VLESS_FLOW, "security": "reality",
        "sni": settings.server_name, "fp": settings.fingerprint,
        "pbk": _Encode(material.server_public_key), "sid": material.short_id,
        "type": "tcp", "headerType": "none", "spx": "/",
    })
    label = quote(f"{profile.identity.stack}-{device_id}", safe="")

    return f"vless://{credential.user_id}@{endpoint.host}:{endpoint.port}?{parameters}#{label}"



def VlessServiceName(profile: VpnProfile) -> str:
    """Return the deterministic systemd unit for this exact stack ownership identity."""

    ValidateVpnTransport(profile, VLESS_CAPABILITIES)
    owner = hashlib.sha256(_Json(asdict(profile.identity))).hexdigest()

    return f"flayer-vless-{owner[:24]}.service"


def PrepareVless(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: VlessRealitySettings,
    material: VlessMaterial,
) -> PreparedVpnTransport:
    """Prepare an owned installer and one private import bundle per declared device."""

    server = RenderVlessServer(profile, settings, material)
    identity = asdict(profile.identity)
    owner = hashlib.sha256(_Json(identity)).hexdigest()
    deployment = _Json({
        "schema_version": 1, "owner": owner, "config_sha256": hashlib.sha256(server).hexdigest(),
        "port": endpoint.port, "xray_version": XRAY_VERSION,
    })
    installer = files("flayer.profiles").joinpath("_vless_guest.py").read_bytes()
    server_bundle = BuildVpnServerBundle(profile, VLESS_TRANSPORT, (
        Artifact("server.json", server), Artifact("install.py", installer),
        Artifact("deployment.json", deployment),
    ))
    device_bundles = tuple(BuildVpnDeviceBundle(profile, VLESS_TRANSPORT, device.device_id, (
        Artifact("client.json", RenderVlessClient(profile, endpoint, settings, material, device.device_id)),
        Artifact("import.txt", (BuildVlessUri(
            profile, endpoint, settings, material, device.device_id,
        ) + "\n").encode("utf-8")),
    )) for device in profile.devices)

    return PreparedVpnTransport(profile, VLESS_CAPABILITIES, server_bundle, device_bundles)
