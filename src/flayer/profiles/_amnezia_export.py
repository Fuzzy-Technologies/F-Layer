"""Encode private AmneziaVPN connection profiles and native scanner QR frames."""

from __future__ import annotations

import base64
import configparser
import importlib
import io
import ipaddress
import json
import struct
import zlib

from flayer.profiles.artifacts import Artifact
from flayer.profiles.vpn import VpnError

QR_CHUNK_BYTES = 850
QR_MAGIC = 1984


def BuildAmneziaArtifacts(
    client: bytes, host: str, device_id: str, dns_servers: tuple[str, ...],
    *, qr: bool = True,
) -> tuple[Artifact, ...]:
    """Wrap one exact Xray policy without server keys or administration credentials."""

    profile: dict[str, object] = {
        "containers": [{"container": "amnezia-xray", "xray": {
            "last_config": client.decode("utf-8"), "isThirdPartyConfig": True,
        }}],
        "defaultContainer": "amnezia-xray", "hostName": host,
        "description": f"F-Layer VLESS {device_id}",
        "dns1": dns_servers[0], "dns2": dns_servers[1] if len(dns_servers) > 1 else dns_servers[0],
    }

    return _EncodeProfile(profile, qr=qr)


def _EncodeProfile(profile: dict[str, object], *, qr: bool) -> tuple[Artifact, ...]:
    """Encode one native profile and optionally its scanner frames without network access."""

    content = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Qt qCompress prefixes the zlib stream with its uncompressed size in network byte order.
    compressed = struct.pack(">I", len(content)) + zlib.compress(content, level=8)
    encoded = base64.urlsafe_b64encode(compressed).rstrip(b"=")
    artifacts = (Artifact("amnezia.vpn", b"vpn://" + encoded + b"\n"),)

    return artifacts + (_QrArtifacts(compressed) if qr else ())


def _QrArtifacts(compressed: bytes) -> tuple[Artifact, ...]:
    """Render numbered qCompress/QDataStream frames understood by the native scanner."""

    try:
        segno = importlib.import_module("segno")

    except ImportError:
        raise VpnError("Install the f-layer[vpn] extra before exporting AmneziaVPN QR codes") from None

    artifacts: list[Artifact] = []
    chunks = [compressed[index:index + QR_CHUNK_BYTES]
              for index in range(0, len(compressed), QR_CHUNK_BYTES)]

    if len(chunks) > 255:
        raise VpnError("AmneziaVPN profile exceeds the native QR frame limit")

    for index, chunk in enumerate(chunks):
        # QDataStream: qint16 magic, quint8 count/index, then a length-prefixed QByteArray.
        frame = struct.pack(">hBBI", QR_MAGIC, len(chunks), index, len(chunk)) + chunk
        payload = base64.urlsafe_b64encode(frame).rstrip(b"=").decode("ascii")
        output = io.BytesIO()
        segno.make_qr(payload, error="L", boost_error=False).save(
            output, kind="svg", scale=5, border=4, light="white",
        )
        artifacts.append(Artifact(f"amnezia-qr-{index + 1:02d}.svg", output.getvalue()))

    return tuple(artifacts)


def BuildAmneziaQrArtifacts(connection: bytes) -> tuple[Artifact, ...]:
    """Render scanner frames from an existing connection key without changing its profile."""

    try:
        encoded = connection.strip().removeprefix(b"vpn://")

        if not connection.startswith(b"vpn://") or not 1 <= len(encoded) <= 1048576:
            raise ValueError

        compressed = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)

        if base64.urlsafe_b64encode(compressed).rstrip(b"=") != encoded:
            raise ValueError

        return _QrArtifacts(compressed)

    except ValueError:
        raise VpnError("Existing AmneziaVPN connection key is invalid") from None


class _AwgConfigParser(configparser.ConfigParser):
    """Preserve case-sensitive AWG protocol keys rather than ConfigParser normalization."""

    def optionxform(self, optionstr: str) -> str:
        """Honor the parser callback while retaining the external configuration contract."""

        return optionstr


def BuildAmneziaWgArtifacts(client: bytes, device_id: str, *, qr: bool = False) -> tuple[Artifact, ...]:
    """Wrap existing AWG bytes and structured 3.1 fields without issuing or rotating keys."""

    from flayer.profiles.amneziawg import AmneziaWgSettings, _Key, _PublicKey
    from flayer.profiles.vpn import VpnEndpoint, VpnRoutes

    obfuscation = (
        "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
        "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition",
        "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
        "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
    )

    try:
        parser = _AwgConfigParser(interpolation=None, strict=True)
        parser.read_string(client.decode("utf-8"))

        if set(parser.sections()) != {"Interface", "Peer"} or parser.defaults():
            raise ValueError

        interface, peer = parser["Interface"], parser["Peer"]
        required = {"PrivateKey", "Address", "MTU", "DNS"}

        if not required <= set(interface) or set(interface) - required - set(obfuscation):
            raise ValueError

        if set(peer) != {"PublicKey", "Endpoint", "AllowedIPs", "PersistentKeepalive"}:
            raise ValueError

        host, port = peer["Endpoint"].rsplit(":", 1)
        endpoint = VpnEndpoint(host, int(port))
        routes = tuple(item.strip() for item in peer["AllowedIPs"].split(","))
        dns_servers = tuple(item.strip() for item in interface["DNS"].split(","))
        VpnRoutes("full" if routes == ("0.0.0.0/0",) else "split", routes, dns_servers, "disabled")
        AmneziaWgSettings(mtu=int(interface["MTU"]))
        address = ipaddress.IPv4Interface(interface["Address"])

        if address.network.prefixlen != 32 or not address.ip.is_private or len(dns_servers) > 2:
            raise ValueError

        if not 0 <= int(peer["PersistentKeepalive"]) <= 65535:
            raise ValueError

        private_key = _Key(interface["PrivateKey"])
        public_key = _PublicKey(private_key)
        server_key = _Key(peer["PublicKey"])
        fields: dict[str, object] = {
            "config": client.decode("utf-8"), "hostName": endpoint.host, "port": endpoint.port,
            "client_ip": str(address.ip),
            "client_priv_key": private_key, "client_pub_key": public_key, "clientId": public_key,
            "server_pub_key": server_key, "allowed_ips": list(routes), "mtu": interface["MTU"],
            "persistent_keep_alive": peer["PersistentKeepalive"],
        }
        fields.update({key: interface[key] for key in obfuscation if key in interface})
        last_config = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        profile: dict[str, object] = {
            "containers": [{"container": "amnezia-awg", "awg": {
                "last_config": last_config, "isThirdPartyConfig": True,
            }}],
            "defaultContainer": "amnezia-awg", "hostName": host,
            "description": f"F-Layer AmneziaWG {device_id}",
            "dns1": dns_servers[0], "dns2": dns_servers[1] if len(dns_servers) > 1 else dns_servers[0],
        }

    except (ValueError, KeyError, configparser.Error, UnicodeError):
        raise VpnError("Existing AmneziaWG device configuration is invalid or unsupported") from None

    return _EncodeProfile(profile, qr=qr)
