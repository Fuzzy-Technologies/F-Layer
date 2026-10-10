"""Encode private AmneziaVPN connection profiles and native scanner QR frames."""

from __future__ import annotations

import base64
import importlib
import io
import json
import struct
import zlib

from flayer.profiles.artifacts import Artifact
from flayer.profiles.vpn import VpnError

QR_CHUNK_BYTES = 850
QR_MAGIC = 1984


def BuildAmneziaArtifacts(
    client: bytes, host: str, device_id: str, dns_servers: tuple[str, ...],
) -> tuple[Artifact, ...]:
    """Wrap one exact Xray policy without server keys or administration credentials."""

    try:
        segno = importlib.import_module("segno")

    except ImportError:
        raise VpnError("Install the f-layer[vpn] extra before exporting AmneziaVPN QR codes") from None

    profile = {
        "containers": [{"container": "amnezia-xray", "xray": {
            "last_config": client.decode("utf-8"), "isThirdPartyConfig": True,
        }}],
        "defaultContainer": "amnezia-xray", "hostName": host,
        "description": f"F-Layer VLESS {device_id}",
        "dns1": dns_servers[0], "dns2": dns_servers[1] if len(dns_servers) > 1 else dns_servers[0],
    }
    content = json.dumps(profile, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Qt qCompress prefixes the zlib stream with its uncompressed size in network byte order.
    compressed = struct.pack(">I", len(content)) + zlib.compress(content, level=8)
    encoded = base64.urlsafe_b64encode(compressed).rstrip(b"=")
    artifacts = [Artifact("amnezia.vpn", b"vpn://" + encoded + b"\n")]
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
