"""Pin the intermediate TCP fallback policy without a live server or private profiles."""

from __future__ import annotations

import base64
import json
import zlib

import pytest
import segno

from flayer.__main__ import Parser
from flayer.core.contracts import StackIdentity
from flayer.profiles._amnezia_export import BuildAmneziaArtifacts
from flayer.profiles.vless import (
    GenerateVlessMaterial,
    RenderVlessClient,
    RenderVlessServer,
    VlessRealitySettings,
)
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnListener, VpnProfile, VpnRoutes
from flayer.vpn_export import _FragmentVlessClient


def test_TcpFallbackRecipeKeepsQuicOptIn() -> None:
    """Keep the documented fragment-only export on the ordinary Vision flow by default."""

    options = Parser().parse_args([
        "vpn", "export", "--project", "example-project", "--device", "phone",
        "--protocol", "vless-reality", "--output", "example-tcp-export",
        "--tls-fragment", "--qr",
    ])

    assert options.tls_fragment and options.qr
    assert options.allow_quic is False, "TCP fallback must not silently enable QUIC"


@pytest.mark.parametrize("device_id", ["phone", "laptop"])
@pytest.mark.parametrize("mode", ["full", "split"])
def test_TcpFallbackBaselineSurvivesNativeProfileAndQr(
    monkeypatch: pytest.MonkeyPatch, device_id: str, mode: str,
) -> None:
    """Retain TCP fallback and exact fragment policy through actual native QR encoding."""

    profile = VpnProfile(
        StackIdentity("example", "vpn", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone"), VpnDevice("laptop")),
        VpnRoutes(mode, ("0.0.0.0/0",) if mode == "full" else ("1.1.1.1/32",),
                  ("1.1.1.1",), "disabled"),
        (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),),
    )
    settings = VlessRealitySettings("www.example.org", "www.example.org")
    material = GenerateVlessMaterial(profile)
    endpoint = VpnEndpoint("198.51.100.20", 443)
    server_before = RenderVlessServer(profile, settings, material)
    source = RenderVlessClient(profile, endpoint, settings, material, device_id)
    original = json.loads(source)
    client_bytes, host = _FragmentVlessClient(source)
    client = json.loads(client_bytes)
    outbound = client["outbounds"][0]

    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision", (
        "TCP fallback must intercept UDP 443 rather than opt into QUIC"
    )
    assert outbound["streamSettings"]["network"] == "tcp"
    assert outbound["streamSettings"]["security"] == "reality"
    assert outbound["streamSettings"]["sockopt"]["dialerProxy"] == "tls-fragment"
    assert client["outbounds"][-1] == {
        "tag": "tls-fragment", "protocol": "freedom",
        "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}},
    }, "The intermediate baseline's fragmentation policy changed"
    assert client["dns"] == {"servers": ["1.1.1.1"], "queryStrategy": "UseIPv4"}
    assert client["routing"] == original["routing"]

    captured: list[str] = []
    original_make_qr = segno.make_qr

    def Capture(payload: str, **options: object) -> object:
        """Capture the actual scanner bytes while retaining real SVG rendering."""

        captured.append(payload)

        return original_make_qr(payload, **options)

    monkeypatch.setattr(segno, "make_qr", Capture)
    artifacts = BuildAmneziaArtifacts(client_bytes, host, device_id, profile.routes.dns_servers, qr=True)
    encoded = artifacts[0].content.strip().removeprefix(b"vpn://")
    compressed = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    chunks: dict[int, bytes] = {}

    for payload in captured:
        frame = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))

        assert int.from_bytes(frame[:2], "big") == 1984
        assert frame[2] == len(captured)
        assert frame[3] not in chunks, "Native QR indexes must be unique"
        assert int.from_bytes(frame[4:8], "big") == len(frame[8:])

        chunks[frame[3]] = frame[8:]

    assert captured and len(artifacts) == len(captured) + 1
    assert b"".join(chunks[index] for index in range(len(chunks))) == compressed
    assert all(b"<svg" in item.content for item in artifacts[1:])

    raw = zlib.decompress(compressed[4:])

    assert len(raw) == int.from_bytes(compressed[:4], "big")

    envelope = json.loads(raw)

    assert envelope["containers"][0]["xray"]["last_config"].encode() == client_bytes, (
        "Native import lost the tested TCP fallback policy"
    )
    assert envelope["dns1"] == envelope["dns2"] == "1.1.1.1"

    client["outbounds"].pop()
    client["outbounds"][0]["streamSettings"].pop("sockopt")

    assert client == original, "Fragment-only export changed existing device or transport policy"
    assert RenderVlessServer(profile, settings, material) == server_before

    server = json.loads(server_before)

    assert {item["flow"] for item in server["inbounds"][0]["settings"]["clients"]} == {"xtls-rprx-vision"}
    assert server["dns"]["queryStrategy"] == "UseIPv4"
    assert server["outbounds"][0]["settings"]["domainStrategy"] == "UseIPv4"
    assert server["log"] == {"loglevel": "none", "access": "none", "error": "none"}
