"""Verify opt-in VLESS policies without a live server or private device profiles."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError, VpnListener, VpnProfile, VpnRoutes
from flayer.vpn_export import _AllowQuicVlessClient, _FragmentVlessClient


def test_TcpFallbackRecipeKeepsQuicOptIn() -> None:
    """Keep the documented fragment-only export on the ordinary Vision flow by default."""

    options = Parser().parse_args([
        "vpn", "export", "--project", "example-project", "--device", "phone",
        "--protocol", "vless-reality", "--output", "example-tcp-export",
        "--tls-fragment", "--qr",
    ])

    assert options.tlsFragment and options.qr
    assert options.allowQuic is False, "TCP fallback must not silently enable QUIC"


@pytest.mark.parametrize("deviceId", ["phone", "laptop"])
@pytest.mark.parametrize("mode", ["full", "split"])
def test_TcpFallbackBaselineSurvivesNativeProfileAndQr(
    monkeypatch: pytest.MonkeyPatch, deviceId: str, mode: str,
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
    serverBefore = RenderVlessServer(profile, settings, material)
    source = RenderVlessClient(profile, endpoint, settings, material, deviceId)
    original = json.loads(source)
    clientBytes, host = _FragmentVlessClient(source)
    client = json.loads(clientBytes)
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
    }, "The exported fragmentation policy changed"
    assert client["dns"] == {"servers": ["1.1.1.1"], "queryStrategy": "UseIPv4"}
    assert client["routing"] == original["routing"]

    captured: list[str] = []
    originalMakeQr = segno.make_qr

    def Capture(payload: str, **options: object) -> object:
        """Capture the actual scanner bytes while retaining real SVG rendering."""

        captured.append(payload)

        return originalMakeQr(payload, **options)

    monkeypatch.setattr(segno, "make_qr", Capture)
    artifacts = BuildAmneziaArtifacts(clientBytes, host, deviceId, profile.routes.dnsServers, qr=True)
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

    assert envelope["containers"][0]["xray"]["last_config"].encode() == clientBytes, (
        "Native import lost the tested TCP fallback policy"
    )
    assert envelope["dns1"] == envelope["dns2"] == "1.1.1.1"

    client["outbounds"].pop()
    client["outbounds"][0]["streamSettings"].pop("sockopt")

    assert client == original, "Fragment-only export changed existing device or transport policy"
    assert RenderVlessServer(profile, settings, material) == serverBefore

    server = json.loads(serverBefore)

    assert {item["flow"] for item in server["inbounds"][0]["settings"]["clients"]} == {"xtls-rprx-vision"}
    assert server["dns"]["queryStrategy"] == "UseIPv4"
    assert server["outbounds"][0]["settings"]["domainStrategy"] == "UseIPv4"
    assert server["log"] == {"loglevel": "none", "access": "none", "error": "none"}


def Client() -> dict[str, Any]:
    """Create synthetic private policy whose unrelated fields must survive transformation."""

    return {
        "log": {"loglevel": "none"},
        "dns": {"servers": ["1.1.1.1"], "queryStrategy": "UseIPv4"},
        "routing": {"domainStrategy": "IPOnDemand", "rules": [
            {"type": "field", "ip": ["::/0"], "outboundTag": "blocked"},
        ]},
        "outbounds": [{
            "tag": "vpn", "protocol": "vless",
            "settings": {"vnext": [{"address": "vpn.example", "port": 443, "users": [{
                "id": "11111111-1111-4111-8111-111111111111", "encryption": "none",
                "flow": "xtls-rprx-vision",
            }]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "www.example.org", "publicKey": "fixture-public-key", "shortId": "01234567",
            }, "sockopt": {"tcpFastOpen": False}},
        }, {"tag": "blocked", "protocol": "blackhole"}],
    }


def ChangedClient(path: tuple[str | int, ...], value: object) -> bytes:
    """Replace one fixture field so malformed-shape cases stay independent of the parser."""

    if not path:
        return json.dumps(value).encode()

    data = Client()
    cursor: Any = data

    for part in path[:-1]:
        cursor = cursor[part]

    cursor[path[-1]] = value

    return json.dumps(data).encode()


@pytest.mark.parametrize("transform", [_AllowQuicVlessClient, _FragmentVlessClient])
@pytest.mark.parametrize("path,value", [
    ((), []),
    (("outbounds",), None),
    (("outbounds",), [False]),
    (("outbounds",), []),
    (("outbounds", 0, "tag"), None),
    (("outbounds", 1, "tag"), "vpn"),
    (("outbounds", 1, "tag"), ["fixture-secret"]),
    (("outbounds", 0, "streamSettings"), None),
    (("outbounds", 0, "streamSettings", "network"), "ws"),
    (("outbounds", 0, "streamSettings", "security"), "tls"),
    (("outbounds", 0, "streamSettings", "realitySettings"), []),
    (("outbounds", 0, "streamSettings", "sockopt"), None),
    (("outbounds", 0, "streamSettings", "sockopt"), {"dialerProxy": "fixture-secret"}),
    (("outbounds", 0, "proxySettings"), {"tag": "fixture-secret"}),
    (("outbounds", 0, "settings"), None),
    (("outbounds", 0, "settings", "vnext"), {}),
    (("outbounds", 0, "settings", "vnext"), []),
    (("outbounds", 0, "settings", "vnext"), [None]),
    (("outbounds", 0, "settings", "vnext", 0, "address"), []),
    (("outbounds", 0, "settings", "vnext", 0, "address"), "fixture-secret@host"),
    (("outbounds", 0, "settings", "vnext", 0, "port"), True),
    (("outbounds", 0, "settings", "vnext", 0, "port"), 65536),
    (("outbounds", 0, "settings", "vnext", 0, "users"), {}),
    (("outbounds", 0, "settings", "vnext", 0, "users"), []),
    (("outbounds", 0, "settings", "vnext", 0, "users"), [None]),
    (("outbounds", 0, "settings", "vnext", 0, "users", 0, "id"), None),
    (("outbounds", 0, "settings", "vnext", 0, "users", 0, "encryption"), "fixture-secret"),
    (("outbounds", 0, "settings", "vnext", 0, "users", 0, "flow"), "fixture-secret"),
    (("outbounds", 0, "settings", "vnext", 0, "users", 0, "flow"), ["fixture-secret"]),
])
def test_TransportOptionsRejectMalformedAndChainedClients(
    transform: Callable[[bytes], tuple[bytes, str]], path: tuple[str | int, ...], value: object,
) -> None:
    """Fail closed for unsupported shapes and proxy chains with a fixed private-safe message."""

    with pytest.raises(VpnError, match="one unchained") as caught:
        transform(ChangedClient(path, value))

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("transform", [_AllowQuicVlessClient, _FragmentVlessClient])
@pytest.mark.parametrize("client", [b"fixture-secret", b"\xff", b"[" * 2000])
def test_InvalidJsonNeverEscapesAsPrivateParserDiagnostics(
    transform: Callable[[bytes], tuple[bytes, str]], client: bytes,
) -> None:
    """Bound malformed UTF-8, syntax and nesting failures behind the export error contract."""

    with pytest.raises(VpnError, match="one unchained") as caught:
        transform(client)

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("transform", [_AllowQuicVlessClient, _FragmentVlessClient])
def test_AmbiguousOutboundAndDeviceSelectionsAreRejected(
    transform: Callable[[bytes], tuple[bytes, str]],
) -> None:
    """Do not guess which endpoint or device credential should receive an option."""

    for case in ("outbound", "endpoint", "user"):
        client = Client()

        if case == "outbound":
            second = json.loads(json.dumps(client["outbounds"][0]))
            second["tag"] = "other-vpn"
            client["outbounds"].append(second)

        elif case == "endpoint":
            client["outbounds"][0]["settings"]["vnext"] *= 2

        else:
            client["outbounds"][0]["settings"]["vnext"][0]["users"] *= 2

        with pytest.raises(VpnError, match="one unchained"):
            transform(json.dumps(client).encode())


def test_FragmentTagCollisionDoesNotPreventIndependentQuicSelection() -> None:
    """Reserve the helper tag only when fragmentation actually adds that outbound."""

    original = Client()
    original["outbounds"].append({"tag": "tls-fragment", "protocol": "freedom"})
    encoded = json.dumps(original).encode()

    with pytest.raises(VpnError, match="unused tls-fragment"):
        _FragmentVlessClient(encoded)

    result, host = _AllowQuicVlessClient(encoded)
    expected = json.loads(encoded)
    expected["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision-udp443"

    assert json.loads(result) == expected and host == "vpn.example"


@pytest.mark.parametrize("tlsFragment,allowQuic", [(False, True), (True, False), (True, True)])
def test_DerivedClientChangesOnlySelectedTransportPolicy(tlsFragment: bool, allowQuic: bool) -> None:
    """Retain complete identity, DNS, routes and existing socket options when composing flags."""

    original = Client()
    encoded = json.dumps(original).encode()
    client = encoded

    if allowQuic:
        client, host = _AllowQuicVlessClient(client)

    if tlsFragment:
        client, host = _FragmentVlessClient(client)

    result = json.loads(client)

    assert host == "vpn.example"
    assert result["dns"] == original["dns"] and result["routing"] == original["routing"]
    assert result["outbounds"][0]["streamSettings"]["sockopt"]["tcpFastOpen"] is False

    if tlsFragment:
        assert result["outbounds"].pop()["settings"]["fragment"] == {
            "packets": "tlshello", "length": "100-200", "interval": "10-20",
        }
        assert result["outbounds"][0]["streamSettings"]["sockopt"].pop("dialerProxy") == "tls-fragment"

    if allowQuic:
        users = result["outbounds"][0]["settings"]["vnext"][0]["users"]

        assert users[0]["flow"] == "xtls-rprx-vision-udp443"

        users[0]["flow"] = "xtls-rprx-vision"

    assert result == original, "Unselected authentication or client policy changed"


@pytest.mark.parametrize("tlsFragment,allowQuic", [(False, False), (False, True), (True, False), (True, True)])
@pytest.mark.parametrize("binaryEnvironment", ["FLAYER_XRAY_BINARY", "FLAYER_LEGACY_XRAY_BINARY"])
def test_RealPinnedXrayAcceptsDerivedClientSyntax(
    tmp_path: Path, tlsFragment: bool, allowQuic: bool, binaryEnvironment: str,
) -> None:
    """Exercise actual parser compatibility without starting a tunnel or contacting a guest."""

    binary = os.environ.get(binaryEnvironment)

    if not binary:
        pytest.skip("The checksum-pinned isolated Xray binary is supplied by Linux CI")

    profile = VpnProfile(
        StackIdentity("example", "vpn", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone"),), VpnRoutes(),
        (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),),
    )
    settings = VlessRealitySettings("www.example.org", "www.example.org")
    material = GenerateVlessMaterial(profile)
    client = RenderVlessClient(profile, VpnEndpoint("198.51.100.20", 443), settings, material, "phone")

    if allowQuic:
        client, _ = _AllowQuicVlessClient(client)

    if tlsFragment:
        client, _ = _FragmentVlessClient(client)

    config = tmp_path / "client.json"
    config.write_bytes(client)
    observed = subprocess.run([binary, "run", "-test", "-config", str(config)],
                              capture_output=True, check=False, timeout=15)

    assert observed.returncode == 0, "Pinned Xray rejected the generated opt-in client configuration"
