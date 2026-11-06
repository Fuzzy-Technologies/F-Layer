"""Verify standard WireGuard key boundaries, retained material and exact peer policy."""

from __future__ import annotations

import base64
import configparser
import json
from dataclasses import dataclass, field, replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError, VpnListener, VpnProfile, VpnRoutes
from flayer.profiles.wireguard import (
    DecodeWireGuardMaterial,
    EncodeWireGuardMaterial,
    GenerateWireGuardMaterial,
    RenderWireGuardClient,
    RenderWireGuardServer,
    WireGuardMaterial,
    WireGuardPeer,
    WireGuardServiceName,
    WireGuardSettings,
)


def Profile(mode: str = "full") -> VpnProfile:
    """Create a transport-specific public profile using documentation-only identities."""

    return VpnProfile(
        StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone", "10.67.0.3"), VpnDevice("laptop", "10.67.0.2")),
        VpnRoutes(mode, ("0.0.0.0/0",) if mode == "full" else ("1.1.1.1/32", "8.8.8.8/32"),
                  ("1.1.1.1", "8.8.8.8"), "disabled"),
        (VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)),),
    )


def PublicKey(privateKey: str) -> str:
    """Independently derive real Curve25519 public bytes for protocol conformance assertions."""

    key = X25519PrivateKey.from_private_bytes(base64.b64decode(privateKey))

    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


@pytest.mark.parametrize("mode", ["full", "split"])
def test_StandardProfilesRetainExactSelectedPolicyAndSecretBoundaries(mode: str) -> None:
    """Keep server/client key roles distinct and exclude all AmneziaWG extension fields."""

    profile = Profile(mode)
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    encoded = EncodeWireGuardMaterial(material)
    restored = DecodeWireGuardMaterial(encoded)
    server = RenderWireGuardServer(profile, settings, restored).decode()
    peers = {peer.deviceId: peer for peer in restored.peers}

    assert restored == material and EncodeWireGuardMaterial(restored) == encoded
    assert server.count("[Peer]") == len(profile.devices)
    assert f"PrivateKey = {material.serverPrivateKey}" in server

    for device in profile.devices:
        peer = peers[device.deviceId]
        client = RenderWireGuardClient(profile, VpnEndpoint("198.51.100.20", 51821), settings,
                                       material, device.deviceId).decode()
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(client)

        assert set(parser.sections()) == {"Interface", "Peer"}
        assert set(parser["Interface"]) == {"privatekey", "address", "dns", "mtu"}
        assert set(parser["Peer"]) == {"publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"}
        assert parser["Interface"]["privatekey"] == peer.privateKey
        assert parser["Interface"]["address"] == f"{device.ipv4Address}/32"
        assert parser["Interface"]["dns"] == ", ".join(profile.routes.dnsServers)
        assert parser["Interface"]["mtu"] == "1280"
        assert parser["Peer"]["endpoint"] == "198.51.100.20:51821"
        assert parser["Peer"]["publickey"] == PublicKey(material.serverPrivateKey)
        assert parser["Peer"]["presharedkey"] == peer.presharedKey
        assert parser["Peer"]["allowedips"] == ", ".join(profile.routes.ipv4Cidrs)
        assert parser["Peer"]["persistentkeepalive"] == "25"
        assert peer.PublicKey == PublicKey(peer.privateKey)
        assert f"PublicKey = {peer.PublicKey}" in server
        assert f"AllowedIPs = {device.ipv4Address}/32" in server
        assert peer.privateKey not in server and material.serverPrivateKey not in client
        assert all(other.privateKey not in client for other in material.peers if other.deviceId != device.deviceId)
        assert peer.privateKey not in repr(material) and peer.presharedKey not in repr(peer)


@pytest.mark.parametrize("deviceId,port", [("unknown", 51821), ("phone", 51820)])
def test_ClientRefusesUnknownDeviceAndMismatchedEndpoint(deviceId: str, port: int) -> None:
    """Reject accidental cross-device exports and endpoint-port substitution."""

    profile = Profile()
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)

    with pytest.raises(VpnError, match="selected device"):
        RenderWireGuardClient(profile, VpnEndpoint("vpn.example", port), settings, material, deviceId)


@pytest.mark.parametrize("endpoint", [
    None, "vpn.example", {"host": "vpn.example", "port": 51821},
    SimpleNamespace(host="vpn.example\nPrivateKey = fixture-secret", port=51821),
], ids=["missing", "string", "mapping", "injected-foreign-object"])
def test_ClientRejectsUnvalidatedEndpointWithoutRenderingCredentials(endpoint: object) -> None:
    """Do not let duck-typed endpoint attributes bypass the validated configuration boundary."""

    profile = Profile()
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)

    with pytest.raises(VpnError, match="validated VpnEndpoint") as caught:
        RenderWireGuardClient(profile, endpoint, settings, material, "phone")  # type: ignore[arg-type]

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("deviceId", [None, ["phone"], "phone\nfixture-secret"], ids=["missing", "list", "injected-name"])
def test_ClientRejectsMalformedDeviceIdentityPrivately(deviceId: object) -> None:
    """Return a fixed validation error before dictionary membership can raise or expose input."""

    profile = Profile()
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)

    with pytest.raises(VpnError, match="device_id") as caught:
        RenderWireGuardClient(profile, VpnEndpoint("vpn.example", 51821), settings, material, deviceId)  # type: ignore[arg-type]

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("network,mtu", [
    ("198.51.100.0/24", 1280), ("10.67.0.1/24", 1280), ("10.67.0.0/29", 1280),
    ("10.0.0.0/8", 1280), ("::/0", 1280), ("10.67.0.0/24", True),
    ("10.67.0.0/24", 575), ("10.67.0.0/24", 1421),
])
def test_SettingsRejectUnsafeNetworkAndMtu(network: str, mtu: int) -> None:
    """Keep tunnel sizing explicit and reject coercion or unsupported address families."""

    with pytest.raises(VpnError, match="canonical RFC1918"):
        WireGuardSettings(network, mtu)


@pytest.mark.parametrize("address", [None, "10.67.0.0", "10.67.0.1", "10.67.0.255", "10.68.0.2"])
def test_InvalidPeerIntentFailsBeforeGeneratingKeys(address: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate assignment rather than issuing credentials for unusable or unrelated addresses."""

    import flayer.profiles.wireguard as wireguard

    profile = replace(Profile(), devices=(VpnDevice("phone", address),))

    def Forbidden() -> str:
        """Detect credential generation before public validation completes."""

        pytest.fail("Invalid WireGuard intent attempted to generate a private key")

    monkeypatch.setattr(wireguard, "_PrivateKey", Forbidden)

    with pytest.raises(VpnError, match="address"):
        GenerateWireGuardMaterial(profile, WireGuardSettings())


def test_WireGuardRejectsTcpListenerBeforeMaterialGeneration() -> None:
    """Do not silently reinterpret a selected TCP port as the standard UDP protocol."""

    profile = replace(Profile(), listeners=(VpnListener("wireguard", "tcp", 51821, ("0.0.0.0/0",)),))

    with pytest.raises(VpnError, match="UDP listener"):
        GenerateWireGuardMaterial(profile, WireGuardSettings())


@pytest.mark.parametrize("case", [
    "duplicate-id", "duplicate-public-key", "duplicate-psk", "psk-is-private", "psk-is-public",
    "psk-is-server-private-alias", "psk-is-other-private-alias",
])
def test_MaterialRejectsSharedOrAmbiguousCredentials(case: str) -> None:
    """Prevent device aliasing and public or reused preshared keys."""

    material = GenerateWireGuardMaterial(Profile(), WireGuardSettings())
    first, second = material.peers

    if case == "duplicate-id":
        second = replace(second, deviceId=first.deviceId)

    elif case == "duplicate-public-key":
        raw = bytearray(base64.b64decode(first.privateKey))
        raw[0] ^= 1
        second = replace(second, privateKey=base64.b64encode(raw).decode())

    elif case == "duplicate-psk":
        second = replace(second, presharedKey=first.presharedKey)

    elif case == "psk-is-private":
        second = replace(second, presharedKey=material.serverPrivateKey)

    elif case in {"psk-is-server-private-alias", "psk-is-other-private-alias"}:
        source = material.serverPrivateKey if case == "psk-is-server-private-alias" else first.privateKey
        raw = bytearray(base64.b64decode(source))
        raw[0] ^= 1
        second = replace(second, presharedKey=base64.b64encode(raw).decode())

        assert second.presharedKey != source and PublicKey(second.presharedKey) == PublicKey(source)

    else:
        second = replace(second, presharedKey=first.PublicKey)

    with pytest.raises(VpnError, match="independent credentials"):
        WireGuardMaterial(material.serverPrivateKey, (first, second))


@pytest.mark.parametrize("case", ["missing", "number", "mapping", "peer", "foreign-dataclass"])
def test_EncoderRejectsOtherCredentialModelsWithoutEcho(case: str) -> None:
    """Never label arbitrary dataclass credentials as a valid WireGuard material document."""

    @dataclass(frozen=True)
    class ForeignCredentials:
        """Represent an unrelated credential model with private fixture-only data."""

        privateKey: str = field(default="fixture-secret", repr=False)

    values: dict[str, object] = {"missing": None, "number": 1, "mapping": {"private_key": "fixture-secret"},
                                "foreign-dataclass": ForeignCredentials()}
    values["peer"] = GenerateWireGuardMaterial(Profile(), WireGuardSettings()).peers[0]

    with pytest.raises(VpnError, match="validated WireGuardMaterial") as caught:
        EncodeWireGuardMaterial(values[case])  # type: ignore[arg-type]

    assert "fixture-secret" not in str(caught.value)


def test_EncoderIncludesOnlySchemaOwnedFieldsFromAMaterialSubclass() -> None:
    """Prevent extra credential fields from silently extending private schema 1."""

    @dataclass(frozen=True, slots=True)
    class ExtendedMaterial(WireGuardMaterial):
        """Carry unrelated fixture-only private metadata that must never enter this codec."""

        administrationSecret: str = field(default="fixture-secret", repr=False)

    material = GenerateWireGuardMaterial(Profile(), WireGuardSettings())
    extended = ExtendedMaterial(material.serverPrivateKey, material.peers)
    encoded = EncodeWireGuardMaterial(extended)

    assert b"fixture-secret" not in encoded and b"administration" not in encoded
    assert DecodeWireGuardMaterial(encoded) == material


@pytest.mark.parametrize("content", [
    b"fixture-secret", b"null", b"[]", b"{}", b'{"schema_version":1,"schema_version":1}',
    b'{"schema_version":true,"server_private_key":"fixture-secret","peers":[]}',
    b"[" * 2000 + b"0" + b"]" * 2000, b"x" * 65537,
], ids=["plain-text", "null", "array", "missing-fields", "duplicate-fields", "boolean-version", "nested-json", "oversize"])
def test_PrivateMaterialDecoderRefusesMalformedPayloadWithoutEcho(content: bytes) -> None:
    """Fail closed on schema ambiguity and oversized or deeply nested private input."""

    with pytest.raises(VpnError, match="invalid or unsupported") as caught:
        DecodeWireGuardMaterial(content)

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("case", ["extra-field", "invalid-server", "invalid-peer", "extra-peer-field", "wrong-schema", "mutable-peer-set"])
def test_MaterialDecoderRejectsCorruptedCompleteDocuments(case: str) -> None:
    """Check semantic corruption after a complete private document has been decoded."""

    payload = json.loads(EncodeWireGuardMaterial(GenerateWireGuardMaterial(Profile(), WireGuardSettings())))

    if case == "extra-field":
        payload["fixture-secret"] = True

    elif case == "invalid-server":
        payload["server_private_key"] = "fixture-secret"

    elif case == "invalid-peer":
        payload["peers"][0]["private_key"] = "fixture-secret"

    elif case == "extra-peer-field":
        payload["peers"][0]["fixture-secret"] = True

    elif case == "wrong-schema":
        payload["schema_version"] = 2

    else:
        payload["peers"] = {"fixture-secret": payload["peers"][0]}

    with pytest.raises(VpnError, match="invalid or unsupported") as caught:
        DecodeWireGuardMaterial(json.dumps(payload).encode())

    assert "fixture-secret" not in str(caught.value)


@pytest.mark.parametrize("value", ["fixture-secret", "", base64.b64encode(bytes(32)).decode(), "!" * 44])
def test_InvalidPeerKeysAreRedacted(value: str) -> None:
    """Never incorporate rejected key bytes into an exception."""

    with pytest.raises(VpnError) as caught:
        WireGuardPeer("phone", value, value)

    assert "fixture-secret" not in str(caught.value)


def test_RetainedMaterialDoesNotBindToDifferentDeviceSelection() -> None:
    """Require explicit enrollment or revocation when selected peer membership changes."""

    profile = Profile()
    material = GenerateWireGuardMaterial(profile, WireGuardSettings())

    with pytest.raises(VpnError, match="exactly its selected devices"):
        RenderWireGuardServer(replace(profile, devices=profile.devices[:1]), WireGuardSettings(), material)

    assert WireGuardServiceName(profile) == WireGuardServiceName(replace(profile, devices=profile.devices[:1]))
    assert WireGuardServiceName(profile) != WireGuardServiceName(replace(
        profile, identity=replace(profile.identity, ownerId="another-owner"),
    ))
    assert json.loads(EncodeWireGuardMaterial(material))["schema_version"] == 1
