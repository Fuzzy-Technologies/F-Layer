"""AmneziaWG peer, routing, installer, and secret-isolation contracts without cloud access."""

from __future__ import annotations

import base64
import configparser
import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles.amneziawg import (
    AMNEZIAWG_GO_REVISION,
    AMNEZIAWG_TOOLS_REVISION,
    GO_LINUX_AMD64_SHA256,
    AmneziaWgDeviceKey,
    AmneziaWgSecrets,
    AmneziaWgServiceName,
    AmneziaWgSettings,
    DecodeAmneziaWgSecrets,
    EncodeAmneziaWgSecrets,
    GenerateAmneziaWgSecrets,
    PrepareAmneziaWg,
)
from flayer.profiles.vpn import (
    LoadVpnProfile,
    VpnDevice,
    VpnEndpoint,
    VpnError,
    VpnListener,
    VpnProfile,
    VpnRoutes,
)


def Profile() -> VpnProfile:
    """Create public example intent with two individually routed devices."""

    return VpnProfile(
        StackIdentity("example", "vpn", "yandex", "example-scope", "example-owner"),
        (VpnDevice("laptop", "10.66.0.2"), VpnDevice("phone", "10.66.0.3")),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",)),),
    )


def PreparedFiles(profile: VpnProfile | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """Render private in-memory files; no credentials are written to tracked fixtures."""

    profile = Profile() if profile is None else profile
    prepared = PrepareAmneziaWg(
        profile, VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(),
        GenerateAmneziaWgSecrets(profile),
    )

    return (
        {item.name: item.content.decode() for item in prepared.server_bundle.files},
        {item.name: item.files[0].content.decode() for item in prepared.device_bundles},
    )


def ParseClient(content: str) -> configparser.ConfigParser:
    """Parse native INI transport configuration while preserving protocol key names."""

    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(content)

    return parser


def test_PeersShareOnlyRequiredServerAndObfuscationKeys() -> None:
    """Every client has its own private key while matching the server public identity."""

    server, clients = PreparedFiles()
    laptop = ParseClient(clients["laptop-amneziawg"])
    phone = ParseClient(clients["phone-amneziawg"])
    interface, peers = server["server.conf"].split("\n[Peer]", 1)
    server_config = ParseClient(interface)

    assert laptop["Interface"]["PrivateKey"] != phone["Interface"]["PrivateKey"]
    assert laptop["Interface"]["PrivateKey"] not in server["server.conf"]
    assert phone["Interface"]["PrivateKey"] not in server["server.conf"]
    assert server_config["Interface"]["PrivateKey"] not in clients["laptop-amneziawg"]
    assert laptop["Peer"]["PublicKey"] == phone["Peer"]["PublicKey"]
    assert laptop["Interface"]["HeaderProtectionKey"] == server_config["Interface"]["HeaderProtectionKey"]
    assert "AllowedIPs = 10.66.0.2/32" in peers
    assert "AllowedIPs = 10.66.0.3/32" in peers
    assert laptop["Peer"]["Endpoint"] == "vpn.example.com:51820"


def test_RepeatedPreparationPreservesExactBytesAndRedactsRepr() -> None:
    """Immutable public intent plus explicit secrets produces identical bundles."""

    profile = Profile()
    values = GenerateAmneziaWgSecrets(profile)
    arguments = (profile, VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(), values)
    first = PrepareAmneziaWg(*arguments)
    second = PrepareAmneziaWg(*arguments)

    assert first == second
    assert values.server_private_key not in repr(values)
    assert values.header_protection_key not in repr(first)
    assert values.device_private_keys[0].private_key not in repr(values.device_private_keys[0])
    assert all(item.sensitive for item in first.server_bundle.files)


def test_DeviceRotationAndRemovalDoNotReissueUnchangedPeers() -> None:
    """Explicit rotation revokes one peer while stable devices and server keep identities."""

    profile = Profile()
    original = GenerateAmneziaWgSecrets(profile)
    rotated = GenerateAmneziaWgSecrets(profile, original, rotate_device_ids=("phone",))
    smaller = replace(profile, devices=profile.devices[:1])
    removed = GenerateAmneziaWgSecrets(smaller, rotated)

    assert original.server_private_key == rotated.server_private_key == removed.server_private_key
    assert original.header_protection_key == removed.header_protection_key
    assert original.device_private_keys[0] == rotated.device_private_keys[0]
    assert original.device_private_keys[1] != rotated.device_private_keys[1]
    assert removed.device_private_keys == original.device_private_keys[:1]


def test_AddDeviceRetainsExistingIdentities() -> None:
    """Adding an explicitly addressed device changes only its new credential."""

    profile = Profile()
    previous = GenerateAmneziaWgSecrets(profile)
    expanded = replace(profile, devices=profile.devices + (VpnDevice("tablet", "10.66.0.4"),))
    current = GenerateAmneziaWgSecrets(expanded, previous)

    assert current.device_private_keys[:2] == previous.device_private_keys
    assert current.device_private_keys[2].device_id == "tablet"


def test_SplitAndFullPoliciesHaveNoUnreachableIpv6Route() -> None:
    """Client routes and server forwarding both reflect the same bounded IPv4 policy."""

    profile = replace(Profile(), routes=VpnRoutes(
        "split", ("10.90.0.0/16", "1.1.1.1/32"), ("1.1.1.1",), "disabled",
    ))
    server, clients = PreparedFiles(profile)

    for content in clients.values():
        client = ParseClient(content)
        assert client["Peer"]["AllowedIPs"] == "10.90.0.0/16, 1.1.1.1/32"
        assert "::/0" not in content
        assert "0.0.0.0/0" not in content

    assert "ip daddr { 10.90.0.0/16, 1.1.1.1/32 }" in server["firewall.nft"]
    assert "169.254.0.0/16" in server["firewall.nft"], "Guest metadata must be unreachable through the tunnel"
    assert "flush ruleset" not in server["firewall.nft"]
    assert "masquerade" in server["firewall.nft"]


def test_InstallerUsesPinnedSourcesOwnedPathsAndNoPrivateKeys() -> None:
    """Provisioning code pins dependencies and never embeds or prints credential values."""

    profile = Profile()
    values = GenerateAmneziaWgSecrets(profile)
    prepared = PrepareAmneziaWg(profile, VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(), values)
    files = {item.name: item.content.decode() for item in prepared.server_bundle.files}
    installer = files["install.sh"]

    for content in (installer, files["network.sh"], files["service.service"], files["firewall.nft"]):
        assert values.server_private_key not in content
        assert values.header_protection_key not in content

    assert AMNEZIAWG_GO_REVISION in installer
    assert AMNEZIAWG_TOOLS_REVISION in installer
    assert GO_LINUX_AMD64_SHA256 in installer
    assert "sha256sum --check --status" in installer
    assert "GOTOOLCHAIN=local" in installer
    assert "-mod=readonly" in installer
    assert "trap Rollback ERR" in installer
    assert "--remove)" in installer and "--check)" in installer
    assert "set -x" not in installer
    assert "Restart=on-failure" in files["service.service"]
    assert installer.index("Replacement requires an explicit expected deployment receipt") < installer.index("apt-get -q update")
    assert 'if Check; then exit 0; fi' in installer


def test_GeneratedShellParsesWithoutExecutingGuestOperations() -> None:
    """Validate real installer shell grammar without contacting infrastructure."""

    server, _ = PreparedFiles()

    for name in ("install.sh", "network.sh"):
        result = subprocess.run(["bash", "-n"], input=server[name], text=True, capture_output=True)
        assert result.returncode == 0, f"Generated {name} must parse as bash: {result.stderr}"


def test_OwnershipChangesSeparateGuestServices() -> None:
    """Same stack display name in another account cannot select the first account's files."""

    profile = Profile()
    other = replace(profile, identity=replace(profile.identity, scope_id="another-example-scope"))

    assert AmneziaWgServiceName(profile) != AmneziaWgServiceName(other)
    assert AmneziaWgServiceName(profile) == AmneziaWgServiceName(replace(profile, devices=profile.devices[:1]))


@pytest.mark.parametrize("address", ["10.66.0.0", "10.66.0.1", "10.66.0.255", "10.67.0.2"])
def test_InvalidPeerSubnetAddressIsRejected(address: str) -> None:
    """Network, server, broadcast, and outside-subnet addresses never enter server files."""

    profile = replace(Profile(), devices=(VpnDevice("laptop", address),))

    with pytest.raises(VpnError, match="usable nonserver"):
        PrepareAmneziaWg(profile, VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(), GenerateAmneziaWgSecrets(profile))


@pytest.mark.parametrize("cidr", ["::/64", "8.8.8.0/24", "10.66.0.2/24", "10.0.0.0/8", "10.66.0.0/30"])
def test_InvalidTunnelNetworkIsRejected(cidr: str) -> None:
    """Only bounded private IPv4 subnets are supported by the guest installer."""

    with pytest.raises(VpnError, match="RFC1918"):
        AmneziaWgSettings(cidr)


@pytest.mark.parametrize("mtu", [True, 0, 1279, 1381, "1280"])
def test_InvalidMtuIsRejected(mtu: object) -> None:
    """Unsafe or coerced packet-size choices fail before configuration generation."""

    with pytest.raises(VpnError, match="MTU"):
        AmneziaWgSettings(mtu=mtu)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["", "not-a-key", base64.b64encode(bytes(32)).decode(), "A" * 44])
def test_InvalidSecretsAreRejectedWithoutDisclosure(value: str) -> None:
    """Malformed credential errors contain the invariant rather than rejected key bytes."""

    with pytest.raises(VpnError, match="32-byte base64") as caught:
        AmneziaWgDeviceKey("laptop", value)

    assert not value or value not in str(caught.value)


def test_SecretDeviceSetAndListenerMustMatchPublicIntent() -> None:
    """Stale secrets, wrong endpoints, and TCP ingress cannot produce an AWG bundle."""

    profile = Profile()
    values = GenerateAmneziaWgSecrets(profile)

    with pytest.raises(VpnError, match="match exactly"):
        PrepareAmneziaWg(replace(profile, devices=profile.devices[:1]), VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(), values)

    with pytest.raises(VpnError, match="matching UDP"):
        PrepareAmneziaWg(profile, VpnEndpoint("vpn.example.com", 51821), AmneziaWgSettings(), values)

    with pytest.raises(VpnError, match="matching UDP"):
        PrepareAmneziaWg(replace(profile, listeners=(replace(profile.listeners[0], protocol="tcp"),)), VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(), values)


def test_KeysAndRotationAreStrictlyBounded() -> None:
    """Credential reuse across identities and unknown rotation targets are refused."""

    profile = Profile()
    values = GenerateAmneziaWgSecrets(profile)

    with pytest.raises(VpnError, match="distinct"):
        AmneziaWgSecrets(values.server_private_key, values.server_private_key, values.device_private_keys)

    with pytest.raises(VpnError, match="currently declared"):
        GenerateAmneziaWgSecrets(profile, values, rotate_device_ids=("missing",))

    with pytest.raises(VpnError, match="1..16 unique"):
        replace(values, device_private_keys=(values.device_private_keys[0],) * 2)


def test_PrivateMaterialRoundTripsForDeferredEndpointPreparation() -> None:
    """Controller material preserves all identities before the cloud endpoint is known."""

    values = GenerateAmneziaWgSecrets(Profile())
    content = EncodeAmneziaWgSecrets(values)

    assert DecodeAmneziaWgSecrets(content) == values
    assert EncodeAmneziaWgSecrets(DecodeAmneziaWgSecrets(content)) == content
    assert len(content) < 16384


@pytest.mark.parametrize("content", [b"", b"x" * 16385, b"[]", b"null", b"\xff", b'{"schema_version":1,"schema_version":1}'])
def test_InvalidPrivateMaterialDoesNotEchoCredentials(content: bytes) -> None:
    """Malformed, oversized, nonobject, and duplicate-key material fails without disclosure."""

    with pytest.raises(VpnError, match="invalid or unsupported"):
        DecodeAmneziaWgSecrets(content)


def test_PrivateMaterialRejectsUnknownFieldsAndBooleanSchemaVersion() -> None:
    """Material schemas cannot silently ignore unsupported secret-bearing fields."""

    data = json.loads(EncodeAmneziaWgSecrets(GenerateAmneziaWgSecrets(Profile())))
    data["schema_version"] = True

    with pytest.raises(VpnError, match="invalid or unsupported"):
        DecodeAmneziaWgSecrets(json.dumps(data).encode())

    data["schema_version"] = 1
    data["device_private_keys"][0]["unexpected"] = "sensitive-example-value"

    with pytest.raises(VpnError, match="invalid or unsupported") as caught:
        DecodeAmneziaWgSecrets(json.dumps(data).encode())

    assert "sensitive-example-value" not in str(caught.value)


def test_PublicExampleCanPrepareSeparateDeviceImports() -> None:
    """The tracked secret-free example remains compatible with the supported public schema."""

    path = Path(__file__).resolve().parents[2] / "examples/vpn/amneziawg.toml"
    profile = LoadVpnProfile(path)
    prepared = PrepareAmneziaWg(
        profile, VpnEndpoint("vpn.example.com", 51820), AmneziaWgSettings(),
        GenerateAmneziaWgSecrets(profile),
    )

    assert {item.name for item in prepared.device_bundles} == {"laptop-amneziawg", "phone-amneziawg"}
