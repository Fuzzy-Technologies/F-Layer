"""Deterministic VPN routing, ownership, sensitivity, and replacement boundaries."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.core.state import ParseState, StateError
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactError,
    RemoveArtifactBundle,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import (
    MAX_VPN_PROFILE_BYTES,
    BuildVpnDeviceBundle,
    BuildVpnServerBundle,
    LoadVpnProfile,
    ParseVpnProfile,
    PreparedVpnTransport,
    ValidateVpnReplacement,
    ValidateVpnTransport,
    VpnCapabilities,
    VpnDevice,
    VpnEndpoint,
    VpnError,
    VpnListener,
    VpnProfile,
    VpnRoutes,
)

IDENTITY = StackIdentity("example", "vpn", "example-cloud", "example-scope", "example-owner")
CAPABILITIES = VpnCapabilities("tunnel", "ip-tunnel", ("full", "split"))
PAYLOAD = b"fixture-only-private-payload"


def Profile() -> VpnProfile:
    """Build public intent for two independently named transports and two devices."""

    return VpnProfile(
        IDENTITY, (VpnDevice("laptop", "10.70.0.2"), VpnDevice("phone", "10.70.0.3")),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("tunnel", "udp", 51820, ("0.0.0.0/0",)),
         VpnListener("proxy", "tcp", 443, ("0.0.0.0/0",))),
    )


def ProfileData() -> dict[str, Any]:
    """Convert known public dataclass intent to TOML-compatible mutable test data."""

    return json.loads(json.dumps(asdict(Profile())))


def Prepared(
    profile: VpnProfile | None = None, *, payload: bytes = PAYLOAD,
    capabilities: VpnCapabilities = CAPABILITIES,
) -> PreparedVpnTransport:
    """Prepare opaque fixture artifacts without generating credentials or contacting a guest."""

    profile = profile or Profile()
    transport = capabilities.transport

    return PreparedVpnTransport(
        profile, capabilities,
        BuildVpnServerBundle(profile, transport, (Artifact("server.json", payload),)),
        tuple(BuildVpnDeviceBundle(
            profile, transport, device.device_id, (Artifact("client.conf", payload),),
        ) for device in profile.devices),
    )


def test_ProfileRemainsTransportAndProviderNeutral() -> None:
    """Accept independent tunnel/proxy consumers without embedding product or provider behavior."""

    profile = Profile()
    parsed = ParseVpnProfile(ProfileData())
    proxy = VpnCapabilities("proxy", "application-proxy", ("full", "split"))

    assert parsed == profile, "Public profile parsing must preserve exact declared intent"
    assert ValidateVpnTransport(profile, CAPABILITIES).protocol == "udp"
    assert ValidateVpnTransport(profile, proxy).protocol == "tcp"
    assert profile.Fingerprint() == parsed.Fingerprint()
    assert Prepared(capabilities=proxy).capabilities.network_mode == "application-proxy"
    assert PAYLOAD.decode() not in json.dumps(asdict(profile))


@pytest.mark.parametrize("changes", [
    {"mode": "unknown"}, {"mode": []}, {"ipv4_cidrs": []}, {"ipv4_cidrs": ()},
    {"ipv4_cidrs": ("10.0.0.0/8",)}, {"ipv4_cidrs": ("::/0",)},
    {"ipv4_cidrs": ("10.0.0.1/24",)}, {"ipv4_cidrs": (123,)},
    {"ipv4_cidrs": ("0.0.0.0/0", "10.0.0.0/8")},
    {"mode": "split"}, {"mode": "split", "ipv4_cidrs": ("0.0.0.0/1", "128.0.0.0/1")},
    {"ipv6_policy": "allow"}, {"ipv6_policy": "block"}, {"ipv6_policy": False},
    {"dns_servers": []}, {"dns_servers": ()}, {"dns_servers": ("1.1.1.1",) * 5},
    {"dns_servers": ("1.1.1.1", "1.1.1.1")}, {"dns_servers": ("::1",)},
    {"dns_servers": ("localhost",)}, {"dns_servers": (False,)},
    {"dns_servers": ("0.0.0.0",)}, {"dns_servers": ("127.0.0.1",)},
    {"dns_servers": ("169.254.169.254",)}, {"dns_servers": ("255.255.255.255",)},
    {"dns_servers": ("224.0.0.1",)},
])
def test_RoutesRejectAmbiguousOrUnreachableIntent(changes: dict[str, Any]) -> None:
    """Never silently broaden routing, coerce types, or advertise unavailable address families."""

    with pytest.raises(VpnError):
        replace(Profile().routes, **changes)


def test_SplitRoutesRequireDnsReachability() -> None:
    """Keep DNS resolution inside the explicitly authorized route set."""

    routes = VpnRoutes("split", ("10.0.0.0/8", "1.1.1.1/32"), ("1.1.1.1",), "disabled")

    assert routes.ipv4_cidrs == ("10.0.0.0/8", "1.1.1.1/32")

    with pytest.raises(VpnError, match="DNS addresses must be reachable"):
        replace(routes, ipv4_cidrs=("10.0.0.0/8",))


@pytest.mark.parametrize("address", ["1.1.1.1", "10.0.0.2/32", "::1", 123])
def test_DeviceAddressesAreExplicitPrivateIpv4(address: Any) -> None:
    """Reject public, malformed, and unsupported per-device address assignments."""

    with pytest.raises(VpnError):
        VpnDevice("laptop", address)


def test_ProxyDevicesMayOmitTunnelAddresses() -> None:
    """An application proxy must not invent an operating-system tunnel address."""

    profile = replace(Profile(), devices=(VpnDevice("laptop"),))
    proxy = VpnCapabilities("proxy", "application-proxy", ("full",))

    assert ValidateVpnTransport(profile, proxy).transport == "proxy"

    with pytest.raises(VpnError, match="explicit private IPv4"):
        ValidateVpnTransport(profile, CAPABILITIES)


@pytest.mark.parametrize("host", [
    "::1", "https://example.org", "localhost", "test.localhost", "EXAMPLE.org", "-bad.org",
    "bad-.org", "example..org", "example.org.", "bad;command", "999.1.1.1", "127.0.0.1", 123,
])
def test_EndpointsRejectInjectionAndUnsupportedAddresses(host: Any) -> None:
    """Require a structured endpoint instead of a shell command, URL, or IPv6 destination."""

    with pytest.raises(VpnError):
        VpnEndpoint(host, 443)


def test_EndpointsAcceptPublicDnsAndIpv4() -> None:
    """Leave actual endpoint resolution and reachability checks to runtime adapters."""

    assert VpnEndpoint("vpn.example.org", 443).host == "vpn.example.org"
    assert VpnEndpoint("203.0.113.10", 443).host == "203.0.113.10"


@pytest.mark.parametrize("port", [True, 0, 65536, "443"])
def test_ListenerAndEndpointPortsRejectCoercion(port: Any) -> None:
    """A boolean or numeric string must not become a network port by accident."""

    with pytest.raises(VpnError):
        VpnListener("tunnel", "udp", port, ("0.0.0.0/0",))

    with pytest.raises(VpnError):
        VpnEndpoint("vpn.example.org", port)


@pytest.mark.parametrize("changes", [
    {"transport": "bad/name"}, {"protocol": "all"}, {"protocol": []},
    {"source_cidrs": ("::/0",)}, {"source_cidrs": ("0.0.0.0/0",) * 17},
])
def test_ListenersRequireBoundedPublicIngress(changes: dict[str, Any]) -> None:
    """Do not expand malformed transport intent into provider firewall rules."""

    with pytest.raises(VpnError):
        replace(Profile().listeners[0], **changes)


@pytest.mark.parametrize("changes", [
    {"network_mode": "vpn"}, {"network_mode": []}, {"route_modes": ()},
    {"route_modes": ["full"]}, {"route_modes": ("full", "full")},
    {"route_modes": ("unknown",)}, {"route_modes": ([],)},
    {"ipv4": False}, {"ipv4": 1}, {"ipv6": True}, {"ipv6": 0},
])
def test_CapabilitiesDoNotAdvertiseUnsupportedBehavior(changes: dict[str, Any]) -> None:
    """Distinguish proxy scope from IP routing and reject unsupported IPv6 promises."""

    with pytest.raises(VpnError):
        replace(CAPABILITIES, **changes)


@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 2}, {"identity": "example"},
    {"routes": {}}, {"devices": ()}, {"devices": []}, {"devices": ("laptop",)},
    {"devices": (VpnDevice("laptop"),) * 17},
    {"devices": (VpnDevice("laptop"), VpnDevice("laptop"))},
    {"devices": (VpnDevice("laptop", "10.0.0.2"), VpnDevice("phone", "10.0.0.2"))},
    {"listeners": ()}, {"listeners": []}, {"listeners": ("tunnel",)},
    {"listeners": (VpnListener("tunnel", "udp", 51820, ("0.0.0.0/0",)),) * 9},
    {"listeners": (VpnListener("tunnel", "udp", 51820, ("0.0.0.0/0",)),) * 2},
    {"listeners": (VpnListener("one", "udp", 51820, ("0.0.0.0/0",)),
                   VpnListener("two", "udp", 51820, ("0.0.0.0/0",)))},
    {"identity": replace(IDENTITY, stack="s" * 63)},
    {"devices": (VpnDevice("d" * 63),)},
])
def test_ProfileRejectsAmbiguousOrUnboundedComposition(changes: dict[str, Any]) -> None:
    """Keep identities, assigned addresses, listener ports, and artifact names collision-free."""

    with pytest.raises(VpnError):
        replace(Profile(), **changes)


def test_CompoundArtifactNamesCannotCollide() -> None:
    """Hyphens in both device and transport names must not create cross-protocol collisions."""

    with pytest.raises(VpnError, match="ambiguous artifact name"):
        replace(
            Profile(), devices=(VpnDevice("laptop"), VpnDevice("laptop-proxy")),
            listeners=(
                VpnListener("proxy", "tcp", 443, ("0.0.0.0/0",)),
                VpnListener("proxy-proxy", "tcp", 8443, ("0.0.0.0/0",)),
            ),
        )


def test_TransportValidationFailsBeforeArtifactGeneration() -> None:
    """Missing or unsupported transports must not be substituted by a default implementation."""

    with pytest.raises(VpnError):
        ValidateVpnTransport(None, CAPABILITIES)

    with pytest.raises(VpnError):
        ValidateVpnTransport(Profile(), None)

    with pytest.raises(VpnError, match="declared listener"):
        ValidateVpnTransport(Profile(), replace(CAPABILITIES, transport="absent"))

    with pytest.raises(VpnError, match="routing mode"):
        ValidateVpnTransport(Profile(), replace(CAPABILITIES, route_modes=("split",)))


def test_ArtifactsArePrivateAndTransportNamespaced() -> None:
    """Two protocols for one device must have separate sensitive ownership namespaces."""

    tunnel = Prepared()
    proxy = Prepared(capabilities=VpnCapabilities("proxy", "application-proxy", ("full",)))

    assert tunnel.server_bundle.name == "vpn-tunnel"
    assert tunnel.device_bundles[0].name == "laptop-tunnel"
    assert proxy.server_bundle.name == "vpn-proxy"
    assert proxy.device_bundles[0].name == "laptop-proxy"
    assert PAYLOAD.decode() not in repr(tunnel)
    assert PAYLOAD.decode() not in repr(tunnel.server_bundle)
    assert tunnel.Fingerprint() == Prepared().Fingerprint()
    assert tunnel.Fingerprint() != Prepared(payload=b"different-fixture-only-payload").Fingerprint()


def test_ArtifactBuildersRejectForeignDevicesAndPublicPayloads() -> None:
    """An opaque transport payload is always sensitive even when the caller labels it public."""

    for profile, transport in ((None, "tunnel"), (Profile(), "absent")):
        with pytest.raises(VpnError):
            BuildVpnServerBundle(profile, transport, (Artifact("server.json", PAYLOAD),))

    for files in ((), [], ("invalid",), (Artifact("server.json", PAYLOAD, False),)):
        with pytest.raises(VpnError):
            BuildVpnServerBundle(Profile(), "tunnel", files)

    with pytest.raises(VpnError, match="declared device"):
        BuildVpnDeviceBundle(Profile(), "tunnel", "unknown", (Artifact("client.conf", PAYLOAD),))


@pytest.mark.parametrize("case", [
    "server-type", "server-owner", "server-kind", "server-name", "server-sensitivity",
    "clients-mutable", "clients-type", "clients-missing", "clients-duplicate", "client-owner",
    "client-kind", "client-sensitivity",
])
def test_PreparedTransportRejectsIncompleteOrForeignBundles(case: str) -> None:
    """Preparation requires every declared device exactly once and one sensitive owned server."""

    prepared = Prepared()
    server = prepared.server_bundle
    clients: Any = prepared.device_bundles
    foreign = replace(IDENTITY, owner_id="another-owner")

    if case == "server-type":
        server = None

    elif case == "server-owner":
        server = replace(server, identity=foreign)

    elif case == "server-kind":
        server = replace(server, kind="device")

    elif case == "server-name":
        server = replace(server, name="another-stack")

    elif case == "server-sensitivity":
        server = replace(server, files=(Artifact("server.json", PAYLOAD, False),))

    elif case == "clients-mutable":
        clients = list(clients)

    elif case == "clients-type":
        clients = ("invalid",)

    elif case == "clients-missing":
        clients = clients[:1]

    elif case == "clients-duplicate":
        clients = clients + clients[:1]

    elif case == "client-owner":
        clients = (replace(clients[0], identity=foreign), clients[1])

    elif case == "client-kind":
        clients = (replace(clients[0], kind="server"), clients[1])

    elif case == "client-sensitivity":
        clients = (replace(clients[0], files=(Artifact("client.conf", PAYLOAD, False),)), clients[1])

    with pytest.raises(VpnError):
        replace(prepared, server_bundle=server, device_bundles=clients)


def test_ReplacementRequiresExactOldBytesAndOwnership() -> None:
    """Authorize replacement against an exact snapshot without treating it as guest revocation."""

    previous = Prepared()
    replacement = Prepared(replace(Profile(), devices=Profile().devices[:1]), payload=b"new-fixture-only-payload")
    ValidateVpnReplacement(previous, replacement, expected_fingerprint=previous.Fingerprint())

    for expected in ("0" * 64, replacement.Fingerprint(), None):
        with pytest.raises(VpnError, match="expected previous fingerprint"):
            ValidateVpnReplacement(previous, replacement, expected_fingerprint=expected)

    foreign = Prepared(replace(Profile(), identity=replace(IDENTITY, scope_id="other-scope")))
    proxy = Prepared(capabilities=VpnCapabilities("proxy", "application-proxy", ("full",)))

    for different in (foreign, proxy):
        with pytest.raises(VpnError, match="preserve exact stack"):
            ValidateVpnReplacement(previous, different, expected_fingerprint=previous.Fingerprint())

    with pytest.raises(VpnError):
        ValidateVpnReplacement(None, replacement, expected_fingerprint=previous.Fingerprint())

    with pytest.raises(VpnError):
        ValidateVpnReplacement(previous, None, expected_fingerprint=previous.Fingerprint())


def test_ArtifactCleanupCannotOverwriteOrRemoveChangedDeviceFiles(tmp_path: Path) -> None:
    """Existing owned-store checks remain authoritative for replacement and cleanup."""

    prepared = Prepared()
    bundle = prepared.device_bundles[0]
    location = WriteArtifactBundle(tmp_path, bundle)
    manifest = (location / "manifest.json").read_text()

    assert PAYLOAD.decode() not in manifest, "Manifests must contain only digests and ownership"

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(tmp_path, bundle)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(tmp_path, replace(IDENTITY, owner_id="another-owner"), kind="device", name=bundle.name)

    (location / "client.conf").write_bytes(b"operator-modified-fixture")

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(tmp_path, IDENTITY, kind="device", name=bundle.name)

    assert (location / "client.conf").read_bytes() == b"operator-modified-fixture"

    (location / "client.conf").write_bytes(PAYLOAD)
    RemoveArtifactBundle(tmp_path, IDENTITY, kind="device", name=bundle.name)

    assert not location.exists(), "Verified local cleanup must remove only its exact owned bundle"


@pytest.mark.parametrize("field", ["private_key", "token", "credentials", "unknown"])
def test_ParserRejectsInlineSecretsWithoutEchoingThem(field: str) -> None:
    """No profile level may silently accept a credential or unknown setting."""

    original = ProfileData()

    for path in ((), ("routes",), ("devices", 0), ("listeners", 0), ("identity",)):
        data = copy.deepcopy(original)
        table = data

        for key in path:
            table = table[key]

        table[field] = PAYLOAD.decode()

        with pytest.raises(VpnError) as caught:
            ParseVpnProfile(data)

        assert PAYLOAD.decode() not in str(caught.value)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("schema_version",), 2),
    (("routes",), []), (("routes", "mode"), 1), (("routes", "ipv6_policy"), False),
    (("routes", "ipv4_cidrs"), "0.0.0.0/0"), (("routes", "dns_servers"), "1.1.1.1"),
    (("devices",), {}), (("listeners",), {}), (("devices", 0), "laptop"),
    (("listeners", 0), "tunnel"), (("listeners", 0, "protocol"), 123),
    (("listeners", 0, "source_cidrs"), "0.0.0.0/0"),
])
def test_ParserRejectsMalformedStructures(path: tuple[Any, ...], value: Any) -> None:
    """Validate decoded tables before constructing immutable profile objects."""

    data = ProfileData()
    table = data

    for key in path[:-1]:
        table = table[key]

    table[path[-1]] = value

    with pytest.raises(VpnError):
        ParseVpnProfile(data)


def test_ParserAcceptsProxyDevicesWithoutAddresses() -> None:
    """A missing optional address differs from a secret or unknown device property."""

    data = ProfileData()
    del data["devices"][0]["ipv4_address"]

    assert ParseVpnProfile(data).devices[0].ipv4_address is None


def test_GenericStateRejectsVpnCredentialFields() -> None:
    """Transport preparation must not widen persisted infrastructure state to include secrets."""

    data = {"schema_version": 1, "identity": asdict(IDENTITY), "resources": [], "vpn": PAYLOAD.decode()}

    with pytest.raises(StateError) as caught:
        ParseState(data, IDENTITY)

    assert PAYLOAD.decode() not in str(caught.value)


def test_ProfileLoaderBoundsInputAndDoesNotReadCredentials(tmp_path: Path) -> None:
    """Load public TOML locally and fail with value-free errors for malformed or oversized files."""

    path = tmp_path / "vpn.toml"
    path.write_text('''schema_version = 1
[identity]
project = "example"
stack = "vpn"
provider = "example-cloud"
scope_id = "example-scope"
owner_id = "example-owner"
[routes]
mode = "full"
ipv4_cidrs = ["0.0.0.0/0"]
dns_servers = ["1.1.1.1"]
ipv6_policy = "disabled"
[[devices]]
device_id = "laptop"
ipv4_address = "10.70.0.2"
[[listeners]]
transport = "tunnel"
protocol = "udp"
port = 51820
source_cidrs = ["0.0.0.0/0"]
''')

    assert LoadVpnProfile(path).devices[0].device_id == "laptop"

    for content in (b"[invalid", b"\xff", b"x" * (MAX_VPN_PROFILE_BYTES + 1)):
        path.write_bytes(content)

        with pytest.raises(VpnError, match="valid bounded VPN profile"):
            LoadVpnProfile(path)

    with pytest.raises(VpnError, match="valid bounded VPN profile"):
        LoadVpnProfile(tmp_path / "absent.toml")
