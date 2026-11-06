"""Verify per-protocol membership cannot change unrelated intent or credential ownership."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_wireguard import Profile

from flayer.profiles.vpn import VpnDevice, VpnError, VpnListener
from flayer.profiles.wireguard import (
    GenerateWireGuardMaterial,
    RenderWireGuardServer,
    WireGuardSettings,
)
from flayer.vpn_selection import ParseProtocolSelections, VpnProtocolSelection


def test_ProjectionExcludesOtherDevicesAndListeners() -> None:
    """Keep existing per-transport hashes and bytes stable across unrelated global changes."""

    selection = VpnProtocolSelection("wireguard", ("phone",), (("phone", "10.67.0.3"),))
    original = Profile()
    before = selection.Project(original)
    changed = replace(original, devices=(*original.devices, VpnDevice("tablet", "10.68.0.2")),
                      listeners=(*original.listeners, VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))))
    after = selection.Project(changed)
    material = GenerateWireGuardMaterial(before, WireGuardSettings())

    assert before.Fingerprint() == after.Fingerprint()
    assert RenderWireGuardServer(before, WireGuardSettings(), material) == RenderWireGuardServer(after, WireGuardSettings(), material)
    assert after.devices == (VpnDevice("phone", "10.67.0.3"),)


def test_VlessProjectionExcludesAwgAddresses() -> None:
    """Do not bind a proxy device's fingerprint to another tunnel's assigned IP."""

    selection = VpnProtocolSelection("vless-reality", ("phone",))
    original = replace(Profile(), listeners=(VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),))
    changed = replace(original, devices=(VpnDevice("phone", "10.66.0.9"),))

    assert selection.Project(original).Fingerprint() == selection.Project(changed).Fingerprint()
    assert selection.Project(changed).devices == (VpnDevice("phone"),)


def test_SelectionOrderIsCanonicalWithoutReassigningAddresses() -> None:
    """Normalize only ordering while retaining explicit stable device/address associations."""

    first = VpnProtocolSelection("wireguard", ("phone", "laptop"), (("phone", "10.67.0.3"), ("laptop", "10.67.0.2")))
    second = VpnProtocolSelection("wireguard", ("laptop", "phone"), (("laptop", "10.67.0.2"), ("phone", "10.67.0.3")))

    assert first == second
    assert first.Project(Profile()).devices == (VpnDevice("laptop", "10.67.0.2"), VpnDevice("phone", "10.67.0.3"))


@pytest.mark.parametrize("members,addresses", [
    ((), ()), (("phone", "phone"), (("phone", "10.67.0.3"),)),
    (("phone",), ()), (("phone",), (("tablet", "10.67.0.3"),)),
    (("phone", "laptop"), (("phone", "10.67.0.3"), ("laptop", "10.67.0.3"))),
    (("phone",), (("phone", "198.51.100.20"),)),
])
def test_AddressMembershipMustBeExactAndPrivate(members: tuple[str, ...], addresses: tuple[tuple[str, str], ...]) -> None:
    """Reject missing, duplicate, foreign and public peer assignments without allocating a replacement."""

    with pytest.raises(VpnError):
        VpnProtocolSelection("wireguard", members, addresses)


def test_UndeclaredMemberCannotBeEnrolledByProjection() -> None:
    """A protocol member must exist in the global device registry before preparation."""

    with pytest.raises(VpnError, match="explicitly declared"):
        VpnProtocolSelection("wireguard", ("tablet",), (("tablet", "10.67.0.4"),)).Project(Profile())


def test_AwgAndVlessRejectAdditionalTunnelAddressMaps() -> None:
    """Keep AWG's legacy address field and the proxy's absence of tunnel addressing unambiguous."""

    for protocol in ("amneziawg", "vless-reality"):
        with pytest.raises(VpnError, match="AWG uses"):
            VpnProtocolSelection(protocol, ("phone",), (("phone", "10.67.0.3"),))


def test_AwgMembersRequireOnlyTheirOwnAssignedAddresses() -> None:
    """An unrelated registry entry without an AWG address must not block this AWG membership."""

    profile = replace(Profile(), devices=(VpnDevice("phone", "10.66.0.2"), VpnDevice("tablet")),
                      listeners=(VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",)),))

    assert VpnProtocolSelection("amneziawg", ("phone",)).Project(profile).devices == (VpnDevice("phone", "10.66.0.2"),)

    with pytest.raises(VpnError, match="explicit device IPv4"):
        VpnProtocolSelection("amneziawg", ("tablet",)).Project(profile)


@pytest.mark.parametrize("protocols,tables", [
    ([], {}), (["wireguard", "wireguard"], {}), (["unknown"], {}),
    (["wireguard"], {}), (["wireguard"], {"wireguard": {}, "vless-reality": {}}),
    (["wireguard"], {"wireguard": {"device_ids": "phone"}}),
    (["wireguard"], {"wireguard": {"device_ids": ["phone"], "device_addresses": []}}),
    (["wireguard"], {"wireguard": {"device_ids": ["phone"], "device_addresses": {"phone": 2}}}),
])
def test_ParserRejectsAmbiguousSelection(protocols: object, tables: dict[str, object]) -> None:
    """Fail before rendering or key generation when selected tables or membership are incomplete."""

    with pytest.raises(VpnError):
        ParseProtocolSelections(protocols, tables, Profile())


def test_ParserUsesFixedProtocolOrderAndExplicitSubsets() -> None:
    """Expose deterministic transport projections regardless of input table or protocol ordering."""

    profile = replace(Profile(), listeners=(*Profile().listeners, VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",))))
    parsed = ParseProtocolSelections(["wireguard", "vless-reality"], {
        "wireguard": {"device_ids": ["phone"], "device_addresses": {"phone": "10.67.0.3"}},
        "vless-reality": {"device_ids": ["laptop"]},
    }, profile)

    assert tuple(selection.protocol for selection in parsed) == ("vless-reality", "wireguard")
    assert parsed[0].Project(profile).devices == (VpnDevice("laptop"),)
    assert parsed[1].Project(profile).devices == (VpnDevice("phone", "10.67.0.3"),)
