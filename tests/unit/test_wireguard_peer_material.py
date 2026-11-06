"""Verify deterministic one-peer intent changes preserve all unrelated WireGuard client bytes."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from test_wireguard import Profile

from flayer.profiles import wireguard
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError
from flayer.profiles.wireguard import (
    EncodeWireGuardMaterial,
    GenerateWireGuardMaterial,
    PrepareWireGuardPeerEnrollment,
    PrepareWireGuardPeerRevocation,
    RenderWireGuardClient,
    RenderWireGuardServer,
    WireGuardPeer,
    WireGuardSettings,
)


@pytest.mark.parametrize("mode", ["full", "split"])
def test_EnrollmentAndRevocationRetainAllOtherClientBytesAndSourceMaterial(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Retained enrollment credentials make repeats deterministic; preparation is not live revocation."""

    profile = Profile(mode)
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    before = EncodeWireGuardMaterial(material)
    newDevice = VpnDevice("tablet", "10.67.0.4")
    staged = GenerateWireGuardMaterial(replace(profile, devices=(newDevice,)), settings).peers[0]
    endpoint = VpnEndpoint("198.51.100.20", 51821)
    clients = {device.deviceId: RenderWireGuardClient(profile, endpoint, settings, material, device.deviceId) for device in profile.devices}
    monkeypatch.setattr(wireguard, "_PrivateKey", lambda: pytest.fail("Peer preparation must not generate or rotate any credential"))

    updated, credentials = PrepareWireGuardPeerEnrollment(profile, settings, material, newDevice, staged)

    assert PrepareWireGuardPeerEnrollment(profile, settings, material, newDevice, staged) == (updated, credentials)
    assert credentials.serverPrivateKey == material.serverPrivateKey and EncodeWireGuardMaterial(material) == before
    assert updated.identity == profile.identity and updated.routes == profile.routes and updated.listeners == profile.listeners
    assert {peer.deviceId: peer for peer in credentials.peers} == {**{peer.deviceId: peer for peer in material.peers}, "tablet": staged}

    for device in profile.devices:
        assert RenderWireGuardClient(updated, endpoint, settings, credentials, device.deviceId) == clients[device.deviceId]

    server = RenderWireGuardServer(updated, settings, credentials)
    assert staged.PublicKey.encode() in server and staged.privateKey.encode() not in server
    restored, retained = PrepareWireGuardPeerRevocation(updated, settings, credentials, "tablet")

    assert retained == material and {device.deviceId: device for device in restored.devices} == {device.deviceId: device for device in profile.devices}
    assert RenderWireGuardServer(restored, settings, retained) == RenderWireGuardServer(profile, settings, material)
    assert staged.PublicKey.encode() not in RenderWireGuardServer(restored, settings, retained)
    assert EncodeWireGuardMaterial(material) == before


@pytest.mark.parametrize("fault", ["duplicate-id", "duplicate-address", "server-address", "network-address", "broadcast-address",
                                  "outside-subnet", "missing-address", "mismatched-id", "server-key", "shared-key", "shared-psk", "fake-device", "fake-peer"])
def test_EnrollmentRejectsUnsafeOrAmbiguousOnePeerChangesWithoutRotatingInput(fault: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject credential aliases, existing identities and invalid addresses before preparing output."""

    profile = Profile()
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    before = EncodeWireGuardMaterial(material)
    device: Any = VpnDevice("tablet", "10.67.0.4")
    peer: Any = GenerateWireGuardMaterial(replace(profile, devices=(device,)), settings).peers[0]

    if fault == "duplicate-id":
        device = replace(device, deviceId="phone")
        peer = replace(peer, deviceId="phone")

    elif fault in {"duplicate-address", "server-address", "network-address", "broadcast-address", "outside-subnet", "missing-address"}:
        device = replace(device, ipv4Address={"duplicate-address": "10.67.0.2", "server-address": "10.67.0.1", "network-address": "10.67.0.0",
                                             "broadcast-address": "10.67.0.255", "outside-subnet": "10.68.0.4", "missing-address": None}[fault])

    elif fault == "mismatched-id":
        peer = replace(peer, deviceId="other")

    elif fault in {"server-key", "shared-key", "shared-psk"}:
        peer = WireGuardPeer(peer.deviceId, material.serverPrivateKey if fault == "server-key" else material.peers[0].privateKey if fault == "shared-key" else peer.privateKey,
                             material.peers[0].presharedKey if fault == "shared-psk" else peer.presharedKey)

    elif fault == "fake-device":
        device = object()

    else:
        peer = object()

    monkeypatch.setattr(wireguard, "_PrivateKey", lambda: pytest.fail("Invalid enrollment cannot rotate keys"))

    with pytest.raises(VpnError):
        PrepareWireGuardPeerEnrollment(profile, settings, material, device, peer)

    assert EncodeWireGuardMaterial(material) == before


def test_RevocationCannotSelectAnUnknownDeviceOrRemoveTheFinalPeer() -> None:
    """Deactivation and erasure are distinct operations, never inferred from an empty peer list."""

    profile = Profile()
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    before = EncodeWireGuardMaterial(material)

    with pytest.raises(VpnError, match="existing selected device"):
        PrepareWireGuardPeerRevocation(profile, settings, material, "unknown")

    remaining, retained = PrepareWireGuardPeerRevocation(profile, settings, material, "phone")

    with pytest.raises(VpnError, match="protocol deactivation"):
        PrepareWireGuardPeerRevocation(remaining, settings, retained, "laptop")

    assert EncodeWireGuardMaterial(material) == before


def test_EnrollmentCannotExceedTheExplicitDeviceCapacity() -> None:
    """Reject another named peer before constructing an over-capacity desired profile."""

    profile = replace(Profile(), devices=tuple(VpnDevice("device-" + str(index), "10.67.0." + str(index + 2)) for index in range(16)))
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    device = VpnDevice("tablet", "10.67.0.50")
    peer = GenerateWireGuardMaterial(replace(profile, devices=(device,)), settings).peers[0]
    before = EncodeWireGuardMaterial(material)

    with pytest.raises(VpnError, match="one new named device"):
        PrepareWireGuardPeerEnrollment(profile, settings, material, device, peer)

    assert EncodeWireGuardMaterial(material) == before
