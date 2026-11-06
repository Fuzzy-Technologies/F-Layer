"""Validate schema-2 selection and per-transport intent without files, credentials or cloud calls."""

from __future__ import annotations

import base64
import copy
import struct
import tomllib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from flayer.profiles.vpn import VpnError
from flayer.vpn_project import PROJECT_TEMPLATE, SelectedVpnProject
from flayer.vpn_project_v2 import ParseSelectedProject, SelectedProjectTemplate

PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"p" * 32).decode("ascii")


def Configuration(protocols: tuple[str, ...] = ("amneziawg", "vless-reality", "wireguard")) -> dict[str, Any]:
    """Make a complete public example document with no inline credentials or private infrastructure IDs."""

    template = SelectedProjectTemplate(protocols)

    return tomllib.loads(template.replace("replace-with-folder-id", "example-folder")
                         .replace("replace-with-ubuntu-2404-amd64-image-id", "example-image"))


@pytest.mark.parametrize("protocols", [
    ("amneziawg",), ("vless-reality",), ("wireguard",), ("amneziawg", "vless-reality"),
    ("amneziawg", "wireguard"), ("vless-reality", "wireguard"), ("amneziawg", "vless-reality", "wireguard"),
])
def test_ExplicitSelectionHasOnlyItsSettingsAndMembers(protocols: tuple[str, ...]) -> None:
    """Every supported combination loads offline, with distinct explicit tunnel address ownership."""

    data = Configuration(protocols)
    project = ParseSelectedProject(Path("example-project"), data, PUBLIC_KEY)

    assert isinstance(project, SelectedVpnProject)
    assert tuple(item.protocol for item in project.protocolSelections) == protocols
    assert tuple(listener.transport for listener in project.vpn.listeners) == protocols
    assert (project.amneziawg is not None) == ("amneziawg" in protocols)
    assert (project.vless is not None) == ("vless-reality" in protocols)
    assert (project.wireguard is not None) == ("wireguard" in protocols)
    assert len(project.Fingerprint()) == 64

    for protocol in protocols:
        profile = project.ProtocolProfile(protocol)

        assert profile.devices[0].deviceId == "laptop" and len(profile.listeners) == 1
        assert profile.devices[0].ipv4Address == {"amneziawg": "10.66.0.2", "wireguard": "10.67.0.2", "vless-reality": None}[protocol]
        assert len(project.TransportFingerprint(protocol)) == 64


def test_SelectionAndDeviceOrderingAreCanonicalWithoutChangingExplicitAddresses() -> None:
    """Equivalent declaration ordering cannot rotate keys or invalidate retained protocol material."""

    data = Configuration()
    data["devices"].append({"device_id": "phone"})
    data["wireguard"]["device_ids"] = ["phone", "laptop"]
    data["wireguard"]["device_addresses"]["phone"] = "10.67.0.9"
    before = ParseSelectedProject(Path("example"), data, PUBLIC_KEY)
    changed = copy.deepcopy(data)
    changed["protocols"].reverse()
    changed["devices"].reverse()
    changed["wireguard"]["device_ids"].reverse()
    after = ParseSelectedProject(Path("example"), changed, PUBLIC_KEY)

    assert before == after and before.Fingerprint() == after.Fingerprint()
    assert {device.deviceId: device.ipv4Address for device in after.ProtocolProfile("wireguard").devices} == {
        "laptop": "10.67.0.2", "phone": "10.67.0.9",
    }


def test_TransportFingerprintsExcludeUnrelatedMembersAddressesListenersAndPlacement() -> None:
    """WireGuard-only edits affect its intent while retaining AWG/VLESS identity and future credentials."""

    data = Configuration()
    before = ParseSelectedProject(Path("example"), data, PUBLIC_KEY)
    changed = copy.deepcopy(data)
    changed["devices"].append({"device_id": "phone"})
    changed["wireguard"]["device_ids"] = ["phone"]
    changed["wireguard"]["device_addresses"] = {"phone": "10.67.0.8"}
    changed["wireguard"]["port"] = 51829
    changed["cloud"]["management_cidrs"] = ["198.51.100.99/32"]
    after = ParseSelectedProject(Path("example"), changed, PUBLIC_KEY)

    assert before.Fingerprint() != after.Fingerprint()
    assert before.TransportFingerprint("wireguard") != after.TransportFingerprint("wireguard")
    assert before.TransportFingerprint("amneziawg") == after.TransportFingerprint("amneziawg")
    assert before.TransportFingerprint("vless-reality") == after.TransportFingerprint("vless-reality")


@pytest.mark.parametrize("fault", [
    "duplicate-protocol", "unknown-protocol", "openvpn", "empty-protocol", "schema-bool", "inactive-table",
    "missing-table", "missing-members", "unknown-member", "empty-members", "duplicate-members", "extra-address",
    "server-address", "outside-subnet", "cloud-overlap", "tunnel-overlap", "udp-collision", "ssh-collision",
    "dns-overflow", "inline-key", "mtu-bool", "non-awg-device-address", "not-table", "missing-map",
])
def test_InvalidSelectionFailsBeforeAnyPrivateMaterialOrNetworkOperation(fault: str) -> None:
    """Reject the whole public intent rather than silently dropping fields, devices or colliding listeners."""

    data = Configuration()

    if fault == "duplicate-protocol":
        data["protocols"].append("wireguard")

    elif fault == "unknown-protocol":
        data["protocols"] = ["unknown"]

    elif fault == "openvpn":
        data["protocols"] = ["openvpn"]

    elif fault == "empty-protocol":
        data["protocols"] = []

    elif fault == "schema-bool":
        data["schema_version"] = True

    elif fault == "inactive-table":
        data["openvpn"] = {"port": 1194}

    elif fault == "missing-table":
        del data["wireguard"]

    elif fault == "missing-members":
        del data["wireguard"]["device_ids"]

    elif fault == "unknown-member":
        data["vless"]["device_ids"] = ["unknown"]

    elif fault == "empty-members":
        data["vless"]["device_ids"] = []

    elif fault == "duplicate-members":
        data["vless"]["device_ids"] *= 2

    elif fault == "extra-address":
        data["wireguard"]["device_addresses"]["unknown"] = "10.67.0.9"

    elif fault == "server-address":
        data["wireguard"]["device_addresses"]["laptop"] = "10.67.0.1"

    elif fault == "outside-subnet":
        data["wireguard"]["device_addresses"]["laptop"] = "10.69.0.2"

    elif fault == "cloud-overlap":
        data["cloud"]["subnet_cidr"] = "10.67.0.0/24"

    elif fault == "tunnel-overlap":
        data["wireguard"]["tunnel_cidr"] = "10.66.0.0/24"
        data["wireguard"]["device_addresses"]["laptop"] = "10.66.0.9"

    elif fault == "udp-collision":
        data["wireguard"]["port"] = 51820

    elif fault == "ssh-collision":
        data["vless"]["port"] = 22

    elif fault == "dns-overflow":
        data["routes"]["dns_servers"] = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

    elif fault == "inline-key":
        data["wireguard"]["private_key"] = "synthetic-private-rejected-value"

    elif fault == "mtu-bool":
        data["wireguard"]["mtu"] = True

    elif fault == "non-awg-device-address":
        data["devices"].append({"device_id": "unassigned", "ipv4_address": "10.66.0.9"})

    elif fault == "not-table":
        data["wireguard"] = []

    else:
        del data["wireguard"]["device_addresses"]

    with pytest.raises(VpnError) as caught:
        ParseSelectedProject(Path("example"), data, PUBLIC_KEY)

    assert "synthetic-private-rejected-value" not in str(caught.value)


@pytest.mark.parametrize("protocols", [(), ("wireguard", "wireguard"), ("openvpn",), ("unknown",), ["wireguard"], None])
def test_InvalidInitSelectionIsNotInterpretedAsLegacyDefault(protocols: Any) -> None:
    """Only an omitted option chooses the old pair; explicit empty/unsupported selections are errors."""

    with pytest.raises(VpnError):
        SelectedProjectTemplate(protocols)


def test_ModelRejectsFakeSelectionAndInactiveSettings() -> None:
    """Public constructors enforce their owned models rather than accepting objects with matching attributes."""

    project = ParseSelectedProject(Path("example"), Configuration(("wireguard",)), PUBLIC_KEY)

    with pytest.raises(VpnError):
        replace(project, protocolSelections=(object(),))

    with pytest.raises(VpnError):
        replace(project, wireguard=None)

    with pytest.raises(VpnError):
        project.ProtocolProfile("vless-reality")

    assert tomllib.loads(PROJECT_TEMPLATE)["schema_version"] == 1
