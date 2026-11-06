"""Explicit protocol membership and canonical intent projections for VPN project schema 2."""

from __future__ import annotations

from dataclasses import dataclass

from flayer.profiles.vpn import MAX_VPN_DEVICES, VpnDevice, VpnError, VpnProfile, _Name

VPN_PROTOCOLS = ("amneziawg", "vless-reality", "wireguard", "openvpn")


@dataclass(frozen=True, slots=True)
class VpnProtocolSelection:
    """One transport's immutable explicit device membership and independently assigned addresses."""

    protocol: str
    deviceIds: tuple[str, ...]
    ipv4Addresses: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Reject ambiguous membership and normalize order without allocating or renaming devices."""

        if (not isinstance(self.protocol, str) or self.protocol not in VPN_PROTOCOLS
                or not isinstance(self.deviceIds, tuple) or not 1 <= len(self.deviceIds) <= MAX_VPN_DEVICES
                or any(not isinstance(name, str) for name in self.deviceIds)
                or len(set(self.deviceIds)) != len(self.deviceIds)):
            raise VpnError("Protocol selection requires a supported protocol and 1..16 unique immutable device IDs")

        for name in self.deviceIds:
            _Name(name, "device_id")

        if (not isinstance(self.ipv4Addresses, tuple) or len(self.ipv4Addresses) > MAX_VPN_DEVICES
                or any(not isinstance(item, tuple) or len(item) != 2
                       or not isinstance(item[0], str) or not isinstance(item[1], str)
                       for item in self.ipv4Addresses)):
            raise VpnError("Protocol addresses require immutable device/address pairs")

        if self.protocol in {"wireguard", "openvpn"}:
            if (len(self.ipv4Addresses) != len(self.deviceIds)
                    or {item[0] for item in self.ipv4Addresses} != set(self.deviceIds)
                    or len({item[1] for item in self.ipv4Addresses}) != len(self.ipv4Addresses)):
                raise VpnError("Protocol address keys must match its exact members with unique addresses")

            for name, address in self.ipv4Addresses:
                VpnDevice(name, address)

        elif self.ipv4Addresses:
            raise VpnError("AWG uses its declared device addresses and VLESS has no tunnel addresses")

        object.__setattr__(self, "deviceIds", tuple(sorted(self.deviceIds)))
        object.__setattr__(self, "ipv4Addresses", tuple(sorted(self.ipv4Addresses)))

    def Project(self, profile: VpnProfile) -> VpnProfile:
        """Exclude other protocols and devices from this transport's validation, hashes and material."""

        if not isinstance(profile, VpnProfile):
            raise VpnError("Protocol projection requires a validated global VPN profile")

        devices = {device.deviceId: device for device in profile.devices}
        listeners = tuple(listener for listener in profile.listeners if listener.transport == self.protocol)

        if not set(self.deviceIds) <= set(devices) or len(listeners) != 1:
            raise VpnError("Protocol members and its single listener must be explicitly declared")

        addresses = dict(self.ipv4Addresses)
        selected = []

        for name in self.deviceIds:
            address = devices[name].ipv4Address if self.protocol == "amneziawg" else addresses.get(name)

            if self.protocol == "amneziawg" and address is None:
                raise VpnError("Every selected AWG member requires its explicit device IPv4 address")

            selected.append(VpnDevice(name, address))

        return VpnProfile(profile.identity, tuple(selected), profile.routes, listeners)


def ParseProtocolSelections(
    protocols: object, tables: dict[str, object], profile: VpnProfile,
) -> tuple[VpnProtocolSelection, ...]:
    """Read exact explicit membership and tunnel address maps before generating any credentials."""

    if (not isinstance(protocols, list) or not isinstance(tables, dict) or not 1 <= len(protocols) <= len(VPN_PROTOCOLS)
            or any(not isinstance(item, str) or item not in VPN_PROTOCOLS for item in protocols)
            or len(set(protocols)) != len(protocols) or set(tables) != set(protocols)):
        raise VpnError("Schema 2 requires unique supported protocols and exactly their settings tables")

    result = []

    for protocol in VPN_PROTOCOLS:
        if protocol not in protocols:
            continue

        table = tables[protocol]

        if (not isinstance(table, dict) or not isinstance(table.get("device_ids"), list)
                or any(not isinstance(name, str) for name in table["device_ids"])):
            raise VpnError("Each selected protocol requires an explicit device_ids array")

        rawAddresses = table.get("device_addresses", {})

        if (not isinstance(rawAddresses, dict)
                or any(not isinstance(name, str) or not isinstance(address, str) for name, address in rawAddresses.items())):
            raise VpnError("Protocol device_addresses must map device IDs to private IPv4 strings")

        selection = VpnProtocolSelection(protocol, tuple(table["device_ids"]), tuple(rawAddresses.items()))
        selection.Project(profile)
        result.append(selection)

    return tuple(result)
