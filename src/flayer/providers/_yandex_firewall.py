"""Normalize scoped security-group policy without retaining raw vendor metadata."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from typing import cast

from flayer.core.contracts import ValidateIdentifier
from flayer.providers.contracts import ProviderResource, ResourceKind
from flayer.providers.lifecycle import JsonValue, ResourceSpec


@dataclass(frozen=True, slots=True)
class SecurityGroupRule:
    """One exact provider rule with immutable addresses, identifier and ownership description."""

    ruleId: str
    direction: str
    protocol: str
    fromPort: int | None
    toPort: int | None
    ipv4Cidrs: tuple[str, ...]
    description: str = ""

    def __post_init__(self) -> None:
        """Reject ambiguous directions, port policies, targets and duplicate CIDRs before comparison."""

        ValidateIdentifier(self.ruleId, "security-group rule identifier")

        if (self.direction not in {"ingress", "egress"} or self.protocol not in {"tcp", "udp", "any"}
                or not isinstance(self.description, str) or len(self.description) > 256
                or any(ord(character) < 32 for character in self.description)
                or not isinstance(self.ipv4Cidrs, tuple) or not 1 <= len(self.ipv4Cidrs) <= 32
                or len(set(self.ipv4Cidrs)) != len(self.ipv4Cidrs)):
            raise ValueError("Security-group rule policy is unsupported")

        if (self.fromPort, self.toPort) != (None, None) and (
            type(self.fromPort) is not int or type(self.toPort) is not int or not 0 <= self.fromPort <= self.toPort <= 65535
        ):
            raise ValueError("Security-group rule port range is invalid")

        for cidr in self.ipv4Cidrs:
            if not isinstance(cidr, str) or str(ipaddress.IPv4Network(cidr, strict=True)) != cidr:
                raise ValueError("Security-group rule CIDR must be canonical IPv4")

        object.__setattr__(self, "ipv4Cidrs", tuple(sorted(self.ipv4Cidrs)))


@dataclass(frozen=True, slots=True)
class SecurityGroupSnapshot:
    """A bounded scoped group observation with complete effective rules and network attachment."""

    resource: ProviderResource
    networkId: str
    rules: tuple[SecurityGroupRule, ...]

    def __post_init__(self) -> None:
        """Require one exact security group and unique provider rule identifiers."""

        if not isinstance(self.resource, ProviderResource) or self.resource.reference.kind != ResourceKind.SECURITY_GROUP:
            raise ValueError("Security-group snapshot has an invalid resource")

        ValidateIdentifier(self.networkId, "security-group network identifier")

        if (not isinstance(self.rules, tuple) or len(self.rules) > 64
                or any(not isinstance(rule, SecurityGroupRule) for rule in self.rules)
                or len({rule.ruleId for rule in self.rules}) != len(self.rules)):
            raise ValueError("Security-group snapshot rules are invalid or ambiguous")

        object.__setattr__(self, "rules", tuple(sorted(self.rules, key=lambda rule: rule.ruleId)))


@dataclass(frozen=True, slots=True)
class InstanceAttachments:
    """Exact single-NIC IPv4 and non-auto-deleting boot attachment, excluding raw instance metadata."""

    resource: ProviderResource
    subnetId: str
    securityGroupIds: tuple[str, ...]
    privateAddress: str
    publicAddress: str
    bootDiskId: str

    def __post_init__(self) -> None:
        """Retain only bounded complete attachment identities and canonical IPv4 addresses."""

        if not isinstance(self.resource, ProviderResource) or self.resource.reference.kind != ResourceKind.INSTANCE:
            raise ValueError("Instance attachment snapshot requires an exact instance")

        ValidateIdentifier(self.subnetId, "instance subnet identifier")
        ValidateIdentifier(self.bootDiskId, "instance boot-disk identifier")

        if (not isinstance(self.securityGroupIds, tuple) or not 1 <= len(self.securityGroupIds) <= 16
                or len(set(self.securityGroupIds)) != len(self.securityGroupIds)):
            raise ValueError("Instance security-group attachments are missing or ambiguous")

        for group in self.securityGroupIds:
            ValidateIdentifier(group, "instance security-group identifier")

        for address in (self.privateAddress, self.publicAddress):
            if not isinstance(address, str) or str(ipaddress.IPv4Address(address)) != address:
                raise ValueError("Instance attachment requires canonical IPv4 addresses")

        object.__setattr__(self, "securityGroupIds", tuple(sorted(self.securityGroupIds)))


def ParseInstanceAttachments(payload: object, resource: ProviderResource) -> InstanceAttachments:
    """Read the documented single-NIC instance shape and reject collateral storage or address attachments."""

    if (not isinstance(payload, dict) or payload.get("id") != resource.reference.resourceId
            or payload.get("folder_id") != resource.reference.scopeId
            or not isinstance(payload.get("network_interfaces"), list) or len(payload["network_interfaces"]) != 1
            or any(payload.get(key, []) != [] for key in ("secondary_disks", "filesystems", "local_disks"))):
        raise ValueError("Instance has unknown, missing or additional attachments")

    boot = payload.get("boot_disk")
    nic = payload["network_interfaces"][0]

    if (not isinstance(boot, dict) or set(boot) - {"mode", "device_name", "auto_delete", "disk_id"}
            or boot.get("mode") != "READ_WRITE" or boot.get("auto_delete", False) is not False
            or not isinstance(nic, dict) or set(nic) - {"index", "mac_address", "subnet_id", "security_group_ids", "primary_v4_address", "primary_v6_address"}
            or type(nic.get("index")) not in {str, int} or nic["index"] not in ("0", 0)
            or nic.get("primary_v6_address") not in (None, {}) or not isinstance(nic.get("security_group_ids"), list)):
        raise ValueError("Instance boot-disk or interface policy is unsupported")

    primary = nic.get("primary_v4_address")

    if not isinstance(primary, dict) or set(primary) - {"address", "one_to_one_nat", "dns_records"}:
        raise ValueError("Instance IPv4 address policy is unsupported")

    nat = primary.get("one_to_one_nat")

    if not isinstance(nat, dict) or set(nat) - {"address", "ip_version", "dns_records"} or nat.get("ip_version") != "IPV4":
        raise ValueError("Instance requires the exact original IPv4 NAT attachment")

    fields = (nic.get("subnet_id"), primary.get("address"), nat.get("address"), boot.get("disk_id"))

    if any(not isinstance(value, str) for value in fields):
        raise ValueError("Instance attachment identities and addresses are missing")

    subnet, private, public, disk = cast(tuple[str, str, str, str], fields)

    return InstanceAttachments(resource, subnet, tuple(nic["security_group_ids"]), private, public, disk)


def _Port(value: object) -> int:
    """Interpret documented protobuf int64 JSON values without accepting booleans or alternate numeric syntax."""

    if type(value) is int and 0 <= value <= 65535:
        return value

    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,4}", value) is not None and int(value) <= 65535:
        return int(value)

    raise ValueError("Security-group observed port is invalid")


def ParseSecurityGroup(payload: object, resource: ProviderResource) -> SecurityGroupSnapshot:
    """Parse documented yc snake_case policy from the same exact scoped resource observation."""

    if (not isinstance(payload, dict) or payload.get("id") != resource.reference.resourceId
            or payload.get("folder_id") != resource.reference.scopeId
            or not isinstance(payload.get("rules"), list) or len(payload["rules"]) > 64
            or not isinstance(payload.get("network_id"), str)):
        raise ValueError("Security-group policy observation is unavailable or outside scope")

    rules = []

    for raw in payload["rules"]:
        if (not isinstance(raw, dict) or set(raw) - {"id", "description", "direction", "ports", "protocol_name", "protocol_number",
                                                   "cidr_blocks", "security_group_id", "predefined_target"}
                or not isinstance(raw.get("id"), str) or not isinstance(raw.get("direction"), str)
                or raw.get("security_group_id") not in {None, ""} or raw.get("predefined_target") not in {None, ""}):
            raise ValueError("Security-group rule contains an unknown target or policy")

        protocol = raw.get("protocol_name")
        number = raw.get("protocol_number")

        if protocol in {None, ""}:
            protocol = {None: "any", "-1": "any", "6": "tcp", "17": "udp"}.get(None if number is None else str(number))

        if not isinstance(protocol, str) or protocol.lower() not in {"tcp", "udp", "any"}:
            raise ValueError("Security-group rule protocol is unsupported")

        protocol = protocol.lower()

        if number is not None and str(number) != {"tcp": "6", "udp": "17", "any": "-1"}[protocol]:
            raise ValueError("Security-group rule protocol fields disagree")

        ports = raw.get("ports")
        first: int | None = None
        last: int | None = None

        if ports is not None:
            if not isinstance(ports, dict) or set(ports) - {"from_port", "to_port"}:
                raise ValueError("Security-group observed port range is ambiguous")

            first, last = _Port(ports.get("from_port", "0")), _Port(ports.get("to_port", "0"))

            if protocol == "any" and (first, last) == (0, 65535):
                first, last = None, None

        blocks = raw.get("cidr_blocks")

        if (not isinstance(blocks, dict) or set(blocks) - {"v4_cidr_blocks", "v6_cidr_blocks"}
                or not isinstance(blocks.get("v4_cidr_blocks"), list)
                or blocks.get("v6_cidr_blocks", []) != []):
            raise ValueError("Security-group rule requires supported explicit IPv4 targets")

        rules.append(SecurityGroupRule(raw["id"], raw["direction"].lower(), protocol, first, last,
                                        tuple(blocks["v4_cidr_blocks"]), raw.get("description", "")))

    return SecurityGroupSnapshot(resource, payload["network_id"], tuple(rules))


def ExpectedRules(spec: ResourceSpec) -> tuple[SecurityGroupRule, ...]:
    """Derive initial effective semantics from exact frozen parameters, not mutable desired listeners."""

    if spec.kind != ResourceKind.SECURITY_GROUP:
        raise ValueError("Expected firewall rules require an exact security-group creation spec")

    rawRules = dict(spec.parameters).get("rules")

    if not isinstance(rawRules, tuple):
        raise ValueError("Expected firewall rules are missing")

    rules = []

    for index, raw in enumerate(rawRules):
        if not isinstance(raw, tuple) or any(not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str) for pair in raw):
            raise ValueError("Expected firewall rule fields are invalid")

        fields = dict(cast(tuple[tuple[str, JsonValue], ...], raw))

        if (len(fields) != len(raw) or set(fields) - {"direction", "protocol", "from_port", "to_port", "cidr"}
                or not {"direction", "protocol", "cidr"} <= set(fields)
                or not isinstance(fields["direction"], str) or not isinstance(fields["protocol"], str)
                or not isinstance(fields["cidr"], str)):
            raise ValueError("Expected firewall rule policy is invalid")

        first = fields.get("from_port")
        last = fields.get("to_port")

        if first is not None and type(first) is not int or last is not None and type(last) is not int:
            raise ValueError("Expected firewall rule ports require integers")

        rules.append(SecurityGroupRule("creation-" + str(index), fields["direction"], fields["protocol"],
                                        first, last, (fields["cidr"],)))

    return tuple(rules)


def RuleSemantics(rules: tuple[SecurityGroupRule, ...]) -> Counter[tuple[str, str, int | None, int | None, str, str]]:
    """Compare complete effective policy with multiplicity while retaining provider IDs separately."""

    return Counter((rule.direction, rule.protocol, rule.fromPort, rule.toPort, cidr, rule.description)
                   for rule in rules for cidr in rule.ipv4Cidrs)
