"""Compile an explicit IPv4 gateway with restricted SSH application forwarding."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import struct
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from flayer.core.contracts import (
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateIdentifier,
    ValidateName,
    ValidateSchemaVersion,
)
from flayer.profiles.artifacts import Artifact, ArtifactBundle, ReadOwnedArtifactFile

PROFILE_SCHEMA_VERSION = 1
PROFILE_NAME = "secure-gateway"
MAX_PROFILE_BYTES = 65536
_USERNAME_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
_IDENTITY_FIELDS = frozenset({"project", "stack", "provider", "scope_id", "owner_id"})
_GATEWAY_FIELDS = frozenset({
    "zone_id", "image_id", "subnet_cidr", "ssh_public_key", "management_cidrs",
})
_OPTIONAL_GATEWAY_FIELDS = frozenset({
    "ssh_username", "ssh_port", "cores", "memory_gib", "boot_disk_gib",
})


class GatewayError(ContractError):
    """Profile intent or a prepared initialization artifact violates its contract."""


def _Integer(value: object, minimum: int, maximum: int, label: str) -> int:
    """Reject coercion and enforce a finite profile sizing or port limit."""

    if type(value) is not int or not minimum <= value <= maximum:
        raise GatewayError(f"{label} must be an integer within {minimum}..{maximum}")

    return value


def _Cidr(value: object, minimumPrefix: int, label: str) -> str:
    """Require canonical IPv4 networks with an explicit bounded prefix."""

    if not isinstance(value, str):
        raise GatewayError(f"{label} must be a canonical IPv4 CIDR")

    try:
        network = ipaddress.IPv4Network(value, strict=True)

    except ValueError:
        raise GatewayError(f"{label} must be a canonical IPv4 CIDR") from None

    if str(network) != value or network.prefixlen < minimumPrefix:
        raise GatewayError(f"{label} must be canonical and use prefix /{minimumPrefix} or narrower")

    return value


def _Cidrs(value: object, minimumPrefix: int, label: str) -> tuple[str, ...]:
    """Limit rule expansion and reject duplicate or overlapping address allowances."""

    if not isinstance(value, tuple) or not 1 <= len(value) <= 16:
        raise GatewayError(f"{label} must contain 1..16 immutable CIDRs")

    cidrs = tuple(_Cidr(item, minimumPrefix, label) for item in value)
    networks = tuple(ipaddress.IPv4Network(item) for item in cidrs)

    if any(left.overlaps(right) for index, left in enumerate(networks) for right in networks[index + 1:]):
        raise GatewayError(f"{label} must not contain duplicate or overlapping CIDRs")

    return cidrs


def _PublicKey(value: object) -> str:
    """Accept only a complete Ed25519 public wire key without comments or private data."""

    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise GatewayError("ssh_public_key must be a complete Ed25519 public key")

    parts = value.split(" ")

    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise GatewayError("ssh_public_key must contain only the Ed25519 type and public blob")

    try:
        blob = base64.b64decode(parts[1], validate=True)
        expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)

        if len(blob) != len(expected) + 32 or not blob.startswith(expected):
            raise ValueError("Invalid public wire key")

        if base64.b64encode(blob).decode("ascii") != parts[1]:
            raise ValueError("Noncanonical public key encoding")

    except (ValueError, binascii.Error):
        raise GatewayError("ssh_public_key must be a complete Ed25519 public key") from None

    return value


def _Username(value: object) -> str:
    """Require an explicit portable non-root account without coercing TOML types."""

    if (
        not isinstance(value, str)
        or _USERNAME_PATTERN.fullmatch(value) is None
        or value == "root"
    ):
        raise GatewayError("ssh_username must be a portable non-root account name")

    return value


def _Host(value: object) -> str:
    """Require a literal IPv4 or canonical lowercase DNS name without SSH tokens."""

    if not isinstance(value, str) or _HOST_PATTERN.fullmatch(value) is None:
        raise GatewayError("Host must be a literal IPv4 or lowercase DNS name")

    if value.replace(".", "").isdigit():
        try:
            address = ipaddress.IPv4Address(value)

        except ValueError:
            raise GatewayError("Host must contain a canonical IPv4 address") from None

        if str(address) != value or address.is_unspecified or address.is_multicast:
            raise GatewayError("Host must contain a unicast IPv4 address")

    elif any(
        not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
        for label in value.split(".")
    ):
        raise GatewayError("Host must contain a canonical lowercase DNS name")

    return value


@dataclass(frozen=True, slots=True)
class GatewayTarget:
    """One exact TCP destination reachable through the SSH gateway."""

    name: str
    host: str
    port: int

    def __post_init__(self) -> None:
        """Exclude wildcards, socket paths, aliases, and unbounded destination ports."""

        ValidateName(self.name, "target name")
        _Host(self.host)
        _Integer(self.port, 1, 65535, "target port")


@dataclass(frozen=True, slots=True)
class GatewayDevice:
    """One device public credential and explicitly bounded connection source networks."""

    deviceId: str
    publicKey: str = field(repr=False)
    sourceCidrs: tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate public credentials without resolving their corresponding private key."""

        ValidateName(self.deviceId, "device_id")
        _PublicKey(self.publicKey)
        _Cidrs(self.sourceCidrs, 24, "device source CIDRs")


@dataclass(frozen=True, slots=True)
class GatewayTransport:
    """A restricted SSH local-forward transport with separately declared device keys."""

    username: str
    targets: tuple[GatewayTarget, ...]
    devices: tuple[GatewayDevice, ...]

    def __post_init__(self) -> None:
        """Keep all transport expansion bounded and forbid ambiguous destinations or keys."""

        _Username(self.username)

        if not isinstance(self.targets, tuple) or not 1 <= len(self.targets) <= 8 or any(
            not isinstance(item, GatewayTarget) for item in self.targets
        ):
            raise GatewayError("Transport requires 1..8 immutable GatewayTarget values")

        if not isinstance(self.devices, tuple) or not 1 <= len(self.devices) <= 16 or any(
            not isinstance(item, GatewayDevice) for item in self.devices
        ):
            raise GatewayError("Transport requires 1..16 immutable GatewayDevice values")

        if len({item.name for item in self.targets}) != len(self.targets) or len({
            (item.host, item.port) for item in self.targets
        }) != len(self.targets):
            raise GatewayError("Transport targets must have unique names and destinations")

        if len({item.deviceId for item in self.devices}) != len(self.devices) or len({
            item.publicKey for item in self.devices
        }) != len(self.devices):
            raise GatewayError("Transport devices must have unique names and public keys")

        if sum(len(item.sourceCidrs) for item in self.devices) > 32:
            raise GatewayError("Transport device sources must not exceed 32 CIDRs")


@dataclass(frozen=True, slots=True)
class GatewayPort:
    """One explicit service allowance; an allowance does not install a listener."""

    protocol: str
    port: int
    cidrs: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require supported transport labels, bounded ports, and explicit IPv4 sources."""

        if not isinstance(self.protocol, str) or self.protocol not in {"tcp", "udp"}:
            raise GatewayError("service protocol must be tcp or udp")

        _Integer(self.port, 1, 65535, "service port")
        _Cidrs(self.cidrs, 0, "service CIDRs")


@dataclass(frozen=True, slots=True)
class GatewayProfile:
    """Explicit cloud placement and Ubuntu 24.04 cloud-init security intent."""

    identity: StackIdentity
    zoneId: str
    imageId: str
    subnetCidr: str
    sshPublicKey: str = field(repr=False)
    managementCidrs: tuple[str, ...]
    transport: GatewayTransport
    servicePorts: tuple[GatewayPort, ...] = ()
    sshUsername: str = "gateway-admin"
    sshPort: int = 22
    cores: int = 2
    memoryGib: int = 2
    bootDiskGib: int = 20
    schemaVersion: int = PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Validate construction independently of the TOML parser."""

        ValidateSchemaVersion(self.schemaVersion)

        if not isinstance(self.identity, StackIdentity):
            raise GatewayError("identity must be a StackIdentity")

        ValidateIdentifier(self.zoneId, "zone_id")
        ValidateIdentifier(self.imageId, "image_id")
        _Cidr(self.subnetCidr, 16, "subnet_cidr")
        network = ipaddress.IPv4Network(self.subnetCidr)
        privateRanges = tuple(ipaddress.IPv4Network(value) for value in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        ))

        if network.prefixlen > 28 or not any(network.subnet_of(item) for item in privateRanges):
            raise GatewayError("subnet_cidr must be an RFC1918 network with prefix /16../28")

        _PublicKey(self.sshPublicKey)
        _Cidrs(self.managementCidrs, 24, "management CIDRs")

        _Username(self.sshUsername)

        if not isinstance(self.transport, GatewayTransport):
            raise GatewayError("transport must be a GatewayTransport")

        if self.transport.username == self.sshUsername or any(
            item.publicKey == self.sshPublicKey for item in self.transport.devices
        ):
            raise GatewayError("Tunnel and administration accounts and public keys must be separate")
        _Integer(self.sshPort, 1, 65535, "ssh_port")
        _Integer(self.cores, 2, 32, "cores")
        _Integer(self.memoryGib, 1, 64, "memory_gib")
        _Integer(self.bootDiskGib, 10, 256, "boot_disk_gib")

        if not isinstance(self.servicePorts, tuple) or len(self.servicePorts) > 8 or any(
            not isinstance(item, GatewayPort) for item in self.servicePorts
        ):
            raise GatewayError("service_ports must contain at most eight GatewayPort values")

        ports = {(item.protocol, item.port) for item in self.servicePorts}

        if len(ports) != len(self.servicePorts) or ("tcp", self.sshPort) in ports:
            raise GatewayError("service ports must be unique and must not expose the SSH port")

        if len(_SshCidrs(self)) + sum(len(item.cidrs) for item in self.servicePorts) > 63:
            raise GatewayError("Profile must reserve one egress rule within its 64-rule budget")


def _ParseTransport(value: object) -> GatewayTransport:
    """Decode the concrete SSH transport without accepting inline private credentials."""

    table = RequireTable(value, "transport")
    ValidateFields(table, frozenset({"kind", "username", "targets", "devices"}), frozenset(), "transport")

    if table["kind"] != "ssh-local-forward":
        raise GatewayError("Only the ssh-local-forward transport is implemented")

    if not isinstance(table["targets"], list) or not isinstance(table["devices"], list):
        raise GatewayError("Transport targets and devices must be arrays")

    targets: list[GatewayTarget] = []
    devices: list[GatewayDevice] = []

    for rawTarget in table["targets"]:
        target = RequireTable(rawTarget, "target")
        ValidateFields(target, frozenset({"name", "host", "port"}), frozenset(), "target")
        targets.append(GatewayTarget(
            name=ValidateName(target["name"], "target name"), host=_Host(target["host"]),
            port=_Integer(target["port"], 1, 65535, "target port"),
        ))

    for rawDevice in table["devices"]:
        device = RequireTable(rawDevice, "device")
        ValidateFields(device, frozenset({"device_id", "public_key", "source_cidrs"}), frozenset(), "device")

        if not isinstance(device["source_cidrs"], list):
            raise GatewayError("Device source_cidrs must be an array")

        devices.append(GatewayDevice(
            deviceId=ValidateName(device["device_id"], "device_id"),
            publicKey=_PublicKey(device["public_key"]), sourceCidrs=tuple(device["source_cidrs"]),
        ))

    return GatewayTransport(_Username(table["username"]), tuple(targets), tuple(devices))


def ParseGatewayProfile(data: Mapping[str, object]) -> GatewayProfile:
    """Reject unknown settings, secret fields, and unversioned profile tables."""

    try:
        ValidateFields(
            data, frozenset({"schema_version", "profile", "guest_contract", "identity", "gateway", "transport"}),
            frozenset({"service_ports"}), "gateway profile",
        )
        ValidateSchemaVersion(data["schema_version"])

        if data["profile"] != PROFILE_NAME or data["guest_contract"] != "ubuntu-24.04-cloud-init":
            raise GatewayError("profile and guest_contract must select the supported server foundation")

        gateway = RequireTable(data["gateway"], "gateway")
        ValidateFields(gateway, _GATEWAY_FIELDS, _OPTIONAL_GATEWAY_FIELDS, "gateway")
        rawCidrs = gateway["management_cidrs"]
        rawPorts = data.get("service_ports", [])

        if not isinstance(rawCidrs, list) or not isinstance(rawPorts, list):
            raise GatewayError("management_cidrs and service_ports must be arrays")

        servicePorts: list[GatewayPort] = []

        for rawPort in rawPorts:
            port = RequireTable(rawPort, "service port")
            ValidateFields(port, frozenset({"protocol", "port", "cidrs"}), frozenset(), "service port")

            if not isinstance(port["protocol"], str) or not isinstance(port["cidrs"], list):
                raise GatewayError("service port requires a protocol and CIDR array")

            servicePorts.append(GatewayPort(
                protocol=port["protocol"],
                port=_Integer(port["port"], 1, 65535, "service port"),
                cidrs=tuple(port["cidrs"]),
            ))

        return GatewayProfile(
            identity=ParseIdentity(data["identity"]),
            zoneId=ValidateIdentifier(gateway["zone_id"], "zone_id"),
            imageId=ValidateIdentifier(gateway["image_id"], "image_id"),
            subnetCidr=_Cidr(gateway["subnet_cidr"], 16, "subnet_cidr"),
            sshPublicKey=_PublicKey(gateway["ssh_public_key"]),
            managementCidrs=tuple(rawCidrs),
            transport=_ParseTransport(data["transport"]),
            servicePorts=tuple(servicePorts),
            sshUsername=_Username(gateway.get("ssh_username", "gateway-admin")),
            sshPort=_Integer(gateway.get("ssh_port", 22), 1, 65535, "ssh_port"),
            cores=_Integer(gateway.get("cores", 2), 2, 32, "cores"),
            memoryGib=_Integer(gateway.get("memory_gib", 2), 1, 64, "memory_gib"),
            bootDiskGib=_Integer(gateway.get("boot_disk_gib", 20), 10, 256, "boot_disk_gib"),
        )

    except ContractError as error:
        raise GatewayError(str(error)) from None


def LoadGatewayProfile(path: str | Path) -> GatewayProfile:
    """Read a bounded explicit profile without consulting credentials or environment defaults."""

    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_PROFILE_BYTES + 1)

        if len(raw) > MAX_PROFILE_BYTES:
            raise GatewayError("Gateway profile exceeds its bounded input size")

        data = tomllib.loads(raw.decode("utf-8"))

    except (OSError, ValueError, RecursionError):
        raise GatewayError("Unable to read a valid bounded gateway profile") from None

    return ParseGatewayProfile(data)


@dataclass(frozen=True, slots=True)
class GatewayPlan:
    """Immutable composition input; serialized lifecycle plans bind an exported artifact."""

    profile: GatewayProfile

    def __post_init__(self) -> None:
        """Reject unsupported plan construction before any resource serialization."""

        if not isinstance(self.profile, GatewayProfile):
            raise GatewayError("profile must be a GatewayProfile")


def CompileGateway(profile: GatewayProfile) -> GatewayPlan:
    """Compile validated profile intent without performing filesystem or provider operations."""

    plan = GatewayPlan(profile)

    for logicalId in ("network", "subnet", "firewall", "address", "boot-disk", "instance"):
        ValidateName(profile.identity.stack + "-" + logicalId, "resource name")

    return plan


def _Firewall(profile: GatewayProfile) -> str:
    """Render bounded IPv4 ingress and deny packet routing for SSH application forwarding."""

    lines = [
        "#!/usr/sbin/nft -f", "flush ruleset", "table inet flayer_filter {",
        "  chain input {", "    type filter hook input priority 0; policy drop;",
        "    ct state invalid drop", "    ct state established,related accept",
        '    iifname "lo" accept', "    udp sport 67 udp dport 68 accept",
    ]

    for cidr in _SshCidrs(profile):
        lines.append(f"    ip saddr {cidr} tcp dport {profile.sshPort} accept")

    for service in profile.servicePorts:
        for cidr in service.cidrs:
            lines.append(f"    ip saddr {cidr} {service.protocol} dport {service.port} accept")

    lines.extend([
        "  }", "  chain forward {", "    type filter hook forward priority 0; policy drop;",
        "  }", "}", "",
    ])

    return "\n".join(lines)


def _SshCidrs(profile: GatewayProfile) -> tuple[str, ...]:
    """Deduplicate SSH connection networks while preserving per-key source authorization."""

    return tuple(dict.fromkeys((
        *profile.managementCidrs,
        *(cidr for device in profile.transport.devices for cidr in device.sourceCidrs),
    )))


def _CloudInit(profile: GatewayProfile) -> bytes:
    """Generate nonsecret initialization for the explicitly selected Ubuntu guest contract."""

    sshConfiguration = "\n".join([
        f"Port {profile.sshPort}", "UsePAM yes", "PermitRootLogin no", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
        "StrictModes yes", "AuthorizedKeysFile /etc/ssh/f-layer-admin-keys",
        "AuthorizedKeysCommand none", "TrustedUserCAKeys none", "AuthorizedPrincipalsFile none",
        "AuthenticationMethods publickey", "AllowUsers " + " ".join((
            *(f"{profile.sshUsername}@{cidr}" for cidr in profile.managementCidrs),
            *(f"{profile.transport.username}@{cidr}" for device in profile.transport.devices for cidr in device.sourceCidrs),
        )),
        "MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no", "AllowAgentForwarding no",
        "AllowTcpForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no",
        "GatewayPorts no", "", f"Match User {profile.transport.username}",
        "    AuthorizedKeysFile /etc/ssh/f-layer-tunnel-keys",
        "    AllowTcpForwarding local", "    PermitOpen " + " ".join(
            f"{target.host}:{target.port}" for target in profile.transport.targets
        ),
        "    PermitListen none", "    MaxSessions 0", "    PermitTTY no", "    PermitUserRC no", "",
    ])
    sysctlConfiguration = "\n".join([
        "net.ipv4.ip_forward=0", "net.ipv4.conf.all.accept_redirects=0",
        "net.ipv4.conf.default.accept_redirects=0", "net.ipv4.conf.all.send_redirects=0",
        "net.ipv4.conf.default.send_redirects=0", "net.ipv4.conf.all.accept_source_route=0",
        "net.ipv4.conf.default.accept_source_route=0", "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1", "",
    ])
    deviceKeys = [
        ','.join((
            'from="' + ','.join(device.sourceCidrs) + '"', "restrict", "port-forwarding",
            *(f'permitopen="{target.host}:{target.port}"' for target in profile.transport.targets),
        )) + " " + device.publicKey for device in profile.transport.devices
    ]
    bootstrap = "\n".join([
        "#!/bin/sh", "set -eu",
        f"if getent passwd {profile.transport.username} >/dev/null; then",
        "    echo 'Dedicated tunnel account already exists; initialization refused' >&2",
        "    exit 1", "else", "    lookup_status=$?",
        '    if [ "$lookup_status" -ne 2 ]; then',
        "        echo 'Unable to verify dedicated tunnel account absence' >&2",
        "        exit 1", "    fi", "fi",
        f"useradd --create-home --shell /bin/bash --user-group {profile.transport.username}",
        f"usermod --lock {profile.transport.username}",
        "install -d -m 0755 /run/sshd", "sshd -t",
        "nft --check --file /etc/nftables.conf", "sysctl --system",
        "systemctl enable --now nftables", "systemctl enable --now unattended-upgrades",
        "systemctl disable --now ssh.socket", "systemctl daemon-reload",
        "systemctl enable --now ssh.service", "systemctl restart ssh.service",
        "install -d -m 0700 /var/lib/f-layer", "touch /var/lib/f-layer/bootstrap-ready", "",
    ])
    files = [
        ("/etc/ssh/sshd_config", "0644", sshConfiguration),
        ("/etc/ssh/f-layer-admin-keys", "0644", profile.sshPublicKey + "\n"),
        ("/etc/ssh/f-layer-tunnel-keys", "0644", "\n".join(deviceKeys) + "\n"),
        ("/etc/sysctl.d/90-f-layer.conf", "0644", sysctlConfiguration),
        ("/etc/nftables.conf", "0644", _Firewall(profile)),
        ("/usr/local/sbin/f-layer-bootstrap", "0700", bootstrap),
    ]
    data = {
        "ssh_pwauth": False, "disable_root": True,
        "users": [{
            "name": profile.sshUsername, "groups": ["sudo"], "shell": "/bin/bash",
            "lock_passwd": True, "sudo": "ALL=(ALL) NOPASSWD:ALL",
            "ssh_authorized_keys": [profile.sshPublicKey],
        }],
        "package_update": True, "package_upgrade": False,
        "packages": ["nftables", "unattended-upgrades"],
        "write_files": [{
            "path": path, "owner": "root:root", "permissions": permissions, "content": content,
        } for path, permissions, content in files],
        "runcmd": [["/bin/sh", "/usr/local/sbin/f-layer-bootstrap"]],
    }

    return ("#cloud-config\n" + json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def BuildServerBundle(profile: GatewayProfile) -> ArtifactBundle:
    """Build initialization bytes without resolving secrets, uploading, or claiming readiness."""

    CompileGateway(profile)

    return ArtifactBundle(
        identity=profile.identity, kind="server", name=profile.identity.stack,
        files=(Artifact("server-cloud-init.json", _CloudInit(profile), sensitive=False),),
    )


def _SshPath(value: str | Path) -> str:
    """Permit explicit literal key and trust paths without expansion or directive injection."""

    text = str(value)
    path = Path(text)
    windowsPath = PureWindowsPath(text)

    if (
        not (path.is_absolute() or windowsPath.is_absolute())
        or ".." in path.parts or ".." in windowsPath.parts or len(text) > 4096
        or any(character in text for character in ('"', "'", "\\", "%", "$", "~"))
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise GatewayError("SSH references require explicit absolute literal paths")

    return text


def BuildSshDeviceBundle(
    profile: GatewayProfile, deviceId: str, *, endpoint: str,
    identityFile: str | Path, knownHostsFile: str | Path, localPorts: tuple[int, ...],
) -> ArtifactBundle:
    """Generate usable local TCP forwards with caller-provided key and trusted-host references."""

    CompileGateway(profile)
    ValidateName(deviceId, "device_id")
    _Host(endpoint)
    keyPath = _SshPath(identityFile)
    trustPath = _SshPath(knownHostsFile)
    device = next((item for item in profile.transport.devices if item.deviceId == deviceId), None)

    if device is None:
        raise GatewayError("Device must be declared in the compiled gateway transport")

    if not isinstance(localPorts, tuple) or len(localPorts) != len(profile.transport.targets):
        raise GatewayError("local_ports must contain one immutable port for each declared target")

    for port in localPorts:
        _Integer(port, 1024, 65535, "local port")

    if len(set(localPorts)) != len(localPorts):
        raise GatewayError("Local forward ports must be unique")

    lines = [
        f"Host {deviceId}", f"    HostName {endpoint}", f"    Port {profile.sshPort}",
        f"    User {profile.transport.username}", f'    IdentityFile "{keyPath}"',
        f'    UserKnownHostsFile "{trustPath}"', "    GlobalKnownHostsFile none",
        "    StrictHostKeyChecking yes", "    VerifyHostKeyDNS no", "    UpdateHostKeys no",
        "    KnownHostsCommand none", "    IdentitiesOnly yes", "    IdentityAgent none",
        "    PreferredAuthentications publickey", "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no", "    ForwardAgent no", "    ForwardX11 no",
        "    RequestTTY no", "    SessionType none", "    ProxyCommand none", "    ProxyJump none",
        "    PermitLocalCommand no", "    CanonicalizeHostname no", "    ExitOnForwardFailure yes",
        "    ConnectTimeout 10", "    ConnectionAttempts 1", "    ServerAliveInterval 15",
        "    ServerAliveCountMax 3",
    ]

    for port, target in zip(localPorts, profile.transport.targets, strict=True):
        lines.append(f"    LocalForward 127.0.0.1:{port} {target.host}:{target.port}")

    descriptor = {
        "schema_version": 1, "device_id": deviceId, "transport": "ssh-local-forward",
        "status": "prepared-unverified", "identity": {
            key: getattr(profile.identity, key) for key in sorted(_IDENTITY_FIELDS)
        },
        "public_key_sha256": hashlib.sha256(device.publicKey.encode("ascii")).hexdigest(),
    }

    return ArtifactBundle(profile.identity, "device", deviceId, (
        Artifact("ssh-client.conf", ("\n".join(lines) + "\n").encode("utf-8"), sensitive=False),
        Artifact("device-info.json", (json.dumps(descriptor, sort_keys=True) + "\n").encode("utf-8"), sensitive=False),
    ))


def RenderPlan(plan: GatewayPlan, *, userDataFile: str | Path) -> str:
    """Bind exact generated bytes to a lifecycle TOML plan without importing future orchestration."""

    if not isinstance(plan, GatewayPlan):
        raise GatewayError("plan must be a GatewayPlan")

    profile = plan.profile
    artifactPath = Path(userDataFile)
    expected = _CloudInit(profile)

    try:
        actual = ReadOwnedArtifactFile(
            artifactPath, profile.identity, kind="server", name=profile.identity.stack,
        )

    except ContractError:
        raise GatewayError("Prepared server artifact ownership or integrity is invalid") from None

    if actual != expected:
        raise GatewayError("Initialization artifact does not match the compiled gateway profile")

    def Quote(value: str) -> str:
        """Keep Unicode scalar paths valid TOML instead of emitting surrogate escapes."""

        return json.dumps(value, ensure_ascii=False)

    lines = ["schema_version = 1", f"profile = {Quote(PROFILE_NAME)}", "", "[identity]"]

    for key in sorted(_IDENTITY_FIELDS):
        lines.append(f"{key} = {Quote(getattr(profile.identity, key))}")

    def AddResource(
        logicalId: str, kind: str, dependencies: tuple[str, ...], properties: Mapping[str, object],
    ) -> None:
        """Append deterministic resource intent with no observed provider identifiers."""

        lines.extend([
            "", "[[resources]]", f"logical_id = {Quote(logicalId)}", f"kind = {Quote(kind)}",
            f"name = {Quote(ValidateName(profile.identity.stack + '-' + logicalId, 'resource name'))}",
            "dependencies = [" + ", ".join(Quote(item) for item in dependencies) + "]",
            "[resources.parameters]",
        ])

        for key, value in properties.items():
            if isinstance(value, str):
                rendered = Quote(value)

            elif type(value) is int:
                rendered = str(value)

            else:
                raise GatewayError("Resource properties must be explicit scalar values")

            lines.append(f"{key} = {rendered}")

    AddResource("network", "network", (), {})
    AddResource("subnet", "subnet", ("network",), {
        "zone_id": profile.zoneId, "ipv4_cidr": profile.subnetCidr,
        "network_dependency": "network",
    })
    AddResource("firewall", "security-group", ("network",), {"network_dependency": "network"})
    rules = [("tcp", profile.sshPort, cidr) for cidr in _SshCidrs(profile)]
    rules.extend((service.protocol, service.port, cidr) for service in profile.servicePorts for cidr in service.cidrs)

    for protocol, port, cidr in rules:
        lines.extend([
            "[[resources.parameters.rules]]", 'direction = "ingress"', f"protocol = {Quote(protocol)}",
            f"from_port = {port}", f"to_port = {port}", f"cidr = {Quote(cidr)}",
        ])

    lines.extend([
        "[[resources.parameters.rules]]", 'direction = "egress"', 'protocol = "any"',
        'cidr = "0.0.0.0/0"',
    ])
    AddResource("address", "address", (), {"zone_id": profile.zoneId})
    AddResource("boot-disk", "disk", (), {
        "zone_id": profile.zoneId, "image_id": profile.imageId, "size_gib": profile.bootDiskGib,
    })
    AddResource("instance", "instance", ("subnet", "firewall", "address", "boot-disk"), {
        "zone_id": profile.zoneId, "cores": profile.cores,
        "memory_gib": profile.memoryGib, "boot_disk_dependency": "boot-disk",
        "subnet_dependency": "subnet", "security_group_dependency": "firewall",
        "address_dependency": "address", "ssh_public_key": profile.sshPublicKey,
        "ssh_username": profile.sshUsername, "user_data_file": str(artifactPath.absolute()),
        "user_data_sha256": hashlib.sha256(expected).hexdigest(),
    })

    return "\n".join(lines) + "\n"
