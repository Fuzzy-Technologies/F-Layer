"""Private local VPN projects composed with owned Yandex lifecycle and trusted guest provisioning."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import struct
import subprocess
import time
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import cast

from flayer.core.contracts import (
    ParseIdentity,
    RequireTable,
    ValidateFields,
    ValidateIdentifier,
    ValidateName,
    ValidateSchemaVersion,
    _WireDict,
)
from flayer.core.lifecycle import DeploymentPlan, LifecycleEngine, LifecycleReport
from flayer.core.state import LoadState
from flayer.guest import (
    PrivatePath,
    ReadPrivate,
    SshGuestProvisioner,
    ValidateSshPathSyntax,
    ValidateVlessRuntimeOptions,
    WritePrivate,
)
from flayer.profiles.amneziawg import (
    AmneziaWgServiceName,
    AmneziaWgSettings,
    DecodeAmneziaWgSecrets,
    EncodeAmneziaWgSecrets,
    GenerateAmneziaWgSecrets,
    PrepareAmneziaWg,
)
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vless import (
    LEGACY_XRAY_VERSION,
    XRAY_VERSION,
    DecodeVlessMaterial,
    EncodeVlessMaterial,
    GenerateVlessMaterial,
    PrepareVless,
    VlessRealitySettings,
    VlessServiceName,
)
from flayer.profiles.vpn import (
    ParseVpnProfile,
    PreparedVpnTransport,
    VpnEndpoint,
    VpnError,
    VpnProfile,
)
from flayer.providers.contracts import (
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import JsonValue, ResourceSpec
from flayer.providers.yandex import YandexCloudSettings
from flayer.providers.yandex_lifecycle import ValidateComputeShape, YandexLifecycleProvider

ADMIN_USERNAME = "flayer-admin"
MAX_SERIAL_BYTES = 1024 * 1024
# LF-normalized installers from the released 2.0.0 baseline and PR #117.
LEGACY_VLESS_INSTALLERS = frozenset({
    "655da13c3b949c835c8429bdc8532f7fce23fb37fc20fe0c2c4de701a0dd3532",
    "ab0867185961a307af41b06acc86cc244dc19303004f9da5e925f26ab7996e12",
})
PROJECT_TEMPLATE = '# Edit the folder, image, management address, and Reality target before preparation.\n# Project files contain private keys and must remain outside Git and shared directories.\nschema_version = 1\n\n[identity]\nproject = "my-vpn"\nstack = "gateway"\nprovider = "yandex-cloud"\nscope_id = "replace-with-folder-id"\nowner_id = "my-team"\n\n[cloud]\nyc_profile = "default"\nzone_id = "ru-central1-a"\nimage_id = "replace-with-ubuntu-2404-amd64-image-id"\nsubnet_cidr = "10.42.0.0/24"\nmanagement_cidrs = ["198.51.100.42/32"] # Replace with your current public IPv4 address.\n\n# Optional explicit sizing: uncomment the entire block before prepare.\n# Confirm regional availability and image minimum disk size first.\n# [resources]\n# platform_id = "standard-v3"\n# cores = 2\n# core_fraction = 50\n# memory_gib = 2\n# disk_size_gib = 10\n# disk_type = "network-hdd"\n\n[routes]\nmode = "full"\nipv4_cidrs = ["0.0.0.0/0"]\ndns_servers = ["1.1.1.1"]\nipv6_policy = "disabled" # Disable client IPv6 to prevent traffic bypass.\n\n[[devices]]\ndevice_id = "laptop"\nipv4_address = "10.66.0.2"\n\n[amneziawg]\nport = 51820\ntunnel_cidr = "10.66.0.0/24"\n\n[vless]\nport = 443\n# Example only: choose an accessible TLS 1.3 / HTTP/2 site for your server location.\ntarget_host = "www.microsoft.com"\nserver_name = "www.microsoft.com"\n'


@dataclass(frozen=True, slots=True)
class CloudPlacement:
    """Public placement and narrowly scoped administrator ingress for one Ubuntu guest."""

    ycProfile: str
    zoneId: str
    imageId: str
    subnetCidr: str
    managementCidrs: tuple[str, ...]

    def __post_init__(self) -> None:
        """Reject placeholders, public subnet ranges, and broadly exposed administration."""

        for value in (self.ycProfile, self.zoneId, self.imageId):
            ValidateIdentifier(value, "cloud setting")

            if value.startswith("replace-with-"):
                raise VpnError("Replace the example cloud identifiers in project.toml before preparation")

        try:
            network = ipaddress.IPv4Network(self.subnetCidr, strict=True)
            private = tuple(ipaddress.IPv4Network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

            if str(network) != self.subnetCidr or not 16 <= network.prefixlen <= 28 or not any(network.subnet_of(item) for item in private):
                raise ValueError

            if not isinstance(self.managementCidrs, tuple) or not 1 <= len(self.managementCidrs) <= 16:
                raise ValueError

            sources = tuple(ipaddress.IPv4Network(item, strict=True) for item in self.managementCidrs)

            if any(str(network) != item or network.prefixlen < 24 for network, item in zip(sources, self.managementCidrs, strict=True)):
                raise ValueError

            if any(left.overlaps(right) for index, left in enumerate(sources) for right in sources[index + 1:]):
                raise ValueError

        except (TypeError, ValueError):
            raise VpnError("Cloud subnet must be private /16../28 and management sources unique IPv4 /24../32") from None


def _PublicKey(content: bytes) -> str:
    """Read only a complete Ed25519 public key without exposing invalid file content."""

    try:
        parts = content.decode("ascii").strip().split()
        prefix = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)

        if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
            raise ValueError

        blob = base64.b64decode(parts[1], validate=True)

        if not blob.startswith(prefix) or len(blob) != len(prefix) + 32 or base64.b64encode(blob).decode("ascii") != parts[1]:
            raise ValueError

        return " ".join(parts[:2])

    except (ValueError, UnicodeError):
        raise VpnError("Project administration and guest trust require valid Ed25519 public keys") from None


@dataclass(frozen=True, slots=True)
class VpnResources:
    """Explicit initial server sizing; absence preserves the legacy project contract."""

    platformId: str
    cores: int
    coreFraction: int
    memoryGib: int
    diskSizeGib: int
    diskType: str

    def __post_init__(self) -> None:
        """Reject unsupported resource requests before key generation or cloud access."""

        try:
            ValidateComputeShape({
                "platform_id": self.platformId, "cores": self.cores,
                "core_fraction": self.coreFraction, "memory_gib": self.memoryGib,
            })

            if type(self.diskSizeGib) is not int or not 10 <= self.diskSizeGib <= 1024:
                raise ValueError("disk_size_gib must be an integer between 10 and 1024")

            if self.diskType not in ("network-hdd", "network-ssd"):
                raise ValueError("disk_type must be network-hdd or network-ssd")

        except ValueError as error:
            raise VpnError(str(error)) from None


@dataclass(frozen=True, slots=True)
class VpnProject:
    """Validated public project intent with explicit private local storage references."""

    root: Path = field(repr=False)
    vpn: VpnProfile
    cloud: CloudPlacement
    amneziawg: AmneziaWgSettings
    vless: VlessRealitySettings
    sshPublicKey: str = field(repr=False)
    resources: VpnResources | None = None

    def Fingerprint(self) -> str:
        """Bind prepared material to all public project settings without persisting secrets."""

        payload: dict[str, object] = {
            "vpn": _WireDict(self.vpn), "cloud": _WireDict(self.cloud),
            "amneziawg": _WireDict(self.amneziawg), "vless": _WireDict(self.vless),
            "ssh_public_key": self.sshPublicKey,
        }

        if self.resources is not None:
            payload["resources"] = _WireDict(self.resources)

        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    @property
    def Artifacts(self) -> Path:
        """Locate the existing private owned-artifact store within this project."""

        return self.root / "artifacts"


@dataclass(frozen=True, slots=True)
class VpnProjectReport:
    """Sanitized lifecycle and guest observations without transport material or provider output."""

    action: str
    status: str
    cloudStatus: str = "not-requested"
    guestStatus: str = "not-requested"
    clientExports: tuple[str, ...] = ()
    recoveryRequired: bool = False
    details: str = ""
    connectivityStatus: str = "not-verified"

    def ExitCode(self) -> int:
        """Treat incomplete cloud or guest operations as unsuccessful without claiming connectivity."""

        return 0 if self.status == "complete" else 1


@dataclass(frozen=True, slots=True)
class VpnRuntimeReport(VpnProjectReport):
    """Expose only runtime receipt and kernel facts, with client connectivity still unverified."""

    version: str = ""
    receiptSha256: str = ""
    previousReceiptSha256: str = ""
    binarySha256: str = ""
    upgradeStatus: str = "none"
    kernelRelease: str = "unavailable"
    kernelPackageVersion: str = "unavailable"
    kernelPatchStatus: str = "not-assessed"


def InitializeVpnProject(directory: str | Path) -> Path:
    """Create one exclusive private project and an administration key without cloud access."""

    path = Path(directory).absolute()
    ValidateSshPathSyntax(path)

    if os.name != "posix" or ".." in path.parts or any(item.is_symlink() for item in (path, *path.parents)):
        raise VpnError("Project initialization requires a POSIX path without symlinks or traversal")

    try:
        path.mkdir(mode=0o700)

    except OSError:
        raise VpnError("Project directory must be new and its parent must already exist") from None

    WritePrivate(path / "project.toml", PROJECT_TEMPLATE.encode("utf-8"))
    WritePrivate(path / ".gitignore", b"*\n")

    try:
        result = subprocess.run(
            ("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "flayer-admin", "-f", str(path / "admin-key")),
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=30,
        )

        if result.returncode != 0:
            raise VpnError("Unable to generate the project administration key; inspect the private project directory")

        (path / "admin-key.pub").chmod(0o600)
        PrivatePath(path / "admin-key")
        _PublicKey(ReadPrivate(path / "admin-key.pub"))
        (path / "artifacts").mkdir(mode=0o700)

    except (OSError, subprocess.TimeoutExpired):
        raise VpnError("Project initialization requires the OpenSSH ssh-keygen command") from None

    return path


def _Table(data: Mapping[str, object], key: str, fields: frozenset[str]) -> Mapping[str, object]:
    """Validate exact public nested fields before interpreting cloud or transport settings."""

    table = RequireTable(data[key], key)
    ValidateFields(table, fields, frozenset(), key)

    return table


def LoadVpnProject(directory: str | Path) -> VpnProject:
    """Read explicit editable public TOML and administration public key from private storage."""

    ValidateSshPathSyntax(Path(directory).absolute())
    root = PrivatePath(Path(directory), directory=True)
    PrivatePath(root / "artifacts", directory=True)

    try:
        data = tomllib.loads(ReadPrivate(root / "project.toml").decode("utf-8"))
        ValidateFields(data, frozenset({
            "schema_version", "identity", "cloud", "routes", "devices", "amneziawg", "vless",
        }), frozenset({"resources"}), "VPN project")
        ValidateSchemaVersion(data["schema_version"])
        cloud = _Table(data, "cloud", frozenset({"yc_profile", "zone_id", "image_id", "subnet_cidr", "management_cidrs"}))
        awg = _Table(data, "amneziawg", frozenset({"port", "tunnel_cidr"}))
        vless = _Table(data, "vless", frozenset({"port", "target_host", "server_name"}))
        identity = ParseIdentity(data["identity"])

        if identity.provider != "yandex-cloud" or identity.scopeId.startswith("replace-with-"):
            raise VpnError("Project requires an explicit Yandex Cloud folder ID")

        if not isinstance(cloud["management_cidrs"], list) or any(
            not isinstance(cloud[key], str) for key in ("yc_profile", "zone_id", "image_id", "subnet_cidr")
        ):
            raise VpnError("Cloud placement requires string settings and a management CIDR array")

        if not isinstance(awg["tunnel_cidr"], str) or not isinstance(vless["target_host"], str) or not isinstance(vless["server_name"], str):
            raise VpnError("Transport network and TLS target settings must be strings")

        vpn = ParseVpnProfile({
            "schema_version": 1, "identity": data["identity"], "routes": data["routes"],
            "devices": data["devices"], "listeners": [
                {"transport": "amneziawg", "protocol": "udp", "port": awg["port"], "source_cidrs": ["0.0.0.0/0"]},
                {"transport": "vless-reality", "protocol": "tcp", "port": vless["port"], "source_cidrs": ["0.0.0.0/0"]},
            ],
        })

        if vless["port"] == 22:
            raise VpnError("VLESS listener must not collide with the administration SSH port")

        for suffix in ("credentials", "bootstrap", "trust"):
            ValidateName(identity.stack + "-" + suffix, "project artifact name")

        placement = CloudPlacement(
            cast(str, cloud["yc_profile"]), cast(str, cloud["zone_id"]), cast(str, cloud["image_id"]),
            cast(str, cloud["subnet_cidr"]), tuple(cloud["management_cidrs"]),
        )
        resources = None

        if "resources" in data:
            sizing = _Table(data, "resources", frozenset({
                "platform_id", "cores", "core_fraction", "memory_gib", "disk_size_gib", "disk_type",
            }))
            resources = VpnResources(
                cast(str, sizing["platform_id"]), cast(int, sizing["cores"]),
                cast(int, sizing["core_fraction"]), cast(int, sizing["memory_gib"]),
                cast(int, sizing["disk_size_gib"]), cast(str, sizing["disk_type"]),
            )

            if placement.zoneId.startswith("kz1-") and resources.platformId != "standard-v3":
                raise VpnError("Kazakhstan VPN deployments require platform_id standard-v3")

        settings = AmneziaWgSettings(awg["tunnel_cidr"])

        if ipaddress.IPv4Network(settings.tunnelCidr).overlaps(ipaddress.IPv4Network(placement.subnetCidr)):
            raise VpnError("VPN tunnel and cloud subnet must not overlap")

        return VpnProject(
            root, vpn, placement, settings, VlessRealitySettings(vless["target_host"], vless["server_name"]),
            _PublicKey(ReadPrivate(root / "admin-key.pub")), resources,
        )

    except (ValueError, RecursionError) as error:
        if isinstance(error, VpnError):
            raise

        raise VpnError("Project configuration is invalid; check its documented fields and types") from None


def _Publish(project: VpnProject, bundle: ArtifactBundle) -> Path:
    """Preserve owned artifacts while recognizing exact historical VLESS installer programs."""

    directory = project.Artifacts / f"{bundle.kind}-{bundle.name}"

    if directory.exists() or directory.is_symlink():
        for artifact in bundle.files:
            actual = ReadOwnedArtifactFile(directory / artifact.name, bundle.identity, kind=bundle.kind, name=bundle.name)

            if (
                bundle.kind == "server"
                and bundle.name == project.vpn.identity.stack + "-vless-reality"
                and artifact.name == "install.py"
            ):
                # Verify the original manifest first; preserve its bytes instead of migrating secrets.
                actual = actual.replace(b"\r\n", b"\n")

                if (actual != artifact.content and hashlib.sha256(actual).hexdigest() in LEGACY_VLESS_INSTALLERS
                        and _VlessRuntimeVersion(project) == LEGACY_XRAY_VERSION):
                    continue

            if actual != artifact.content:
                raise VpnError("Existing project artifacts differ. Keep the old project for cloud cleanup, then initialize a new private project")

        return directory

    return WriteArtifactBundle(project.Artifacts, bundle)


def _VlessRuntimeVersion(project: VpnProject) -> str:
    """Retain a verified prepared bundle's runtime baseline without rewriting its manifest."""

    name = project.vpn.identity.stack + "-vless-reality"
    directory = project.Artifacts / ("server-" + name)

    if not directory.exists() and not directory.is_symlink():
        return XRAY_VERSION

    raw = ReadOwnedArtifactFile(directory / "deployment.json", project.vpn.identity, kind="server", name=name)

    try:
        descriptor = json.loads(raw)

        if not isinstance(descriptor, dict) or descriptor.get("xray_version") not in {LEGACY_XRAY_VERSION, XRAY_VERSION}:
            raise ValueError

        return str(descriptor["xray_version"])

    except (TypeError, ValueError, RecursionError):
        raise VpnError("Prepared VLESS runtime descriptor is invalid or unsupported") from None


def _MaterialBundle(project: VpnProject) -> ArtifactBundle:
    """Issue credentials once and retain them only in a separate controller-owned private bundle."""

    name = project.vpn.identity.stack + "-credentials"
    directory = project.Artifacts / f"server-{name}"
    proof = (project.Fingerprint() + "\n").encode("ascii")

    if directory.exists() or directory.is_symlink():
        existingProof = ReadOwnedArtifactFile(directory / "project.sha256", project.vpn.identity, kind="server", name=name)

        if existingProof != proof:
            raise VpnError("Project settings changed after preparation. Restore the old settings for destroy, then initialize a new private project")

        files = tuple(Artifact(filename, ReadOwnedArtifactFile(
            directory / filename, project.vpn.identity, kind="server", name=name,
        )) for filename in ("amneziawg.json", "vless.json"))
        DecodeAmneziaWgSecrets(files[0].content)
        DecodeVlessMaterial(files[1].content)

        return ArtifactBundle(project.vpn.identity, "server", name, (*files, Artifact("project.sha256", proof, False)))

    return ArtifactBundle(project.vpn.identity, "server", name, (
        Artifact("amneziawg.json", EncodeAmneziaWgSecrets(GenerateAmneziaWgSecrets(project.vpn))),
        Artifact("vless.json", EncodeVlessMaterial(GenerateVlessMaterial(project.vpn))),
        Artifact("project.sha256", proof, False),
    ))


def _Transports(project: VpnProject, material: ArtifactBundle, endpoint: str) -> tuple[PreparedVpnTransport, ...]:
    """Render both protocols from retained credentials and one observed server IPv4 endpoint."""

    content = {item.name: item.content for item in material.files}
    ports = {item.transport: item.port for item in project.vpn.listeners}

    return (
        PrepareAmneziaWg(project.vpn, VpnEndpoint(endpoint, ports["amneziawg"]), project.amneziawg, DecodeAmneziaWgSecrets(content["amneziawg.json"])),
        PrepareVless(project.vpn, VpnEndpoint(endpoint, ports["vless-reality"]), project.vless,
                     DecodeVlessMaterial(content["vless.json"]), runtimeVersion=_VlessRuntimeVersion(project)),
    )


def _Bootstrap(project: VpnProject) -> ArtifactBundle:
    """Create a nonsecret fresh Ubuntu bootstrap with separate VPN forwarding ownership."""

    firewall = [
        "#!/usr/sbin/nft -f", "flush ruleset", "table inet flayer_bootstrap {", "  chain input {",
        "    type filter hook input priority 0; policy drop;", "    ct state invalid drop",
        "    ct state established,related accept", '    iifname "lo" accept',
        "    udp sport 67 udp dport 68 accept", "    ip protocol icmp limit rate 10/second accept",
    ]

    for cidr in project.cloud.managementCidrs:
        firewall.append(f"    ip saddr {cidr} tcp dport 22 accept")

    for listener in project.vpn.listeners:
        for cidr in listener.sourceCidrs:
            firewall.append(f"    ip saddr {cidr} {listener.protocol} dport {listener.port} accept")

    firewall.extend(["  }", "}", ""])
    sshConfig = "\n".join((
        "Port 22", "UsePAM yes", "PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
        "PubkeyAuthentication yes", "AuthenticationMethods publickey", "AllowUsers " + ADMIN_USERNAME,
        "AuthorizedKeysFile /etc/ssh/flayer-admin-keys", "AuthorizedKeysCommand none", "TrustedUserCAKeys none",
        "X11Forwarding no", "AllowAgentForwarding no", "AllowTcpForwarding no", "PermitTunnel no",
        "HostKey /etc/ssh/ssh_host_ed25519_key", "",
    ))
    bootstrap = "\n".join((
        "#!/bin/sh", "set -eu", "install -d -m 0755 /run/sshd", "sshd -t",
        "nft --check --file /etc/nftables.conf", "sysctl --system",
        "systemctl enable --now nftables", "systemctl disable --now ssh.socket",
        "systemctl daemon-reload", "systemctl enable --now ssh.service", "systemctl restart ssh.service",
        "install -d -m 0700 /var/lib/f-layer", "touch /var/lib/f-layer/bootstrap-ready",
        "printf 'FLAYER_HOSTKEY " + project.Fingerprint() + " '",
        "cut -d ' ' -f 1,2 /etc/ssh/ssh_host_ed25519_key.pub", "",
    ))
    files = (
        ("/etc/ssh/sshd_config", "0644", sshConfig),
        ("/etc/ssh/flayer-admin-keys", "0644", project.sshPublicKey + "\n"),
        ("/etc/nftables.conf", "0644", "\n".join(firewall)),
        ("/etc/sysctl.d/90-flayer-vpn.conf", "0644", "net.ipv4.ip_forward=0\nnet.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\n"),
        ("/usr/local/sbin/flayer-bootstrap", "0700", bootstrap),
    )
    document = {
        "ssh_pwauth": False, "disable_root": True,
        "users": [{"name": ADMIN_USERNAME, "groups": ["sudo"], "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [project.sshPublicKey]}],
        "package_update": True, "package_upgrade": False,
        "packages": ["nftables", "python3", "ca-certificates"],
        "write_files": [{"path": path, "owner": "root:root", "permissions": permissions, "content": content}
                        for path, permissions, content in files],
        "runcmd": [["/bin/sh", "-c", "/usr/local/sbin/flayer-bootstrap > /dev/ttyS0 2>&1"]],
    }
    content = ("#cloud-config\n" + json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")

    return ArtifactBundle(project.vpn.identity, "server", project.vpn.identity.stack + "-bootstrap", (
        Artifact("cloud-init.json", content, False),
    ))


def _VerifyAdministrationKey(project: VpnProject) -> None:
    """Check the private administration key matches its public bootstrap value before cloud creation."""

    path = PrivatePath(project.root / "admin-key")

    try:
        result = subprocess.run(
            ("ssh-keygen", "-y", "-P", "", "-f", str(path)),
            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=10,
        )

        if result.returncode != 0 or _PublicKey(result.stdout) != project.sshPublicKey:
            raise VpnError("Administration key does not match admin-key.pub; restore the original project key pair")

    except (OSError, subprocess.TimeoutExpired):
        raise VpnError("Unable to verify the project administration key with ssh-keygen") from None


def PrepareVpnProject(project: VpnProject) -> VpnProjectReport:
    """Prepare private materials and verify both renderers locally without exporting false endpoints."""

    ValidateSshPathSyntax(project.root)
    _VerifyAdministrationKey(project)
    material = _MaterialBundle(project)
    transports = _Transports(project, material, "192.0.2.1")
    bootstrap = _Bootstrap(project)
    _Publish(project, material)

    for transport in transports:
        _Publish(project, transport.serverBundle)

    _Publish(project, bootstrap)

    return VpnProjectReport("prepare", "complete", details="Local server artifacts prepared; client exports follow actual address allocation")


def _Freeze(value: object) -> JsonValue:
    """Build immutable provider parameters from local compiler-owned dictionaries and arrays."""

    if isinstance(value, dict):
        return tuple((str(key), _Freeze(item)) for key, item in value.items())

    if isinstance(value, (list, tuple)):
        return tuple(_Freeze(item) for item in value)

    if value is None or type(value) in {str, int, bool}:
        return cast(JsonValue, value)

    raise VpnError("Compiled cloud parameters contain an unsupported value")


def CompileVpnProject(project: VpnProject) -> DeploymentPlan:
    """Compile six owned resources while binding only the verified nonsecret bootstrap file."""

    bundle = _Bootstrap(project)
    directory = project.Artifacts / f"server-{bundle.name}"
    path = directory / "cloud-init.json"
    actual = ReadOwnedArtifactFile(path, project.vpn.identity, kind="server", name=bundle.name)

    if actual != bundle.files[0].content:
        raise VpnError("Prepared bootstrap does not match the current public project settings")

    resources: list[ResourceSpec] = []

    def Add(logicalId: str, kind: ResourceKind, dependencies: tuple[str, ...], options: dict[str, object]) -> None:
        """Append one exact typed resource to the owned dependency graph."""

        resources.append(ResourceSpec(logicalId, kind, ValidateName(project.vpn.identity.stack + "-" + logicalId, "resource name"),
                                      tuple((key, _Freeze(value)) for key, value in options.items()), dependencies))

    Add("network", ResourceKind.NETWORK, (), {})
    Add("subnet", ResourceKind.SUBNET, ("network",), {
        "zone_id": project.cloud.zoneId, "ipv4_cidr": project.cloud.subnetCidr, "network_dependency": "network",
    })
    rules: list[object] = [{"direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": cidr}
                           for cidr in project.cloud.managementCidrs]
    rules.extend({"direction": "ingress", "protocol": listener.protocol, "from_port": listener.port,
                  "to_port": listener.port, "cidr": cidr} for listener in project.vpn.listeners for cidr in listener.sourceCidrs)
    rules.append({"direction": "egress", "protocol": "any", "cidr": "0.0.0.0/0"})
    Add("firewall", ResourceKind.SECURITY_GROUP, ("network",), {"network_dependency": "network", "rules": rules})
    Add("address", ResourceKind.ADDRESS, (), {"zone_id": project.cloud.zoneId})
    disk: dict[str, object] = {"zone_id": project.cloud.zoneId, "image_id": project.cloud.imageId, "size_gib": 20}
    instance: dict[str, object] = {
        "zone_id": project.cloud.zoneId, "cores": 2, "memory_gib": 2, "boot_disk_dependency": "boot-disk",
        "subnet_dependency": "subnet", "security_group_dependency": "firewall", "address_dependency": "address",
        "ssh_public_key": project.sshPublicKey, "ssh_username": ADMIN_USERNAME, "user_data_file": str(path),
        "user_data_sha256": hashlib.sha256(actual).hexdigest(),
    }

    if project.resources is not None:
        sizing = project.resources
        disk.update(size_gib=sizing.diskSizeGib, type=sizing.diskType)
        instance.update(cores=sizing.cores, memory_gib=sizing.memoryGib,
                        platform_id=sizing.platformId, core_fraction=sizing.coreFraction)

    Add("boot-disk", ResourceKind.DISK, (), disk)
    Add("instance", ResourceKind.INSTANCE, ("subnet", "firewall", "address", "boot-disk"), instance)

    return DeploymentPlan(project.vpn.identity, tuple(resources))


class VpnYandexProvider(YandexLifecycleProvider):
    """Add one authenticated read-only public host-key channel to the existing lifecycle adapter."""

    def ReadHostKey(self, instance: ProviderResource, fingerprint: str) -> str | None:
        """Extract one exact bootstrap marker without logging unrelated serial-console contents."""

        observed = self.GetResource(instance.reference)

        if observed.reference != instance.reference or observed.labels != instance.labels:
            raise VpnError("Instance ownership changed before authenticated host-key retrieval")

        payload = self._ReadJson(("compute", "instance", "get-serial-port-output", "--id", instance.reference.resourceId, "--port", "1"), "guest-host-key")

        if not isinstance(payload, dict) or not isinstance(payload.get("contents"), str):
            raise VpnError("Authenticated serial-console response is unavailable or malformed")

        contents = payload["contents"]

        try:
            if len(contents.encode("utf-8")) > MAX_SERIAL_BYTES:
                raise VpnError("Authenticated serial-console response exceeds its bounded size")

            marker = "FLAYER_HOSTKEY " + fingerprint + " "
            keys = {_PublicKey(line[len(marker):].encode("ascii")) for line in contents.splitlines() if line.startswith(marker)}

        except UnicodeError:
            raise VpnError("Authenticated serial-console host-key marker contains invalid encoding") from None

        if len(keys) > 1:
            raise VpnError("Authenticated serial console contains conflicting host-key pins")

        return next(iter(keys)) if keys else None


def _OwnedEndpoints(project: VpnProject, provider: VpnYandexProvider) -> tuple[ProviderResource, str]:
    """Resolve the exact persisted instance and address, then independently verify every owner field."""

    state = LoadState(project.root / "state.json", project.vpn.identity)

    if state is None:
        raise VpnError("Cloud state is unavailable; deploy the owned project first")

    observed = {}

    for logicalId, kind in (("instance", ResourceKind.INSTANCE), ("address", ResourceKind.ADDRESS)):
        locator = next((item for item in state.resources if item.logicalId == logicalId), None)

        if locator is None or locator.kind != kind.value:
            raise VpnError("Required cloud instance or reserved address is not recorded")

        reference = ResourceReference(project.vpn.identity.provider, project.vpn.identity.scopeId, kind, locator.resourceId)
        resource = provider.GetResource(reference)
        labels = tuple(sorted({**project.vpn.identity.OwnershipLabels(), "flayer-resource": logicalId}.items()))

        if resource.reference != reference or not resource.HasLabels(labels):
            raise VpnError("Observed VPN endpoint does not match the exact persisted ownership")

        observed[logicalId] = resource

    address = observed["address"].publicAddresses

    if len(address) != 1 or observed["instance"].publicAddresses != address:
        raise VpnError("Guest public IPv4 must match the exact owned reserved address")

    VpnEndpoint(address[0], 22)

    return observed["instance"], address[0]


def _HostTrust(
    project: VpnProject, provider: VpnYandexProvider, instance: ProviderResource, endpoint: str,
    *, wait: bool, sleep: Callable[[float], None] = time.sleep,
) -> Path:
    """Pin an IAM-authenticated public guest key and refuse changes to any existing trusted pin."""

    key = None

    for attempt in range(25 if wait else 1):
        key = provider.ReadHostKey(instance, project.Fingerprint())

        if key is not None:
            break

        if wait and attempt < 24:
            sleep(5)

    if key is None:
        raise VpnError("Guest bootstrap host key is not available yet; rerun deploy after cloud-init finishes")

    content = f"{endpoint} {key}\n".encode("ascii")
    bundle = ArtifactBundle(project.vpn.identity, "server", project.vpn.identity.stack + "-trust", (
        Artifact("known-hosts.txt", content, False),
    ))
    directory = _Publish(project, bundle)

    return directory / "known-hosts.txt"



def _Incomplete(action: str, report: LifecycleReport) -> VpnProjectReport:
    """Preserve truthful cloud progress and recovery requirements after an interrupted operation."""

    return VpnProjectReport(action, "incomplete", report.status, recoveryRequired=report.recoveryRequired,
                            details="Cloud operation did not finish; retained state is required for recovery")


def _CheckCloudAccess(provider: VpnYandexProvider) -> None:
    """Stop before lifecycle operations when the selected profile cannot read its folder."""

    status = provider.CheckAuthentication()

    if status.available and status.authenticated is True and status.errorCode is None:
        return

    code = status.errorCode or ProviderErrorCode.COMMAND_FAILED
    guidance = {
        ProviderErrorCode.AUTHENTICATION: "Reauthenticate the project.toml [cloud].yc_profile using the official local sign-in flow; keep credentials out of chat.",
        ProviderErrorCode.PERMISSION_DENIED: "Verify the configured profile and its read permission for identity.scope_id; do not change IAM automatically.",
        ProviderErrorCode.TIMEOUT: "Check connectivity and the configured profile with a read-only folder query; a timeout alone does not prove expired credentials or an API outage.",
        ProviderErrorCode.UNAVAILABLE: "Install or restore access to the Yandex Cloud CLI in this controller environment.",
    }.get(code, "Verify the configured profile, folder and CLI access with a read-only query before retrying.")

    raise VpnError(f"Cloud access preflight failed ({code.value}). {guidance} No cloud lifecycle operation started; existing state and recovery requirements are unchanged.")


def RunVpnProject(
    project: VpnProject, action: str, *, allowMutation: bool = False, scopeConfirm: str = "",
    rollback: bool = False, provider: VpnYandexProvider | None = None,
    guestFactory: Callable[..., SshGuestProvisioner] = SshGuestProvisioner,
) -> VpnProjectReport:
    """Compose explicit cloud consent, durable resources, authenticated guest install, and client export."""

    ValidateSshPathSyntax(project.root)

    if action not in {"prepare", "deploy", "status", "destroy", "recover"}:
        raise VpnError("VPN project action is unsupported")

    if action == "prepare":
        return PrepareVpnProject(project)

    if action in {"deploy", "destroy", "recover"} and (not allowMutation or scopeConfirm != project.vpn.identity.scopeId):
        raise VpnError("Cloud mutation requires --allow-mutation and exact --scope-confirm folder ID")

    if action == "deploy":
        state = LoadState(project.root / "state.json", project.vpn.identity)
        oldTrust = project.Artifacts / f"server-{project.vpn.identity.stack}-trust"
        oldExports = tuple(project.Artifacts / f"device-{device.deviceId}-{listener.transport}"
                            for device in project.vpn.devices for listener in project.vpn.listeners)

        if (state is None or not state.resources) and any(path.exists() or path.is_symlink() for path in (oldTrust, *oldExports)):
            raise VpnError("Previous server trust or client exports remain after cloud cleanup. Initialize a new private project before another deployment")

        PrepareVpnProject(project)

    plan = CompileVpnProject(project)
    provider = provider or VpnYandexProvider(YandexCloudSettings(project.vpn.identity.scopeId, project.cloud.ycProfile))
    engine = LifecycleEngine(plan, provider, project.root / "state.json")
    _CheckCloudAccess(provider)

    if action == "destroy":
        report = engine.Destroy()

        if report.status != "complete":
            return _Incomplete(action, report)

        return VpnProjectReport(action, "complete", "complete", "destroyed", details="Cloud resources removed; private local artifacts retained")

    if action == "recover":
        report = engine.Recover(rollback=rollback)

        if report.status != "complete":
            return _Incomplete(action, report)

        return VpnProjectReport(action, "complete", "complete", details="Cloud recovery completed; run deploy to provision and check both VPN services")

    report = engine.Create() if action == "deploy" else engine.Status()

    if report.status != "complete":
        return _Incomplete(action, report)

    instance, endpoint = _OwnedEndpoints(project, provider)
    trust = _HostTrust(project, provider, instance, endpoint, wait=action == "deploy")
    material = _MaterialBundle(project)
    transports = _Transports(project, material, endpoint)
    guest = guestFactory(VpnEndpoint(endpoint, 22), ADMIN_USERNAME, project.root / "admin-key", trust)

    if action == "deploy":
        for transport in transports:
            _Publish(project, transport.serverBundle)

        guest.Install(tuple((item.capabilities.transport, item.serverBundle) for item in transports))

    services = (AmneziaWgServiceName(project.vpn) + ".service", VlessServiceName(project.vpn))
    observations = guest.ServiceStatus(services)

    if not all(active for _, active in observations):
        return VpnProjectReport(action, "incomplete", "complete", "inactive", details="Cloud resources exist but a VPN service is not active")

    exports = []

    if action == "deploy":
        for transport in transports:
            for bundle in transport.deviceBundles:
                directory = _Publish(project, bundle)
                exports.append(str(directory.relative_to(project.root)))

    return VpnProjectReport(action, "complete", "complete", "services-active", tuple(exports),
                            details="Guest services are active; authenticated client traffic, DNS and Internet access are not verified")


def RunVpnRuntime(
    project: VpnProject, action: str, *, allowMutation: bool = False, scopeConfirm: str = "",
    expectedVersion: str = "", expectedReceipt: str = "", provider: VpnYandexProvider | None = None,
    guestFactory: Callable[..., SshGuestProvisioner] = SshGuestProvisioner,
) -> VpnRuntimeReport:
    """Maintain only an existing owned Xray runtime after explicit consent and read-only cloud checks."""

    ValidateVlessRuntimeOptions(action, expectedVersion, expectedReceipt)

    if action != "runtime-status" and (not allowMutation or scopeConfirm != project.vpn.identity.scopeId):
        raise VpnError("Runtime mutation requires --allow-mutation and exact --scope-confirm folder ID")

    if action == "runtime-status" and (allowMutation or scopeConfirm):
        raise VpnError("Runtime status is read-only and does not accept mutation consent")

    ValidateSshPathSyntax(project.root)
    _VerifyAdministrationKey(project)
    materialName = project.vpn.identity.stack + "-credentials"
    proof = ReadOwnedArtifactFile(project.Artifacts / ("server-" + materialName) / "project.sha256",
                                  project.vpn.identity, kind="server", name=materialName)

    if proof != (project.Fingerprint() + "\n").encode("ascii"):
        raise VpnError("Runtime maintenance requires the unchanged prepared project settings")

    name = project.vpn.identity.stack + "-vless-reality"
    directory = project.Artifacts / ("server-" + name)
    content = {filename: ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=name)
               for filename in ("server.json", "deployment.json", "install.py")}
    installer = files("flayer.profiles").joinpath("_vless_guest.py").read_bytes().replace(b"\r\n", b"\n")

    if (content["install.py"].replace(b"\r\n", b"\n") != installer
            and hashlib.sha256(content["install.py"].replace(b"\r\n", b"\n")).hexdigest() not in LEGACY_VLESS_INSTALLERS):
        raise VpnError("Prepared VLESS installer is not a recognized current or historical program")

    try:
        descriptor = json.loads(content["deployment.json"])
        owner = hashlib.sha256((json.dumps(_WireDict(project.vpn.identity), indent=2, sort_keys=True) + "\n").encode()).hexdigest()
        port = next(listener.port for listener in project.vpn.listeners if listener.transport == "vless-reality")

        if (not isinstance(descriptor, dict)
                or set(descriptor) != {"schema_version", "owner", "config_sha256", "port", "xray_version"}
                or type(descriptor["schema_version"]) is not int or descriptor["schema_version"] != 1
                or descriptor["owner"] != owner or type(descriptor["port"]) is not int or descriptor["port"] != port
                or descriptor["xray_version"] not in {LEGACY_XRAY_VERSION, XRAY_VERSION}
                or descriptor["config_sha256"] != hashlib.sha256(content["server.json"]).hexdigest()):
            raise ValueError

    except (ValueError, TypeError, StopIteration, RecursionError):
        raise VpnError("Prepared VLESS runtime bundle has an invalid descriptor or configuration hash") from None

    bundle = ArtifactBundle(project.vpn.identity, "server", name, (
        Artifact("server.json", content["server.json"]), Artifact("deployment.json", content["deployment.json"]),
        Artifact("install.py", installer),
    ))
    provider = provider or VpnYandexProvider(YandexCloudSettings(project.vpn.identity.scopeId, project.cloud.ycProfile))
    _CheckCloudAccess(provider)
    observed = LifecycleEngine(CompileVpnProject(project), provider, project.root / "state.json").Status()

    if observed.status != "complete":
        raise VpnError("Runtime maintenance requires complete owned cloud state; resolve lifecycle recovery first")

    instance, endpoint = _OwnedEndpoints(project, provider)
    trust = _HostTrust(project, provider, instance, endpoint, wait=False)
    guest = guestFactory(VpnEndpoint(endpoint, 22), ADMIN_USERNAME, project.root / "admin-key", trust)
    runtime = guest.VlessRuntime(bundle, action, expectedVersion=expectedVersion, expectedReceipt=expectedReceipt)

    return VpnRuntimeReport(
        action, "incomplete" if runtime["upgrade_status"] == "interrupted" else "complete", "complete", "runtime-observed",
        recoveryRequired=runtime["upgrade_status"] == "interrupted",
        details="Runtime receipt verified; kernel patch and client traffic remain unverified",
        version=runtime["version"], receiptSha256=runtime["receipt_sha256"], binarySha256=runtime["binary_sha256"],
        previousReceiptSha256=runtime["previous_receipt_sha256"],
        upgradeStatus=runtime["upgrade_status"], kernelRelease=runtime["kernel_release"],
        kernelPackageVersion=runtime["kernel_package_version"], kernelPatchStatus=runtime["kernel_patch_status"],
    )
