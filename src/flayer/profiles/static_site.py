"""Prepare a bounded static HTTP page for an explicitly selected fresh Ubuntu guest."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
import ipaddress
import json
import os
import re
import stat
import struct
import tomllib
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from flayer.core.contracts import (
    IDENTITY_FIELDS,
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateIdentifier,
    ValidateName,
    ValidateSchemaVersion,
)
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    RemoveArtifactBundle,
    WriteArtifactBundle,
)

PROFILE_NAME = "static-site"
GUEST_CONTRACT = "ubuntu-24.04-cloud-init"
MAX_PROFILE_BYTES = 32768
CLOUD_INIT_FILENAME = "static-site-cloud-init.json"
PLAN_FILENAME = "deployment-plan.toml"
_USERNAME_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_PLACEMENT_FIELDS = frozenset({"zone_id", "image_id", "subnet_cidr"})
_SIZING_FIELDS = frozenset({"cores", "memory_gib", "boot_disk_gib"})


class StaticSiteError(ContractError):
    """The static site violates its bounded profile or prepared artifact contract."""


def _Integer(value: object, minimum: int, maximum: int, label: str) -> int:
    """Reject coercion and constrain resource requests before external operations."""

    if type(value) is not int or not minimum <= value <= maximum:
        raise StaticSiteError(f"{label} must be an integer within {minimum}..{maximum}")

    return value


def _Cidr(value: object, minimum_prefix: int, label: str) -> str:
    """Require an explicit canonical IPv4 network without host bits or IPv6."""

    if not isinstance(value, str):
        raise StaticSiteError(f"{label} must be a canonical IPv4 CIDR")

    try:
        network = ipaddress.IPv4Network(value, strict=True)

    except ValueError:
        raise StaticSiteError(f"{label} must be a canonical IPv4 CIDR") from None

    if str(network) != value or network.prefixlen < minimum_prefix:
        raise StaticSiteError(f"{label} must use canonical prefix /{minimum_prefix} or narrower")

    return value


def _Cidrs(value: object, minimum_prefix: int, label: str) -> tuple[str, ...]:
    """Bound rule expansion and reject duplicate or overlapping source networks."""

    if not isinstance(value, tuple) or not 1 <= len(value) <= 16:
        raise StaticSiteError(f"{label} must contain 1..16 immutable CIDRs")

    cidrs = tuple(_Cidr(item, minimum_prefix, label) for item in value)
    networks = tuple(ipaddress.IPv4Network(item) for item in cidrs)

    if any(left.overlaps(right) for index, left in enumerate(networks)
           for right in networks[index + 1:]):
        raise StaticSiteError(f"{label} must not contain duplicate or overlapping CIDRs")

    return cidrs


def _PublicKey(value: object) -> str:
    """Accept one canonical Ed25519 public wire key without comments or options."""

    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise StaticSiteError("admin public_key must be a complete Ed25519 public key")

    parts = value.split(" ")

    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise StaticSiteError("admin public_key must contain only its type and public blob")

    try:
        blob = base64.b64decode(parts[1], validate=True)
        expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)

        if len(blob) != len(expected) + 32 or not blob.startswith(expected):
            raise ValueError("Invalid public wire key")

        if base64.b64encode(blob).decode("ascii") != parts[1]:
            raise ValueError("Noncanonical public encoding")

    except (ValueError, binascii.Error):
        raise StaticSiteError("admin public_key must be a complete Ed25519 public key") from None

    return value


def _Username(value: object) -> str:
    """Require an explicit portable non-root administrator without command interpolation."""

    if (not isinstance(value, str) or _USERNAME_PATTERN.fullmatch(value) is None
        or value in {"root", "www-data", "nginx"}):
        raise StaticSiteError("admin username must be portable and separate from root and web accounts")

    return value


def _Text(value: object, maximum: int, label: str, *, multiline: bool = False) -> str:
    """Accept publishable bounded text, excluding controls and invalid Unicode scalars."""

    if not isinstance(value, str) or not value.strip():
        raise StaticSiteError(f"{label} must contain nonempty plain text")

    if any(unicodedata.category(character).startswith("C")
           and not (multiline and character == "\n") for character in value):
        raise StaticSiteError(f"{label} must not contain control characters")

    if len(value.encode("utf-8")) > maximum:
        raise StaticSiteError(f"{label} must not exceed {maximum} UTF-8 bytes")

    return value


@dataclass(frozen=True, slots=True)
class StaticSiteProfile:
    """Explicit Yandex placement and one escaped static page with separate SSH authority."""

    identity: StackIdentity
    zone_id: str
    image_id: str
    subnet_cidr: str
    admin_username: str
    admin_public_key: str = field(repr=False)
    admin_source_cidrs: tuple[str, ...]
    http_source_cidrs: tuple[str, ...]
    title: str = field(repr=False)
    body: str = field(repr=False)
    cores: int = 2
    memory_gib: int = 2
    boot_disk_gib: int = 20
    schema_version: int = 1
    guest_contract: str = GUEST_CONTRACT

    def __post_init__(self) -> None:
        """Keep direct construction as strict as the versioned TOML input boundary."""

        ValidateSchemaVersion(self.schema_version)

        if not isinstance(self.identity, StackIdentity) or self.identity.provider != "yandex-cloud":
            raise StaticSiteError("identity must explicitly select the supported yandex-cloud provider")

        if self.guest_contract != GUEST_CONTRACT:
            raise StaticSiteError("guest_contract must select ubuntu-24.04-cloud-init")

        ValidateIdentifier(self.zone_id, "zone_id")
        ValidateIdentifier(self.image_id, "image_id")
        network = ipaddress.IPv4Network(_Cidr(self.subnet_cidr, 16, "subnet_cidr"))
        private_ranges = tuple(ipaddress.IPv4Network(value) for value in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        ))

        if network.prefixlen > 28 or not any(network.subnet_of(item) for item in private_ranges):
            raise StaticSiteError("subnet_cidr must be RFC1918 with prefix /16../28")

        _Username(self.admin_username)
        _PublicKey(self.admin_public_key)
        _Cidrs(self.admin_source_cidrs, 24, "admin source CIDRs")
        _Cidrs(self.http_source_cidrs, 0, "HTTP source CIDRs")
        _Text(self.title, 160, "site title")
        _Text(self.body, 8192, "site body", multiline=True)
        _Integer(self.cores, 2, 32, "cores")
        _Integer(self.memory_gib, 1, 64, "memory_gib")
        _Integer(self.boot_disk_gib, 10, 256, "boot_disk_gib")


def ParseStaticSiteProfile(data: Mapping[str, object]) -> StaticSiteProfile:
    """Decode a strict concrete profile without accepting commands or private credentials."""

    try:
        ValidateFields(data, frozenset({
            "schema_version", "profile", "guest_contract", "identity", "placement", "admin", "site",
        }), frozenset(), "static-site profile")
        ValidateSchemaVersion(data["schema_version"])

        if data["profile"] != PROFILE_NAME or data["guest_contract"] != GUEST_CONTRACT:
            raise StaticSiteError("profile and guest_contract must select the supported static site")

        placement = RequireTable(data["placement"], "placement")
        admin = RequireTable(data["admin"], "admin")
        site = RequireTable(data["site"], "site")
        ValidateFields(placement, _PLACEMENT_FIELDS, _SIZING_FIELDS, "placement")
        ValidateFields(admin, frozenset({"username", "public_key", "source_cidrs"}),
                       frozenset(), "admin")
        ValidateFields(site, frozenset({"title", "body", "http_source_cidrs"}),
                       frozenset(), "site")

        if not isinstance(admin["source_cidrs"], list) or not isinstance(site["http_source_cidrs"], list):
            raise StaticSiteError("Admin and HTTP source CIDRs must be explicit arrays")

        return StaticSiteProfile(
            identity=ParseIdentity(data["identity"]),
            zone_id=ValidateIdentifier(placement["zone_id"], "zone_id"),
            image_id=ValidateIdentifier(placement["image_id"], "image_id"),
            subnet_cidr=_Cidr(placement["subnet_cidr"], 16, "subnet_cidr"),
            admin_username=_Username(admin["username"]),
            admin_public_key=_PublicKey(admin["public_key"]),
            admin_source_cidrs=tuple(admin["source_cidrs"]),
            http_source_cidrs=tuple(site["http_source_cidrs"]),
            title=_Text(site["title"], 160, "site title"),
            body=_Text(site["body"], 8192, "site body", multiline=True),
            cores=_Integer(placement.get("cores", 2), 2, 32, "cores"),
            memory_gib=_Integer(placement.get("memory_gib", 2), 1, 64, "memory_gib"),
            boot_disk_gib=_Integer(placement.get("boot_disk_gib", 20), 10, 256, "boot_disk_gib"),
        )

    except ContractError as error:
        raise StaticSiteError(str(error)) from None


def LoadStaticSiteProfile(path: str | Path) -> StaticSiteProfile:
    """Read bounded regular UTF-8 TOML without following symlinks or blocking on special files."""

    descriptor: int | None = None

    try:
        profile_path = Path(path).absolute()

        if ".." in profile_path.parts or any(item.is_symlink() for item in (profile_path, *profile_path.parents)):
            raise StaticSiteError("Profile paths must not contain traversal or symlinks")

        descriptor = os.open(profile_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_PROFILE_BYTES:
            raise StaticSiteError("Profile input must be a bounded regular file")

        with os.fdopen(descriptor, "rb") as source:
            descriptor = None
            raw = source.read(MAX_PROFILE_BYTES + 1)

        if len(raw) > MAX_PROFILE_BYTES:
            raise StaticSiteError("Static-site profile exceeds its bounded input size")

        data = tomllib.loads(raw.decode("utf-8"))

    except (OSError, ValueError, RecursionError):
        raise StaticSiteError("Unable to read a valid bounded static-site profile") from None

    finally:
        if descriptor is not None:
            os.close(descriptor)

    return ParseStaticSiteProfile(data)


@dataclass(frozen=True, slots=True)
class StaticSitePlan:
    """Immutable profile intent whose serialized plan binds an exact owned initialization."""

    profile: StaticSiteProfile

    def __post_init__(self) -> None:
        """Reject unsupported values before resource or artifact serialization."""

        if not isinstance(self.profile, StaticSiteProfile):
            raise StaticSiteError("profile must be a StaticSiteProfile")


def CompileStaticSite(profile: StaticSiteProfile) -> StaticSitePlan:
    """Validate composed names without invoking storage, lifecycle, or provider mutation."""

    plan = StaticSitePlan(profile)

    for logical_id in ("network", "subnet", "firewall", "address", "boot-disk", "instance", "plan"):
        ValidateName(profile.identity.stack + "-" + logical_id, "resource or bundle name")

    return plan


def _Page(profile: StaticSiteProfile) -> str:
    """Escape all profile text into fixed markup with no template or script execution."""

    title = html.escape(profile.title, quote=True)
    body = html.escape(profile.body, quote=True)

    return "\n".join([
        "<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{title}</title>", "</head>", "<body>", f"<h1>{title}</h1>",
        f'<p style="white-space: pre-wrap">{body}</p>', "</body>", "</html>", "",
    ])


def _Firewall(profile: StaticSiteProfile) -> str:
    """Allow declared SSH and HTTP sources while denying routed traffic and other ingress."""

    lines = [
        "#!/usr/sbin/nft -f", "flush ruleset", "table inet flayer_filter {", "  chain input {",
        "    type filter hook input priority 0; policy drop;", "    ct state invalid drop",
        "    ct state established,related accept", '    iifname "lo" accept',
        "    udp sport 67 udp dport 68 accept",
    ]

    for cidr in profile.admin_source_cidrs:
        lines.append(f"    ip saddr {cidr} tcp dport 22 accept")

    for cidr in profile.http_source_cidrs:
        lines.append(f"    ip saddr {cidr} tcp dport 80 accept")

    lines.extend([
        "  }", "  chain forward {", "    type filter hook forward priority 0; policy drop;",
        "  }", "}", "",
    ])

    return "\n".join(lines)


def _CloudInit(profile: StaticSiteProfile) -> bytes:
    """Generate only fixed nonsecret guest operations and escaped publishable page text."""

    ssh_configuration = "\n".join([
        "Port 22", "UsePAM yes", "PermitRootLogin no", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "StrictModes yes",
        "AuthorizedKeysFile /etc/ssh/f-layer-static-admin-keys", "AuthorizedKeysCommand none",
        "TrustedUserCAKeys none", "AuthorizedPrincipalsFile none", "AuthenticationMethods publickey",
        "AllowUsers " + " ".join(f"{profile.admin_username}@{cidr}" for cidr in profile.admin_source_cidrs),
        "MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no", "AllowAgentForwarding no",
        "AllowTcpForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no",
        "GatewayPorts no", "PermitUserRC no", "",
    ])
    nginx_configuration = "\n".join([
        "user www-data;", "worker_processes auto;", "pid /run/nginx.pid;",
        "events { worker_connections 128; }", "http {", "    default_type text/html;",
        "    server_tokens off;", "    access_log off;", "    server {", "        listen 80 default_server;",
        "        server_name _;", "        root /var/www/f-layer-static;", "        autoindex off;",
        "        add_header X-Content-Type-Options nosniff always;",
        "        add_header Content-Security-Policy \"default-src 'none'; style-src 'unsafe-inline'\" always;",
        "        location = / { try_files /index.html =404; }",
        "        location = /index.html { try_files /index.html =404; }",
        "        location / { return 404; }", "    }", "}", "",
    ])
    sysctl_configuration = "\n".join([
        "net.ipv4.ip_forward=0", "net.ipv4.conf.all.accept_redirects=0",
        "net.ipv4.conf.default.accept_redirects=0", "net.ipv4.conf.all.send_redirects=0",
        "net.ipv4.conf.default.send_redirects=0", "net.ipv4.conf.all.accept_source_route=0",
        "net.ipv4.conf.default.accept_source_route=0", "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1", "",
    ])
    bootstrap = "\n".join([
        "#!/bin/sh", "set -eu", "install -d -m 0755 /run/sshd",
        "chown root:root /etc/ssh/f-layer-static-admin-keys",
        "chmod 0644 /etc/ssh/f-layer-static-admin-keys",
        "chown root:root /var/www/f-layer-static /var/www/f-layer-static/index.html",
        "chmod 0755 /var/www/f-layer-static", "chmod 0644 /var/www/f-layer-static/index.html",
        "sshd -t", "nft --check --file /etc/nftables.conf", "nginx -t -c /etc/nginx/nginx.conf",
        "sysctl --system", "systemctl enable --now nftables",
        "systemctl enable --now unattended-upgrades", "systemctl disable --now ssh.socket",
        "systemctl daemon-reload", "systemctl enable --now ssh.service",
        "systemctl restart ssh.service", "systemctl enable --now nginx.service",
        "systemctl restart nginx.service", "",
    ])
    files = [
        ("/etc/ssh/sshd_config", "0644", ssh_configuration),
        ("/etc/ssh/f-layer-static-admin-keys", "0644", profile.admin_public_key + "\n"),
        ("/etc/nginx/nginx.conf", "0644", nginx_configuration),
        ("/var/www/f-layer-static/index.html", "0644", _Page(profile)),
        ("/etc/sysctl.d/90-f-layer-static.conf", "0644", sysctl_configuration),
        ("/etc/nftables.conf", "0644", _Firewall(profile)),
        ("/usr/local/sbin/f-layer-static-bootstrap", "0700", bootstrap),
    ]
    data = {
        "ssh_pwauth": False, "disable_root": True,
        "users": [{
            "name": profile.admin_username, "groups": ["sudo"], "shell": "/bin/bash",
            "lock_passwd": True, "sudo": "ALL=(ALL) NOPASSWD:ALL",
        }],
        "package_update": True, "package_upgrade": False,
        "packages": ["nginx", "nftables", "unattended-upgrades"],
        "write_files": [{
            "path": path, "owner": "root:root", "permissions": permissions, "content": content,
        } for path, permissions, content in files],
        "runcmd": [["/bin/sh", "/usr/local/sbin/f-layer-static-bootstrap"]],
    }

    return ("#cloud-config\n" + json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")


def BuildStaticSiteBundle(profile: StaticSiteProfile) -> ArtifactBundle:
    """Create public initialization bytes without credentials or guest readiness claims."""

    CompileStaticSite(profile)

    return ArtifactBundle(profile.identity, "server", profile.identity.stack, (
        Artifact(CLOUD_INIT_FILENAME, _CloudInit(profile), sensitive=False),
    ))


def RenderStaticSitePlan(plan: StaticSitePlan, *, user_data_file: str | Path) -> str:
    """Bind the existing six-resource lifecycle contract to verified owned initialization."""

    if not isinstance(plan, StaticSitePlan):
        raise StaticSiteError("plan must be a StaticSitePlan")

    profile = plan.profile
    artifact_path = Path(user_data_file)
    expected = _CloudInit(profile)

    if artifact_path.name != CLOUD_INIT_FILENAME:
        raise StaticSiteError("Initialization must reference the exact static-site artifact filename")

    try:
        actual = ReadOwnedArtifactFile(artifact_path, profile.identity, kind="server",
                                       name=profile.identity.stack)

    except ContractError:
        raise StaticSiteError("Prepared static-site artifact ownership or integrity is invalid") from None

    if actual != expected:
        raise StaticSiteError("Initialization artifact does not match the compiled static-site profile")

    def Quote(value: str) -> str:
        """Serialize Unicode scalar strings as valid TOML without path expansion."""

        return json.dumps(value, ensure_ascii=False)

    lines = ["schema_version = 1", f"profile = {Quote(PROFILE_NAME)}", "", "[identity]"]

    for key in sorted(IDENTITY_FIELDS):
        lines.append(f"{key} = {Quote(getattr(profile.identity, key))}")

    def AddResource(
        logical_id: str, kind: str, dependencies: tuple[str, ...], parameters: Mapping[str, object],
    ) -> None:
        """Render deterministic scalar resource intent without observed cloud identifiers."""

        lines.extend([
            "", "[[resources]]", f"logical_id = {Quote(logical_id)}", f"kind = {Quote(kind)}",
            f"name = {Quote(ValidateName(profile.identity.stack + '-' + logical_id, 'resource name'))}",
            "dependencies = [" + ", ".join(Quote(item) for item in dependencies) + "]",
            "[resources.parameters]",
        ])

        for key, value in parameters.items():
            if isinstance(value, str):
                rendered = Quote(value)

            elif type(value) is int:
                rendered = str(value)

            else:
                raise StaticSiteError("Resource parameters must be explicit scalar values")

            lines.append(f"{key} = {rendered}")

    AddResource("network", "network", (), {})
    AddResource("subnet", "subnet", ("network",), {
        "zone_id": profile.zone_id, "ipv4_cidr": profile.subnet_cidr,
        "network_dependency": "network",
    })
    AddResource("firewall", "security-group", ("network",), {"network_dependency": "network"})

    for port, cidrs in ((22, profile.admin_source_cidrs), (80, profile.http_source_cidrs)):
        for cidr in cidrs:
            lines.extend([
                "[[resources.parameters.rules]]", 'direction = "ingress"', 'protocol = "tcp"',
                f"from_port = {port}", f"to_port = {port}", f"cidr = {Quote(cidr)}",
            ])

    lines.extend([
        "[[resources.parameters.rules]]", 'direction = "egress"', 'protocol = "any"',
        'cidr = "0.0.0.0/0"',
    ])
    AddResource("address", "address", (), {"zone_id": profile.zone_id})
    AddResource("boot-disk", "disk", (), {
        "zone_id": profile.zone_id, "image_id": profile.image_id, "size_gib": profile.boot_disk_gib,
    })
    AddResource("instance", "instance", ("subnet", "firewall", "address", "boot-disk"), {
        "zone_id": profile.zone_id, "cores": profile.cores, "memory_gib": profile.memory_gib,
        "boot_disk_dependency": "boot-disk", "subnet_dependency": "subnet",
        "security_group_dependency": "firewall", "address_dependency": "address",
        "ssh_public_key": profile.admin_public_key, "ssh_username": profile.admin_username,
        "user_data_file": str(artifact_path.absolute()),
        "user_data_sha256": hashlib.sha256(expected).hexdigest(),
    })

    return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True)
class StaticSitePreparation:
    """Local bundle references for a prepared plan; deployment and readiness remain unverified."""

    server_directory: Path
    plan_directory: Path

    @property
    def PlanFile(self) -> Path:
        """Locate the prepared TOML inside its separately owned private plan bundle."""

        return self.plan_directory / PLAN_FILENAME


def PrepareStaticSite(profile: StaticSiteProfile, *, artifact_root: str | Path) -> StaticSitePreparation:
    """Publish exclusive owned bundles; preserve a verified plan after publication failure."""

    plan = CompileStaticSite(profile)
    server_bundle = BuildStaticSiteBundle(profile)
    server_directory = WriteArtifactBundle(artifact_root, server_bundle)
    plan_text: str | None = None

    try:
        plan_text = RenderStaticSitePlan(plan, user_data_file=server_directory / CLOUD_INIT_FILENAME)
        plan_directory = WriteArtifactBundle(artifact_root, ArtifactBundle(
            profile.identity, "server", profile.identity.stack + "-plan", (
                Artifact(PLAN_FILENAME, plan_text.encode("utf-8"), sensitive=False),
            ),
        ))

    except BaseException:
        published_plan = False

        if plan_text is not None:
            try:
                actual = ReadOwnedArtifactFile(
                    Path(artifact_root) / ("server-" + profile.identity.stack + "-plan") / PLAN_FILENAME,
                    profile.identity, kind="server", name=profile.identity.stack + "-plan",
                )
                published_plan = actual == plan_text.encode("utf-8")

            except ContractError:
                pass

        if not published_plan:
            RemoveArtifactBundle(
                artifact_root, profile.identity, kind="server", name=profile.identity.stack,
                expected_bundle=server_bundle,
            )

        raise

    return StaticSitePreparation(server_directory, plan_directory)


def Main(argv: Sequence[str] | None = None) -> int:
    """Prepare bounded local artifacts only; never instantiate or invoke a cloud provider."""

    parser = argparse.ArgumentParser(description="Prepare an owned static-site lifecycle plan locally")
    parser.add_argument("profile_file", help="Explicit version-one static-site TOML profile")
    parser.add_argument("--artifact-root", required=True, help="Private POSIX artifact root")
    arguments = parser.parse_args(argv)

    try:
        prepared = PrepareStaticSite(LoadStaticSiteProfile(arguments.profile_file),
                                     artifact_root=arguments.artifact_root)

    except ContractError:
        print(json.dumps({"status": "failed", "reason": "Profile or owned artifact preparation failed"}))

        return 1

    print(json.dumps({"status": "prepared-unverified", "plan_file": str(prepared.PlanFile.absolute())},
                     sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
