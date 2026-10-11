"""Deterministic gateway schema, resource graph, and initialization boundaries."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles import (
    BuildServerBundle,
    BuildSshDeviceBundle,
    CompileGateway,
    GatewayDevice,
    GatewayError,
    GatewayPlan,
    GatewayPort,
    GatewayProfile,
    GatewayTarget,
    GatewayTransport,
    LoadGatewayProfile,
    ParseGatewayProfile,
    RenderPlan,
    WriteArtifactBundle,
)

PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
).decode("ascii")
DEVICE_KEY = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"y" * 32
).decode("ascii")
IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")


def ProfileData() -> dict[str, object]:
    """Provide explicit synthetic placement and a public test key."""

    return {
        "transport": {
            "kind": "ssh-local-forward", "username": "gateway-tunnel",
            "targets": [{"name": "web", "host": "example.org", "port": 443}],
            "devices": [{"device_id": "laptop", "public_key": DEVICE_KEY, "source_cidrs": ["198.51.100.42/32"]}],
        },
        "schema_version": 1, "profile": "secure-gateway",
        "guest_contract": "ubuntu-24.04-cloud-init",
        "identity": {
            "project": "example", "stack": "gateway", "provider": "yandex-cloud",
            "scope_id": "example-folder", "owner_id": "example-owner",
        },
        "gateway": {
            "zone_id": "example-zone", "image_id": "example-image",
            "subnet_cidr": "10.42.0.0/24", "ssh_public_key": PUBLIC_KEY,
            "management_cidrs": ["198.51.100.42/32"],
        },
        "service_ports": [{"protocol": "udp", "port": 51820, "cidrs": ["0.0.0.0/0"]}],
    }


def Profile() -> GatewayProfile:
    """Create validated synthetic intent for tests without infrastructure access."""

    return ParseGatewayProfile(ProfileData())


def test_ProfileDefaultsRemainExplicitAndSecure() -> None:
    """Prevent metadata fallback, public SSH ingress, and transport installation claims."""

    profile = Profile()
    bundle = BuildServerBundle(profile)
    data = json.loads(bundle.files[0].content.removeprefix(b"#cloud-config\n"))
    files = {item["path"]: item["content"] for item in data["write_files"]}

    assert profile.identity == IDENTITY
    assert data["ssh_pwauth"] is False and data["disable_root"] is True
    assert data["users"][0]["lock_passwd"] is True
    assert data["users"][0]["ssh_authorized_keys"] == [PUBLIC_KEY]
    assert "PasswordAuthentication no" in files["/etc/ssh/sshd_config"]
    assert "ip saddr 198.51.100.42/32 tcp dport 22 accept" in files["/etc/nftables.conf"]
    assert "ip saddr 0.0.0.0/0 tcp dport 22" not in files["/etc/nftables.conf"]
    assert "policy drop" in files["/etc/nftables.conf"]
    assert "net.ipv4.ip_forward=0" in files["/etc/sysctl.d/90-f-layer.conf"]
    assert "set -eu\n" in files["/usr/local/sbin/f-layer-bootstrap"]
    assert data["packages"] == ["nftables", "unattended-upgrades"]
    assert PUBLIC_KEY not in repr(profile) and PUBLIC_KEY not in repr(bundle)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("profile", "other"),
    ("guest_contract", "unknown"), ("credentials", {"token": "synthetic-secret"}),
    ("service_ports", {}), ("gateway", []), ("identity", []),
])
def test_ProfileRootSchemaFailsClosed(field: str, value: object) -> None:
    """Reject incompatible versions, typos, inline credentials, and structural coercion."""

    data = ProfileData()
    data[field] = value

    with pytest.raises(GatewayError) as caught:
        ParseGatewayProfile(data)

    assert "synthetic-secret" not in str(caught.value)


@pytest.mark.parametrize("field,value", [
    ("zone_id", "bad zone"), ("image_id", ""), ("subnet_cidr", "8.8.0.0/24"),
    ("subnet_cidr", "10.42.0.1/24"), ("subnet_cidr", "10.0.0.0/8"),
    ("subnet_cidr", "10.42.0.0/29"), ("subnet_cidr", "2001:db8::/64"),
    ("subnet_cidr", 123), ("management_cidrs", ["0.0.0.0/0"]),
    ("management_cidrs", ["198.51.100.0/24", "198.51.100.42/32"]),
    ("management_cidrs", ["198.51.100.42/32", "198.51.100.42/32"]),
    ("management_cidrs", []), ("management_cidrs", "198.51.100.42/32"),
    ("ssh_username", "root"), ("ssh_username", "admin;reboot"), ("ssh_username", 123),
    ("ssh_port", True), ("ssh_port", 0), ("ssh_port", 65536),
    ("cores", 0), ("cores", 33), ("memory_gib", 0), ("memory_gib", 65),
    ("boot_disk_gib", 9), ("boot_disk_gib", 257),
    ("private_key", "synthetic-private-value"),
])
def test_GatewaySettingsRejectUnsafeInput(field: str, value: object) -> None:
    """Exercise source scope, sizing, secret, and shell-injection schema boundaries."""

    data = ProfileData()
    settings = dict(data["gateway"])  # type: ignore[arg-type]
    settings[field] = value
    data["gateway"] = settings

    with pytest.raises(GatewayError) as caught:
        ParseGatewayProfile(data)

    assert "synthetic-private-value" not in str(caught.value)


@pytest.mark.parametrize("public_key", [
    "", "ssh-rsa AAAA", "ssh-ed25519 !!!!", "ssh-ed25519 AAAA",
    PUBLIC_KEY + " private-comment", PUBLIC_KEY.replace("ssh-ed25519 ", "ssh-ed25519  "),
    " ".join(("-----BEGIN", "OPENSSH", "PRIVATE", "KEY-----")), 123, "x" * 257,
])
def test_PublicKeyWireBoundary(public_key: object) -> None:
    """Reject malformed blobs, comments, unsupported algorithms, and private material."""

    data = ProfileData()
    settings = dict(data["gateway"])  # type: ignore[arg-type]
    settings["ssh_public_key"] = public_key
    data["gateway"] = settings

    with pytest.raises(GatewayError):
        ParseGatewayProfile(data)


@pytest.mark.parametrize("ports", [
    [{"protocol": "icmp", "port": 1, "cidrs": ["0.0.0.0/0"]}],
    [{"protocol": "tcp", "port": 22, "cidrs": ["0.0.0.0/0"]}],
    [{"protocol": "udp", "port": 0, "cidrs": ["0.0.0.0/0"]}],
    [{"protocol": "udp", "port": 80, "cidrs": "0.0.0.0/0"}],
    [{"protocol": 123, "port": 80, "cidrs": ["0.0.0.0/0"]}],
    [{"protocol": "udp", "port": 80, "cidrs": []}],
    [{"protocol": "udp", "port": 80, "cidrs": ["::/0"]}],
    [{"protocol": "udp", "port": 80, "cidrs": ["0.0.0.0/0"], "secret": "value"}],
    [{"protocol": "udp", "port": 80, "cidrs": ["0.0.0.0/0"]}] * 2,
    [{"protocol": "udp", "port": 100 + index, "cidrs": ["0.0.0.0/0"]} for index in range(9)],
])
def test_ServiceAllowancesAreBounded(ports: object) -> None:
    """Ensure service permissions cannot widen SSH access or expand without limits."""

    data = ProfileData()
    data["service_ports"] = ports

    with pytest.raises(GatewayError):
        ParseGatewayProfile(data)


def test_DirectModelsValidateAsStrictlyAsParser() -> None:
    """Keep immutable construction from bypassing decoded-input invariants."""

    profile = Profile()

    for changes in (
        {"identity": "foreign"}, {"schema_version": True}, {"service_ports": []},
        {"service_ports": ("bad",)}, {"management_cidrs": ["198.51.100.42/32"]},
        {"management_cidrs": tuple(f"198.51.100.{index}/32" for index in range(17))},
    ):
        with pytest.raises(ValueError):
            replace(profile, **changes)

    with pytest.raises(GatewayError):
        GatewayPlan("invalid")  # type: ignore[arg-type]

    with pytest.raises(GatewayError):
        GatewayPort("tcp", True, ("0.0.0.0/0",))


def test_CompiledPlanBindsSixOwnedResourcesAndArtifact(tmp_path: Path) -> None:
    """Expose boot-disk ownership and exact cloud-init content in deterministic lifecycle intent."""

    profile = Profile()
    directory = WriteArtifactBundle(tmp_path / "artifacts", BuildServerBundle(profile))
    path = directory / "server-cloud-init.json"
    rendered = RenderPlan(CompileGateway(profile), user_data_file=path)
    data = tomllib.loads(rendered)
    resources = {resource["logical_id"]: resource for resource in data["resources"]}
    parameters = resources["instance"]["parameters"]

    assert len(resources) == 6
    assert resources["boot-disk"]["kind"] == "disk"
    assert resources["boot-disk"]["parameters"]["image_id"] == "example-image"
    assert resources["instance"]["dependencies"] == ["subnet", "firewall", "address", "boot-disk"]
    assert parameters["boot_disk_dependency"] == "boot-disk"
    assert "boot_disk_gib" not in parameters and "image_id" not in parameters
    assert parameters["user_data_file"] == str(path.absolute())
    assert parameters["user_data_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert parameters["ssh_username"] == profile.ssh_username
    assert resources["firewall"]["kind"] == "security-group"
    assert resources["firewall"]["parameters"]["rules"] == [
        {"direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "198.51.100.42/32"},
        {"direction": "ingress", "protocol": "udp", "from_port": 51820, "to_port": 51820, "cidr": "0.0.0.0/0"},
        {"direction": "egress", "protocol": "any", "cidr": "0.0.0.0/0"},
    ]
    assert rendered == RenderPlan(CompileGateway(profile), user_data_file=path)


def test_RenderRefusesWrongArtifactAndInvalidPlan(tmp_path: Path) -> None:
    """Prevent stale or foreign initialization from silently changing deployment intent."""

    directory = WriteArtifactBundle(tmp_path / "artifacts", BuildServerBundle(Profile()))
    path = directory / "server-cloud-init.json"
    path.write_bytes(b"synthetic-secret-replacement")

    with pytest.raises(GatewayError) as caught:
        RenderPlan(CompileGateway(Profile()), user_data_file=path)

    assert "synthetic-secret" not in str(caught.value)

    with pytest.raises(GatewayError):
        RenderPlan("invalid", user_data_file=path)  # type: ignore[arg-type]


def test_LoadBoundedProfileAndSuppressReadFailures(tmp_path: Path) -> None:
    """Reject unreadable, recursive, oversized, and malformed input without echoing raw data."""

    path = tmp_path / "profile.toml"
    path.write_text('schema_version = 1\nsecret = "synthetic-secret"\n')

    with pytest.raises(GatewayError) as caught:
        LoadGatewayProfile(path)

    assert "synthetic-secret" not in str(caught.value)

    for content in (b"[invalid", b"\xff", b"x" * 65537, b"number=" + b"9" * 5000):
        path.write_bytes(content)

        with pytest.raises(GatewayError):
            LoadGatewayProfile(path)

    with pytest.raises(GatewayError):
        LoadGatewayProfile(tmp_path / "absent.toml")


def test_OptionalServicesAndCustomSshSettings(tmp_path: Path) -> None:
    """Preserve an explicit custom management port without installing any service."""

    profile = replace(Profile(), ssh_port=2222, service_ports=(), ssh_username="operator")
    directory = WriteArtifactBundle(tmp_path / "artifacts", BuildServerBundle(profile))
    data = tomllib.loads(RenderPlan(CompileGateway(profile), user_data_file=directory / "server-cloud-init.json"))
    rules = next(item for item in data["resources"] if item["kind"] == "security-group")["parameters"]["rules"]

    assert rules[0]["from_port"] == 2222
    assert len(rules) == 2


def test_RequiredProfileFieldsCannotBeOmitted() -> None:
    """Preserve explicit provider placement, ownership, and management sources."""

    data = ProfileData()

    for name in list(data):
        if name != "service_ports":
            incomplete = copy.deepcopy(data)
            incomplete.pop(name)

            with pytest.raises(GatewayError):
                ParseGatewayProfile(incomplete)


@pytest.mark.parametrize("host", [
    "*", "example.org:443", "-example.org", "example..org", "example.org.",
    "EXAMPLE.org", "0.0.0.0", "224.0.0.1", "001.2.3.4", "999.1.2.3", "::1",
    "example.org\nPermitOpen any", "x" * 64 + ".org", "localhost/path", "${HOST}",
])
def test_TransportDestinationsRejectWildcardsAndInjection(host: str) -> None:
    """Keep forwarding limited to exact nonexpanding names and TCP destinations."""

    with pytest.raises(GatewayError):
        GatewayTarget("target", host, 443)


@pytest.mark.parametrize("changes", [
    {"kind": "vpn"}, {"username": "root"}, {"targets": []}, {"targets": {}},
    {"devices": []}, {"devices": {}}, {"private_key": "synthetic-secret"},
    {"targets": [{"name": "web", "host": "example.org", "port": True}]},
    {"targets": [{"name": "web", "host": "example.org", "port": 443, "command": "reboot"}]},
    {"devices": [{"device_id": "laptop", "public_key": DEVICE_KEY, "source_cidrs": "198.51.100.42/32"}]},
    {"devices": [{"device_id": "laptop", "public_key": DEVICE_KEY, "source_cidrs": ["0.0.0.0/0"]}]},
])
def test_TransportSchemaIsConcreteAndBounded(changes: dict[str, object]) -> None:
    """Reject unsupported transports, missing devices, and implicit private credentials."""

    data = ProfileData()
    settings = dict(data["transport"])  # type: ignore[arg-type]
    settings.update(changes)
    data["transport"] = settings

    with pytest.raises(GatewayError) as caught:
        ParseGatewayProfile(data)

    assert "synthetic-secret" not in str(caught.value)


def test_TransportRoleKeysAndCollectionsCannotBeAmbiguous() -> None:
    """Separate administrator authority from each device forwarding credential."""

    profile = Profile()
    transport = profile.transport

    for changes in (
        {"transport": "invalid"},
        {"transport": replace(transport, username=profile.ssh_username)},
        {"transport": replace(transport, devices=(GatewayDevice("laptop", PUBLIC_KEY, ("198.51.100.42/32",)),))},
    ):
        with pytest.raises(GatewayError):
            replace(profile, **changes)

    for changes in (
        {"targets": []}, {"targets": ("invalid",)}, {"targets": transport.targets * 2},
        {"devices": []}, {"devices": ("invalid",)}, {"devices": transport.devices * 2},
        {"targets": tuple(GatewayTarget(f"target-{index}", "example.org", 400 + index) for index in range(9))},
        {"devices": transport.devices * 17},
    ):
        with pytest.raises(GatewayError):
            replace(transport, **changes)

    first = GatewayDevice("laptop", DEVICE_KEY, tuple(f"198.51.100.{index}/32" for index in range(16)))
    second = GatewayDevice("phone", PUBLIC_KEY, tuple(f"203.0.113.{index}/32" for index in range(16)))
    third_key = DEVICE_KEY[:-4] + "enp6"

    with pytest.raises(GatewayError):
        GatewayTransport("gateway-tunnel", transport.targets, (
            first, second, GatewayDevice("tablet", third_key, ("192.0.2.1/32",)),
        ))


def test_GeneratedServerActuallyRestrictsUsableTcpForwarding() -> None:
    """Provide a concrete transport while denying tunnel users shell and arbitrary destinations."""

    profile = Profile()
    data = json.loads(BuildServerBundle(profile).files[0].content.removeprefix(b"#cloud-config\n"))
    config = next(item["content"] for item in data["write_files"] if item["path"] == "/etc/ssh/sshd_config")
    keys = next(item for item in data["write_files"] if item["path"] == "/etc/ssh/f-layer-tunnel-keys")

    assert len(data["users"]) == 1, "The tunnel account must be created only after proving it was absent"
    assert keys["owner"] == "root:root"
    assert 'from="198.51.100.42/32",restrict,port-forwarding,permitopen="example.org:443" ' + DEVICE_KEY + "\n" == keys["content"]
    assert "Match User gateway-tunnel\n" in config and "    AllowTcpForwarding local\n" in config
    assert "PermitOpen example.org:443" in config
    assert "PermitListen none" in config and "MaxSessions 0" in config
    assert "AllowStreamLocalForwarding no" in config and "PermitTTY no" in config
    assert "gateway-admin@198.51.100.42/32" in config
    assert "gateway-tunnel@198.51.100.42/32" in config
    assert "AuthorizedKeysFile /etc/ssh/f-layer-admin-keys" in config
    assert "AuthorizedKeysFile /etc/ssh/f-layer-tunnel-keys" in config
    assert "AuthorizedKeysCommand none" in config and "TrustedUserCAKeys none" in config


def test_DeviceConfigurationHasExactLoopbackForwardsAndExplicitTrust(tmp_path: Path) -> None:
    """Generate a directly usable client configuration without reading key or trust files."""

    bundle = BuildSshDeviceBundle(
        Profile(), "laptop", endpoint="203.0.113.42", identity_file="/example/device key",
        known_hosts_file="/example/trusted hosts", local_ports=(8443,),
    )
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    config = (directory / "ssh-client.conf").read_text()

    assert "Host laptop\n" in config
    assert "User gateway-tunnel" in config
    assert 'IdentityFile "/example/device key"' in config
    assert 'UserKnownHostsFile "/example/trusted hosts"' in config
    assert "StrictHostKeyChecking yes" in config and "GlobalKnownHostsFile none" in config
    assert "LocalForward 127.0.0.1:8443 example.org:443" in config
    assert "ExitOnForwardFailure yes" in config and "SessionType none" in config
    assert "IdentityAgent none" in config
    assert "PRIVATE KEY" not in config
    assert json.loads((directory / "device-info.json").read_text())["status"] == "prepared-unverified"


@pytest.mark.parametrize("changes", [
    {"device_id": "unknown"}, {"endpoint": "host;reboot"}, {"local_ports": []},
    {"local_ports": ()}, {"local_ports": (1023,)}, {"local_ports": (65536,)},
    {"local_ports": (True,)}, {"local_ports": (8443, 8444)},
    {"identity_file": "relative-key"}, {"identity_file": "/key/%h"},
    {"identity_file": "/key/../private"}, {"identity_file": '/key/"\nProxyCommand reboot'},
    {"known_hosts_file": "/trust/${HOME}"}, {"known_hosts_file": "/trust/~user"},
])
def test_DeviceConfigurationRejectsExpansionAndBindingErrors(changes: dict[str, object]) -> None:
    """Block SSH directive injection and undeclared devices before exporting client intent."""

    settings = {
        "device_id": "laptop", "endpoint": "203.0.113.42", "identity_file": "/example/key",
        "known_hosts_file": "/example/trust", "local_ports": (8443,),
    }
    settings.update(changes)

    with pytest.raises(ValueError):
        BuildSshDeviceBundle(Profile(), **settings)  # type: ignore[arg-type]


def test_DuplicateLocalPortsAndExpandedRulesAreRejected() -> None:
    """Keep transport exports and provider ingress expansion finite and unambiguous."""

    profile = Profile()
    targets = (profile.transport.targets[0], GatewayTarget("database", "127.0.0.1", 5432))
    profile = replace(profile, transport=replace(profile.transport, targets=targets))

    with pytest.raises(GatewayError):
        BuildSshDeviceBundle(profile, "laptop", endpoint="gateway.example.org", identity_file="/example/key", known_hosts_file="/example/trust", local_ports=(8443, 8443))

    with pytest.raises(GatewayError):
        replace(profile, service_ports=tuple(GatewayPort("udp", 600 + index, tuple(f"192.0.2.{host}/32" for host in range(16))) for index in range(8)))

    with pytest.raises(ValueError):
        CompileGateway(replace(profile, identity=replace(IDENTITY, stack="x" * 63)))


def test_RuleBudgetReservesMandatoryEgressSlot(tmp_path: Path) -> None:
    """Keep every accepted gateway security group within the adapter's complete rule limit."""

    profile = Profile()
    ports = tuple(GatewayPort("udp", 700 + index, tuple(
        f"192.0.2.{host}/32" for host in range(count)
    )) for index, count in enumerate((16, 16, 16, 14)))
    profile = replace(profile, service_ports=ports)
    directory = WriteArtifactBundle(tmp_path / "artifacts", BuildServerBundle(profile))
    plan = tomllib.loads(RenderPlan(CompileGateway(profile), user_data_file=directory / "server-cloud-init.json"))
    rules = next(item for item in plan["resources"] if item["kind"] == "security-group")["parameters"]["rules"]

    assert len(rules) == 64, "The 63 ingress rule boundary must preserve one explicit egress rule"

    with pytest.raises(GatewayError):
        replace(profile, service_ports=ports[:-1] + (GatewayPort("udp", 703, tuple(f"192.0.2.{host}/32" for host in range(15))),))


@pytest.mark.skipif(shutil.which("sshd") is None, reason="OpenSSH server is an optional development validator")
def test_InstalledOpenSshParsesCompleteServerConfiguration(tmp_path: Path) -> None:
    """Validate concrete server syntax without host keys, accounts, or a running daemon."""

    data = json.loads(BuildServerBundle(Profile()).files[0].content.removeprefix(b"#cloud-config\n"))
    config = next(item["content"] for item in data["write_files"] if item["path"] == "/etc/ssh/sshd_config")
    path = tmp_path / "sshd_config"
    path.write_text(config)
    result = subprocess.run([str(shutil.which("sshd")), "-G", "-f", str(path)], capture_output=True, text=True, check=False, timeout=5)

    if result.returncode and "unknown option -- G" in result.stderr:
        pytest.skip("Installed OpenSSH predates offline -G configuration validation")

    assert result.returncode == 0, "Generated SSH server configuration must parse without startup"
    assert "allowtcpforwarding no\n" in result.stdout
    assert "allowstreamlocalforwarding no\n" in result.stdout
    assert "passwordauthentication no\n" in result.stdout


@pytest.mark.skipif(
    any(shutil.which(name) is None for name in ("sshd", "ssh-keygen"))
    or (os.getuid() == 0 and not Path("/run/sshd").is_dir()),
    reason="Server syntax validation requires OpenSSH and its existing privilege-separation directory",
)
def test_InstalledOpenSshEnforcesServerRoleConfig(tmp_path: Path) -> None:
    """Check effective role authority offline using only an isolated synthetic host key."""

    profile = Profile()
    data = json.loads(BuildServerBundle(profile).files[0].content.removeprefix(b"#cloud-config\n"))
    server_config = next(item["content"] for item in data["write_files"] if item["path"] == "/etc/ssh/sshd_config")
    server_path = tmp_path / "sshd_config"
    server_path.write_text(server_config)
    host_key = tmp_path / "synthetic-host-key"
    result = subprocess.run([
        str(shutil.which("ssh-keygen")), "-t", "ed25519", "-N", "", "-f", str(host_key),
    ], capture_output=True, check=False, text=True, timeout=5)

    assert result.returncode == 0, "Synthetic host key must remain inside the isolated test directory"

    for user, forwarding in (("gateway-tunnel", "local"), ("gateway-admin", "no")):
        result = subprocess.run([
            str(shutil.which("sshd")), "-T", "-f", str(server_path), "-h", str(host_key), "-C",
            f"user={user},host=client.example.org,addr=198.51.100.42",
        ], capture_output=True, check=False, text=True, timeout=5)

        assert result.returncode == 0, "Generated server configuration must parse in OpenSSH"
        assert f"allowtcpforwarding {forwarding}\n" in result.stdout

        if user == "gateway-tunnel":
            assert "maxsessions 0\n" in result.stdout and "permitopen example.org:443\n" in result.stdout


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client is an optional development validator")
def test_InstalledOpenSshParsesDeviceConfiguration(tmp_path: Path) -> None:
    """Verify client syntax without reading a private key, resolving DNS, or opening a socket."""

    profile = Profile()
    bundle = BuildSshDeviceBundle(profile, "laptop", endpoint="203.0.113.42", identity_file="/example/key", known_hosts_file="/example/trust", local_ports=(8443,))
    client_path = tmp_path / "ssh_client"
    client_path.write_bytes(bundle.files[0].content)
    result = subprocess.run([str(shutil.which("ssh")), "-G", "-F", str(client_path), "laptop"], capture_output=True, text=True, check=False, timeout=5)

    assert result.returncode == 0, "Generated device configuration must parse without network access"
    assert "stricthostkeychecking true\n" in result.stdout
    assert "localforward 127.0.0.1:8443 example.org:443\n" in result.stdout.replace("[", "").replace("]", "")


def test_UnicodeArtifactPathsAndWindowsDeviceReferencesRemainLiteral(tmp_path: Path) -> None:
    """Serialize actual Unicode scalar paths and Windows client references without expansion."""

    profile = Profile()
    directory = WriteArtifactBundle(tmp_path / "artifacts-🚀", BuildServerBundle(profile))
    plan = tomllib.loads(RenderPlan(CompileGateway(profile), user_data_file=directory / "server-cloud-init.json"))
    instance = next(item for item in plan["resources"] if item["kind"] == "instance")

    assert instance["parameters"]["user_data_file"] == str(directory / "server-cloud-init.json")

    bundle = BuildSshDeviceBundle(profile, "laptop", endpoint="203.0.113.42", identity_file="C:/Keys/laptop-key", known_hosts_file="C:/Keys/trusted-hosts", local_ports=(8443,))

    assert 'IdentityFile "C:/Keys/laptop-key"' in bundle.files[0].content.decode("utf-8")


def test_ServerInitializationRequiresMatchingOwnedProfile(tmp_path: Path) -> None:
    """Reject a foreign manifest even when its initialization bytes are identical."""

    profile = Profile()
    foreign = replace(profile, identity=replace(profile.identity, owner_id="different-owner"))
    directory = WriteArtifactBundle(tmp_path / "artifacts", BuildServerBundle(foreign))

    with pytest.raises(GatewayError):
        RenderPlan(CompileGateway(profile), user_data_file=directory / "server-cloud-init.json")

    other = replace(profile, ssh_port=2222)
    directory = WriteArtifactBundle(tmp_path / "second-root", BuildServerBundle(other))

    with pytest.raises(GatewayError):
        RenderPlan(CompileGateway(profile), user_data_file=directory / "server-cloud-init.json")


@pytest.mark.parametrize("lookup_status,useradd_status", [(0, 0), (2, 0), (3, 0), (2, 1)])
def test_BootstrapAccountGuardAndPersistentServiceActivation(tmp_path: Path, lookup_status: int, useradd_status: int) -> None:
    """Execute shell sequencing against isolated command fakes without touching host accounts or services."""

    data = json.loads(BuildServerBundle(Profile()).files[0].content.removeprefix(b"#cloud-config\n"))
    script = next(item["content"] for item in data["write_files"] if item["path"] == "/usr/local/sbin/f-layer-bootstrap")
    path = tmp_path / "bootstrap.sh"
    path.write_text(script)
    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "commands.log"

    for command in ("getent", "useradd", "usermod", "install", "sshd", "nft", "sysctl", "systemctl", "touch"):
        fake = commands / command
        status = lookup_status if command == "getent" else useradd_status if command == "useradd" else 0
        fake.write_text(
            '#!/bin/sh\n' + f'printf "%s\\n" "{command} $*" >> "$GATEWAY_TEST_LOG_PATH"\n'
            + f"exit {status}\n"
        )
        fake.chmod(0o700)

    result = subprocess.run(["/bin/sh", str(path)], capture_output=True, text=True, check=False, timeout=5, env={
        "PATH": str(commands), "GATEWAY_TEST_LOG_PATH": str(log),
    })
    calls = log.read_text().splitlines()

    if lookup_status != 2 or useradd_status:
        assert result.returncode == 1
        assert not any("systemctl" in call or "touch" in call for call in calls)

        if lookup_status != 2:
            assert calls == ["getent passwd gateway-tunnel"]

        if lookup_status == 0:
            assert "already exists" in result.stderr

        elif lookup_status == 3:
            assert "Unable to verify" in result.stderr

    else:
        assert result.returncode == 0
        assert "useradd --create-home --shell /bin/bash --user-group gateway-tunnel" in calls
        assert "usermod --lock gateway-tunnel" in calls

        disable = calls.index("systemctl disable --now ssh.socket")
        reload = calls.index("systemctl daemon-reload")
        enable = calls.index("systemctl enable --now ssh.service")
        restart = calls.index("systemctl restart ssh.service")

        assert disable < reload < enable < restart
        assert calls[-1] == "touch /var/lib/f-layer/bootstrap-ready"
