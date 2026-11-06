"""Validate guest inputs and upstream policy without executing a guest command or local VPN."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from flayer.core.contracts import StackIdentity
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnListener, VpnProfile, VpnRoutes
from flayer.profiles.wireguard import GenerateWireGuardMaterial, PrepareWireGuard, WireGuardSettings


def Prepared(mode: str = "full") -> Any:
    """Use documentation-only identities and fresh synthetic credentials, entirely in memory."""

    profile = VpnProfile(
        StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone", "10.67.0.2"), VpnDevice("laptop", "10.67.0.3")),
        VpnRoutes(mode, ("0.0.0.0/0",) if mode == "full" else ("1.1.1.1/32",), ("1.1.1.1",), "disabled"),
        (VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)),),
    )
    settings = WireGuardSettings()

    return PrepareWireGuard(profile, VpnEndpoint("198.51.100.20", 51821), settings,
                            GenerateWireGuardMaterial(profile, settings))


def Vendor(status: str = "released", version: str = "6.8.0-999.999") -> bytes:
    """Model a future released vendor record; this is not a claim about the live pending fix."""

    return guest._Encode({"id": guest.KERNEL_CVE, "packages": [{"name": "linux", "statuses": [
        {"release_codename": "noble", "status": status, "description": version},
    ]}]})


def Nft(owner: str, nonce: str, *, echo: bool = False) -> bytes:
    """Model nft JSON with distinct handles and rule order, independently from the policy compiler."""

    table = guest._Table(owner)
    entries = [
        {"table": {"family": "ip", "name": table, "comment": f"flayer:wireguard:{owner}:{nonce}", "handle": 1}},
        {"chain": {"family": "ip", "table": table, "name": "forward", "type": "filter", "hook": "forward", "prio": -10, "policy": "accept", "handle": 2}},
        {"chain": {"family": "ip", "table": table, "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept", "handle": 3}},
        {"rule": {"family": "ip", "table": table, "chain": "forward", "expr": [{"accept": None}], "handle": 4}},
        {"rule": {"family": "ip", "table": table, "chain": "postrouting", "expr": [{"masquerade": None}], "handle": 5}},
    ]

    return guest._Encode({"nftables": [{"metainfo": {"version": "fixture"}},
                                     *[{"add": row} if echo else row for row in entries]]})


@pytest.mark.parametrize("mode", ["full", "split"])
def test_PreparationBindsServerAndProgramWithoutDeployingOrRotating(mode: str) -> None:
    """Validate complete sensitive bundles and their exact configuration/runtime digests."""

    prepared = Prepared(mode)
    files = {item.name: item.content for item in prepared.serverBundle.files}
    request = json.loads(files["deployment.json"])

    assert set(files) == {"server.conf", "deployment.json", "install.py"}
    assert request["program_sha256"] == guest._Digest(files["install.py"])
    assert request["config_sha256"] == guest._Digest(files["server.conf"])
    assert request["tools_version"] == guest.TOOLS_VERSION
    assert request["tools_sha256"] == guest.TOOLS_SHA256
    assert all(item.sensitive for item in prepared.serverBundle.files)
    assert request["port"] == 51821 and request["mtu"] == 1280
    assert len(prepared.deviceBundles) == 2
    assert all(tuple(item.name for item in bundle.files) == ("wireguard.conf",) for bundle in prepared.deviceBundles)
    assert files["server.conf"] not in repr(prepared).encode()
    assert b"10.67.0.2/32" in files["server.conf"] and b"10.67.0.3/32" in files["server.conf"]
    assert b"--allow-mutation" in files["install.py"]


@pytest.mark.parametrize("status", ["pending", "needed", "ignored", "not-affected", "deferred", "", None])
def test_UnreleasedVendorRecordCannotAuthorizeActivation(status: Any) -> None:
    """A described future version and upstream release cannot substitute for Ubuntu noble's released fix."""

    data = json.loads(Vendor(status))
    data["packages"][0]["statuses"].append({"release_codename": "upstream", "status": "released", "description": "6.8.0-1.1"})

    with pytest.raises(guest.GuestError, match="not confirmed"):
        guest._VendorEvidence(guest._Encode(data), "6.8.0-999.999")


@pytest.mark.parametrize("fault", ["cve", "duplicate-package", "duplicate-release", "missing", "version", "too-old", "json"])
def test_AmbiguousVendorEvidenceFailsClosed(fault: str) -> None:
    """Reject wrong release identity, unsupported version families and malformed responses."""

    data = json.loads(Vendor())
    version = "6.8.0-999.999"

    if fault == "cve":
        data["id"] = "CVE-0000-0000"

    elif fault == "duplicate-package":
        data["packages"].append(copy.deepcopy(data["packages"][0]))

    elif fault == "duplicate-release":
        data["packages"][0]["statuses"] *= 2

    elif fault == "missing":
        data["packages"] = []

    elif fault == "version":
        data["packages"][0]["statuses"][0]["description"] = "6.17.0-1.1"

    elif fault == "too-old":
        version = "6.8.0-998.998"

    with pytest.raises(guest.GuestError):
        guest._VendorEvidence(b"{" if fault == "json" else guest._Encode(data), version)


def test_ReleasedEvidenceIsBoundToExactResponseAndVersion(monkeypatch: pytest.MonkeyPatch) -> None:
    """Retain only a named CVE baseline, never a claim that every kernel issue is fixed."""

    monkeypatch.setattr(guest.time, "time", lambda: 1234567890)
    content = Vendor()
    evidence = guest._VendorEvidence(content, "6.8.0-1000.1000")

    assert evidence == {"cve_id": guest.KERNEL_CVE, "source_sha256": guest._Digest(content),
                        "fixed_version": "6.8.0-999.999", "checked_at": 1234567890}


@pytest.mark.parametrize("content", [b'{"a":1,"a":2}', b'{"a":{"x":1,"x":2}}', b"", b"[", b"x" * 1048577],
                         ids=["duplicate", "nested-duplicate", "empty", "syntax", "oversize"])
def test_ManagedJsonRejectsDuplicateAndUnboundedDataWithoutEcho(content: bytes) -> None:
    """No parser error includes private supplied input."""

    with pytest.raises(guest.GuestError, match="invalid or ambiguous"):
        guest._Json(content)


@pytest.mark.parametrize("fault", ["mode", "owner", "port", "subnet", "mtu", "routes", "overlap", "peers", "address", "key", "config", "program", "extra", "files"])
def test_DescriptorRefusesInvalidOrChangedInputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Test private descriptor validation on portable temporary files without POSIX permission emulation."""

    for item in Prepared().serverBundle.files:
        (tmp_path / item.name).write_bytes(item.content)

    path = tmp_path / "deployment.json"
    request = json.loads(path.read_bytes())

    if fault == "mode":
        request["schema_version"] = True

    elif fault == "owner":
        request["owner"] = "../foreign"

    elif fault == "port":
        request["port"] = True

    elif fault == "subnet":
        request["tunnel_cidr"] = "198.51.100.0/24"

    elif fault == "mtu":
        request["mtu"] = 9000

    elif fault == "routes":
        request["ipv4_routes"] = ["::/0"]

    elif fault == "overlap":
        request["ipv4_routes"] = ["0.0.0.0/0", "1.1.1.1/32"]

    elif fault == "peers":
        request["peers"] *= 2

    elif fault == "address":
        request["peers"][0]["ipv4_address"] = "10.67.0.1"

    elif fault == "key":
        request["peers"][0]["public_key"] = "private-invalid-value"

    elif fault in {"config", "program"}:
        request[fault + "_sha256"] = "0" * 64

    elif fault == "extra":
        request["command"] = "untrusted"

    else:
        (tmp_path / "foreign.conf").write_bytes(b"retain")

    path.write_bytes(guest._Encode(request))
    monkeypatch.setattr(guest, "_Directory", lambda *args, **kwargs: None)
    monkeypatch.setattr(guest, "_Read", lambda path, **kwargs: path.read_bytes())

    with pytest.raises((guest.GuestError, ValueError)) as caught:
        guest._Request(tmp_path)

    assert "private-invalid-value" not in str(caught.value)


@pytest.mark.parametrize("fault", ["none", "psk-public", "duplicate", "extra", "endpoint", "address", "port"])
def test_ServerConfigBindsPeerPolicyAndRejectsCredentialRoleConfusion(
    monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Use independent X25519 derivation instead of invoking wg or trusting the renderer's output."""

    files = {item.name: item.content for item in Prepared().serverBundle.files}
    request = json.loads(files["deployment.json"])
    config = files["server.conf"]

    def Run(command: list[str], *, payload: bytes | None = None, **kwargs: object) -> tuple[int, bytes]:
        """Implement only wg pubkey with an independent crypto library; refuse all other commands."""

        assert command == ["synthetic-wg", "pubkey"] and payload is not None
        key = X25519PrivateKey.from_private_bytes(base64.b64decode(payload.strip()))

        return 0, base64.b64encode(key.public_key().public_bytes_raw()) + b"\n"

    monkeypatch.setattr(guest, "_Run", Run)

    if fault == "psk-public":
        lines = config.decode().splitlines()
        index = next(index for index, line in enumerate(lines) if line.startswith("PresharedKey"))
        lines[index] = "PresharedKey = " + request["peers"][0]["public_key"]
        config = ("\n".join(lines) + "\n").encode()

    elif fault == "duplicate":
        config += b"AllowedIPs = 10.67.0.3/32\n"

    elif fault in {"extra", "endpoint"}:
        config += b"PostUp = untrusted\n" if fault == "extra" else b"Endpoint = 198.51.100.20:51821\n"

    elif fault == "address":
        config = config.replace(b"10.67.0.2/32", b"10.67.0.8/32")

    elif fault == "port":
        config = config.replace(b"51821", b"51822")

    if fault != "none":
        with pytest.raises(guest.GuestError):
            guest._Config(config, request, Path("synthetic-wg"))

    else:
        privateKey, publicKey, peers = guest._Config(config, request, Path("synthetic-wg"))

        assert privateKey != publicKey and len(peers) == 2
        assert set(peers) == {peer["public_key"] for peer in request["peers"]}


def test_NftNormalizationPreservesPolicyAndOwnership() -> None:
    """Only handles, metadata and add notifications may differ between staged and live rules."""

    owner, nonce = "a" * 64, "b" * 32
    original = Nft(owner, nonce)

    assert guest._NftFingerprint(original, owner, nonce) == guest._NftFingerprint(Nft(owner, nonce, echo=True), owner, nonce)
    changed = json.loads(original)
    changed["nftables"][3]["chain"]["prio"] = 0

    assert guest._NftFingerprint(guest._Encode(changed), owner, nonce) != guest._NftFingerprint(original, owner, nonce)

    with pytest.raises(guest.GuestError, match="foreign"):
        guest._NftFingerprint(original, owner, "c" * 32)

    with pytest.raises(guest.GuestError):
        guest._NftFingerprint(original, "c" * 64, nonce)


def test_CompiledFirewallIsInterfaceScopedAndNeverFlushesExistingPolicy() -> None:
    """Scope source validation, destinations and NAT to this transport, retaining other forwarding users."""

    request = json.loads(next(item.content for item in Prepared("split").serverBundle.files if item.name == "deployment.json"))
    text = guest._Firewall(request, "a" * 32).decode()

    assert "flush" not in text and "hook input" not in text
    assert "1.1.1.1/32" in text and "0.0.0.0/0" not in text
    assert guest._Interface(request["owner"]) in text and request["owner"] in text
    assert "masquerade" in text and "ct state established,related" in text
    assert "10.67.0.2" in text and "10.67.0.3" in text
