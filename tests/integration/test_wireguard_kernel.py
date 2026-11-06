"""Check pinned wg and real nft JSON only inside an ephemeral Linux CI network namespace."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnListener, VpnProfile, VpnRoutes
from flayer.profiles.wireguard import (
    GenerateWireGuardMaterial,
    PrepareWireGuard,
    PrepareWireGuardPeerEnrollment,
    PrepareWireGuardPeerRevocation,
    WireGuardSettings,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.environ.get("FLAYER_WG_CONFORMANCE") != "isolated-ci",
    reason="Real kernel/tool conformance runs only in the explicitly isolated Linux CI namespace",
)


def test_PinnedToolsAndNftEchoMatchObservedKernelPolicy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify native output, strict normalized rules and unrelated-table preservation without host VPN routes."""

    binary = Path(os.environ["FLAYER_WG_TOOLS_BINARY"]).resolve(strict=True)
    profile = VpnProfile(
        StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone", "10.67.0.2"),),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)),),
    )
    settings = WireGuardSettings()
    prepared = PrepareWireGuard(profile, VpnEndpoint("198.51.100.20", 51821), settings,
                                GenerateWireGuardMaterial(profile, settings))
    files = {item.name: item.content for item in prepared.serverBundle.files}
    request = json.loads(files["deployment.json"])
    nonce = "a" * 32
    policy, config = tmp_path / "firewall.nft", tmp_path / "server.conf"
    policy.write_bytes(guest._Firewall(request, nonce))
    config.write_bytes(files["server.conf"])
    config.chmod(0o600)
    interface = guest._Interface(request["owner"])
    helper = """
import json
import subprocess
import sys

def Run(arguments):
    return subprocess.run(arguments, capture_output=True, check=True, timeout=30).stdout.decode()

policy, config, binary, interface, table = sys.argv[1:]
Run(["nft", "add", "table", "ip", "unrelated_fixture"])
echo = json.loads(Run(["nft", "-j", "-e", "-f", policy]))
live = json.loads(Run(["nft", "-j", "list", "table", "ip", table]))
Run(["ip", "link", "add", "name", interface, "type", "wireguard"])
Run([binary, "syncconf", interface, config])
dump = Run([binary, "show", interface, "dump"])
Run(["nft", "add", "rule", "ip", table, "forward", "accept"])
changed = json.loads(Run(["nft", "-j", "list", "table", "ip", table]))
unrelated = json.loads(Run(["nft", "-j", "list", "table", "ip", "unrelated_fixture"]))
Run(["ip", "link", "delete", "dev", interface])
print(json.dumps({"echo": echo, "live": live, "changed": changed, "unrelated": unrelated, "dump": dump}))
"""
    result = subprocess.run(
        ["sudo", "-n", "unshare", "--net", "--", "/usr/bin/python3", "-", str(policy), str(config),
         str(binary), interface, guest._Table(request["owner"])],
        input=helper.encode(), capture_output=True, check=False, timeout=120,
    )

    assert result.returncode == 0, "Isolated native conformance failed: " + result.stderr.decode(errors="replace")[:1000]
    data = json.loads(result.stdout)
    expected = guest._NftFingerprint(guest._Encode(data["echo"]), request["owner"], nonce)

    assert guest._NftFingerprint(guest._Encode(data["live"]), request["owner"], nonce) == expected
    assert guest._NftFingerprint(guest._Encode(data["changed"]), request["owner"], nonce) != expected
    assert any(item.get("table", {}).get("name") == "unrelated_fixture" for item in data["unrelated"]["nftables"])
    root = tmp_path / "owned"
    root.mkdir(mode=0o700)
    (root / "server.conf").write_bytes(files["server.conf"])
    (root / "server.conf").chmod(0o600)
    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())

    def Run(command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        """Compare real captured kernel state using the exact same pinned public-key derivation tool."""

        if command[1] == "show":
            return 0, data["dump"].encode()

        assert command[1] == "pubkey"
        process = subprocess.run([str(binary), "pubkey"], input=kwargs["payload"], capture_output=True, check=True, timeout=5)

        return 0, process.stdout

    monkeypatch.setattr(guest, "_Run", Run)
    guest._WireGuardState(root, request)


def test_RealPeerSyncAndAtomicTableReplacementRetainInterfaceAndUnrelatedPolicy(tmp_path: Path) -> None:
    """Conform enrollment, revocation and rejected nft batches inside a fresh CI namespace only."""

    from dataclasses import replace

    binary = Path(os.environ["FLAYER_WG_TOOLS_BINARY"]).resolve(strict=True)
    profile = VpnProfile(
        StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone", "10.67.0.2"), VpnDevice("laptop", "10.67.0.3")),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)),),
    )
    settings = WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    device = VpnDevice("tablet", "10.67.0.4")
    newPeer = GenerateWireGuardMaterial(replace(profile, devices=(device,)), settings).peers[0]
    expanded, expandedMaterial = PrepareWireGuardPeerEnrollment(profile, settings, material, device, newPeer)
    revoked, revokedMaterial = PrepareWireGuardPeerRevocation(expanded, settings, expandedMaterial, "phone")
    endpoint = VpnEndpoint("198.51.100.20", 51821)
    requests = []
    paths = []
    nonce = "a" * 32

    for name, desired, credentials in (("old", profile, material), ("enrolled", expanded, expandedMaterial), ("revoked", revoked, revokedMaterial)):
        bundle = PrepareWireGuard(desired, endpoint, settings, credentials).serverBundle
        files = {item.name: item.content for item in bundle.files}
        request = json.loads(files["deployment.json"])
        requests.append(request)
        policy, config = tmp_path / (name + ".nft"), tmp_path / (name + ".conf")
        policy.write_bytes(guest._Firewall(request, nonce))
        config.write_bytes(files["server.conf"])
        config.chmod(0o600)
        paths.extend((str(policy), str(config)))

    helper = """
import json
import subprocess
import sys

def Run(arguments, content=None):
    return subprocess.run(arguments, input=content, capture_output=True, check=True, timeout=30).stdout.decode()

def Observe(table):
    return json.loads(Run(["nft", "-j", "list", "table", "ip", table]))

def Replace(policy, table):
    with open(policy, "rb") as stream:
        content = ("delete table ip " + table + "\\n").encode() + stream.read()
    Run(["nft", "-f", "-"], content)

binary, interface, table, oldPolicy, oldConfig, newPolicy, newConfig, revokePolicy, revokeConfig = sys.argv[1:]
Run(["nft", "add", "table", "ip", "unrelated_fixture"])
unrelatedBefore = Observe("unrelated_fixture")
Run(["nft", "-f", oldPolicy])
oldLive = Observe(table)
bad = ("delete table ip " + table + "\\nadd rule ip missing_fixture absent_chain accept\\n").encode()
failure = subprocess.run(["nft", "-f", "-"], input=bad, capture_output=True, check=False, timeout=30)
if failure.returncode == 0:
    raise RuntimeError("Invalid nft batch was accepted")
afterFailure = Observe(table)
Run(["ip", "link", "add", "name", interface, "type", "wireguard"])
Run([binary, "syncconf", interface, oldConfig])
indexBefore = json.loads(Run(["ip", "-j", "link", "show", "dev", interface]))[0]["ifindex"]
Run([binary, "syncconf", interface, newConfig])
Replace(newPolicy, table)
enrolled = Observe(table)
enrolledDump = Run([binary, "show", interface, "dump"])
expectedEnrolled = json.loads(Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", newPolicy]))
Replace(revokePolicy, table)
Run([binary, "syncconf", interface, revokeConfig])
revoked = Observe(table)
revokedDump = Run([binary, "show", interface, "dump"])
expectedRevoked = json.loads(Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", revokePolicy]))
indexAfter = json.loads(Run(["ip", "-j", "link", "show", "dev", interface]))[0]["ifindex"]
unrelatedAfter = Observe("unrelated_fixture")
Run(["ip", "link", "delete", "dev", interface])
print(json.dumps({"old": oldLive, "after_failure": afterFailure, "enrolled": enrolled, "revoked": revoked,
                  "expected_enrolled": expectedEnrolled, "expected_revoked": expectedRevoked,
                  "enrolled_dump": enrolledDump, "revoked_dump": revokedDump,
                  "index_before": indexBefore, "index_after": indexAfter,
                  "unrelated_before": unrelatedBefore, "unrelated_after": unrelatedAfter}))
"""
    owner = requests[0]["owner"]
    result = subprocess.run(["sudo", "-n", "unshare", "--net", "--", "/usr/bin/python3", "-", str(binary),
                             guest._Interface(owner), guest._Table(owner), *paths],
                            input=helper.encode(), capture_output=True, check=False, timeout=180)

    assert result.returncode == 0, "Isolated peer/nft conformance failed: " + result.stderr.decode(errors="replace")[:1000]
    data = json.loads(result.stdout)
    def Fingerprint(key: str) -> str:
        """Compare independent echo/live observations through the strict production normalizer."""

        return guest._NftFingerprint(guest._Encode(data[key]), owner, nonce)

    assert Fingerprint("old") == Fingerprint("after_failure"), "A rejected atomic batch removed or changed the old owned table"
    assert Fingerprint("enrolled") == Fingerprint("expected_enrolled")
    assert Fingerprint("revoked") == Fingerprint("expected_revoked")
    assert Fingerprint("old") != Fingerprint("enrolled") != Fingerprint("revoked")
    assert data["index_before"] == data["index_after"], "Peer changes recreated the existing interface"
    assert [item for item in data["unrelated_before"]["nftables"] if "metainfo" not in item] == [
        item for item in data["unrelated_after"]["nftables"] if "metainfo" not in item]
    phone = next(peer.PublicKey for peer in material.peers if peer.deviceId == "phone")
    laptop = next(peer.PublicKey for peer in material.peers if peer.deviceId == "laptop")

    assert phone in data["enrolled_dump"] and phone not in data["revoked_dump"]
    assert laptop in data["enrolled_dump"] and laptop in data["revoked_dump"]
    assert newPeer.PublicKey in data["enrolled_dump"] and newPeer.PublicKey in data["revoked_dump"]
