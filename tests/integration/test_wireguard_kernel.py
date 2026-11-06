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
from flayer.profiles.wireguard import GenerateWireGuardMaterial, PrepareWireGuard, WireGuardSettings

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
