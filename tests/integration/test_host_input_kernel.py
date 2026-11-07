"""Conform owned input replacement and boot replay only inside an ephemeral Linux CI network namespace."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from test_vpn_host_input import Policy

from flayer import _vpn_host_input as host
from flayer._vpn_creation import _Json

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.environ.get("FLAYER_WG_CONFORMANCE") != "isolated-ci",
    reason="Real input-table conformance runs only inside the explicitly isolated Linux CI namespace",
)


@pytest.mark.parametrize("protocols", [("wireguard",), ("amneziawg", "vless-reality", "wireguard")])
def test_AtomicInputDeltaBootReplayAndRollbackPreserveUnrelatedKernelPolicy(tmp_path: Path, protocols: tuple[str, ...]) -> None:
    """Use the real parser/kernel for original, final-disabled and coexisting transports without touching runner host networking."""

    _, _, before = Policy(tmp_path / "never-created", protocols)
    listener = next(item for item in before.listeners if item.transport == "wireguard")
    transition = host.InputTransition(before, listener, "disable", "a" * 32)
    after, restored = transition.After(), transition.Restored()
    contents = {"initial.nft": before.Table(), "new.nft": after.Table(), "live.nft": transition.LiveScript(),
                "restored.nft": restored.Table(), "rollback.nft": transition.LiveScript(rollback=True), "boot.nft": after.BootFile(),
                "invalid.nft": transition.LiveScript() + b"add rule inet missing_fixture input accept\n"}

    for name, content in contents.items():
        (tmp_path / name).write_bytes(content)

    helper = """
import json
import subprocess
import sys

def Run(arguments):
    return subprocess.run(arguments, capture_output=True, check=True, timeout=30).stdout.decode()

def Read():
    return json.loads(Run(["nft", "-j", "list", "table", "inet", "flayer_bootstrap"]))

def Compile(path):
    return json.loads(Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", path]))

initial, desired, live, restored, rollback, boot, invalid = sys.argv[1:]
Run(["nft", "add", "table", "ip", "unrelated_fixture"])
Run(["nft", "add", "chain", "ip", "unrelated_fixture", "output"])
Run(["nft", "add", "rule", "ip", "unrelated_fixture", "output", "counter"])
unrelatedBefore = json.loads(Run(["nft", "-j", "list", "table", "ip", "unrelated_fixture"]))
Run(["nft", "-f", initial])
original = Read()
rejected = subprocess.run(["nft", "-f", invalid], capture_output=True, check=False, timeout=30)
afterFailure = Read()
Run(["nft", "-f", live])
updated = Read()
Run(["nft", "-f", boot])
reloaded = Read()
Run(["nft", "-f", boot])
repeated = Read()
freshHelper = '''
import subprocess
import sys
subprocess.run(["nft", "-f", sys.argv[1]], capture_output=True, check=True, timeout=30)
subprocess.run(["nft", "-f", sys.argv[1]], capture_output=True, check=True, timeout=30)
print(subprocess.run(["nft", "-j", "list", "table", "inet", "flayer_bootstrap"], capture_output=True, check=True, timeout=30).stdout.decode())
'''
fresh = json.loads(Run(["unshare", "--net", "--", "/usr/bin/python3", "-c", freshHelper, boot]))
Run(["nft", "-f", rollback])
returned = Read()
unrelatedAfter = json.loads(Run(["nft", "-j", "list", "table", "ip", "unrelated_fixture"]))
print(json.dumps({"initial": original, "expected_initial": Compile(initial), "rejected": rejected.returncode != 0,
                  "after_failure": afterFailure, "updated": updated, "expected_updated": Compile(desired),
                  "reloaded": reloaded, "repeated": repeated, "fresh": fresh,
                  "restored": returned, "expected_restored": Compile(restored),
                  "unrelated_before": unrelatedBefore, "unrelated_after": unrelatedAfter}))
"""
    arguments = [str(tmp_path / name) for name in contents]
    result = subprocess.run(["sudo", "-n", "unshare", "--net", "--", "/usr/bin/python3", "-", *arguments],
                            input=helper.encode(), capture_output=True, check=False, timeout=120)

    assert result.returncode == 0, "Isolated input policy conformance failed: " + result.stderr.decode(errors="replace")[:1000]
    data = json.loads(result.stdout)
    oldFingerprint = before.NativeFingerprint(_Json(data["initial"]))
    expected = after.NativeFingerprint(_Json(data["expected_updated"]))

    assert data["rejected"] and before.NativeFingerprint(_Json(data["after_failure"])) == oldFingerprint
    assert before.NativeFingerprint(_Json(data["expected_initial"])) == oldFingerprint
    assert all(after.NativeFingerprint(_Json(data[name])) == expected for name in ("updated", "reloaded", "repeated", "fresh"))
    assert restored.NativeFingerprint(_Json(data["restored"])) == restored.NativeFingerprint(_Json(data["expected_restored"]))
    assert data["unrelated_before"] == data["unrelated_after"]
    assert not (tmp_path / "never-created").exists()
