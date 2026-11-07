"""Conform owned input replacement and boot replay only inside an ephemeral Linux CI network namespace."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from flayer import _vpn_host_input as host
from flayer._vpn_creation import LoadCreationBaseline, _Json
from flayer.profiles import (
    _host_input_guest,
    _host_input_policy,
    _protocol_reservation,
    _wireguard_guest,
    _wireguard_peer,
)
from flayer.vpn_project import InitializeVpnProject, LoadVpnProject, SelectedVpnProject
from flayer.vpn_project_v2 import PrepareSelectedProject

pytestmark = pytest.mark.skipif(
    os.name != "posix" or os.environ.get("FLAYER_WG_CONFORMANCE") != "isolated-ci",
    reason="Real input-table conformance runs only inside the explicitly isolated Linux CI namespace",
)


@pytest.mark.parametrize("protocols", [("wireguard",), ("amneziawg", "vless-reality", "wireguard")])
def test_AtomicInputDeltaBootReplayAndRollbackPreserveUnrelatedKernelPolicy(tmp_path: Path, protocols: tuple[str, ...]) -> None:
    """Use the real parser/kernel for original, final-disabled and coexisting transports without touching runner host networking."""

    root = InitializeVpnProject(tmp_path / "fixture-project", protocols=protocols)
    path = root / "project.toml"
    path.write_text(path.read_text(encoding="utf-8").replace("replace-with-folder-id", "example-folder").replace(
        "replace-with-ubuntu-2404-amd64-image-id", "example-image"), encoding="utf-8")
    project = LoadVpnProject(root)
    assert isinstance(project, SelectedVpnProject)
    PrepareSelectedProject(project)
    baseline = LoadCreationBaseline(project)
    before = host.BindBootstrap(baseline, project.cloud.managementCidrs, project.vpn.listeners)
    originalFiles = {str(item.relative_to(root)): hashlib.sha256(item.read_bytes()).hexdigest() for item in root.rglob("*") if item.is_file()}
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
    assert {str(item.relative_to(root)): hashlib.sha256(item.read_bytes()).hexdigest() for item in root.rglob("*") if item.is_file()} == originalFiles


def test_ReservedGuestInputBackendConformsWithRealNftAndPrivateFiles(tmp_path: Path) -> None:
    """Run the shipped stdlib backends with real coordination and absence proof inside a disposable Linux network namespace."""

    root = InitializeVpnProject(tmp_path / "controller", protocols=("amneziawg", "vless-reality"))
    path = root / "project.toml"
    path.write_text(path.read_text(encoding="utf-8").replace("replace-with-folder-id", "example-folder").replace(
        "replace-with-ubuntu-2404-amd64-image-id", "example-image"), encoding="utf-8")
    project = LoadVpnProject(root)
    assert isinstance(project, SelectedVpnProject)
    PrepareSelectedProject(project)
    before = host.BindBootstrap(LoadCreationBaseline(project), project.cloud.managementCidrs, project.vpn.listeners)
    transition = host.InputTransition(before, next(item for item in before.listeners if item.transport == "vless-reality"), "disable", "a" * 32)
    request = {"schema_version": 1, "cloud_plan_sha256": "b" * 64, "input": transition.Record()}
    requestPath = tmp_path / "public-input.json"
    requestPath.write_bytes(_Json(request))
    modules = (_wireguard_guest, _wireguard_peer, _protocol_reservation, _host_input_policy, _host_input_guest)
    helper = '''
import json
import os
from pathlib import Path
import sys
import time
import types

def Load(path):
    """Load shipped stdlib-only sources without the CLI package or third-party dependencies."""

    module = types.ModuleType(Path(path).stem)
    module.__file__ = path
    exec(compile(Path(path).read_bytes(), path, "exec"), module.__dict__)

    return module

guest, peer, authority, policy, inputs = [Load(path) for path in sys.argv[3:]]
fixture = Path(sys.argv[1])
fixture.mkdir(mode=0o700)
guest.BASE = fixture / "opt/flayer/wireguard"
guest.SYSTEMD = fixture / "systemd"
guest.LOCK = fixture / "operation.lock"
guest.SYSTEMD.mkdir(mode=0o755)
inputs.BOOT = fixture / "etc/nftables.conf"
inputs.BOOT.parent.mkdir(mode=0o755)
request = json.loads(Path(sys.argv[2]).read_bytes())
values = policy.Transition(request["input"])
inputs.BOOT.write_bytes(policy.Boot(values[0]))
inputs.BOOT.chmod(0o644)
guest._Run(["nft", "add", "table", "ip", "unrelated_fixture"])
guest._Run(["nft", "add", "chain", "ip", "unrelated_fixture", "output"])
unrelated = guest._Run(["nft", "-j", "list", "table", "ip", "unrelated_fixture"])[1]
guest._Run(["nft", "-f", "-"], payload=policy.Table(values[0]))
owner = policy.Owner(values[0])
intent = {"schema_version": 1, "owner": owner, "creation_sha256": values[0]["creation_sha256"],
          "previous_state_sha256": "c" * 64, "operation_id": request["input"]["operation_id"],
          "plan_sha256": policy.Digest(policy.Json(request)), "plan_expires_at": int(time.time()) + 600,
          "wireguard_state": "absent", "wireguard_receipt_sha256": "", "wireguard_absence_sha256": guest._AbsenceDigest(owner),
          "wireguard_history_sha256": peer._History(guest, owner)}
intent["previous_authority_sha256"] = authority._Initial(guest, intent)
reserved = authority.Reserve(guest, peer, intent, allowMutation=True)
authority.Expose(guest, peer, intent, reserved["reservation_sha256"], allowMutation=True)
prepared = inputs.Prepare(guest, peer, authority, policy, request, intent, allowMutation=True)
assert prepared["phase"] == "prepared"
applied = inputs.Apply(guest, peer, authority, policy, request, intent, allowMutation=True)
assert applied["phase"] == "applied"
assert inputs.Status(guest, peer, authority, policy, request, intent) == applied
assert inputs.Apply(guest, peer, authority, policy, request, intent, allowMutation=True) == applied
returned = inputs.Apply(guest, peer, authority, policy, request, intent, allowMutation=True, rollback=True)
assert returned["phase"] == "rolled-back"
assert inputs.Apply(guest, peer, authority, policy, request, intent, allowMutation=True, rollback=True) == returned
assert inputs.BOOT.read_bytes() == policy.Boot(values[2])
assert guest._Run(["nft", "-j", "list", "table", "ip", "unrelated_fixture"])[1] == unrelated
assert peer._History(guest, owner) == intent["wireguard_history_sha256"]
print(json.dumps({"prepared": prepared, "applied": applied, "restored": returned}))
'''
    arguments = [str(tmp_path / "isolated-guest"), str(requestPath), *(str(Path(module.__file__).resolve()) for module in modules)]
    result = subprocess.run(["sudo", "-n", "unshare", "--net", "--", "/usr/bin/python3", "-", *arguments],
                            input=helper.encode(), capture_output=True, check=False, timeout=120)

    assert result.returncode == 0, "Isolated reserved input transaction failed: " + result.stderr.decode(errors="replace")[:1000]
    outcomes = json.loads(result.stdout)
    assert outcomes["applied"]["boot_sha256"] == hashlib.sha256(transition.After().BootFile()).hexdigest()
    assert outcomes["restored"]["boot_sha256"] == hashlib.sha256(transition.Restored().BootFile()).hexdigest()
