"""Exercise the installed VPN project workflow outside the source checkout."""

from __future__ import annotations

import json
import os
import sys
import venv
from pathlib import Path

import pytest
from test_distribution import DistributionArtifacts, _Run
from test_distribution import distribution_artifacts as distribution_artifacts


def test_InstalledVpnConsoleCreatesAndPreparesPrivateProject(
    distribution_artifacts: DistributionArtifacts, tmp_path: Path,
) -> None:
    """Exercise project creation and both protocol renderers using an installed wheel outside source."""

    wheelhouse = os.environ.get("FLAYER_DISTRIBUTION_WHEELHOUSE")

    if not wheelhouse or os.name != "posix":
        pytest.skip("Installed VPN projects require the CI dependency wheelhouse and a POSIX host")

    environment_root = tmp_path / "project-environment"
    venv.EnvBuilder(with_pip=False).create(environment_root)
    python = environment_root / "bin" / "python"
    console = environment_root / "bin" / "flayer"
    _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "install", "--no-index",
         "--find-links", str(Path(wheelhouse).resolve()),
         f"f-layer[vpn] @ {distribution_artifacts.wheel.as_uri()}"], tmp_path,
    )
    project = tmp_path / "customer-project"
    _Run([str(console), "project", "init", str(project)], tmp_path)
    configuration = project / "project.toml"
    configuration.write_text(configuration.read_text().replace(
        "replace-with-folder-id", "example-folder"
    ).replace("replace-with-ubuntu-2404-amd64-image-id", "example-image") + '''
[resources]
platform_id = "standard-v3"
cores = 2
core_fraction = 50
memory_gib = 2
disk_size_gib = 10
disk_type = "network-hdd"
''')
    result = json.loads(_Run(
        [str(console), "vpn", "prepare", "--project", str(project), "--format", "json"], tmp_path,
    ))

    assert result["status"] == "complete", "Installed project preparation must render both transports"
    assert (project / "artifacts" / "server-gateway-amneziawg" / "install.sh").is_file()
    assert (project / "artifacts" / "server-gateway-vless-reality" / "install.py").is_file()
    assert not (project / "state.json").exists(), "Offline installed preparation must not create cloud state"
    assert not tuple((project / "artifacts").glob("device-*")), "Unallocated example endpoints must never become client exports"
    before = {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}
    _Run([str(python), "-c", (
        "from importlib.resources import files\n"
        "resource = files('flayer.profiles').joinpath('_vless_guest.py')\n"
        "resource.write_bytes(resource.read_bytes().replace(b'\\r\\n', b'\\n').replace(b'\\n', b'\\r\\n'))\n"
    )], tmp_path)
    repeated = json.loads(_Run(
        [str(console), "vpn", "prepare", "--project", str(project), "--format", "json"], tmp_path,
    ))

    assert repeated["status"] == "complete", "A CRLF packaged resource prevented installed project reuse"
    assert before == {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}, "Cross-package retry modified retained project artifacts"
    plan = json.loads(_Run([str(python), "-c", (
        "import json, sys\n"
        "from flayer.vpn_project import LoadVpnProject, CompileVpnProject\n"
        "from flayer.providers.yandex_lifecycle import _Rules\n"
        "project = LoadVpnProject(sys.argv[1])\n"
        "plan = {item.logical_id: dict(item.parameters) "
        "for item in CompileVpnProject(project).resources}\n"
        "plan['firewall_cli_rules'] = _Rules(plan['firewall']['rules'])\n"
        "print(json.dumps(plan))\n"
    ), str(project)], tmp_path))

    assert (plan["instance"]["platform_id"], plan["instance"]["core_fraction"]) == ("standard-v3", 50), "Installed wheel lost explicit compute sizing"
    assert (plan["boot-disk"]["size_gib"], plan["boot-disk"]["type"]) == (10, "network-hdd"), "Installed wheel lost HDD sizing"
    rules = plan["firewall_cli_rules"]

    assert "direction=egress,protocol=any,v4-cidrs=0.0.0.0/0,from-port=0,to-port=65535" in rules, "Installed VPN egress would be rejected by yc"
    assert any("protocol=udp," in rule and ",from-port=51820,to-port=51820" in rule for rule in rules), "AmneziaWG listener ports changed"
    assert any("protocol=tcp," in rule and ",from-port=443,to-port=443" in rule for rule in rules), "VLESS listener ports changed"
    failed = json.loads(_Run([str(python), "-c", (
        "import sys\n"
        "from unittest.mock import patch\n"
        "from flayer.__main__ import Main\n"
        "from flayer.providers.yandex import CommandResult\n"
        "with patch('flayer.providers.yandex.SubprocessCommandRunner.Run', return_value=CommandResult(1, '', 'Unauthenticated token expired fixture-secret')) as runner:\n"
        "    code = Main(['vpn', 'deploy', '--project', sys.argv[1], '--allow-mutation', '--scope-confirm', 'example-folder', '--format', 'json'])\n"
        "    assert code == 2 and runner.call_count == 1\n"
        "    assert runner.call_args.args[0][1:4] == ('resource-manager', 'folder', 'get')\n"
    ), str(project)], tmp_path))

    assert "preflight failed (authentication)" in failed["message"] and "Reauthenticate" in failed["message"]
    assert "fixture-secret" not in json.dumps(failed), "Installed CLI leaked raw authentication output"
    assert before == {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}, "Denied installed deployment changed retained project files"

    # Seed synthetic device artifacts through installed renderers, without claiming live deployment.
    _Run([str(python), "-c", (
        "import sys\n"
        "from flayer.vpn_project import LoadVpnProject, _MaterialBundle, _Transports\n"
        "from flayer.profiles.artifacts import WriteArtifactBundle\n"
        "project = LoadVpnProject(sys.argv[1])\n"
        "for transport in _Transports(project, _MaterialBundle(project), '203.0.113.20'):\n"
        "    for bundle in transport.device_bundles:\n"
        "        WriteArtifactBundle(project.Artifacts, bundle)\n"
    ), str(project)], tmp_path)
    exported_source = {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}

    for protocol in ("amneziawg", "vless-reality"):
        result = json.loads(_Run([str(console), "vpn", "export", "--project", str(project),
                                 "--device", "laptop", "--protocol", protocol,
                                 "--output", str(tmp_path / protocol), "--qr", "--format", "json"], tmp_path))
        directory = Path(result["client_exports"][0])

        assert result["status"] == "complete" and result["cloud_status"] == "not-requested"
        assert result["connectivity_status"] == "not-verified", "Local export claimed client traffic"
        assert (directory / "amnezia.vpn").read_bytes().startswith(b"vpn://")
        assert tuple(directory.glob("amnezia-qr-*.svg")), "Installed CLI did not export native scanner frames"
        assert "vpn://" not in json.dumps(result), "CLI printed a private connection key"

    assert exported_source == {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}, "Installed export modified source credentials or state"
