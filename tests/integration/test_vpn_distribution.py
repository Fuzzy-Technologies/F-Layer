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
