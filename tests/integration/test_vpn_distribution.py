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
    ).replace("replace-with-ubuntu-2404-amd64-image-id", "example-image"))
    result = json.loads(_Run(
        [str(console), "vpn", "prepare", "--project", str(project), "--format", "json"], tmp_path,
    ))

    assert result["status"] == "complete", "Installed project preparation must render both transports"
    assert (project / "artifacts" / "server-gateway-amneziawg" / "install.sh").is_file()
    assert (project / "artifacts" / "server-gateway-vless-reality" / "install.py").is_file()
    assert not (project / "state.json").exists(), "Offline installed preparation must not create cloud state"
    assert not tuple((project / "artifacts").glob("device-*")), "Unallocated example endpoints must never become client exports"
