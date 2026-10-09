"""Exercise real offline distributions, rebuild parity and installed console behavior."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import venv
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path

import pytest
from packaging.requirements import Requirement

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class DistributionArtifacts:
    """Disposable artifacts and the isolated installation for a real package build."""

    wheel: Path
    sdist: Path
    rebuilt_wheel: Path
    python: Path
    console: Path
    outside_source: Path


def _Run(command: list[str], cwd: Path) -> str:
    """Run an offline packaging command with inherited source import overrides removed."""

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment.setdefault("SOURCE_DATE_EPOCH", "1704067200")
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INDEX"] = "1"
    environment["PIP_CONFIG_FILE"] = os.devnull
    result = subprocess.run(
        command, cwd=cwd, env=environment, capture_output=True, text=True,
        timeout=60, check=False,
    )

    assert result.returncode == 0, (
        f"Offline distribution command failed: {result.stdout}\n{result.stderr}"
    )

    return result.stdout


@pytest.fixture(scope="module")
def distribution_artifacts(tmp_path_factory: pytest.TempPathFactory) -> DistributionArtifacts:
    """Build, safely unpack, rebuild and install distributions without an index."""

    temporary_root = tmp_path_factory.mktemp("distribution")
    supplied_directory = os.environ.get("FLAYER_DISTRIBUTION_DIRECTORY")
    output = Path(supplied_directory).resolve() if supplied_directory else temporary_root / "original"

    if not supplied_directory:
        _Run(
            [sys.executable, "-m", "hatchling", "build", "--directory", str(output)],
            PROJECT_ROOT,
        )

    wheels = tuple(output.glob("*.whl"))
    sdists = tuple(output.glob("*.tar.gz"))
    assert len(wheels) == len(sdists) == 1, "Installation smoke requires one wheel and one sdist"
    wheel, sdist = wheels[0], sdists[0]
    unpacked = temporary_root / "unpacked"
    unpacked.mkdir()

    with tarfile.open(sdist) as archive:
        for member in archive.getmembers():
            relative_path = Path(member.name)
            assert (
                not relative_path.is_absolute() and ".." not in relative_path.parts
                and (member.isdir() or member.isfile())
            ), "Built sdist contains an unsafe path or nonregular member"

            if member.isdir():
                (unpacked / relative_path).mkdir(parents=True, exist_ok=True)
                continue

            stream = archive.extractfile(member)
            assert stream is not None, "Built sdist regular member has no content"
            destination = unpacked / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)

            with stream:
                destination.write_bytes(stream.read())

    source_root = next(unpacked.iterdir())
    rebuilt_output = temporary_root / "rebuilt"
    _Run(
        [sys.executable, "-m", "hatchling", "build", "--target", "wheel",
         "--directory", str(rebuilt_output)],
        source_root,
    )
    environment_root = temporary_root / "environment"
    venv.EnvBuilder(with_pip=False).create(environment_root)
    binary_root = environment_root / ("Scripts" if os.name == "nt" else "bin")
    python = binary_root / ("python.exe" if os.name == "nt" else "python")
    _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "install",
         "--no-index", str(wheel)],
        temporary_root,
    )

    return DistributionArtifacts(
        wheel, sdist, next(rebuilt_output.glob("*.whl")), python,
        binary_root / ("flayer.exe" if os.name == "nt" else "flayer"), temporary_root,
    )


def test_DistributionMetadataAndTypedEntryPoint(
    distribution_artifacts: DistributionArtifacts,
) -> None:
    """The wheel carries real public metadata, types, license and the correct entry point."""

    with zipfile.ZipFile(distribution_artifacts.wheel) as archive:
        names = archive.namelist()
        metadata_path = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadata_path))
        entry_points = next(name for name in names if name.endswith("/entry_points.txt"))

        assert metadata["Name"] == "f-layer", "Distribution name drifted from its public identity"
        assert metadata["Requires-Python"] == ">=3.11", "Supported Python floor drifted"
        assert metadata["License-Expression"] == "Apache-2.0", "Wheel lost its license expression"
        assert metadata["Description-Content-Type"] == "text/markdown", "README metadata is wrong"
        assert "flayer/py.typed" in names, "Typed package marker is absent from the wheel"
        assert any(name.endswith("/licenses/LICENSE") for name in names), "License file is absent"
        assert "flayer = flayer.__main__:Main" in archive.read(entry_points).decode(), (
            "Installed console entry point targets a different function"
        )
        assert all(
            "extra ==" in requirement for requirement in metadata.get_all("Requires-Dist", [])
        ), "Package unexpectedly requires runtime dependencies"
        assert "vpn" in metadata.get_all("Provides-Extra", []), "VPN installation extra is absent"
        requirements = [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]
        assert any(
            requirement.name == "cryptography" and str(requirement.specifier) == "==50.0.2"
            and requirement.marker is not None and requirement.marker.evaluate({"extra": "vpn"})
            for requirement in requirements
        ), "VPN extra lost its reviewed cryptography dependency"
        assert any(
            value == "Documentation, https://fuzzy-technologies.github.io/F-Layer/"
            for value in metadata.get_all("Project-URL", [])
        ), "Installed package metadata has no documentation link"

    with tarfile.open(distribution_artifacts.sdist) as archive:
        names = archive.getnames()

        assert any(name.endswith("/tools/validate.py") for name in names), (
            "Source distribution cannot reproduce the canonical validator"
        )
        assert not any(
            part in {".venv", "_build", "__pycache__", ".coverage", ".git"}
            for name in names for part in Path(name).parts
        ), "Source distribution contains local or generated artifacts"


def test_SdistRebuildAndIsolatedConsoleParity(
    distribution_artifacts: DistributionArtifacts,
) -> None:
    """An exported sdist rebuilds the same wheel and its installed CLI runs in isolation."""

    assert hashlib.sha256(distribution_artifacts.wheel.read_bytes()).digest() == hashlib.sha256(
        distribution_artifacts.rebuilt_wheel.read_bytes()
    ).digest(), "Wheel rebuilt from sdist differs from the original distribution"
    code = (
        "import flayer, importlib.metadata as m, json; "
        "print(json.dumps({'runtime':flayer.__version__, 'metadata':m.version('f-layer'), "
        "'path':flayer.__file__}))"
    )
    result = json.loads(_Run(
        [str(distribution_artifacts.python), "-I", "-c", code],
        distribution_artifacts.outside_source,
    ))

    assert result["runtime"] == result["metadata"], "Runtime and installed versions disagree"
    assert not Path(result["path"]).is_relative_to(PROJECT_ROOT), (
        "Isolated installation test imported the checkout instead of the wheel"
    )
    console_help = _Run(
        [str(distribution_artifacts.console), "--help"], distribution_artifacts.outside_source,
    )
    module_help = _Run(
        [str(distribution_artifacts.python), "-I", "-m", "flayer", "--help"],
        distribution_artifacts.outside_source,
    )

    assert console_help == module_help, "Console and module CLI help surfaces disagree"


def test_InstalledConsoleRunsWithoutSourceOrCloudTools(
    distribution_artifacts: DistributionArtifacts,
) -> None:
    """A fresh wheel installation performs real local diagnostics without cloud credentials."""

    result = json.loads(_Run(
        [str(distribution_artifacts.console), "check", "--format", "json"],
        distribution_artifacts.outside_source,
    ))

    assert result["command"] == "check", "Installed console ran the wrong diagnostic command"
    assert result["status"] == "ok", "Installed wheel cannot complete local runtime checks"
    assert result["checks"][0]["name"] == "python-runtime", "Runtime diagnostic is missing"
    assert "No broken requirements found" in _Run(
        [sys.executable, "-m", "pip", "--python", str(distribution_artifacts.python), "check"],
        distribution_artifacts.outside_source,
    ), "Fresh core installation has unresolved dependencies"
    assert _Run(
        [str(distribution_artifacts.python), "-I", "-c",
         "import importlib.util; print(importlib.util.find_spec('cryptography') is None)"],
        distribution_artifacts.outside_source,
    ).strip() == "True", "Core installation unexpectedly pulled in the optional VPN dependency"


def test_VpnExtraInstallsAndGeneratesKeys(
    distribution_artifacts: DistributionArtifacts, tmp_path: Path,
) -> None:
    """The documented VPN extra resolves offline and provides working key generation."""

    wheelhouse = os.environ.get("FLAYER_DISTRIBUTION_WHEELHOUSE")

    if not wheelhouse:
        pytest.skip("VPN dependency wheelhouse is required; release CI downloads it before smoke")

    environment_root = tmp_path / "vpn-environment"
    venv.EnvBuilder(with_pip=False).create(environment_root)
    binary_root = environment_root / ("Scripts" if os.name == "nt" else "bin")
    python = binary_root / ("python.exe" if os.name == "nt" else "python")
    wheel_specification = f"f-layer[vpn] @ {distribution_artifacts.wheel.as_uri()}"
    _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "install", "--no-index",
         "--find-links", str(Path(wheelhouse).resolve()), wheel_specification],
        tmp_path,
    )
    code = (
        "import json; from cryptography.hazmat.primitives.asymmetric import rsa, x25519; "
        "left=x25519.X25519PrivateKey.generate(); right=x25519.X25519PrivateKey.generate(); "
        "shared=left.exchange(right.public_key()) == right.exchange(left.public_key()); "
        "key=rsa.generate_private_key(public_exponent=65537,key_size=2048); "
        "print(json.dumps({'x25519':shared,'rsa_bits':key.key_size}))"
    )
    result = json.loads(_Run([str(python), "-I", "-c", code], tmp_path))

    assert result == {"x25519": True, "rsa_bits": 2048}, "Installed VPN crypto backend is unusable"
    assert "No broken requirements found" in _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "check"], tmp_path,
    ), "Fresh VPN installation has unresolved dependencies"


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
