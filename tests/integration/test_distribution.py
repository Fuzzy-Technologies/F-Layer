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
    environment["SOURCE_DATE_EPOCH"] = "1704067200"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INDEX"] = "1"
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
    output = temporary_root / "original"
    _Run(
        [sys.executable, "-m", "hatchling", "build", "--directory", str(output)],
        PROJECT_ROOT,
    )
    wheel = next(output.glob("*.whl"))
    sdist = next(output.glob("*.tar.gz"))
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
         "--no-index", "--no-deps", str(wheel)],
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
