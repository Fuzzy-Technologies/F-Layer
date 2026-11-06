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
    rebuiltWheel: Path
    python: Path
    console: Path
    outsideSource: Path


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


@pytest.fixture(scope="module", name='distributionArtifacts')
def DistributionArtifactsFixture(tmp_path_factory: pytest.TempPathFactory) -> DistributionArtifacts:
    """Build, safely unpack, rebuild and install distributions without an index."""

    temporaryRoot = tmp_path_factory.mktemp("distribution")
    suppliedDirectory = os.environ.get("FLAYER_DISTRIBUTION_DIRECTORY")
    output = Path(suppliedDirectory).resolve() if suppliedDirectory else temporaryRoot / "original"

    if not suppliedDirectory:
        _Run(
            [sys.executable, "-m", "hatchling", "build", "--directory", str(output)],
            PROJECT_ROOT,
        )

    wheels = tuple(output.glob("*.whl"))
    sdists = tuple(output.glob("*.tar.gz"))

    assert len(wheels) == len(sdists) == 1, "Installation smoke requires one wheel and one sdist"

    wheel, sdist = wheels[0], sdists[0]
    unpacked = temporaryRoot / "unpacked"
    unpacked.mkdir()

    with tarfile.open(sdist) as archive:
        for member in archive.getmembers():
            relativePath = Path(member.name)

            assert (
                not relativePath.is_absolute() and ".." not in relativePath.parts
                and (member.isdir() or member.isfile())
            ), "Built sdist contains an unsafe path or nonregular member"

            if member.isdir():
                (unpacked / relativePath).mkdir(parents=True, exist_ok=True)
                continue

            stream = archive.extractfile(member)

            assert stream is not None, "Built sdist regular member has no content"

            destination = unpacked / relativePath
            destination.parent.mkdir(parents=True, exist_ok=True)

            with stream:
                destination.write_bytes(stream.read())

    sourceRoot = next(unpacked.iterdir())
    rebuiltOutput = temporaryRoot / "rebuilt"
    _Run(
        [sys.executable, "-m", "hatchling", "build", "--target", "wheel",
         "--directory", str(rebuiltOutput)],
        sourceRoot,
    )
    environmentRoot = temporaryRoot / "environment"
    venv.EnvBuilder(with_pip=False).create(environmentRoot)
    binaryRoot = environmentRoot / ("Scripts" if os.name == "nt" else "bin")
    python = binaryRoot / ("python.exe" if os.name == "nt" else "python")
    _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "install",
         "--no-index", str(wheel)],
        temporaryRoot,
    )

    return DistributionArtifacts(
        wheel, sdist, next(rebuiltOutput.glob("*.whl")), python,
        binaryRoot / ("flayer.exe" if os.name == "nt" else "flayer"), temporaryRoot,
    )


def test_DistributionMetadataAndTypedEntryPoint(
    distributionArtifacts: DistributionArtifacts,
) -> None:
    """The wheel carries real public metadata, types, license and the correct entry point."""

    with zipfile.ZipFile(distributionArtifacts.wheel) as archive:
        names = archive.namelist()
        metadataPath = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = BytesParser().parsebytes(archive.read(metadataPath))
        entryPoints = next(name for name in names if name.endswith("/entry_points.txt"))

        assert metadata["Name"] == "f-layer", "Distribution name drifted from its public identity"
        assert metadata["Requires-Python"] == ">=3.11", "Supported Python floor drifted"
        assert metadata["License-Expression"] == "Apache-2.0", "Wheel lost its license expression"
        assert metadata["Description-Content-Type"] == "text/markdown", "README metadata is wrong"
        assert "flayer/py.typed" in names, "Typed package marker is absent from the wheel"
        assert any(name.endswith("/licenses/LICENSE") for name in names), "License file is absent"
        assert "flayer = flayer.__main__:Main" in archive.read(entryPoints).decode(), (
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

    with tarfile.open(distributionArtifacts.sdist) as archive:
        names = archive.getnames()

        assert any(name.endswith("/tools/validate.py") for name in names), (
            "Source distribution cannot reproduce the canonical validator"
        )
        assert not any(
            part in {".venv", "_build", "__pycache__", ".coverage", ".git"}
            for name in names for part in Path(name).parts
        ), "Source distribution contains local or generated artifacts"


def test_SdistRebuildAndIsolatedConsoleParity(
    distributionArtifacts: DistributionArtifacts,
) -> None:
    """An exported sdist rebuilds the same wheel and its installed CLI runs in isolation."""

    assert hashlib.sha256(distributionArtifacts.wheel.read_bytes()).digest() == hashlib.sha256(
        distributionArtifacts.rebuiltWheel.read_bytes()
    ).digest(), "Wheel rebuilt from sdist differs from the original distribution"

    code = (
        "import flayer, importlib.metadata as m, json; "
        "print(json.dumps({'runtime':flayer.__version__, 'metadata':m.version('f-layer'), "
        "'path':flayer.__file__}))"
    )
    result = json.loads(_Run(
        [str(distributionArtifacts.python), "-I", "-c", code],
        distributionArtifacts.outsideSource,
    ))

    assert result["runtime"] == result["metadata"], "Runtime and installed versions disagree"
    assert not Path(result["path"]).is_relative_to(PROJECT_ROOT), (
        "Isolated installation test imported the checkout instead of the wheel"
    )

    consoleHelp = _Run(
        [str(distributionArtifacts.console), "--help"], distributionArtifacts.outsideSource,
    )
    moduleHelp = _Run(
        [str(distributionArtifacts.python), "-I", "-m", "flayer", "--help"],
        distributionArtifacts.outsideSource,
    )

    assert consoleHelp == moduleHelp, "Console and module CLI help surfaces disagree"


def test_InstalledConsoleRunsWithoutSourceOrCloudTools(
    distributionArtifacts: DistributionArtifacts,
) -> None:
    """A fresh wheel installation performs real local diagnostics without cloud credentials."""

    result = json.loads(_Run(
        [str(distributionArtifacts.console), "check", "--format", "json"],
        distributionArtifacts.outsideSource,
    ))

    assert result["command"] == "check", "Installed console ran the wrong diagnostic command"
    assert result["status"] == "ok", "Installed wheel cannot complete local runtime checks"
    assert result["checks"][0]["name"] == "python-runtime", "Runtime diagnostic is missing"
    assert "No broken requirements found" in _Run(
        [sys.executable, "-m", "pip", "--python", str(distributionArtifacts.python), "check"],
        distributionArtifacts.outsideSource,
    ), "Fresh core installation has unresolved dependencies"
    assert _Run(
        [str(distributionArtifacts.python), "-I", "-c",
         "import importlib.util; print(importlib.util.find_spec('cryptography') is None)"],
        distributionArtifacts.outsideSource,
    ).strip() == "True", "Core installation unexpectedly pulled in the optional VPN dependency"


def test_VpnExtraInstallsAndGeneratesKeys(
    distributionArtifacts: DistributionArtifacts, tmp_path: Path,
) -> None:
    """The documented VPN extra resolves offline and provides working key generation."""

    wheelhouse = os.environ.get("FLAYER_DISTRIBUTION_WHEELHOUSE")

    if not wheelhouse:
        pytest.skip("VPN dependency wheelhouse is required; release CI downloads it before smoke")

    environmentRoot = tmp_path / "vpn-environment"
    venv.EnvBuilder(with_pip=False).create(environmentRoot)
    binaryRoot = environmentRoot / ("Scripts" if os.name == "nt" else "bin")
    python = binaryRoot / ("python.exe" if os.name == "nt" else "python")
    wheelSpecification = f"f-layer[vpn] @ {distributionArtifacts.wheel.as_uri()}"
    _Run(
        [sys.executable, "-m", "pip", "--python", str(python), "install", "--no-index",
         "--find-links", str(Path(wheelhouse).resolve()), wheelSpecification],
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
