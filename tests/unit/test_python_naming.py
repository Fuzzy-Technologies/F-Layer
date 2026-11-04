"""Reject owned naming regressions while preserving external interfaces and stable wire data."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, make_dataclass
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity, _WireDict
from tools.python_naming import Audit, FindViolations, Main


@pytest.mark.parametrize("source", [
    "def LoadData(inputPath):\n    outputData = inputPath\n    return outputData\n",
    "class CloudPlacement:\n    ycProfile: str\n    _cachePath: str\n",
    "MAX_REQUEST_BYTES = 1024\n_privateValue = 1\n__hiddenValue = 2\n",
    "class Example:\n    def __init__(self, ownerId):\n        self.ownerId = ownerId\n",
    "from subprocess import check_output\nresult = check_output(['echo'], capture_output=True)\n",
    "import pytest\n@pytest.fixture\ndef ProjectFixture(tmp_path):\n    return tmp_path\n",
    "def test_Example(tmp_path):\n    localPath = tmp_path\n",
])
def test_AcceptsHouseStyleAndExternalContracts(source: str) -> None:
    """Accept owned camelCase, PascalCase and constants without rewriting foreign keywords."""

    assert FindViolations(source, "tests/unit/example.py") == ()


@pytest.mark.parametrize("source,identifier", [
    ("owned_value = 1\n", "owned_value"),
    ("def LoadData(input_path):\n    pass\n", "input_path"),
    ("class CloudPlacement:\n    yc_profile: str\n", "yc_profile"),
    ("def LoadData():\n    with open('x') as data_file:\n        pass\n", "data_file"),
    ("def LoadData():\n    return [file_path for file_path in []]\n", "file_path"),
    ("def load_data():\n    pass\n", "load_data"),
    ("class lower_case:\n    pass\n", "lower_case"),
    ("def test_wrong_suffix():\n    pass\n", "test_wrong_suffix"),
    ("def Helper(tmp_path):\n    pass\n", "tmp_path"),
    ("import subprocess as process_tools\n", "process_tools"),
    ("class Example:\n    def Load(self):\n        self.private_field = 1\n", "private_field"),
    ("def LoadData():\n    try:\n        pass\n    except ValueError as caught_error:\n        pass\n", "caught_error"),
])
def test_RejectsOwnedIdentifiers(source: str, identifier: str) -> None:
    """Fail real declarations, including bindings hidden in loops, aliases and comprehensions."""

    assert identifier in {item.name for item in FindViolations(source, "tests/unit/example.py")}


def test_ExceptionsAreBoundToExactExternalDefinitions() -> None:
    """An argparse override exception cannot excuse an unrelated class or local variable."""

    valid = "class DiagnosticArgumentParser:\n    def error(self, message):\n        pass\n"
    invalid = "class OtherParser:\n    def error(self, message):\n        pass\n"

    assert FindViolations(valid, "src/flayer/__main__.py") == ()
    assert FindViolations(invalid, "src/flayer/__main__.py")
    assert FindViolations(valid.replace("pass", "local_value = message"), "src/flayer/__main__.py")


def test_RepositoryDiscoveryIncludesUntrackedPythonAndStubs(tmp_path: Path) -> None:
    """New source cannot bypass the gate merely because it has not been staged yet."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "new_module.py").write_text("owned_value = 1\n", encoding="utf-8")
    (tmp_path / "new_module.pyi").write_text("owned_field: str\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("ignored/\n", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored/private.py").write_text("ignored_value = 1\n", encoding="utf-8")

    assert {item.path for item in Audit(tmp_path)} == {"new_module.py", "new_module.pyi"}
    assert Main(["--root", str(tmp_path)]) == 1


def test_WireSerializationRetainsExistingNamesAndRawProtocolKeys() -> None:
    """Freeze old dataclass wire output independently of the newly named Python attributes."""

    @dataclass
    class Current:
        """Represent renamed owned fields carrying an unchanged external protocol mapping."""

        ownerId: str
        deviceIds: tuple[str, ...]
        payload: dict[str, object]

    legacyType = make_dataclass("Legacy", [("owner_id", str), ("device_ids", tuple), ("payload", dict)])
    protocol = {"streamSettings": {"serverName": "example.org"}, "external_field": 1}
    current = Current("example-owner", ("phone", "laptop"), protocol)
    legacy = legacyType("example-owner", ("phone", "laptop"), protocol)

    assert _WireDict(current) == asdict(legacy)
    assert json.dumps(_WireDict(current), sort_keys=True) == json.dumps(asdict(legacy), sort_keys=True)
    assert asdict(current)["ownerId"] == "example-owner"
    assert _WireDict(StackIdentity("example", "vpn", "yandex-cloud", "example-folder", "example-owner")) == {
        "project": "example", "stack": "vpn", "provider": "yandex-cloud",
        "scope_id": "example-folder", "owner_id": "example-owner",
    }


def test_WireSerializationRejectsNonDataclassValues() -> None:
    """Do not silently accept dictionaries as owned dataclass records."""

    with pytest.raises(TypeError):
        _WireDict({"ownerId": "example-owner"})
