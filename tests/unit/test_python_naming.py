"""Reject owned naming regressions while preserving external interfaces and stable wire data."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, make_dataclass
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity, _WireDict
from tools.python_naming import Audit, EmbeddedSources, FindViolations, Main, PythonBlocks
from tools.validate import BuildImportSmoke


@pytest.mark.parametrize("source", [
    "def LoadData(inputPath):\n    outputData = inputPath\n    return outputData\n",
    "class CloudPlacement:\n    ycProfile: str\n    _cachePath: str\n",
    "MAX_REQUEST_BYTES = 1024\n_privateValue = 1\n__hiddenValue = 2\n",
    "class Example:\n    def __init__(self, ownerId):\n        self.ownerId = ownerId\n",
    "from subprocess import check_output\nresult = check_output(['echo'], capture_output=True)\n",
    "import pytest\n@pytest.fixture\ndef ProjectFixture(tmp_path):\n    return tmp_path\n",
    "def test_Example(tmp_path):\n    localPath = tmp_path\n",
    "parser.add_argument('--artifact-root', dest='artifactRoot')\n",
    "parser.add_argument('profileFile', metavar='profile_file')\n",
    "def Load(options: argparse.Namespace):\n    return options.artifactRoot\n",
    "match value:\n    case {'id': deviceId, **otherFields}:\n        pass\n",
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
    ("def Load(options: argparse.Namespace):\n    return options.artifact_root\n", "artifact_root"),
    ("options = parser.parse_args()\ngetattr(options, 'artifact_root')\n", "artifact_root"),
    ("parser.add_argument('--artifact-root', dest='artifact_root')\n", "artifact_root"),
    ("parser.add_argument('-a', '--artifact-root')\n", "artifact_root"),
    ("parser.add_argument('profile_file')\n", "profile_file"),
    ("match value:\n    case {'id': device_id, **other_fields}:\n        pass\n", "other_fields"),
    ("match value:\n    case [*device_ids]:\n        pass\n", "device_ids"),
    ("def LoadData():\n    global owned_value\n", "owned_value"),
    ("def LoadData():\n    nonlocal owned_value\n", "owned_value"),
    ("def test_Example(tmp_path):\n    callback = lambda tmp_path: tmp_path\n", "tmp_path"),
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


def test_TestPrefixesAreRestrictedToTestModules() -> None:
    """The framework exception must not excuse owned production callables or parameters."""

    source = "def test_Example(tmp_path):\n    return tmp_path\n"

    assert FindViolations(source, "tests/unit/example.py") == ()
    assert {item.name for item in FindViolations(source, "src/example.py")} == {"test_Example", "tmp_path"}


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


@pytest.mark.parametrize("suffix,source,firstLine", [
    (".md", "# Example\n\n```python\nowned_value = 1\n```\n", 4),
    (".md", "```bash\npython - <<'PY'\nowned_value = 1\nPY\n```\n", 3),
    (".yml", "run: |\n  python3 - <<'PY'\n  owned_value = 1\n  PY\n", 3),
    (".toml", "body = '''\n```py\nowned_value = 1\n```\n'''\n", 3),
])
def test_EmbeddedExamplesRetainOriginalDiagnosticLines(suffix: str, source: str, firstLine: int) -> None:
    """Audit actual Python fences and heredocs without treating shell or TOML keys as bindings."""

    assert PythonBlocks(source, suffix) == ((firstLine, "owned_value = 1"),)
    assert FindViolations(PythonBlocks(source, suffix)[0][1])[0].name == "owned_value"
    assert PythonBlocks("```toml\nscope_id = 'example'\n```\n", ".md") == ()


def test_RepositoryAuditIncludesDocumentationAndExecutableFixtures(tmp_path: Path) -> None:
    """Reject regressions in examples and generated Python, reporting their owning source file."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "example.md").write_text("# Example\n\n```python\nowned_value = 1\n```\n", encoding="utf-8")
    (tmp_path / "fixture.py").write_text('SCRIPT = """import os\\nowned_value = 1\\n"""\n', encoding="utf-8")

    failures = Audit(tmp_path)

    assert {(item.path, item.line, item.name) for item in failures} == {
        ("example.md", 4, "owned_value"), ("fixture.py", 2, "owned_value"),
    }
    assert EmbeddedSources('DATA = """schema_version = 1\\nprofile = \'demo\'\\n"""\n') == ()


def test_FormattedEmbeddedModulesAreCheckedWithoutEvaluatingExpressions() -> None:
    """F-string fixtures cannot hide bindings or execute interpolation during a source audit."""

    source = 'SCRIPT = f"""import os\\nroot = {UntrustedCall()!r}\\nowned_value = 1\\n"""\n'
    blocks = EmbeddedSources(source)

    assert len(blocks) == 1
    assert "UntrustedCall" not in blocks[0][1]
    assert {item.name for item in FindViolations(blocks[0][1])} == {"owned_value"}


def test_ImportSmokeGeneratorUsesOwnedCamelCaseNames(tmp_path: Path) -> None:
    """Check the executable generated smoke test independently of the template extractor."""

    assert FindViolations(BuildImportSmoke(tmp_path)) == ()


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
