"""Verify fail-closed validation, coverage floors, and checkout import isolation."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from tools import validate


def WriteCoverageReport(
    report_path: Path,
    statements: int = 10,
    covered_lines: int = 10,
    branches: int = 10,
    covered_branches: int = 10,
) -> None:
    """Write measured-counter fixtures for the coverage-floor contract."""

    report_path.write_text(
        json.dumps(
            {
                "totals": {
                    "num_statements": statements,
                    "covered_lines": covered_lines,
                    "num_branches": branches,
                    "covered_branches": covered_branches,
                },
            },
        ),
        encoding="utf-8",
    )


def test_EnvironmentUsesOnlyCurrentCheckout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An ambient editable checkout cannot displace current local sources."""

    monkeypatch.setenv("PYTHONPATH", "/unrelated/checkout/src")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "ambient_plugin")
    monkeypatch.setenv("MYPYPATH", "/unrelated/type_stubs")
    environment = validate.BuildEnvironment(tmp_path, tmp_path / ".coverage")

    assert environment["PYTHONPATH"] == os.pathsep.join(
        (str(tmp_path / "src"), str(tmp_path)),
    ), "Validation retained an unrelated source path"
    assert environment["PYTHONSAFEPATH"] == "1", "Unsafe implicit cwd imports were not excluded"
    assert environment["PIP_NO_INDEX"] == "1", "Package installation permits network access"
    assert environment["COVERAGE_FILE"] == str(tmp_path / ".coverage"), (
        "Coverage output can leak between worktrees"
    )
    assert environment["PYTEST_ADDOPTS"] == "", "Ambient options can skip required tests"
    assert environment["PYTEST_PLUGINS"] == "", "Ambient plugins can alter test behavior"
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1", (
        "Unrelated installed plugins can alter test behavior"
    )
    assert environment["MYPYPATH"] == "", "Unrelated type stubs can mask typing errors"


@pytest.mark.parametrize(
    ("covered_lines", "covered_branches"),
    [(8, 8), (10, 10)],
)
def test_CoverageAcceptsExactFloor(
    tmp_path: Path,
    covered_lines: int,
    covered_branches: int,
) -> None:
    """Both coverage ratios accept the exact 80-percent boundary."""

    report_path = tmp_path / "coverage.json"
    WriteCoverageReport(
        report_path, covered_lines=covered_lines, covered_branches=covered_branches,
    )

    validate.CheckCoverage(report_path)


def test_CoverageRejectsLowBranchesDespiteHighOverall(tmp_path: Path) -> None:
    """High statement coverage cannot conceal insufficient exercised branches."""

    report_path = tmp_path / "coverage.json"
    WriteCoverageReport(
        report_path, statements=100, covered_lines=100, branches=10, covered_branches=7,
    )

    with pytest.raises(ValueError, match="Branch coverage is below 80%"):
        validate.CheckCoverage(report_path)


def test_CoverageRejectsLowOverallDespiteHighBranches(tmp_path: Path) -> None:
    """High branch coverage cannot conceal untested statements."""

    report_path = tmp_path / "coverage.json"
    WriteCoverageReport(
        report_path, statements=100, covered_lines=70, branches=10, covered_branches=10,
    )

    with pytest.raises(ValueError, match="Overall coverage is below 80%"):
        validate.CheckCoverage(report_path)


def test_CoverageAllowsModulesWithoutBranches(tmp_path: Path) -> None:
    """A nonempty straight-line package has no branch obligations."""

    report_path = tmp_path / "coverage.json"
    WriteCoverageReport(report_path, branches=0, covered_branches=0)

    validate.CheckCoverage(report_path)


@pytest.mark.parametrize(
    "report",
    [
        {},
        [],
        {"totals": None},
        {"totals": {}},
        {"totals": {"num_statements": True}},
        {"totals": {"num_statements": -1}},
        {"totals": {"num_statements": 1.5}},
    ],
)
def test_CoverageRejectsMalformedReports(tmp_path: Path, report: object) -> None:
    """Missing or invalid counters never become a passing coverage result."""

    report_path = tmp_path / "coverage.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError):
        validate.CheckCoverage(report_path)


@pytest.mark.parametrize(
    ("statements", "covered_lines", "branches", "covered_branches"),
    [(0, 0, 0, 0), (10, 11, 10, 10), (10, 10, 10, 11)],
)
def test_CoverageRejectsImpossibleTotals(
    tmp_path: Path,
    statements: int,
    covered_lines: int,
    branches: int,
    covered_branches: int,
) -> None:
    """Empty measurement and counters above the measured total fail validation."""

    report_path = tmp_path / "coverage.json"
    WriteCoverageReport(report_path, statements, covered_lines, branches, covered_branches)

    with pytest.raises(ValueError, match="empty or contain inconsistent"):
        validate.CheckCoverage(report_path)


@pytest.mark.parametrize(
    "failed_stage",
    [
        "compile", "Ruff", "mypy", "pytest", "coverage report", "local source import",
        "offline package installation", "installed package import", "CLI help",
    ],
)
def test_GateStopsAtFirstFailedCommand(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_stage: str,
) -> None:
    """No later check runs after an earlier stage fails."""

    command_names: list[str] = []
    coverage_paths: list[Path] = []
    cli_path = tmp_path / "src" / "flayer" / "__main__.py"
    cli_path.parent.mkdir(parents=True)
    cli_path.write_text("", encoding="utf-8")

    def FakeRunCommand(
        stage_name: str,
        arguments: Sequence[str],
        working_directory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Record execution order and emulate only the coverage report side effect."""

        command_names.append(stage_name)

        if stage_name == "coverage report" and stage_name != failed_stage:
            report_path = Path(arguments[-1])
            coverage_paths.append(report_path)
            WriteCoverageReport(report_path)

        return 7 if stage_name == failed_stage else 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)
    exit_code = validate.RunGate(tmp_path)

    assert exit_code == 7, "Validation lost the failing stage's exit code"
    assert command_names[-1] == failed_stage, "Validation continued after a failed command"
    assert all(not path.exists() for path in coverage_paths), (
        "Temporary coverage output survived a failed gate"
    )


@pytest.mark.parametrize("report_text", [None, "{", "{}"])
def test_GateRejectsMissingOrMalformedCoverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report_text: str | None,
) -> None:
    """A successful export command without valid measurement cannot pass the gate."""

    command_names: list[str] = []

    def FakeRunCommand(
        stage_name: str,
        arguments: Sequence[str],
        working_directory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Represent a broken exporter that exits successfully but omits valid data."""

        command_names.append(stage_name)

        if stage_name == "coverage report" and report_text is not None:
            Path(arguments[-1]).write_text(report_text, encoding="utf-8")

        return 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)

    assert validate.RunGate(tmp_path) == 1, "Broken coverage measurement passed validation"
    assert command_names[-1] == "coverage report", "Gate continued with invalid coverage"


@pytest.mark.parametrize("has_cli", [False, True])
def test_GateRunsWholePlanFromCheckoutRoot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    has_cli: bool,
) -> None:
    """All required checks use the given checkout independently of the caller's cwd."""

    checkout_root = tmp_path / "checkout"
    checkout_root.mkdir()
    monkeypatch.chdir(tmp_path)
    command_names: list[str] = []

    if has_cli:
        cli_path = checkout_root / "src" / "flayer" / "__main__.py"
        cli_path.parent.mkdir(parents=True)
        cli_path.write_text("", encoding="utf-8")

    def FakeRunCommand(
        stage_name: str,
        arguments: Sequence[str],
        working_directory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Inspect stage cwd, source precedence, and offline installation switches."""

        command_names.append(stage_name)
        expected_pythonpath = os.pathsep.join(
            (str(checkout_root / "src"), str(checkout_root)),
        )
        assert environment["PYTHONPATH"] == expected_pythonpath, (
            "Stage inherited a different checkout's sources"
        )

        if stage_name in {"compile", "Ruff", "mypy", "pytest", "coverage report", "CLI help"}:
            assert working_directory == checkout_root, "Stage used the caller's cwd"

        if stage_name == "offline package installation":
            assert {"--no-index", "--no-deps", "--no-build-isolation"}.issubset(arguments), (
                "Installation smoke permits dependency downloads"
            )

        if stage_name == "coverage report":
            WriteCoverageReport(Path(arguments[-1]))

        return 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)

    assert validate.RunGate(Path("checkout")) == 0, "Complete successful gate returned failure"
    assert command_names == [
        "compile", "Ruff", "mypy", "pytest", "coverage report", "local source import",
        "offline package installation", "installed package import",
        *(["CLI help"] if has_cli else []),
    ], "The required validation stages were skipped or reordered"


def test_ImportSmokeSelectsCheckoutOverAmbientPackage(tmp_path: Path) -> None:
    """A real isolated interpreter imports this checkout when ambient sources conflict."""

    source_root = tmp_path / "source"
    package_root = source_root / "flayer"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text(
        '"""Isolated package fixture."""\n', encoding="utf-8",
    )
    ambient_root = tmp_path / "ambient"
    ambient_package = ambient_root / "flayer"
    ambient_package.mkdir(parents=True)
    (ambient_package / "__init__.py").write_text(
        'raise RuntimeError("Wrong checkout imported")\n', encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ambient_root)
    result = subprocess.run(
        [sys.executable, "-I", "-c", validate.BuildImportSmoke(source_root)],
        cwd=ambient_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, f"Local import smoke selected ambient code: {result.stderr}"
    assert str(package_root / "__init__.py") in result.stdout, (
        "Import smoke did not report the expected local package"
    )


def test_RunCommandPreservesFailureCode(tmp_path: Path) -> None:
    """A real failing subprocess remains a validation failure."""

    assert validate.RunCommand(
        "intentional failure", (sys.executable, "-c", "raise SystemExit(9)"),
        tmp_path, os.environ,
    ) == 9, "Subprocess failure was swallowed"


def test_RunCommandRejectsMissingExecutable(tmp_path: Path) -> None:
    """A missing validation executable produces failure instead of skipping the check."""

    assert validate.RunCommand(
        "missing tool", (str(tmp_path / "missing-executable"),), tmp_path, os.environ,
    ) == 1, "Unavailable tool was treated as a passing check"


def test_RunCommandRejectsTimeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timeout is an explicit failure and never triggers a retry."""

    def RaiseTimeout(*arguments: object, **keyword_arguments: object) -> None:
        """Represent a tool that exceeds the stage time limit."""

        raise subprocess.TimeoutExpired("tool", 600)

    monkeypatch.setattr(subprocess, "run", RaiseTimeout)

    assert validate.RunCommand(
        "timed out tool", ("tool",), tmp_path, os.environ,
    ) == 1, "Timed-out tool was treated as passing"


def test_TestStageIsDiscoveredFromDirectory(request: pytest.FixtureRequest) -> None:
    """A test in tests/unit receives the unit marker without manual annotation."""

    assert request.node.get_closest_marker("unit") is not None, (
        "Directory-based test stage discovery did not classify a unit test"
    )


def RunCollectionFixture(
    fixture_root: Path,
    stage_names: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    """Collect an isolated test tree with the repository's actual discovery hook."""

    marker_config = "\n".join(
        f"    {stage_name}: isolated test stage"
        for stage_name in ("unit", "contract", "functional", "integration", "e2e")
    )
    (fixture_root / "pytest.ini").write_text(
        f"[pytest]\ntestpaths = tests\naddopts = --strict-markers\nmarkers =\n{marker_config}\n",
        encoding="utf-8",
    )
    tests_root = fixture_root / "tests"
    tests_root.mkdir()
    (tests_root / "conftest.py").write_text(
        (Path(__file__).resolve().parents[1] / "conftest.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    for stage_name in stage_names:
        stage_root = tests_root / stage_name
        stage_root.mkdir()
        (stage_root / f"test_{stage_name}.py").write_text(
            f'"""Isolated collection fixture."""\n\n'
            f'def test_{stage_name.capitalize()}() -> None:\n'
            f'    """Represent one discoverable stage test."""\n\n'
            f'    assert True, "Collection fixture failed unexpectedly"\n',
            encoding="utf-8",
        )

    environment = dict(os.environ)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTEST_ADDOPTS"] = ""
    environment["PYTEST_PLUGINS"] = ""

    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=fixture_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_CollectionDiscoversEveryStage(tmp_path: Path) -> None:
    """All five stage directories participate in default pytest discovery."""

    stage_names = ("unit", "contract", "functional", "integration", "e2e")
    result = RunCollectionFixture(tmp_path, stage_names)

    assert result.returncode == 0, f"Supported test stages failed collection: {result.stderr}"

    for stage_name in stage_names:
        assert f"tests/{stage_name}/" in result.stdout, (
            f"Default discovery omitted the {stage_name} stage"
        )

    assert "5 tests collected" in result.stdout, "Default discovery lost a test stage"


def test_CollectionRejectsUnclassifiedStage(tmp_path: Path) -> None:
    """An unsupported stage directory cannot silently bypass marker classification."""

    result = RunCollectionFixture(tmp_path, ("unclassified",))

    assert result.returncode != 0, "Unclassified tests incorrectly passed collection"
    assert "Test must belong to a supported stage" in result.stderr, (
        "Collection failed without explaining the unsupported stage"
    )


def test_TestNetworkIsDenied() -> None:
    """Test fixtures cannot accidentally contact real provider infrastructure."""

    with pytest.raises(RuntimeError, match="Real socket networking is disabled"):
        socket.create_connection(("cloud.invalid", 443))

    with pytest.raises(RuntimeError, match="Real socket networking is disabled"):
        socket.getaddrinfo("cloud.invalid", 443)

    with socket.socket() as connection:
        with pytest.raises(RuntimeError, match="Real socket networking is disabled"):
            connection.connect(("127.0.0.1", 443))
