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
    reportPath: Path,
    statements: int = 10,
    coveredLines: int = 10,
    branches: int = 10,
    coveredBranches: int = 10,
) -> None:
    """Write measured-counter fixtures for the coverage-floor contract."""

    reportPath.write_text(
        json.dumps(
            {
                "totals": {
                    "num_statements": statements,
                    "covered_lines": coveredLines,
                    "num_branches": branches,
                    "covered_branches": coveredBranches,
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
    ('coveredLines', 'coveredBranches'),
    [(8, 8), (10, 10)],
)
def test_CoverageAcceptsExactFloor(
    tmp_path: Path,
    coveredLines: int,
    coveredBranches: int,
) -> None:
    """Both coverage ratios accept the exact 80-percent boundary."""

    reportPath = tmp_path / "coverage.json"
    WriteCoverageReport(
        reportPath, coveredLines=coveredLines, coveredBranches=coveredBranches,
    )

    validate.CheckCoverage(reportPath)


def test_CoverageRejectsLowBranchesDespiteHighOverall(tmp_path: Path) -> None:
    """High statement coverage cannot conceal insufficient exercised branches."""

    reportPath = tmp_path / "coverage.json"
    WriteCoverageReport(
        reportPath, statements=100, coveredLines=100, branches=10, coveredBranches=7,
    )

    with pytest.raises(ValueError, match="Branch coverage is below 80%"):
        validate.CheckCoverage(reportPath)


def test_CoverageRejectsLowOverallDespiteHighBranches(tmp_path: Path) -> None:
    """High branch coverage cannot conceal untested statements."""

    reportPath = tmp_path / "coverage.json"
    WriteCoverageReport(
        reportPath, statements=100, coveredLines=70, branches=10, coveredBranches=10,
    )

    with pytest.raises(ValueError, match="Overall coverage is below 80%"):
        validate.CheckCoverage(reportPath)


def test_CoverageAllowsModulesWithoutBranches(tmp_path: Path) -> None:
    """A nonempty straight-line package has no branch obligations."""

    reportPath = tmp_path / "coverage.json"
    WriteCoverageReport(reportPath, branches=0, coveredBranches=0)

    validate.CheckCoverage(reportPath)


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

    reportPath = tmp_path / "coverage.json"
    reportPath.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError):
        validate.CheckCoverage(reportPath)


@pytest.mark.parametrize(
    ("statements", 'coveredLines', "branches", 'coveredBranches'),
    [(0, 0, 0, 0), (10, 11, 10, 10), (10, 10, 10, 11)],
)
def test_CoverageRejectsImpossibleTotals(
    tmp_path: Path,
    statements: int,
    coveredLines: int,
    branches: int,
    coveredBranches: int,
) -> None:
    """Empty measurement and counters above the measured total fail validation."""

    reportPath = tmp_path / "coverage.json"
    WriteCoverageReport(reportPath, statements, coveredLines, branches, coveredBranches)

    with pytest.raises(ValueError, match="empty or contain inconsistent"):
        validate.CheckCoverage(reportPath)


@pytest.mark.parametrize(
    'failedStage',
    [
        "compile", "Ruff", "mypy", "pytest", "coverage report", "local source import",
        "offline package installation", "installed package import", "CLI help",
    ],
)
def test_GateStopsAtFirstFailedCommand(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failedStage: str,
) -> None:
    """No later check runs after an earlier stage fails."""

    commandNames: list[str] = []
    coveragePaths: list[Path] = []
    cliPath = tmp_path / "src" / "flayer" / "__main__.py"
    cliPath.parent.mkdir(parents=True)
    cliPath.write_text("", encoding="utf-8")

    def FakeRunCommand(
        stageName: str,
        arguments: Sequence[str],
        workingDirectory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Record execution order and emulate only the coverage report side effect."""

        commandNames.append(stageName)

        if stageName == "coverage report" and stageName != failedStage:
            reportPath = Path(arguments[-1])
            coveragePaths.append(reportPath)
            WriteCoverageReport(reportPath)

        return 7 if stageName == failedStage else 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)
    exitCode = validate.RunGate(tmp_path)

    assert exitCode == 7, "Validation lost the failing stage's exit code"
    assert commandNames[-1] == failedStage, "Validation continued after a failed command"
    assert all(not path.exists() for path in coveragePaths), (
        "Temporary coverage output survived a failed gate"
    )


@pytest.mark.parametrize('reportText', [None, "{", "{}"])
def test_GateRejectsMissingOrMalformedCoverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reportText: str | None,
) -> None:
    """A successful export command without valid measurement cannot pass the gate."""

    commandNames: list[str] = []

    def FakeRunCommand(
        stageName: str,
        arguments: Sequence[str],
        workingDirectory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Represent a broken exporter that exits successfully but omits valid data."""

        commandNames.append(stageName)

        if stageName == "coverage report" and reportText is not None:
            Path(arguments[-1]).write_text(reportText, encoding="utf-8")

        return 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)

    assert validate.RunGate(tmp_path) == 1, "Broken coverage measurement passed validation"
    assert commandNames[-1] == "coverage report", "Gate continued with invalid coverage"


@pytest.mark.parametrize('hasCli', [False, True])
def test_GateRunsWholePlanFromCheckoutRoot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hasCli: bool,
) -> None:
    """All required checks use the given checkout independently of the caller's cwd."""

    checkoutRoot = tmp_path / "checkout"
    checkoutRoot.mkdir()
    monkeypatch.chdir(tmp_path)
    commandNames: list[str] = []

    if hasCli:
        cliPath = checkoutRoot / "src" / "flayer" / "__main__.py"
        cliPath.parent.mkdir(parents=True)
        cliPath.write_text("", encoding="utf-8")

    def FakeRunCommand(
        stageName: str,
        arguments: Sequence[str],
        workingDirectory: Path,
        environment: Mapping[str, str],
    ) -> int:
        """Inspect stage cwd, source precedence, and offline installation switches."""

        commandNames.append(stageName)
        expectedPythonpath = os.pathsep.join(
            (str(checkoutRoot / "src"), str(checkoutRoot)),
        )

        assert environment["PYTHONPATH"] == expectedPythonpath, (
            "Stage inherited a different checkout's sources"
        )

        if stageName in {"compile", "Ruff", "mypy", "pytest", "coverage report", "CLI help"}:
            assert workingDirectory == checkoutRoot, "Stage used the caller's cwd"

        if stageName == "offline package installation":
            assert {"--no-index", "--no-deps", "--no-build-isolation"}.issubset(arguments), (
                "Installation smoke permits dependency downloads"
            )

        if stageName == "coverage report":
            WriteCoverageReport(Path(arguments[-1]))

        return 0

    monkeypatch.setattr(validate, "RunCommand", FakeRunCommand)

    assert validate.RunGate(Path("checkout")) == 0, "Complete successful gate returned failure"
    assert commandNames == [
        "compile", "Ruff", "mypy", "pytest", "coverage report", "local source import",
        "offline package installation", "installed package import",
        *(["CLI help"] if hasCli else []),
    ], "The required validation stages were skipped or reordered"


def test_ImportSmokeSelectsCheckoutOverAmbientPackage(tmp_path: Path) -> None:
    """A real isolated interpreter imports this checkout when ambient sources conflict."""

    sourceRoot = tmp_path / "source"
    packageRoot = sourceRoot / "flayer"
    packageRoot.mkdir(parents=True)
    (packageRoot / "__init__.py").write_text(
        '"""Isolated package fixture."""\n', encoding="utf-8",
    )
    ambientRoot = tmp_path / "ambient"
    ambientPackage = ambientRoot / "flayer"
    ambientPackage.mkdir(parents=True)
    (ambientPackage / "__init__.py").write_text(
        'raise RuntimeError("Wrong checkout imported")\n', encoding="utf-8",
    )
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(ambientRoot)
    result = subprocess.run(
        [sys.executable, "-I", "-c", validate.BuildImportSmoke(sourceRoot)],
        cwd=ambientRoot,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, f"Local import smoke selected ambient code: {result.stderr}"
    assert str(packageRoot / "__init__.py") in result.stdout, (
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

    def RaiseTimeout(*arguments: object, **keywordArguments: object) -> None:
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
    fixtureRoot: Path,
    stageNames: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    """Collect an isolated test tree with the repository's actual discovery hook."""

    markerConfig = "\n".join(
        f"    {stageName}: isolated test stage"
        for stageName in ("unit", "contract", "functional", "integration", "e2e")
    )
    (fixtureRoot / "pytest.ini").write_text(
        f"[pytest]\ntestpaths = tests\naddopts = --strict-markers\nmarkers =\n{markerConfig}\n",
        encoding="utf-8",
    )
    testsRoot = fixtureRoot / "tests"
    testsRoot.mkdir()
    (testsRoot / "conftest.py").write_text(
        (Path(__file__).resolve().parents[1] / "conftest.py").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    for stageName in stageNames:
        stageRoot = testsRoot / stageName
        stageRoot.mkdir()
        (stageRoot / f"test_{stageName}.py").write_text(
            f'"""Isolated collection fixture."""\n\n'
            f'def test_{stageName.capitalize()}() -> None:\n'
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
        cwd=fixtureRoot,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def test_CollectionDiscoversEveryStage(tmp_path: Path) -> None:
    """All five stage directories participate in default pytest discovery."""

    stageNames = ("unit", "contract", "functional", "integration", "e2e")
    result = RunCollectionFixture(tmp_path, stageNames)

    assert result.returncode == 0, f"Supported test stages failed collection: {result.stderr}"

    for stageName in stageNames:
        assert f"tests/{stageName}/" in result.stdout, (
            f"Default discovery omitted the {stageName} stage"
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
