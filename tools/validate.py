"""Run the same offline, fail-closed validation gate locally and in CI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COVERAGE_FLOOR = 80


def BuildEnvironment(repoRoot: Path, coveragePath: Path) -> dict[str, str]:
    """Prefer this checkout's sources over any ambient editable installation."""

    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(repoRoot / "src"), str(repoRoot)))
    environment["PYTHONSAFEPATH"] = "1"
    environment["COVERAGE_FILE"] = str(coveragePath)
    environment["COVERAGE_RCFILE"] = str(repoRoot / "pyproject.toml")
    environment["PYTEST_ADDOPTS"] = ""
    environment["PYTEST_PLUGINS"] = ""
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["MYPYPATH"] = ""
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_NO_INDEX"] = "1"

    return environment


def RunCommand(
    stageName: str,
    arguments: Sequence[str],
    workingDirectory: Path,
    environment: Mapping[str, str],
) -> int:
    """Execute one bounded stage and preserve a nonzero result without retries."""

    print(f"Validation: {stageName}", flush=True)

    try:
        result = subprocess.run(
            arguments,
            cwd=workingDirectory,
            env=environment,
            check=False,
            timeout=600,
        )

    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Validation failed during {stageName}: {error}", file=sys.stderr)

        return 1

    if result.returncode != 0:
        print(
            f"Validation failed during {stageName}: exit code {result.returncode}",
            file=sys.stderr,
        )

    return result.returncode


def ReadCounter(totals: Mapping[str, object], name: str) -> int:
    """Reject absent, boolean, negative, and nonintegral coverage counters."""

    value = totals.get(name)

    if type(value) is not int or value < 0:
        raise ValueError(f"Coverage counter {name!r} must be a nonnegative integer")

    return value


def CheckCoverage(reportPath: Path) -> None:
    """Enforce the overall and branch floors independently from coverage JSON."""

    report = json.loads(reportPath.read_text(encoding="utf-8"))

    if not isinstance(report, dict) or not isinstance(report.get("totals"), dict):
        raise ValueError("Coverage report must contain a totals object")

    totals = report["totals"]
    statements = ReadCounter(totals, "num_statements")
    coveredLines = ReadCounter(totals, "covered_lines")
    branches = ReadCounter(totals, "num_branches")
    coveredBranches = ReadCounter(totals, "covered_branches")

    if statements == 0 or coveredLines > statements or coveredBranches > branches:
        raise ValueError("Coverage totals are empty or contain inconsistent counters")

    coveredTotal = coveredLines + coveredBranches
    measuredTotal = statements + branches

    if coveredTotal * 100 < COVERAGE_FLOOR * measuredTotal:
        raise ValueError(f"Overall coverage is below {COVERAGE_FLOOR}%")

    if branches and coveredBranches * 100 < COVERAGE_FLOOR * branches:
        raise ValueError(f"Branch coverage is below {COVERAGE_FLOOR}%")

    overallPercent = coveredTotal * 100 / measuredTotal
    branchPercent = coveredBranches * 100 / branches if branches else 100.0
    print(
        f"Coverage: overall {overallPercent:.2f}%, branches {branchPercent:.2f}% "
        f"({branches} measured branches)",
        flush=True,
    )


def BuildImportSmoke(importRoot: Path) -> str:
    """Check that the imported package belongs to the intended source or install root."""

    return (
        "from pathlib import Path\nimport sys\n"
        f"expected_root = Path({str(importRoot)!r}).resolve()\n"
        "sys.path.insert(0, str(expected_root))\nimport flayer\n\n"
        "assert flayer.__file__ is not None, 'Package has no concrete import location'\n\n"
        "actual_path = Path(flayer.__file__).resolve()\n\n"
        "assert actual_path.is_relative_to(expected_root), "
        "f'Imported package outside expected root: {actual_path}'\n\n"
        "print(f'Package import: {actual_path}')"
    )


def RunGate(repoRoot: Path) -> int:
    """Stop at the first failed stage and discard temporary coverage and install output."""

    repoRoot = repoRoot.resolve()

    with tempfile.TemporaryDirectory(prefix="flayer-validation-") as temporaryDirectory:
        temporaryRoot = Path(temporaryDirectory)
        environment = BuildEnvironment(repoRoot, temporaryRoot / ".coverage")
        commands: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("compile", ("-m", "compileall", "-q", "-f", "src", "tests", "tools")),
            ("Python naming", ("-m", "tools.python_naming")),
            ("Ruff", ("-m", "ruff", "check", ".")),
            ("mypy", ("-m", "mypy")),
            ("pytest", ("-m", "pytest", "-p", "pytest_cov.plugin")),
            (
                "coverage report",
                ("-m", "coverage", "json", "-o", str(temporaryRoot / "coverage.json")),
            ),
        )

        for stageName, arguments in commands:
            exitCode = RunCommand(
                stageName, (sys.executable, *arguments), repoRoot, environment,
            )

            if exitCode != 0:
                return exitCode

        try:
            CheckCoverage(temporaryRoot / "coverage.json")

        except (OSError, ValueError) as error:
            print(f"Validation failed during coverage floor: {error}", file=sys.stderr)

            return 1

        sourceResult = RunCommand(
            "local source import",
            (sys.executable, "-I", "-c", BuildImportSmoke(repoRoot / "src")),
            temporaryRoot,
            environment,
        )

        if sourceResult != 0:
            return sourceResult

        installRoot = temporaryRoot / "installed"
        installResult = RunCommand(
            "offline package installation",
            (
                sys.executable, "-m", "pip", "--disable-pip-version-check", "--no-input",
                "install", "--no-index", "--no-deps", "--no-build-isolation",
                "--target", str(installRoot), str(repoRoot),
            ),
            temporaryRoot,
            environment,
        )

        if installResult != 0:
            return installResult

        installedResult = RunCommand(
            "installed package import",
            (sys.executable, "-I", "-c", BuildImportSmoke(installRoot)),
            temporaryRoot,
            environment,
        )

        if installedResult != 0:
            return installedResult

        if (repoRoot / "src" / "flayer" / "__main__.py").is_file():
            cliResult = RunCommand(
                "CLI help",
                (sys.executable, "-m", "flayer", "--help"),
                repoRoot,
                environment,
            )

            if cliResult != 0:
                return cliResult

        else:
            print("CLI smoke: no package CLI in this checkout", flush=True)

    print("Validation passed", flush=True)

    return 0


def Main() -> int:
    """Run the complete gate from the checkout containing this script."""

    return RunGate(REPOSITORY_ROOT)


if __name__ == "__main__":
    raise SystemExit(Main())
