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


def BuildEnvironment(repo_root: Path, coverage_path: Path) -> dict[str, str]:
    """Prefer this checkout's sources over any ambient editable installation."""

    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join((str(repo_root / "src"), str(repo_root)))
    environment["PYTHONSAFEPATH"] = "1"
    environment["COVERAGE_FILE"] = str(coverage_path)
    environment["COVERAGE_RCFILE"] = str(repo_root / "pyproject.toml")
    environment["PYTEST_ADDOPTS"] = ""
    environment["PYTEST_PLUGINS"] = ""
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["MYPYPATH"] = ""
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_NO_INDEX"] = "1"

    return environment


def RunCommand(
    stage_name: str,
    arguments: Sequence[str],
    working_directory: Path,
    environment: Mapping[str, str],
) -> int:
    """Execute one bounded stage and preserve a nonzero result without retries."""

    print(f"Validation: {stage_name}", flush=True)

    try:
        result = subprocess.run(
            arguments,
            cwd=working_directory,
            env=environment,
            check=False,
            timeout=600,
        )

    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Validation failed during {stage_name}: {error}", file=sys.stderr)

        return 1

    if result.returncode != 0:
        print(
            f"Validation failed during {stage_name}: exit code {result.returncode}",
            file=sys.stderr,
        )

    return result.returncode


def ReadCounter(totals: Mapping[str, object], name: str) -> int:
    """Reject absent, boolean, negative, and nonintegral coverage counters."""

    value = totals.get(name)

    if type(value) is not int or value < 0:
        raise ValueError(f"Coverage counter {name!r} must be a nonnegative integer")

    return value


def CheckCoverage(report_path: Path) -> None:
    """Enforce the overall and branch floors independently from coverage JSON."""

    report = json.loads(report_path.read_text(encoding="utf-8"))

    if not isinstance(report, dict) or not isinstance(report.get("totals"), dict):
        raise ValueError("Coverage report must contain a totals object")

    totals = report["totals"]
    statements = ReadCounter(totals, "num_statements")
    covered_lines = ReadCounter(totals, "covered_lines")
    branches = ReadCounter(totals, "num_branches")
    covered_branches = ReadCounter(totals, "covered_branches")

    if statements == 0 or covered_lines > statements or covered_branches > branches:
        raise ValueError("Coverage totals are empty or contain inconsistent counters")

    covered_total = covered_lines + covered_branches
    measured_total = statements + branches

    if covered_total * 100 < COVERAGE_FLOOR * measured_total:
        raise ValueError(f"Overall coverage is below {COVERAGE_FLOOR}%")

    if branches and covered_branches * 100 < COVERAGE_FLOOR * branches:
        raise ValueError(f"Branch coverage is below {COVERAGE_FLOOR}%")

    overall_percent = covered_total * 100 / measured_total
    branch_percent = covered_branches * 100 / branches if branches else 100.0
    print(
        f"Coverage: overall {overall_percent:.2f}%, branches {branch_percent:.2f}% "
        f"({branches} measured branches)",
        flush=True,
    )


def BuildImportSmoke(import_root: Path) -> str:
    """Check that the imported package belongs to the intended source or install root."""

    return (
        "from pathlib import Path\nimport sys\n"
        f"expected_root = Path({str(import_root)!r}).resolve()\n"
        "sys.path.insert(0, str(expected_root))\nimport flayer\n\n"
        "assert flayer.__file__ is not None, 'Package has no concrete import location'\n\n"
        "actual_path = Path(flayer.__file__).resolve()\n\n"
        "assert actual_path.is_relative_to(expected_root), "
        "f'Imported package outside expected root: {actual_path}'\n\n"
        "print(f'Package import: {actual_path}')"
    )


def RunGate(repo_root: Path) -> int:
    """Stop at the first failed stage and discard temporary coverage and install output."""

    repo_root = repo_root.resolve()

    with tempfile.TemporaryDirectory(prefix="flayer-validation-") as temporary_directory:
        temporary_root = Path(temporary_directory)
        environment = BuildEnvironment(repo_root, temporary_root / ".coverage")
        commands: tuple[tuple[str, tuple[str, ...]], ...] = (
            ("compile", ("-m", "compileall", "-q", "-f", "src", "tests", "tools")),
            ("Ruff", ("-m", "ruff", "check", ".")),
            ("mypy", ("-m", "mypy")),
            ("pytest", ("-m", "pytest", "-p", "pytest_cov.plugin")),
            (
                "coverage report",
                ("-m", "coverage", "json", "-o", str(temporary_root / "coverage.json")),
            ),
        )

        for stage_name, arguments in commands:
            exit_code = RunCommand(
                stage_name, (sys.executable, *arguments), repo_root, environment,
            )

            if exit_code != 0:
                return exit_code

        try:
            CheckCoverage(temporary_root / "coverage.json")

        except (OSError, ValueError) as error:
            print(f"Validation failed during coverage floor: {error}", file=sys.stderr)

            return 1

        source_result = RunCommand(
            "local source import",
            (sys.executable, "-I", "-c", BuildImportSmoke(repo_root / "src")),
            temporary_root,
            environment,
        )

        if source_result != 0:
            return source_result

        install_root = temporary_root / "installed"
        install_result = RunCommand(
            "offline package installation",
            (
                sys.executable, "-m", "pip", "--disable-pip-version-check", "--no-input",
                "install", "--no-index", "--no-deps", "--no-build-isolation",
                "--target", str(install_root), str(repo_root),
            ),
            temporary_root,
            environment,
        )

        if install_result != 0:
            return install_result

        installed_result = RunCommand(
            "installed package import",
            (sys.executable, "-I", "-c", BuildImportSmoke(install_root)),
            temporary_root,
            environment,
        )

        if installed_result != 0:
            return installed_result

        if (repo_root / "src" / "flayer" / "__main__.py").is_file():
            cli_result = RunCommand(
                "CLI help",
                (sys.executable, "-m", "flayer", "--help"),
                repo_root,
                environment,
            )

            if cli_result != 0:
                return cli_result

        else:
            print("CLI smoke: no package CLI in this checkout", flush=True)

    print("Validation passed", flush=True)

    return 0


def Main() -> int:
    """Run the complete gate from the checkout containing this script."""

    return RunGate(REPOSITORY_ROOT)


if __name__ == "__main__":
    raise SystemExit(Main())
