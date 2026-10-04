"""Read-only diagnostic CLI with no implicit infrastructure or network discovery."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import NoReturn

from .diagnostics import (
    BenchmarkLimits,
    CheckResult,
    DiagnosticReport,
    DiagnosticStatus,
    ProbeEndpoint,
    ProviderStatus,
    RenderJson,
    RenderText,
    RunBenchmark,
    RuntimeChecks,
)


class DiagnosticArgumentParser(argparse.ArgumentParser):
    """Suppress raw invalid argument values that may contain private endpoint material."""

    def error(self, message: str) -> NoReturn:
        """Preserve argparse's exit contract while keeping untrusted argument text private."""

        self.exit(2, f"{self.prog}: error: invalid command arguments\n")


def Parser() -> argparse.ArgumentParser:
    """Build an offline help surface and bounded command options."""

    parser = DiagnosticArgumentParser(prog="python -m flayer", description="F-Layer diagnostics")
    commands = parser.add_subparsers(dest="command", required=True)

    for command in ("status", "check", "health", "benchmark"):
        child = commands.add_parser(command)
        child.add_argument("--format", choices=("text", "json"), default="text")

        if command in ("health", "benchmark"):
            child.add_argument("--endpoint", help="Explicit HTTP(S) endpoint without credentials")
            child.add_argument("--timeout", type=float, default=3.0, metavar="SECONDS")

        if command == "benchmark":
            child.add_argument("--count", type=int, default=3)
            child.add_argument("--bytes", type=int, default=64 * 1024, dest="byte_limit")

    return parser


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run diagnostics, report unsupported observations truthfully, and return their outcome."""

    args = Parser().parse_args(arguments)

    try:
        if args.command == "status":
            checks = (*RuntimeChecks(), ProviderStatus())

        elif args.command == "check":
            checks = RuntimeChecks()

        elif not args.endpoint:
            checks = (CheckResult(
                "endpoint", DiagnosticStatus.UNSUPPORTED, "An explicit endpoint is required"
            ),)

        elif args.command == "health":
            checks = (ProbeEndpoint(args.endpoint, args.timeout),)

        else:
            limits = BenchmarkLimits(args.timeout, args.count, args.byte_limit)
            checks = RunBenchmark(args.endpoint, limits)

    except ValueError:
        report = DiagnosticReport(args.command, (CheckResult(
            "input", DiagnosticStatus.FAILED, "Invalid endpoint or diagnostic limits"
        ),))
        print(RenderJson(report) if args.format == "json" else RenderText(report))

        return 2

    report = DiagnosticReport(args.command, checks)
    print(RenderJson(report) if args.format == "json" else RenderText(report))

    return report.ExitCode()


if __name__ == "__main__":
    raise SystemExit(Main())
