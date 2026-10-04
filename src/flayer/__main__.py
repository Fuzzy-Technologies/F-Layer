"""Explicit diagnostics and opt-in owned lifecycle CLI without implicit cloud discovery."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from dataclasses import asdict
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

    parser = DiagnosticArgumentParser(prog="python -m flayer", description="F-Layer diagnostics and owned lifecycle")
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

    lifecycle = commands.add_parser("lifecycle", help="Explicit owned stack lifecycle")
    actions = lifecycle.add_subparsers(dest="action", required=True)

    for action in ("create", "status", "destroy", "recover"):
        child = actions.add_parser(action)
        child.add_argument("--config", required=True, help="Explicit lifecycle plan TOML path")
        child.add_argument("--state", required=True, help="Explicit owned snapshot path")
        child.add_argument("--yc-profile", required=True, help="Explicit preauthenticated yc profile")
        child.add_argument("--format", choices=("text", "json"), default="text")

        if action != "status":
            child.add_argument("--allow-mutation", action="store_true")
            child.add_argument("--scope-confirm", required=True, help="Repeat the exact folder ID")

        if action == "recover":
            child.add_argument("--rollback", action="store_true")

    return parser


def _Lifecycle(args: argparse.Namespace) -> int:
    """Require concrete scope opt-in before constructing a mutating provider adapter."""

    from .core.lifecycle import LifecycleEngine, LifecycleError, LoadDeploymentPlan
    from .core.state import StateError
    from .providers.contracts import ProviderError
    from .providers.yandex import YandexCloudSettings
    from .providers.yandex_lifecycle import YandexLifecycleProvider

    try:
        plan = LoadDeploymentPlan(args.config)

        if plan.identity.provider != "yandex-cloud":
            raise LifecycleError("CLI lifecycle provider is unsupported")

        if args.action != "status" and (
            not args.allow_mutation or args.scope_confirm != plan.identity.scope_id
        ):
            raise LifecycleError("Mutation requires explicit opt-in and exact scope confirmation")

        provider = YandexLifecycleProvider(YandexCloudSettings(
            folder_id=plan.identity.scope_id, profile=args.yc_profile,
        ))
        engine = LifecycleEngine(plan, provider, args.state)

        if args.action == "create":
            report = engine.Create()

        elif args.action == "status":
            report = engine.Status()

        elif args.action == "destroy":
            report = engine.Destroy()

        else:
            report = engine.Recover(rollback=args.rollback)

    except (LifecycleError, StateError, ProviderError, ValueError):
        payload = {"action": args.action, "status": "failed", "recovery_required": True}
        print(json.dumps(payload) if args.format == "json" else "Lifecycle operation blocked or failed")

        return 2

    print(json.dumps(asdict(report), sort_keys=True) if args.format == "json" else
          f"Lifecycle {report.action}: {report.status}; resources={len(report.resources)}; "
          f"recovery_required={str(report.recovery_required).lower()}")

    return report.ExitCode()


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run explicit diagnostics or authorized lifecycle actions and return their outcome."""

    args = Parser().parse_args(arguments)

    if args.command == "lifecycle":
        return _Lifecycle(args)

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
