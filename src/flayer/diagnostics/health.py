"""Injected health probes and freshness validation without cloud access assumptions."""

from __future__ import annotations

import math
import sys
import time
from collections.abc import Iterable, Mapping
from typing import Protocol

from .contracts import CheckResult, DiagnosticStatus


class HealthProbe(Protocol):
    """An adapter supplies read-only observations without transferring authorization."""

    def __call__(self) -> CheckResult:
        """Perform an adapter-bounded probe and return one structured observation."""

        ...


def RuntimeChecks() -> tuple[CheckResult, ...]:
    """Check only supported Python execution; never imply remote infrastructure health."""

    supported = sys.version_info >= (3, 11)

    return (
        CheckResult(
            "python-runtime",
            DiagnosticStatus.OK if supported else DiagnosticStatus.FAILED,
            "Python runtime is supported" if supported else "Python 3.11 or newer is required",
            {"version": ".".join(str(part) for part in sys.version_info[:3])},
        ),
    )


def RunChecks(probes: Iterable[HealthProbe]) -> tuple[CheckResult, ...]:
    """Collect injected observations and suppress raw exception text on probe failure."""

    checks: list[CheckResult] = []

    for probe in probes:
        try:
            result = probe()

            if not isinstance(result, CheckResult):
                raise TypeError("Probe must return CheckResult")

            checks.append(result)

        except Exception:
            checks.append(CheckResult(
                "probe", DiagnosticStatus.FAILED, "Probe failed without safe structured evidence"
            ))

    if not checks:
        checks.append(CheckResult(
            "probe", DiagnosticStatus.UNSUPPORTED, "No health probe was supplied"
        ))

    return tuple(checks)


def ProviderStatus(observation: Mapping[str, object] | None = None) -> CheckResult:
    """Interpret a supplied generic provider observation without discovering resources."""

    if observation is None:
        return CheckResult(
            "provider-state", DiagnosticStatus.UNSUPPORTED, "No provider observation was supplied"
        )

    if not isinstance(observation, Mapping):
        return CheckResult(
            "provider-state", DiagnosticStatus.FAILED, "Provider observation must be a mapping"
        )

    state = observation.get("state")

    if state not in ("ready", "pending", "failed", "absent"):
        return CheckResult(
            "provider-state", DiagnosticStatus.FAILED, "Provider observation has an invalid state"
        )

    status = {
        "ready": DiagnosticStatus.OK,
        "pending": DiagnosticStatus.WARNING,
        "failed": DiagnosticStatus.FAILED,
        "absent": DiagnosticStatus.FAILED,
    }[str(state)]

    return CheckResult("provider-state", status, "Provider state observed", {"state": state})


def EvaluateHealthReport(
    report: Mapping[str, object] | None,
    max_age_seconds: float = 300,
    current_time: float | None = None,
) -> CheckResult:
    """Validate versioned health evidence and separate stale evidence from failed health."""

    now = time.time() if current_time is None else current_time

    if (
        isinstance(max_age_seconds, bool)
        or not isinstance(max_age_seconds, (int, float))
        or not math.isfinite(max_age_seconds)
        or max_age_seconds <= 0
        or isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(now)
    ):
        raise ValueError("Health freshness bounds must be finite and positive")

    if report is None:
        return CheckResult(
            "health-report", DiagnosticStatus.UNSUPPORTED, "No health report was supplied"
        )

    if not isinstance(report, Mapping):
        return CheckResult(
            "health-report", DiagnosticStatus.FAILED, "Health report must be a mapping"
        )

    if type(report.get("schema_version")) is not int or report.get("schema_version") != 1:
        return CheckResult(
            "health-report", DiagnosticStatus.UNSUPPORTED, "Health report schema is unsupported"
        )

    timestamp = report.get("timestamp")
    outcome = report.get("status")

    if (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
        or outcome not in ("ok", "warning", "failed")
    ):
        return CheckResult(
            "health-report", DiagnosticStatus.FAILED, "Health report fields are invalid"
        )

    age = now - timestamp
    details: dict[str, object] = {"age_seconds": age, "max_age_seconds": max_age_seconds}

    if age < 0 or age > max_age_seconds:
        return CheckResult(
            "health-report", DiagnosticStatus.STALE,
            "Health report is expired or dated in the future", details,
        )

    return CheckResult(
        "health-report", DiagnosticStatus(str(outcome)), "Health report is current", details
    )
