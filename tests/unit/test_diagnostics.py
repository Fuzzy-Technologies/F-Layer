"""Deterministic safety and outcome tests for diagnostic contracts and health evidence."""

from __future__ import annotations

import json
import sys

import pytest

from flayer.__main__ import Main
from flayer.diagnostics import (
    CheckResult,
    DiagnosticReport,
    DiagnosticStatus,
    EvaluateHealthReport,
    ProviderStatus,
    Redact,
    RenderJson,
    RenderText,
    RunChecks,
    RuntimeChecks,
)


@pytest.mark.parametrize("status, code", [
    (DiagnosticStatus.OK, 0), (DiagnosticStatus.WARNING, 1),
    (DiagnosticStatus.FAILED, 1), (DiagnosticStatus.STALE, 3),
    (DiagnosticStatus.UNSUPPORTED, 4),
])
def test_ReportOutcomes(status: DiagnosticStatus, code: int) -> None:
    """Each outcome has a stable schema and truthful exit code."""

    report = DiagnosticReport("health", (CheckResult("probe", status, "Observation"),))
    encoded = json.loads(RenderJson(report))

    assert encoded["status"] == status.value, "Report status differs from its single check"
    assert encoded["schema_version"] == 1, "Report must declare its wire version"
    assert report.ExitCode() == code, "CLI outcome must preserve the diagnostic status"
    assert f"[{status.value}] probe: Observation" in RenderText(report), "Text lost an observation"


def test_ReportAggregatesFailuresAndEmptyIsUnsupported() -> None:
    """An OK check cannot mask failure, and absent evidence cannot imply success."""

    checks = tuple(CheckResult("probe", status, "Observation") for status in DiagnosticStatus)

    assert DiagnosticReport("health", checks).Status is DiagnosticStatus.FAILED, \
        "Aggregate failure was hidden by another observation"
    assert DiagnosticReport("health", ()).Status is DiagnosticStatus.UNSUPPORTED, \
        "Missing evidence must remain unsupported"


def test_RecursiveRedactionAndTextSafety() -> None:
    """Nested credentials and arbitrary object representations never reach public output."""

    report = DiagnosticReport("check", (CheckResult(
        "safe", DiagnosticStatus.FAILED,
        "Failed https://user:fixture-password@fixture.invalid/path?token=fixture-token\ncontinued",
        {"nested": [{"Authorization": "fixture-authorization", "private_key": "fixture-key"}],
         "text": "Bearer fixture-bearer", "object": object(), "raw": b"fixture-private",
         "numeric": float("nan"), "ip": "192.0.2.10"},
    ),))
    output = RenderJson(report) + RenderText(report)

    for secret in ("fixture-password", "fixture-token", "fixture-authorization", "fixture-key",
                   "fixture-bearer", "fixture-private", "192.0.2.10"):
        assert secret not in output, "Sensitive content reached diagnostic output"

    assert "[redacted]" in output, "Redaction must be visible without exposing its input"
    assert len(RenderText(report).splitlines()) == 2, "Messages must not inject output lines"
    assert Redact((1, True, None, 2.5)) == [1, True, None, 2.5], "Safe scalar data was altered"


def test_RunChecksCapturesStructuredResultsAndSuppressesExceptions() -> None:
    """An adapter failure cannot print arbitrary cloud exception text."""

    def SuccessfulProbe() -> CheckResult:
        """Supply one successful isolated observation."""

        return CheckResult("fixture", DiagnosticStatus.OK, "Observed")

    def FailedProbe() -> CheckResult:
        """Simulate an exception containing private unstructured content."""

        raise OSError("fixture-secret-in-error")

    def InvalidProbe() -> CheckResult:
        """Simulate an invalid external adapter return value."""

        return None  # type: ignore[return-value]

    checks = RunChecks((SuccessfulProbe, FailedProbe, InvalidProbe))
    output = RenderJson(DiagnosticReport("health", checks))

    assert [check.status for check in checks] == [
        DiagnosticStatus.OK, DiagnosticStatus.FAILED, DiagnosticStatus.FAILED
    ], "Probe failures were not preserved"
    assert "fixture-secret-in-error" not in output, "Exception text must remain private"
    assert RunChecks(())[0].status is DiagnosticStatus.UNSUPPORTED, "Empty probes imply no support"


@pytest.mark.parametrize("state, status", [
    ("ready", DiagnosticStatus.OK), ("pending", DiagnosticStatus.WARNING),
    ("failed", DiagnosticStatus.FAILED), ("absent", DiagnosticStatus.FAILED),
    ("unexpected", DiagnosticStatus.FAILED),
])
def test_ProviderStatusRequiresAnExplicitObservation(state: str, status: DiagnosticStatus) -> None:
    """Generic state interpretation neither discovers resources nor echoes raw provider fields."""

    result = ProviderStatus({"state": state, "token": "fixture-secret"})

    assert result.status is status, "Provider state mapping changed"
    assert "fixture-secret" not in str(result.AsDict()), "Raw provider fields were copied"
    assert ProviderStatus().status is DiagnosticStatus.UNSUPPORTED, "No provider was selected"


@pytest.mark.parametrize("report, expected", [
    (None, DiagnosticStatus.UNSUPPORTED),
    ({"schema_version": 2}, DiagnosticStatus.UNSUPPORTED),
    ({"schema_version": True}, DiagnosticStatus.UNSUPPORTED),
    ({"schema_version": 1}, DiagnosticStatus.FAILED),
    ({"schema_version": 1, "timestamp": True, "status": "ok"}, DiagnosticStatus.FAILED),
    ({"schema_version": 1, "timestamp": float("nan"), "status": "ok"}, DiagnosticStatus.FAILED),
    ({"schema_version": 1, "timestamp": 90, "status": "bad"}, DiagnosticStatus.FAILED),
    ({"schema_version": 1, "timestamp": 101, "status": "ok"}, DiagnosticStatus.STALE),
    ({"schema_version": 1, "timestamp": 79, "status": "ok"}, DiagnosticStatus.STALE),
    ({"schema_version": 1, "timestamp": 80, "status": "ok"}, DiagnosticStatus.OK),
    ({"schema_version": 1, "timestamp": 90, "status": "warning"}, DiagnosticStatus.WARNING),
    ({"schema_version": 1, "timestamp": 90, "status": "failed"}, DiagnosticStatus.FAILED),
])
def test_HealthFreshnessContracts(report: dict[str, object] | None,
                                expected: DiagnosticStatus) -> None:
    """Expired, malformed, failed, and unsupported health evidence remain distinct."""

    result = EvaluateHealthReport(report, max_age_seconds=20, current_time=100)

    assert result.status is expected, "Freshness or reported outcome was misclassified"


@pytest.mark.parametrize("max_age, now", [
    (0, 1), (float("inf"), 1), (1, float("nan")), (True, 1), (1, False), ("bad", 1), (1, "bad")
])
def test_HealthRejectsUnboundedFreshness(max_age: float, now: float) -> None:
    """Freshness validation must not accept nonfinite evidence boundaries."""

    with pytest.raises(ValueError):
        EvaluateHealthReport(None, max_age, now)


def test_HealthUsesCurrentTime(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default clock use is deterministic when injected by tests."""

    monkeypatch.setattr("flayer.diagnostics.health.time.time", lambda: 100)
    result = EvaluateHealthReport({"schema_version": 1, "timestamp": 100, "status": "ok"})

    assert result.status is DiagnosticStatus.OK, "Current evidence should be fresh"


def test_RuntimeOnlyDescribesLocalExecution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Runtime compatibility cannot imply infrastructure or endpoint health."""

    assert RuntimeChecks()[0].status is DiagnosticStatus.OK, "Supported runtime was rejected"

    monkeypatch.setattr(sys, "version_info", (3, 10, 0))

    assert RuntimeChecks()[0].status is DiagnosticStatus.FAILED, "Unsupported runtime passed"


@pytest.mark.parametrize("arguments, code, outcome", [
    (["check", "--format", "json"], 0, "ok"),
    (["status", "--format", "json"], 4, "unsupported"),
    (["health", "--format", "json"], 4, "unsupported"),
    (["benchmark", "--format", "json"], 4, "unsupported"),
    (["health", "--endpoint", "https://fixture.invalid/?token=fixture-secret",
      "--format", "json"], 2, "failed"),
    (["benchmark", "--endpoint", "https://fixture.invalid", "--count", "999",
      "--format", "json"], 2, "failed"),
])
def test_CliOfflineAndInvalidInput(arguments: list[str], code: int, outcome: str,
                                  capsys: pytest.CaptureFixture[str]) -> None:
    """Offline defaults and invalid inputs produce truthful output without network work."""

    exit_code = Main(arguments)
    output = capsys.readouterr().out

    assert exit_code == code, "CLI exit code differs from requested diagnostic outcome"
    assert json.loads(output)["status"] == outcome, "CLI outcome was lost in JSON"
    assert "fixture-secret" not in output, "Input validation echoed a sensitive URL"


def test_CliHelpAndText(capsys: pytest.CaptureFixture[str]) -> None:
    """Offline help and text execution are available through the module entry point."""

    with pytest.raises(SystemExit) as error:
        Main(["--help"])

    assert error.value.code == 0, "Help must not report a diagnostic failure"
    assert "benchmark" in capsys.readouterr().out, "Help lost a supported command"
    assert Main(["check"]) == 0, "Local runtime check must succeed"
    assert "check: ok" in capsys.readouterr().out, "Text output lost its summary"


def test_CliArgumentErrorsSuppressSensitiveValues(capsys: pytest.CaptureFixture[str]) -> None:
    """Even argparse conversion errors must not echo arbitrary private command values."""

    with pytest.raises(SystemExit) as error:
        Main(["benchmark", "--count", "fixture-secret"])

    assert error.value.code == 2, "Invalid arguments require the input error exit code"
    assert "fixture-secret" not in capsys.readouterr().err, "Argument parser leaked input"


def test_RedactionSanitizesMappingKeysWithoutDroppingCollisions() -> None:
    """Untrusted keys are sanitized and collisions retain all redacted observations."""

    result = Redact({
        "https://fixture.invalid/token=fixture-secret": 1,
        "192.0.2.10": 2,
        "fixture_token_value": "fixture-secret",
        "safe_key": {"Authorization": "fixture-secret"},
    })
    output = json.dumps(result)

    assert "fixture-secret" not in output and "fixture.invalid" not in output, \
        "Sensitive mapping keys reached public output"
    assert "192.0.2.10" not in output, "Address-shaped mapping key was exposed"
    assert isinstance(result, dict) and len(result) == 4, "Sanitization dropped collided keys"
    assert "[redacted]:2" in output, "Collision suffix must be deterministic"


def test_RedactionBoundsCyclicAdapterData() -> None:
    """Cyclic external detail objects cannot recurse forever during public serialization."""

    value: dict[str, object] = {}
    value["nested"] = value

    assert "[redacted]" in json.dumps(Redact(value)), "Cyclic details were not bounded"


def test_InvalidObservationShapesFailClosed() -> None:
    """Untyped external data must not break generic observation interpretation."""

    assert ProviderStatus([]).status is DiagnosticStatus.FAILED, \
        "Malformed provider observation was not rejected"  # type: ignore[arg-type]
    assert EvaluateHealthReport([]).status is DiagnosticStatus.FAILED, \
        "Malformed health report was not rejected"  # type: ignore[arg-type]


def test_CheckAndReportRejectMalformedInputs() -> None:
    """Invalid status and shape fail at construction instead of crashing output rendering."""

    with pytest.raises(ValueError):
        CheckResult("probe", "ok", "Observation")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        CheckResult("", DiagnosticStatus.OK, "Observation")

    with pytest.raises(ValueError):
        CheckResult("probe", DiagnosticStatus.OK, "Observation", [])  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        DiagnosticReport("health", (None,))  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        DiagnosticReport("health", [])  # type: ignore[arg-type]

    def InvalidProbe() -> CheckResult:
        """Simulate an adapter attempting to construct an invalid typed result."""

        return CheckResult("probe", "bad", "Observation")  # type: ignore[arg-type]

    assert RunChecks((InvalidProbe,))[0].status is DiagnosticStatus.FAILED, \
        "Malformed adapter result did not fail closed"
