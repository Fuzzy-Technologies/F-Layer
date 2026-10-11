"""Read-only conversions project trusted caller-selected models into minimal evidence."""

from __future__ import annotations

from collections import Counter
from typing import cast

from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LifecycleObservation, LifecycleReport
from flayer.core.state import StackState
from flayer.diagnostics.contracts import DiagnosticReport

from .contracts import (
    MAX_CHECKS,
    MAX_RESOURCES,
    METRIC_BOUNDS,
    RESOURCE_STATUSES,
    CheckEvidence,
    DiagnosticEvidence,
    IntegrationError,
    IntegrationOperation,
    IntegrationRequest,
    IntegrationResult,
    LifecycleEvidence,
    Metric,
    RequireIdentity,
    ResourceCount,
    StateEvidence,
)


def AdaptDiagnostics(
    request: IntegrationRequest, report: DiagnosticReport, observed_identity: StackIdentity,
) -> IntegrationResult:
    """Bind selected status, health, or benchmark observations and omit arbitrary source text."""

    RequireIdentity(observed_identity, request.identity)

    if (
        request.operation not in {
            IntegrationOperation.STATUS, IntegrationOperation.HEALTH, IntegrationOperation.BENCHMARK,
        }
        or not isinstance(report, DiagnosticReport)
        or report.command != request.operation.value
        or len(report.checks) > MAX_CHECKS
    ):
        raise IntegrationError("Diagnostic source does not match the integration request")

    checks = tuple(CheckEvidence(check.status, tuple(
        Metric(name, cast(int | float | None, check.details[name])) for name in sorted(METRIC_BOUNDS)
        if name in check.details
    )) for check in report.checks)

    return IntegrationResult(request, DiagnosticEvidence(checks))


def AdaptState(request: IntegrationRequest, state: StackState) -> IntegrationResult:
    """Summarize recorded ownership without exporting locators or claiming remote readiness."""

    if request.operation is not IntegrationOperation.STATE or not isinstance(state, StackState):
        raise IntegrationError("Owned state source does not match the integration request")

    RequireIdentity(state.identity, request.identity)

    return IntegrationResult(request, StateEvidence(len(state.resources)))


def AdaptLifecycle(
    request: IntegrationRequest, report: LifecycleReport, observed_identity: StackIdentity,
) -> IntegrationResult:
    """Summarize supplied lifecycle evidence with caller-bound scope, never remote attestation."""

    RequireIdentity(observed_identity, request.identity)

    if (
        request.operation is not IntegrationOperation.LIFECYCLE_REPORT
        or not isinstance(report, LifecycleReport)
        or not isinstance(report.resources, tuple)
        or len(report.resources) > MAX_RESOURCES
        or any(not isinstance(resource, LifecycleObservation) for resource in report.resources)
        or any(not isinstance(resource.status, str) or resource.status not in RESOURCE_STATUSES
               for resource in report.resources)
    ):
        raise IntegrationError("Lifecycle source does not match the integration request")

    counts = Counter(resource.status for resource in report.resources)
    evidence = LifecycleEvidence(
        report.action, report.status, report.recovery_required,
        tuple(ResourceCount(status, count) for status, count in sorted(counts.items())),
    )

    return IntegrationResult(request, evidence)
