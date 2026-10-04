"""Consumer-neutral immutable envelopes for strictly allowlisted integration evidence."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeAlias

from flayer.core.contracts import ContractError, StackIdentity, ValidateSchemaVersion
from flayer.diagnostics.contracts import STATUS_PRIORITY, DiagnosticStatus

MAX_WIRE_BYTES = 64 * 1024
MAX_CHECKS = 128
MAX_RESOURCES = 4096
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
METRIC_BOUNDS = {
    "duration_seconds": (0, 30),
    "received_bytes": (0, 1024 * 1024),
    "byte_limit": (1, 1024 * 1024),
    "http_status": (100, 599),
    "throughput_mbps": (0, 1_000_000_000_000),
}
INTEGER_METRICS = frozenset({"received_bytes", "byte_limit", "http_status"})
NULLABLE_METRICS = frozenset({"http_status", "throughput_mbps"})
LIFECYCLE_ACTIONS = frozenset({"status", "create", "destroy", "recover"})
LIFECYCLE_STATUSES = frozenset({
    "complete", "incomplete", "uncertain", "rolled-back", "rollback-incomplete",
})
RESOURCE_STATUSES = frozenset({"recorded", "present", "missing", "not-recorded"})


class IntegrationError(ContractError):
    """An envelope violates the bounded evidence contract without exposing its input."""


class IntegrationOperation(StrEnum):
    """Supported observations convey no infrastructure execution authorization."""

    STATUS = "status"
    HEALTH = "health"
    BENCHMARK = "benchmark"
    STATE = "state"
    LIFECYCLE_REPORT = "lifecycle-report"


def RequireIdentity(actual: StackIdentity, expected: StackIdentity) -> None:
    """Require all ownership and provider scope fields to match independently held context."""

    if not isinstance(expected, StackIdentity) or actual != expected:
        raise IntegrationError("Integration identity does not match the expected ownership boundary")


def ValidateCount(value: object) -> int:
    """Reject coercion and bound recorded-resource and observation counts."""

    if type(value) is not int or not 0 <= value <= MAX_RESOURCES:
        raise IntegrationError("Integration resource count exceeds its supported bounds")

    return value


@dataclass(frozen=True, slots=True)
class IntegrationRequest:
    """Non-authorizing observation intent bound to exact scope, owner, and correlation."""

    identity: StackIdentity
    request_id: str
    operation: IntegrationOperation
    schema_version: int = 1

    def __post_init__(self) -> None:
        """Validate direct requests with the same strict rules as decoded requests."""

        ValidateSchemaVersion(self.schema_version)

        if (
            not isinstance(self.identity, StackIdentity)
            or not isinstance(self.request_id, str)
            or REQUEST_ID_PATTERN.fullmatch(self.request_id) is None
            or not isinstance(self.operation, IntegrationOperation)
        ):
            raise IntegrationError("Integration request fields do not match the contract")


@dataclass(frozen=True, slots=True)
class Metric:
    """One allowlisted bounded measurement that cannot contain strings or raw payloads."""

    name: str
    value: int | float | None

    def __post_init__(self) -> None:
        """Require finite measurements, strict integer metrics, and supported nullable fields."""

        if not isinstance(self.name, str) or self.name not in METRIC_BOUNDS:
            raise IntegrationError("Integration metric is unsupported")

        if self.value is None:
            if self.name not in NULLABLE_METRICS:
                raise IntegrationError("Integration metric cannot be null")

            return

        lower, upper = METRIC_BOUNDS[self.name]

        if (
            type(self.value) not in {int, float}
            or (self.name in INTEGER_METRICS and type(self.value) is not int)
            or not lower <= self.value <= upper
            or not math.isfinite(self.value)
        ):
            raise IntegrationError("Integration metric exceeds its supported bounds")


@dataclass(frozen=True, slots=True)
class CheckEvidence:
    """A diagnostic outcome and measurements without private names, prose, or details."""

    status: DiagnosticStatus
    metrics: tuple[Metric, ...] = ()

    def __post_init__(self) -> None:
        """Reject mutable or duplicate measurements and invalid diagnostic outcomes."""

        if (
            not isinstance(self.status, DiagnosticStatus)
            or not isinstance(self.metrics, tuple)
            or len(self.metrics) > len(METRIC_BOUNDS)
            or any(not isinstance(metric, Metric) for metric in self.metrics)
            or len({metric.name for metric in self.metrics}) != len(self.metrics)
        ):
            raise IntegrationError("Integration check fields do not match the contract")

        object.__setattr__(self, "metrics", tuple(sorted(self.metrics, key=lambda metric: metric.name)))


@dataclass(frozen=True, slots=True)
class DiagnosticEvidence:
    """Ordered diagnostic checks retain truthful aggregation without external text."""

    checks: tuple[CheckEvidence, ...]

    def __post_init__(self) -> None:
        """Bound diagnostic evidence and require immutable validated observations."""

        if (
            not isinstance(self.checks, tuple)
            or len(self.checks) > MAX_CHECKS
            or any(not isinstance(check, CheckEvidence) for check in self.checks)
        ):
            raise IntegrationError("Integration diagnostic evidence exceeds its supported bounds")

    @property
    def Status(self) -> DiagnosticStatus:
        """Use the established severity contract, including unsupported empty evidence."""

        return max(
            (check.status for check in self.checks), key=STATUS_PRIORITY.__getitem__,
            default=DiagnosticStatus.UNSUPPORTED,
        )


@dataclass(frozen=True, slots=True)
class StateEvidence:
    """A local owned-state count makes no remote existence or health assertion."""

    resource_count: int

    def __post_init__(self) -> None:
        """Validate the minimal non-identifying inventory summary."""

        ValidateCount(self.resource_count)


@dataclass(frozen=True, slots=True)
class ResourceCount:
    """One stable lifecycle observation category without resource locators."""

    status: str
    count: int

    def __post_init__(self) -> None:
        """Reject arbitrary provider text and unbounded lifecycle category counts."""

        if not isinstance(self.status, str) or self.status not in RESOURCE_STATUSES:
            raise IntegrationError("Integration lifecycle resource status is unsupported")

        ValidateCount(self.count)


@dataclass(frozen=True, slots=True)
class LifecycleEvidence:
    """Historical lifecycle outcome and recovery requirement convey no mutation permission."""

    action: str
    status: str
    recovery_required: bool
    resources: tuple[ResourceCount, ...]

    def __post_init__(self) -> None:
        """Require only known lifecycle actions, outcomes, and immutable aggregate counts."""

        if (
            not isinstance(self.action, str) or self.action not in LIFECYCLE_ACTIONS
            or not isinstance(self.status, str) or self.status not in LIFECYCLE_STATUSES
            or type(self.recovery_required) is not bool
            or not isinstance(self.resources, tuple)
            or len(self.resources) > len(RESOURCE_STATUSES)
            or any(not isinstance(resource, ResourceCount) for resource in self.resources)
            or len({resource.status for resource in self.resources}) != len(self.resources)
        ):
            raise IntegrationError("Integration lifecycle evidence fields do not match the contract")

        ValidateCount(sum(resource.count for resource in self.resources))


Evidence: TypeAlias = DiagnosticEvidence | StateEvidence | LifecycleEvidence


@dataclass(frozen=True, slots=True)
class IntegrationResult:
    """Allowlisted evidence bound to the exact original validated observation request."""

    request: IntegrationRequest
    evidence: Evidence

    def __post_init__(self) -> None:
        """Prevent operation and evidence type mismatches during direct construction."""

        if not isinstance(self.request, IntegrationRequest):
            raise IntegrationError("Integration result requires a validated request")

        expected_type: type[Evidence] = {
            IntegrationOperation.STATE: StateEvidence,
            IntegrationOperation.LIFECYCLE_REPORT: LifecycleEvidence,
        }.get(self.request.operation, DiagnosticEvidence)

        if not isinstance(self.evidence, expected_type):
            raise IntegrationError("Integration evidence does not match the requested operation")
