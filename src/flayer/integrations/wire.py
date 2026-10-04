"""Bounded strict JSON codecs validate representations without dispatch or authorization."""

from __future__ import annotations

import json
from typing import cast

from flayer.core.contracts import ParseIdentity, RequireTable, StackIdentity, ValidateFields
from flayer.diagnostics.contracts import DiagnosticStatus

from .contracts import (
    MAX_CHECKS,
    MAX_WIRE_BYTES,
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

MAX_JSON_DEPTH = 8
MAX_JSON_VALUES = 4096
ENVELOPE_FIELDS = frozenset({
    "schema_version", "envelope", "identity", "request_id", "operation",
})


def _UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate fields at every object level without displaying their values."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise IntegrationError("Integration JSON contains duplicate fields")

        result[key] = value

    return result


def _RejectConstant(value: str) -> object:
    """Reject nonstandard JSON numeric tokens without returning rejected text."""

    raise IntegrationError("Integration JSON requires finite standard numbers")


def _BoundStructure(value: object, depth: int, remaining: list[int]) -> None:
    """Bound decoded nesting and total values before schema traversal."""

    remaining[0] -= 1

    if depth > MAX_JSON_DEPTH or remaining[0] < 0:
        raise IntegrationError("Integration JSON exceeds its structural bounds")

    if isinstance(value, dict):
        for item in value.values():
            _BoundStructure(item, depth + 1, remaining)

    elif isinstance(value, list):
        for item in value:
            _BoundStructure(item, depth + 1, remaining)


def _Decode(payload: str) -> object:
    """Read only bounded UTF-8 JSON strings and sanitize every decoding error."""

    try:
        if not isinstance(payload, str) or len(payload) > MAX_WIRE_BYTES:
            raise IntegrationError("Integration JSON exceeds its byte limit")

        if len(payload.encode("utf-8")) > MAX_WIRE_BYTES:
            raise IntegrationError("Integration JSON exceeds its byte limit")

        decoded: object = json.loads(
            payload, object_pairs_hook=_UniqueObject, parse_constant=_RejectConstant,
        )
        _BoundStructure(decoded, 0, [MAX_JSON_VALUES])

        return decoded

    except (ValueError, RecursionError, UnicodeError):
        raise IntegrationError("Unable to parse a valid bounded integration envelope") from None


def _Request(value: object, expected_identity: StackIdentity, envelope: str) -> IntegrationRequest:
    """Bind decoded metadata to caller context with an exact envelope schema."""

    table = RequireTable(value, "integration envelope")
    extra_fields = frozenset({"evidence"}) if envelope == "result" else frozenset()
    ValidateFields(table, ENVELOPE_FIELDS | extra_fields, frozenset(), "integration envelope")

    if table["envelope"] != envelope:
        raise IntegrationError("Integration envelope kind is unsupported")

    identity = ParseIdentity(table["identity"])
    RequireIdentity(identity, expected_identity)
    request_id = table["request_id"]
    operation = table["operation"]

    if not isinstance(request_id, str) or not isinstance(operation, str):
        raise IntegrationError("Integration correlation and operation require strings")

    return IntegrationRequest(
        identity, request_id, IntegrationOperation(operation), cast(int, table["schema_version"]),
    )


def ParseRequest(payload: str, expected_identity: StackIdentity) -> IntegrationRequest:
    """Validate untrusted read-only intent without invoking any operation or permission check."""

    try:
        return _Request(_Decode(payload), expected_identity, "request")

    except ValueError:
        raise IntegrationError("Unable to parse a valid owned integration request") from None


def _Array(value: object, limit: int) -> list[object]:
    """Require bounded JSON arrays rather than accepting iterable or coerced values."""

    if not isinstance(value, list) or len(value) > limit:
        raise IntegrationError("Integration evidence requires a bounded array")

    return value


def _ParseDiagnostic(value: object) -> DiagnosticEvidence:
    """Validate allowlisted checks and a severity summary consistent with their outcomes."""

    table = RequireTable(value, "diagnostic evidence")
    ValidateFields(table, frozenset({"status", "checks"}), frozenset(), "diagnostic evidence")
    checks: list[CheckEvidence] = []

    for item in _Array(table["checks"], MAX_CHECKS):
        check = RequireTable(item, "check evidence")
        ValidateFields(check, frozenset({"status", "metrics"}), frozenset(), "check evidence")
        metrics = RequireTable(check["metrics"], "check metrics")
        ValidateFields(metrics, frozenset(), frozenset(METRIC_BOUNDS), "check metrics")
        checks.append(CheckEvidence(DiagnosticStatus(check["status"]), tuple(
            Metric(name, cast(int | float | None, metric))
            for name, metric in sorted(metrics.items())
        )))

    evidence = DiagnosticEvidence(tuple(checks))

    if table["status"] != evidence.Status.value:
        raise IntegrationError("Integration diagnostic summary does not match its checks")

    return evidence


def _ParseLifecycle(value: object) -> LifecycleEvidence:
    """Decode only stable lifecycle outcomes and bounded observation category counts."""

    table = RequireTable(value, "lifecycle evidence")
    ValidateFields(table, frozenset({"action", "status", "recovery_required", "resources"}),
                   frozenset(), "lifecycle evidence")
    resources: list[ResourceCount] = []

    for item in _Array(table["resources"], len(RESOURCE_STATUSES)):
        resource = RequireTable(item, "resource count")
        ValidateFields(resource, frozenset({"status", "count"}), frozenset(), "resource count")
        resources.append(ResourceCount(cast(str, resource["status"]), cast(int, resource["count"])))

    return LifecycleEvidence(
        cast(str, table["action"]), cast(str, table["status"]),
        cast(bool, table["recovery_required"]), tuple(resources),
    )


def ParseResult(payload: str, expected_request: IntegrationRequest) -> IntegrationResult:
    """Bind an untrusted representation to its request without asserting authenticity."""

    try:
        if not isinstance(expected_request, IntegrationRequest):
            raise IntegrationError("Integration result requires an originating request")

        value = _Decode(payload)
        request = _Request(value, expected_request.identity, "result")

        if request != expected_request:
            raise IntegrationError("Integration result does not match the originating request")

        table = RequireTable(value, "integration result")

        if request.operation is IntegrationOperation.STATE:
            state = RequireTable(table["evidence"], "state evidence")
            ValidateFields(state, frozenset({"resource_count"}), frozenset(), "state evidence")

            return IntegrationResult(request, StateEvidence(cast(int, state["resource_count"])))

        if request.operation is IntegrationOperation.LIFECYCLE_REPORT:
            return IntegrationResult(request, _ParseLifecycle(table["evidence"]))

        return IntegrationResult(request, _ParseDiagnostic(table["evidence"]))

    except (ValueError, TypeError):
        raise IntegrationError("Unable to parse a valid correlated integration result") from None


def _Metadata(request: IntegrationRequest, envelope: str) -> dict[str, object]:
    """Represent validated non-secret routing metadata without consumer-specific fields."""

    return {
        "schema_version": request.schema_version, "envelope": envelope,
        "identity": {
            "project": request.identity.project, "stack": request.identity.stack,
            "provider": request.identity.provider, "scope_id": request.identity.scope_id,
            "owner_id": request.identity.owner_id,
        },
        "request_id": request.request_id,
        "operation": request.operation.value,
    }


def _Encode(value: dict[str, object]) -> str:
    """Produce deterministic standard JSON within the same byte limit as parsing."""

    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    if len(payload.encode("utf-8")) > MAX_WIRE_BYTES:
        raise IntegrationError("Serialized integration envelope exceeds its byte limit")

    return payload


def SerializeRequest(request: IntegrationRequest) -> str:
    """Serialize validated observation intent without resolving targets or credentials."""

    if not isinstance(request, IntegrationRequest):
        raise IntegrationError("Integration serialization requires a validated request")

    return _Encode(_Metadata(request, "request"))


def SerializeResult(result: IntegrationResult) -> str:
    """Serialize only explicitly allowed evidence, never source objects or raw adapter data."""

    if not isinstance(result, IntegrationResult):
        raise IntegrationError("Integration serialization requires a validated result")

    value = _Metadata(result.request, "result")
    evidence = result.evidence

    if isinstance(evidence, DiagnosticEvidence):
        value["evidence"] = {
            "status": evidence.Status.value,
            "checks": [{"status": check.status.value,
                        "metrics": {metric.name: metric.value for metric in check.metrics}}
                       for check in evidence.checks],
        }

    elif isinstance(evidence, StateEvidence):
        value["evidence"] = {"resource_count": evidence.resource_count}

    else:
        value["evidence"] = {
            "action": evidence.action, "status": evidence.status,
            "recovery_required": evidence.recovery_required,
            "resources": [{"status": resource.status, "count": resource.count}
                          for resource in evidence.resources],
        }

    return _Encode(value)
