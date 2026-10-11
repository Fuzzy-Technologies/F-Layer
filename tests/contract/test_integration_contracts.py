"""Strict wire compatibility, privacy, bounds, and ownership correlation contracts."""

from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.diagnostics import DiagnosticStatus
from flayer.integrations import (
    CheckEvidence,
    DiagnosticEvidence,
    IntegrationError,
    IntegrationOperation,
    IntegrationRequest,
    IntegrationResult,
    LifecycleEvidence,
    Metric,
    ParseRequest,
    ParseResult,
    ResourceCount,
    SerializeRequest,
    SerializeResult,
    StateEvidence,
)
from flayer.integrations.contracts import MAX_CHECKS, MAX_WIRE_BYTES

IDENTITY = StackIdentity("example", "sandbox", "fake", "scope-example", "example-owner")
EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "integrations"


def Request(operation: IntegrationOperation = IntegrationOperation.STATUS) -> IntegrationRequest:
    """Construct a synthetic exact-scope request for isolated contract tests."""

    return IntegrationRequest(IDENTITY, "example-001", operation)


def ResultData() -> dict[str, Any]:
    """Return editable synthetic diagnostic wire data without private infrastructure values."""

    result = IntegrationResult(Request(), DiagnosticEvidence((CheckEvidence(DiagnosticStatus.OK),)))

    return json.loads(SerializeResult(result))


@pytest.mark.parametrize("operation", list(IntegrationOperation))
def test_VersionOneSyntheticExamplesRoundTrip(operation: IntegrationOperation) -> None:
    """Every published F-Layer-side example retains schema, identity, and request correlation."""

    stem = operation.value
    request_text = (EXAMPLES / f"{stem}-request.json").read_text(encoding="utf-8")
    result_text = (EXAMPLES / f"{stem}-result.json").read_text(encoding="utf-8")
    request = ParseRequest(request_text, IDENTITY)
    result = ParseResult(result_text, request)

    assert request.operation is operation, "Example operation disagrees with its fixture name"
    assert ParseRequest(SerializeRequest(request), IDENTITY) == request, \
        "Request serialization changed the version-one contract"
    assert ParseResult(SerializeResult(result), request) == result, \
        "Result serialization changed the version-one evidence contract"
    assert SerializeResult(result) == SerializeResult(result), "Wire serialization is nondeterministic"


@pytest.mark.parametrize("field", list(asdict(IDENTITY)))
def test_AllIdentityFieldsMustMatchCallerContext(field: str) -> None:
    """Stack names alone cannot route evidence across projects, owners, providers, or scopes."""

    foreign = replace(IDENTITY, **{field: "foreign"})

    with pytest.raises(IntegrationError):
        ParseRequest(SerializeRequest(Request()), foreign)

    data = ResultData()
    data["identity"][field] = "foreign"

    with pytest.raises(IntegrationError):
        ParseResult(json.dumps(data), Request())


@pytest.mark.parametrize("field, value", [
    ("request_id", "different"), ("operation", "health"), ("schema_version", 2),
])
def test_ResultMustMatchExactOriginatingRequest(field: str, value: object) -> None:
    """Even same-scope results cannot be silently attached to a different observation request."""

    data = ResultData()
    data[field] = value

    with pytest.raises(IntegrationError):
        ParseResult(json.dumps(data), Request())


@pytest.mark.parametrize("operation", ["create", "destroy", "recover", "rollback", "apply", "execute"])
def test_MutationRequestsAreRejectedWithoutDispatch(operation: str) -> None:
    """A wire operation name cannot invoke or authorize the durable lifecycle mutation APIs."""

    data = json.loads(SerializeRequest(Request()))
    data["operation"] = operation

    with pytest.raises(IntegrationError):
        ParseRequest(json.dumps(data), IDENTITY)


@pytest.mark.parametrize("field, value", [
    ("schema_version", True), ("schema_version", "1"), ("schema_version", 0),
    ("request_id", ""), ("request_id", "a" * 65), ("request_id", "https://fixture.invalid"),
    ("request_id", False), ("operation", {}), ("envelope", "result"),
    ("credentials", "fixture-sensitive-marker"), ("parameters", {"endpoint": "fixture"}),
])
def test_RequestRejectsSchemaExpansionAndInvalidTypes(field: str, value: object) -> None:
    """Input validation is strict and error messages do not repeat rejected payloads."""

    data = json.loads(SerializeRequest(Request()))
    data[field] = value

    with pytest.raises(IntegrationError) as error:
        ParseRequest(json.dumps(data), IDENTITY)

    assert "fixture-sensitive-marker" not in str(error.value), "Parsing echoed rejected input"


@pytest.mark.parametrize("payload", [
    "[]", "null", "{", '{"schema_version":1,"schema_version":1}',
    '{"outer":{"token":"fixture-sensitive-marker","token":"other"}}',
    '{"number":NaN}', '{"number":Infinity}', "[" * 2000 + "]" * 2000,
    json.dumps({"nested": [[[[[[[[[[0]]]]]]]]]]}),
    json.dumps({"items": [0] * 4097}), "x" * (MAX_WIRE_BYTES + 1),
    "é" * (MAX_WIRE_BYTES // 2 + 1), "\ud800",
])
def test_UntrustedJsonIsBoundedAndErrorOutputIsSafe(payload: str) -> None:
    """Malformed, duplicate, deep, large, and invalid UTF-8 inputs fail with fixed diagnostics."""

    with pytest.raises(IntegrationError) as error:
        ParseRequest(payload, IDENTITY)

    assert "fixture-sensitive-marker" not in str(error.value), "JSON errors exposed private input"


@pytest.mark.parametrize("location, field, value", [
    ("result", "authorization", "fixture-sensitive-marker"),
    ("evidence", "messages", ["fixture-sensitive-marker"]),
    ("evidence", "status", "ok-but-private"),
    ("evidence", "checks", {}),
    ("evidence", "checks", [{}] * (MAX_CHECKS + 1)),
    ("check", "name", "fixture-sensitive-marker"),
    ("check", "status", "unknown"),
    ("check", "metrics", []),
    ("metrics", "token", "fixture-sensitive-marker"),
    ("metrics", "duration_seconds", "fixture-sensitive-marker"),
    ("metrics", "http_status", True),
    ("metrics", "received_bytes", -1),
])
def test_ResultRejectsArbitraryPayloadsAndContradictoryOutcomes(
    location: str, field: str, value: object,
) -> None:
    """The result boundary accepts only a strict allowlist and cannot upgrade failed evidence."""

    data = ResultData()
    targets = {
        "result": data, "evidence": data["evidence"],
        "check": data["evidence"]["checks"][0],
        "metrics": data["evidence"]["checks"][0]["metrics"],
    }
    targets[location][field] = value

    with pytest.raises(IntegrationError) as error:
        ParseResult(json.dumps(data), Request())

    assert "fixture-sensitive-marker" not in str(error.value), "Result validation exposed raw input"


def test_FailedAndEmptyEvidenceCannotImplySuccess() -> None:
    """Aggregation retains established severity and considers absent checks unsupported."""

    checks = (CheckEvidence(DiagnosticStatus.OK), CheckEvidence(DiagnosticStatus.FAILED))
    result = IntegrationResult(Request(), DiagnosticEvidence(checks))
    data = json.loads(SerializeResult(result))
    data["evidence"]["status"] = "ok"

    with pytest.raises(IntegrationError):
        ParseResult(json.dumps(data), Request())

    assert result.evidence.Status is DiagnosticStatus.FAILED, "Failed checks were hidden"
    assert DiagnosticEvidence(()).Status is DiagnosticStatus.UNSUPPORTED, \
        "Missing evidence incorrectly implied success"


@pytest.mark.parametrize("evidence", [
    DiagnosticEvidence((CheckEvidence(DiagnosticStatus.OK, (
        Metric("duration_seconds", 0.5), Metric("received_bytes", 64),
        Metric("http_status", 206), Metric("throughput_mbps", None),
    )),)),
    StateEvidence(0),
    LifecycleEvidence("create", "uncertain", True, (ResourceCount("recorded", 2),)),
])
def test_ValidEvidenceRoundTripsIncludingHistoricalMutationOutcomes(evidence: Any) -> None:
    """Historical mutation outcomes are data and never become supported mutation requests."""

    operation = (
        IntegrationOperation.STATE if isinstance(evidence, StateEvidence)
        else IntegrationOperation.LIFECYCLE_REPORT if isinstance(evidence, LifecycleEvidence)
        else IntegrationOperation.STATUS
    )
    result = IntegrationResult(Request(operation), evidence)

    assert ParseResult(SerializeResult(result), result.request) == result, \
        "Valid evidence lost information during its strict wire round trip"


@pytest.mark.parametrize("operation, evidence", [
    (IntegrationOperation.STATE, {"resource_count": True}),
    (IntegrationOperation.STATE, {"resource_count": 4097}),
    (IntegrationOperation.STATE, {"resource_count": 0, "resource_id": "fixture"}),
    (IntegrationOperation.LIFECYCLE_REPORT, {
        "action": "execute", "status": "complete", "recovery_required": False, "resources": [],
    }),
    (IntegrationOperation.LIFECYCLE_REPORT, {
        "action": "status", "status": "complete", "recovery_required": 0, "resources": [],
    }),
    (IntegrationOperation.LIFECYCLE_REPORT, {
        "action": "status", "status": "complete", "recovery_required": False,
        "resources": [{"status": "present", "count": 1, "resource_id": "fixture"}],
    }),
])
def test_StateAndLifecycleEvidenceRejectPrivateOrMalformedFields(
    operation: IntegrationOperation, evidence: object,
) -> None:
    """State and lifecycle result schemas never permit extra resource identifiers."""

    request = Request(operation)
    data = json.loads(SerializeRequest(request))
    data.update(envelope="result", evidence=evidence)

    with pytest.raises(IntegrationError):
        ParseResult(json.dumps(data), request)
