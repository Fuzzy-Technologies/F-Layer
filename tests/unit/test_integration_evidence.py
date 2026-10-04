"""Allowlisted projection safety and immutable integration model validation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LifecycleObservation, LifecycleReport
from flayer.core.state import ResourceState, StackState
from flayer.diagnostics import CheckResult, DiagnosticReport, DiagnosticStatus
from flayer.integrations import (
    AdaptDiagnostics,
    AdaptLifecycle,
    AdaptState,
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
from flayer.integrations.wire import _Encode

IDENTITY = StackIdentity("example", "sandbox", "fake", "scope-example", "example-owner")
PRIVATE_MARKER = "fixture-sensitive-marker"


@dataclass(frozen=True)
class ExtendedIdentity(StackIdentity):
    """Simulate host metadata that must never silently expand the exact wire allowlist."""

    credential: str = PRIVATE_MARKER


@dataclass(frozen=True)
class ExtendedStateEvidence(StateEvidence):
    """Simulate a local evidence extension that carries prohibited private host data."""

    payload: str = PRIVATE_MARKER


@dataclass(frozen=True)
class ExtendedLifecycleEvidence(LifecycleEvidence):
    """Simulate extended local lifecycle fields excluded from version-one serialization."""

    payload: str = PRIVATE_MARKER


def Request(operation: IntegrationOperation) -> IntegrationRequest:
    """Bind the test request to synthetic ownership and correlation metadata."""

    return IntegrationRequest(IDENTITY, "example-001", operation)


def test_AdaptersOmitAllNonAllowlistedSourceData() -> None:
    """Source prose, binary credentials, arbitrary payloads, and resource locators never serialize."""

    request = Request(IntegrationOperation.HEALTH)
    report = DiagnosticReport("health", (CheckResult(
        PRIVATE_MARKER, DiagnosticStatus.STALE, PRIVATE_MARKER,
        {"token": PRIVATE_MARKER.encode(), "payload": {"private": PRIVATE_MARKER},
         "endpoint": "https://fixture.invalid", "duration_seconds": 0.5},
    ),))
    state = StackState(IDENTITY, (ResourceState("private-logical", "network", PRIVATE_MARKER),))
    lifecycle = LifecycleReport("recover", "uncertain", (
        LifecycleObservation(PRIVATE_MARKER, "recorded", PRIVATE_MARKER, PRIVATE_MARKER),
    ), True)
    results = (
        AdaptDiagnostics(request, report, IDENTITY),
        AdaptState(Request(IntegrationOperation.STATE), state),
        AdaptLifecycle(Request(IntegrationOperation.LIFECYCLE_REPORT), lifecycle, IDENTITY),
    )

    for result in results:
        payload = SerializeResult(result)

        assert PRIVATE_MARKER not in payload, "Integration output exposed private source data"
        assert "private-logical" not in payload, "Integration output exposed logical resource names"
        assert "fixture.invalid" not in payload, "Integration output exposed a private endpoint"
        assert ParseResult(payload, result.request) == result, "Safe adapter output is not parseable"

    assert results[0].evidence.Status is DiagnosticStatus.STALE, "Sanitization hid stale evidence"
    assert results[1].evidence.resource_count == 1, "Owned resource summary lost its count"
    assert results[2].evidence.recovery_required, "Lifecycle recovery requirement was hidden"


def test_LocalSubclassFieldsCannotExpandWireAllowlist() -> None:
    """Generic dataclass dumping must not disclose new identity or evidence fields."""

    identity = ExtendedIdentity("example", "sandbox", "fake", "scope-example", "example-owner")
    state_request = IntegrationRequest(identity, "example-001", IntegrationOperation.STATE)
    lifecycle_request = IntegrationRequest(
        identity, "example-001", IntegrationOperation.LIFECYCLE_REPORT,
    )
    payloads = (
        SerializeRequest(state_request),
        SerializeResult(IntegrationResult(state_request, ExtendedStateEvidence(0))),
        SerializeResult(IntegrationResult(lifecycle_request, ExtendedLifecycleEvidence(
            "status", "complete", False, (),
        ))),
    )

    for payload in payloads:
        assert PRIVATE_MARKER not in payload, "Extended local models leaked non-allowlisted fields"
        assert "credential" not in payload, "Identity subclass expanded the strict wire schema"
        assert "payload" not in payload, "Evidence subclass expanded the strict wire schema"


@pytest.mark.parametrize("adapter, source, operation", [
    (AdaptDiagnostics, DiagnosticReport("status", ()), IntegrationOperation.STATUS),
    (AdaptLifecycle, LifecycleReport("status", "complete"), IntegrationOperation.LIFECYCLE_REPORT),
])
def test_SourceIdentityBindingRequiresIndependentCallerContext(
    adapter: Any, source: Any, operation: IntegrationOperation,
) -> None:
    """Caller binding matches every field but does not attest where an observation came from."""

    with pytest.raises(IntegrationError):
        adapter(Request(operation), source, replace(IDENTITY, owner_id="foreign"))


@pytest.mark.parametrize("report", [
    None, DiagnosticReport("benchmark", ()),
    DiagnosticReport("status", (CheckResult("check", DiagnosticStatus.OK, ""),) * 129),
    DiagnosticReport("status", (CheckResult("check", DiagnosticStatus.OK, "", {
        "duration_seconds": PRIVATE_MARKER,
    }),)),
])
def test_DiagnosticsRejectWrongSourcesAndInvalidKnownMetrics(report: Any) -> None:
    """Wrong operation and invalid allowlisted values fail rather than silently implying success."""

    with pytest.raises(IntegrationError):
        AdaptDiagnostics(Request(IntegrationOperation.STATUS), report, IDENTITY)


def test_AdaptersRejectWrongOperationsAndForeignState() -> None:
    """Evidence source selection cannot cross ownership or operation boundaries."""

    with pytest.raises(IntegrationError):
        AdaptDiagnostics(Request(IntegrationOperation.STATE), DiagnosticReport("state", ()), IDENTITY)

    with pytest.raises(IntegrationError):
        AdaptState(Request(IntegrationOperation.STATUS), StackState(IDENTITY))

    with pytest.raises(IntegrationError):
        AdaptState(Request(IntegrationOperation.STATE), None)

    with pytest.raises(IntegrationError):
        AdaptState(Request(IntegrationOperation.STATE), StackState(replace(IDENTITY, stack="foreign")))

    with pytest.raises(IntegrationError):
        AdaptLifecycle(Request(IntegrationOperation.STATE), LifecycleReport("status", "complete"),
                       IDENTITY)


@pytest.mark.parametrize("report", [
    None, LifecycleReport("status", "complete", []),
    LifecycleReport("status", "complete", (None,)),
    LifecycleReport("status", "complete", (LifecycleObservation("fixture", PRIVATE_MARKER),)),
    LifecycleReport("status", "complete", (LifecycleObservation("fixture", "present"),) * 4097),
])
def test_LifecycleRejectsMalformedAndUnboundedSourceEvidence(report: Any) -> None:
    """Malformed local reports cannot export provider text or cause unbounded aggregation."""

    with pytest.raises(IntegrationError):
        AdaptLifecycle(Request(IntegrationOperation.LIFECYCLE_REPORT), report, IDENTITY)


@pytest.mark.parametrize("name, value", [
    ("private", "fixture"), ("duration_seconds", None), ("duration_seconds", -1),
    ("duration_seconds", 31), ("duration_seconds", float("nan")),
    ("duration_seconds", float("inf")), ("duration_seconds", True),
    ("received_bytes", 1.5), ("received_bytes", 1024 * 1024 + 1),
    ("http_status", 99), ("http_status", 600), ("throughput_mbps", 1e13),
])
def test_MetricsRequireBoundedFiniteNonSecretValues(name: str, value: Any) -> None:
    """Measurement bounds reject coercion, booleans, infinities, and arbitrary strings."""

    with pytest.raises(IntegrationError):
        Metric(name, value)


@pytest.mark.parametrize("model, values", [
    (IntegrationRequest, (None, "example", IntegrationOperation.STATUS)),
    (IntegrationRequest, (IDENTITY, "example", "status")),
    (CheckEvidence, ("ok", ())),
    (CheckEvidence, (DiagnosticStatus.OK, [])),
    (CheckEvidence, (DiagnosticStatus.OK, (None,))),
    (CheckEvidence, (DiagnosticStatus.OK, (Metric("http_status", None),) * 2)),
    (DiagnosticEvidence, ([],)), (DiagnosticEvidence, ((None,),)),
    (StateEvidence, (False,)), (StateEvidence, (4097,)),
    (ResourceCount, ("unknown", 1)), (ResourceCount, ("present", -1)),
    (LifecycleEvidence, ("private", "complete", False, ())),
    (LifecycleEvidence, ("status", "private", False, ())),
    (LifecycleEvidence, ("status", "complete", None, ())),
    (LifecycleEvidence, ("status", "complete", False, [])),
    (LifecycleEvidence, ("status", "complete", False, (None,))),
    (LifecycleEvidence, ("status", "complete", False, (ResourceCount("present", 1),) * 2)),
    (LifecycleEvidence, ("status", "complete", False,
                        (ResourceCount("present", 4096), ResourceCount("recorded", 1)))),
    (IntegrationResult, (None, StateEvidence(0))),
    (IntegrationResult, (Request(IntegrationOperation.STATUS), StateEvidence(0))),
])
def test_DirectModelsRejectMutableMalformedAndMismatchedEvidence(model: Any, values: Any) -> None:
    """Direct construction enforces the same invariants as the untrusted JSON boundary."""

    with pytest.raises(ValueError):
        model(*values)


def test_CodecEntryPointsRejectInvalidDirectInputsAndEnforceSerializationLimit() -> None:
    """Public codecs fail predictably on wrong objects and apply a symmetric output byte limit."""

    with pytest.raises(IntegrationError):
        SerializeRequest(None)

    with pytest.raises(IntegrationError):
        SerializeResult(None)

    with pytest.raises(IntegrationError):
        ParseRequest(b"{}", IDENTITY)

    with pytest.raises(IntegrationError):
        ParseResult("{}", None)

    with pytest.raises(IntegrationError):
        _Encode({"fixture": "x" * 65536})

    request = Request(IntegrationOperation.STATUS)

    assert ParseRequest(SerializeRequest(request), IDENTITY) == request, \
        "Validated requests failed ordinary serialization"
