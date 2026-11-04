"""Offline reference consumer workflow using F-Layer-side integration contracts."""

from __future__ import annotations

from pathlib import Path

from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import DeploymentPlan, LifecycleEngine
from flayer.core.state import LoadState, ResourceState, SaveState, StackState
from flayer.diagnostics import (
    BenchmarkLimits,
    CheckResult,
    DiagnosticReport,
    DiagnosticStatus,
    EndpointMeasurement,
    ProviderStatus,
    RunBenchmark,
    RunChecks,
)
from flayer.integrations import (
    AdaptDiagnostics,
    AdaptLifecycle,
    AdaptState,
    IntegrationOperation,
    IntegrationRequest,
    ParseRequest,
    ParseResult,
    SerializeRequest,
    SerializeResult,
)
from flayer.providers.contracts import (
    ProviderIdentity,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import ResourceSpec

IDENTITY = StackIdentity("example", "sandbox", "fake", "scope-example", "example-owner")


class ObservationProvider:
    """A fake read-only resource lookup records calls and exposes no mutation implementation."""

    def __init__(self, resource: ProviderResource) -> None:
        """Initialize an isolated preexisting observed resource."""

        self.resource = resource
        self.lookups = 0

    @property
    def Identity(self) -> ProviderIdentity:
        """Return synthetic provider scope without resolving credentials."""

        return ProviderIdentity("fake", "scope-example", "fixture")

    def ValidateSpec(self, spec: ResourceSpec) -> None:
        """Validate the single synthetic resource kind without external effects."""

        assert spec.kind is ResourceKind.NETWORK, "Reference workflow unexpectedly changed kind"

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Read one synthetic exact locator and count observations only."""

        assert reference == self.resource.reference, "Lifecycle requested a foreign fixture locator"

        self.lookups += 1

        return self.resource


def test_ReferenceConsumerReadsExistingSourcesWithoutDispatch(tmp_path: Path) -> None:
    """A consumer supplies explicit trusted sources after parse; neither parsing nor adapters execute."""

    def Probe() -> CheckResult:
        """Return fixture health evidence without network or guest execution."""

        return CheckResult("fixture", DiagnosticStatus.OK, "Synthetic health observation")

    transportCalls: list[tuple[str, float, int]] = []

    def Transport(endpoint: str, timeoutSeconds: float, byteLimit: int) -> EndpointMeasurement:
        """Record host-selected benchmark bounds and produce metrics without HTTP traffic."""

        transportCalls.append((endpoint, timeoutSeconds, byteLimit))

        return EndpointMeasurement(DiagnosticStatus.OK, 0.5, byteLimit, 206)

    diagnosticSources = (
        DiagnosticReport("status", (ProviderStatus(),)),
        DiagnosticReport("health", RunChecks((Probe,))),
        DiagnosticReport("benchmark", RunBenchmark(
            "https://fixture.invalid", BenchmarkLimits(1, 1, 64), Transport,
        )),
    )

    for report in diagnosticSources:
        request = IntegrationRequest(IDENTITY, "example-001", IntegrationOperation(report.command))
        parsed = ParseRequest(SerializeRequest(request), IDENTITY)
        result = AdaptDiagnostics(parsed, report, IDENTITY)

        assert ParseResult(SerializeResult(result), request) == result, \
            "Reference diagnostic evidence failed consumer correlation"
        assert result.evidence.Status is report.Status, "Integration changed source evidence severity"

    assert transportCalls == [("https://fixture.invalid", 1, 64)], \
        "Host-selected benchmark transport bounds changed"

    spec = ResourceSpec("network", ResourceKind.NETWORK, "example-network")
    reference = ResourceReference("fake", "scope-example", ResourceKind.NETWORK, "fixture-resource")
    provider = ObservationProvider(ProviderResource(
        reference, spec.name, "RUNNING", labels=spec.OwnershipLabels(IDENTITY),
    ))
    state = StackState(IDENTITY, (ResourceState("network", "network", "fixture-resource"),))
    statePath = tmp_path / "owned-state.json"
    SaveState(statePath, state, IDENTITY)
    before = statePath.read_bytes()
    stateRequest = IntegrationRequest(IDENTITY, "example-002", IntegrationOperation.STATE)
    lifecycleRequest = IntegrationRequest(
        IDENTITY, "example-003", IntegrationOperation.LIFECYCLE_REPORT,
    )
    ParseRequest(SerializeRequest(lifecycleRequest), IDENTITY)

    assert provider.lookups == 0, "Parsing dispatched a provider operation"

    loaded = LoadState(statePath, IDENTITY)
    stateResult = AdaptState(stateRequest, loaded)
    engine = LifecycleEngine(DeploymentPlan(IDENTITY, (spec,)), provider, statePath)
    report = engine.Status()
    lookupsBeforeAdapter = provider.lookups
    lifecycleResult = AdaptLifecycle(lifecycleRequest, report, engine.plan.identity)

    assert stateResult.evidence.resourceCount == 1, "Recorded ownership summary is incorrect"
    assert lifecycleResult.evidence.status == "complete", "Present owned resources became incomplete"
    assert lifecycleResult.evidence.resources[0].status == "present", \
        "Lifecycle observation category was lost"
    assert provider.lookups == lookupsBeforeAdapter == 1, "Evidence adapter dispatched provider work"
    assert statePath.read_bytes() == before, "Read-only reference workflow changed persisted state"
    assert ParseResult(SerializeResult(lifecycleResult), lifecycleRequest) == lifecycleResult, \
        "Lifecycle reference evidence failed the consumer wire round trip"
