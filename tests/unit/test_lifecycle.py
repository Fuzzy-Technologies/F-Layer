"""Deterministic ownership, interruption, idempotency and rollback lifecycle contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity, _WireDict
from flayer.core.lifecycle import (
    CoreKind,
    DeploymentPlan,
    LifecycleEngine,
    LifecycleError,
    LoadDeploymentPlan,
    ProviderKind,
    _JournalPath,
    _LoadJournal,
)
from flayer.core.state import LoadState, ResourceState, SaveState, StackState, StateError
from flayer.providers.contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ProviderIdentity,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import LifecycleProvider, MutationError, ResourceSpec

IDENTITY = StackIdentity("example", "sandbox", "fake", "folder-test", "test-owner")
NETWORK = ResourceSpec("network", ResourceKind.NETWORK, "example-network")
SUBNET = ResourceSpec("subnet", ResourceKind.SUBNET, "example-subnet", dependencies=("network",))
INSTANCE = ResourceSpec("instance", ResourceKind.INSTANCE, "example-instance", dependencies=("subnet",))
PLAN = DeploymentPlan(IDENTITY, (INSTANCE, SUBNET, NETWORK))


class FakeProvider:
    """An isolated provider that records mutations and injects exact failure windows."""

    def __init__(self) -> None:
        """Initialize independent observed inventory and deterministic fault switches."""

        self.resources: dict[str, ProviderResource] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.failCreate: str | None = None
        self.uncertainCreate: str | None = None
        self.interruptCreate: str | None = None
        self.failDelete: str | None = None
        self.interruptDelete: str | None = None
        self.findError = False
        self.lookupError = False
        self.invalidScope = False
        self.unconfirmedDelete = False

    @property
    def Identity(self) -> ProviderIdentity:
        """Expose the explicit fake scope without accessing infrastructure."""

        return ProviderIdentity("fake", "folder-test", "fixture")

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Advertise the fake's owned lifecycle operations without cloud permission claims."""

        return frozenset({ProviderCapability.CREATE_RESOURCE, ProviderCapability.DELETE_RESOURCE})

    def ValidateSpec(self, spec: ResourceSpec) -> None:
        """Require the fake's supported kinds without adding external work."""

        if spec.kind == ResourceKind.ADDRESS:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "validate", False)

    def FindResource(self, spec: ResourceSpec, identity: StackIdentity) -> ProviderResource | None:
        """Resolve only a logical test locator and optionally inject discovery failure."""

        if self.findError:
            raise ProviderError(ProviderErrorCode.PERMISSION_DENIED, "find")

        resource = self.resources.get(spec.logicalId)

        if resource is not None and self.invalidScope:
            return ProviderResource(ResourceReference("fake", "foreign", spec.kind, "foreign-id"),
                                    spec.name, labels=spec.OwnershipLabels(identity))

        return resource

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Read one exact test reference; missing differs from denied permission."""

        if self.lookupError:
            raise ProviderError(ProviderErrorCode.PERMISSION_DENIED, "get")

        for resource in self.resources.values():
            if resource.reference == reference:
                return resource

        raise ProviderError(ProviderErrorCode.NOT_FOUND, "get")

    def Put(self, spec: ResourceSpec, identity: StackIdentity = IDENTITY) -> ProviderResource:
        """Simulate one resource that is already present with exact ownership labels."""

        resource = ProviderResource(
            ResourceReference(identity.provider, identity.scopeId, spec.kind, f"id-{spec.logicalId}"),
            spec.name, labels=spec.OwnershipLabels(identity),
        )
        self.resources[spec.logicalId] = resource

        return resource

    def CreateResource(
        self, spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource],
        operationId: str,
    ) -> ProviderResource:
        """Simulate failure before submission, after acceptance, or during interruption."""

        assert set(dependencies) == set(spec.dependencies), "Dependencies must precede creation"

        if self.failCreate == spec.logicalId:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "create", False)

        if self.uncertainCreate == spec.logicalId:
            raise MutationError(ProviderErrorCode.TIMEOUT, "create", True)

        self.created.append(spec.logicalId)
        item = self.Put(spec, identity)
        resource = ProviderResource(item.reference, item.name,
                                    labels=(*item.labels, ("flayer-operation", operationId)))
        self.resources[spec.logicalId] = resource

        if self.interruptCreate == spec.logicalId:
            raise KeyboardInterrupt

        return resource

    def DeleteResource(
        self, reference: ResourceReference, identity: StackIdentity, logicalId: str,
        operationId: str | None = None,
    ) -> None:
        """Delete one fake ID unless failure or interruption leaves durable uncertainty."""

        assert reference.scopeId == identity.scopeId, "Deletion must remain in the exact scope"

        if self.failDelete == logicalId:
            raise MutationError(ProviderErrorCode.TIMEOUT, "delete", True)

        if operationId is not None:
            assert dict(self.resources[logicalId].labels).get("flayer-operation") == operationId, \
                "Rollback must retain its exact creation operation label"

        self.deleted.append(logicalId)

        if not self.unconfirmedDelete:
            self.resources.pop(logicalId, None)

        if self.interruptDelete == logicalId:
            raise KeyboardInterrupt


def Engine(tmpPath: Path, provider: FakeProvider | None = None) -> LifecycleEngine:
    """Create a new isolated engine with explicit local persistence."""

    return LifecycleEngine(PLAN, provider or FakeProvider(), tmpPath / "stack.json")


def test_CreateStatusDestroyAreIdempotentAndOrdered(tmp_path: Path) -> None:
    """Resource creation and exact cleanup follow dependencies and converge on retry."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)

    assert isinstance(provider, LifecycleProvider)
    assert engine.Status().status == "incomplete"
    assert engine.Create().ExitCode() == 0
    assert provider.created == ["network", "subnet", "instance"]
    assert engine.Status().status == "complete"
    assert engine.Create().status == "complete"
    assert provider.created == ["network", "subnet", "instance"]
    assert engine.Destroy().status == "complete"
    assert provider.deleted == ["instance", "subnet", "network"]
    assert engine.Destroy().ExitCode() == 0
    assert LoadState(engine.statePath, IDENTITY) == StackState(IDENTITY)


def test_PreexistingResourcesSurviveRollback(tmp_path: Path) -> None:
    """A later definite failure cleans new resources and preserves adopted ownership."""

    provider = FakeProvider()
    provider.Put(NETWORK)
    provider.failCreate = "instance"
    engine = Engine(tmp_path, provider)
    report = engine.Create()

    assert report.status == "rolled-back" and report.ExitCode() == 1
    assert provider.deleted == ["subnet"]
    assert set(provider.resources) == {"network"}
    assert LoadState(engine.statePath, IDENTITY).resources == (
        ResourceState("network", "network", "id-network"),
    )
    assert not _JournalPath(engine.statePath).exists()


def test_AmbiguousMissingCreateNeverDuplicatesOnRecovery(tmp_path: Path) -> None:
    """A timeout without visible resource retains uncertainty and never retries creation."""

    provider = FakeProvider()
    provider.uncertainCreate = "subnet"
    engine = Engine(tmp_path, provider)
    report = engine.Create()

    assert report.status == "uncertain" and report.recoveryRequired
    assert engine.Status().recoveryRequired

    with pytest.raises(LifecycleError, match="recovery"):
        engine.Create()

    with pytest.raises(LifecycleError, match="recovery"):
        engine.Destroy()

    assert engine.Recover().status == "uncertain"
    assert engine.Recover(rollback=True).status == "uncertain"
    assert provider.created == ["network"]
    assert provider.deleted == []


def test_InterruptedCreateRecoversAcceptedResourceWithoutDuplication(tmp_path: Path) -> None:
    """A process interruption after submission is reconciled by exact ownership labels."""

    provider = FakeProvider()
    provider.interruptCreate = "subnet"
    engine = Engine(tmp_path, provider)

    with pytest.raises(KeyboardInterrupt):
        engine.Create()

    assert not engine.statePath.with_name(".stack.json.operation.lock").exists()

    provider.interruptCreate = None

    assert engine.Recover().status == "complete"
    assert provider.created == ["network", "subnet", "instance"]


def test_InterruptedCreateCanRollbackOnlyNewResources(tmp_path: Path) -> None:
    """Explicit recovery rollback removes accepted creations and keeps the prior resource."""

    provider = FakeProvider()
    provider.Put(NETWORK)
    provider.interruptCreate = "instance"
    engine = Engine(tmp_path, provider)

    with pytest.raises(KeyboardInterrupt):
        engine.Create()

    assert engine.Recover(rollback=True).status == "rolled-back"
    assert provider.deleted == ["instance", "subnet"]
    assert set(provider.resources) == {"network"}


def test_RollbackFailureCanResumeSafely(tmp_path: Path) -> None:
    """A failed deletion retains created locators until explicit cleanup recovery."""

    provider = FakeProvider()
    provider.failCreate = "instance"
    provider.failDelete = "subnet"
    engine = Engine(tmp_path, provider)

    assert engine.Create().status == "rollback-incomplete"
    assert _LoadJournal(engine.statePath, PLAN).action == "rollback"

    provider.failDelete = None

    assert engine.Recover().status == "rolled-back"
    assert not provider.resources


def test_DestroyFailureAndInterruptionRemainRecoverable(tmp_path: Path) -> None:
    """Both rejection and accepted interrupted delete preserve exact remaining locators."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    engine.Create()
    provider.failDelete = "subnet"

    assert engine.Destroy().status == "incomplete"
    assert set(provider.resources) == {"network", "subnet"}

    with pytest.raises(LifecycleError, match="cannot be rolled back"):
        engine.Recover(rollback=True)

    provider.failDelete = None
    provider.interruptDelete = "subnet"

    with pytest.raises(KeyboardInterrupt):
        engine.Recover()

    provider.interruptDelete = None

    assert engine.Recover().status == "complete"
    assert provider.deleted == ["instance", "subnet", "network"]


def test_UnconfirmedDeletionFailsClosed(tmp_path: Path) -> None:
    """Successful command output cannot remove persisted state while a resource remains."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    engine.Create()
    provider.unconfirmedDelete = True

    assert engine.Destroy().recoveryRequired
    assert len(LoadState(engine.statePath, IDENTITY).resources) == 3


def test_SnapshotFailureAfterCreationKeepsJournalForRecovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Confirmed creation is journaled before a snapshot failure can lose its locator."""

    import flayer.core.lifecycle as lifecycle

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    actualSave = lifecycle.SaveState
    calls = 0

    def FailSecondSave(path: Path, state: StackState, identity: StackIdentity) -> None:
        """Inject a disk failure exactly after the first accepted resource creation."""

        nonlocal calls
        calls += 1

        if calls == 2:
            raise StateError("Synthetic disk failure")

        actualSave(path, state, identity)

    monkeypatch.setattr(lifecycle, "SaveState", FailSecondSave)

    with pytest.raises(StateError):
        engine.Create()

    assert len(_LoadJournal(engine.statePath, PLAN).created) == 1

    monkeypatch.setattr(lifecycle, "SaveState", actualSave)

    assert engine.Recover().status == "complete"
    assert provider.created == ["network", "subnet", "instance"]


def test_MissingRecordedResourceAndPreexistingDependencyFailBeforeMutation(tmp_path: Path) -> None:
    """A broken prior resource graph cannot be silently repaired or adopted."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    SaveState(engine.statePath, StackState(IDENTITY, (
        ResourceState("network", "network", "old-id"),
    )), IDENTITY)

    with pytest.raises(LifecycleError, match="missing or replaced"):
        engine.Create()

    engine.statePath.unlink()
    provider.Put(SUBNET)

    with pytest.raises(LifecycleError, match="depends on a missing"):
        engine.Create()

    assert not provider.created and not _JournalPath(engine.statePath).exists()


def test_ForeignObservationAndForeignStateBlockBeforeMutation(tmp_path: Path) -> None:
    """Core repeats adapter scope enforcement and never trusts labels or state alone."""

    provider = FakeProvider()
    provider.Put(NETWORK)
    provider.invalidScope = True
    engine = Engine(tmp_path, provider)

    with pytest.raises(LifecycleError, match="ownership"):
        engine.Create()

    foreign = StackIdentity("example", "sandbox", "fake", "foreign", "test-owner")
    SaveState(engine.statePath, StackState(foreign), foreign)

    with pytest.raises(StateError, match="identity"):
        engine.Destroy()

    assert provider.created == provider.deleted == []


def test_ExactLookupRejectsMissingLabelsAndWrongReferences(tmp_path: Path) -> None:
    """A persisted ID cannot authorize deletion after its ownership labels changed."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    engine.Create()
    item = provider.resources["instance"]
    provider.resources["instance"] = ProviderResource(item.reference, item.name)

    with pytest.raises(LifecycleError, match="ownership"):
        engine.Destroy()

    assert not provider.deleted


def test_ReadPermissionFailureIsNotMisreportedAsMissing(tmp_path: Path) -> None:
    """Denied inventory or exact lookup returns an error rather than success or absence."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    provider.findError = True

    with pytest.raises(ProviderError):
        engine.Create()

    provider.findError = False
    engine.Create()
    provider.lookupError = True

    with pytest.raises(ProviderError):
        engine.Status()


def test_DestroySkipsAlreadyMissingExactResource(tmp_path: Path) -> None:
    """Confirmed remote absence permits local cleanup without a destructive lookup by name."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    engine.Create()
    del provider.resources["instance"]

    assert engine.Status().resources[0].status == "present"
    assert any(item.status == "missing" for item in engine.Status().resources)
    assert engine.Destroy().status == "complete"
    assert provider.deleted == ["subnet", "network"]


def test_ExclusiveLockAndNoRecoveryJournalFailOffline(tmp_path: Path) -> None:
    """An existing operation lock blocks all work and is never removed automatically."""

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    lock = tmp_path / ".stack.json.operation.lock"
    lock.write_text("operator review required", encoding="utf-8")

    with pytest.raises(LifecycleError, match="lock"):
        engine.Create()

    assert lock.exists() and not provider.created

    lock.unlink()

    with pytest.raises(LifecycleError, match="No interrupted"):
        engine.Recover()


@pytest.mark.parametrize("resources", [
    (NETWORK, NETWORK),
    (ResourceSpec("network", ResourceKind.NETWORK, "name", dependencies=("unknown",)),),
    (ResourceSpec("network", ResourceKind.NETWORK, "name", dependencies=("subnet",)), SUBNET),
])
def test_InvalidDependencyPlansFailOffline(resources: tuple[ResourceSpec, ...]) -> None:
    """Duplicate identifiers, absent dependencies and cycles are rejected before IO."""

    with pytest.raises(LifecycleError):
        DeploymentPlan(IDENTITY, resources)


@pytest.mark.parametrize("identity,resources", [(None, ()), (IDENTITY, []), (IDENTITY, ("bad",))])
def test_InvalidDirectPlanTypesFailOffline(identity: object, resources: object) -> None:
    """Direct model construction cannot bypass immutable plan validation."""

    with pytest.raises(LifecycleError):
        DeploymentPlan(identity, resources)


def test_ProviderMismatchUnsupportedSpecAndInvalidStateFailOffline(tmp_path: Path) -> None:
    """Wrong adapter identity, unsupported specs, and out-of-plan state never mutate."""

    provider = FakeProvider()
    foreign = StackIdentity("example", "sandbox", "other", "folder-test", "test-owner")

    with pytest.raises(LifecycleError, match="Provider identity"):
        LifecycleEngine(DeploymentPlan(foreign, ()), provider, tmp_path / "state.json")

    with pytest.raises(LifecycleError, match="validated"):
        LifecycleEngine("bad", provider, tmp_path / "state.json")

    with pytest.raises(MutationError):
        LifecycleEngine(DeploymentPlan(IDENTITY, (
            ResourceSpec("address", ResourceKind.ADDRESS, "name"),
        )), provider, tmp_path / "state.json")

    engine = Engine(tmp_path, provider)
    SaveState(engine.statePath, StackState(IDENTITY, (
        ResourceState("unknown", "network", "id-test"),
    )), IDENTITY)

    with pytest.raises(LifecycleError, match="outside"):
        engine.Status()


def PlanText(resources: str) -> str:
    """Return a portable synthetic lifecycle TOML document."""

    return 'schema_version = 1\nprofile = "generic"\n[identity]\nproject = "example"\nstack = "sandbox"\nprovider = "fake"\nscope_id = "folder-test"\nowner_id = "test-owner"\n' + resources


def test_LoadPlanStrictParametersKindsAndFingerprint(tmp_path: Path) -> None:
    """TOML collections freeze deeply and security-group spelling bridges explicitly."""

    path = tmp_path / "plan.toml"
    path.write_text(PlanText('''
[[resources]]
logical_id = "security"
kind = "security-group"
name = "example-security"
[resources.parameters]
rules = [{ protocol = "tcp", port = 443 }]
'''), encoding="utf-8")
    plan = LoadDeploymentPlan(path)

    assert plan.resources[0].kind is ResourceKind.SECURITY_GROUP
    assert CoreKind(plan.resources[0].kind) == "security-group"
    assert plan.Fingerprint() == LoadDeploymentPlan(path).Fingerprint()
    assert plan.resources[0].parameters == (("rules", ((("port", 443), ("protocol", "tcp")),)),)


@pytest.mark.parametrize("suffix", [
    'resources = "bad"',
    'resources = [{logical_id="network",kind="unknown",name="name"}]',
    'resources = [{logical_id="network",kind="network",name="name",oops=true}]',
    'resources = [{logical_id="network",kind="network",name="name",dependencies="bad"}]',
    'resources = [{logical_id="network",kind="network",name="name",dependencies=[1]}]',
    'resources = [{logical_id="network",kind="network",name="name",parameters={value=1.2}}]',
    'resources = [{logical_id="network",kind="network",name="name",parameters=[]}]',
])
def test_MalformedPlansFailClosed(tmp_path: Path, suffix: str) -> None:
    """Malformed resource options and unknown kinds cannot reach an adapter."""

    path = tmp_path / "plan.toml"
    path.write_text(PlanText("").replace("[identity]", suffix + "\n[identity]"), encoding="utf-8")

    with pytest.raises(LifecycleError):
        LoadDeploymentPlan(path)


def test_MissingInvalidVersionAndUnknownPlanFieldsFailClosed(tmp_path: Path) -> None:
    """Unsupported schema and extra fields remain explicit loading failures."""

    path = tmp_path / "plan.toml"

    with pytest.raises(LifecycleError):
        LoadDeploymentPlan(path)

    for text in ("invalid toml [", PlanText("").replace("schema_version = 1", "schema_version = 2"),
                 PlanText("").replace("[identity]", "resources = []\nunknown = true\n[identity]")):
        path.write_text(text, encoding="utf-8")

        with pytest.raises(LifecycleError):
            LoadDeploymentPlan(path)

    with pytest.raises(LifecycleError):
        ProviderKind("unknown")


@pytest.mark.parametrize("change", [
    {"action": []}, {"pending": "unknown"}, {"fingerprint": "bad"},
    {"schema_version": True}, {"extra": True}, {"created": "bad"},
    {"operation_id": "bad"}, {"operation_id": True},
    {"created": [{"logical_id": "unknown", "kind": "network", "resource_id": "id"}]},
    {"created": [{"logical_id": "network", "kind": "disk", "resource_id": "id"}]},
    {"action": "rollback", "pending": "network"},
    {"action": "destroy", "pending": "network"},
])
def test_CorruptJournalCannotAuthorizeRecovery(tmp_path: Path, change: dict[str, object]) -> None:
    """All recovery authorizations are tied to exact plan, identity and eligible resources."""

    engine = Engine(tmp_path)
    data: dict[str, object] = {
        "schema_version": 1, "identity": _WireDict(IDENTITY), "fingerprint": PLAN.Fingerprint(),
        "action": "create", "original": [], "created": [], "pending": None, "operation_id": "a" * 32,
    }
    data.update(change)
    _JournalPath(engine.statePath).write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(LifecycleError):
        engine.Recover()


def test_JournalDuplicateFieldsOwnershipAndOverlapsFailClosed(tmp_path: Path) -> None:
    """Ambiguous JSON and overlap with the original resource set cannot authorize rollback."""

    engine = Engine(tmp_path)
    path = _JournalPath(engine.statePath)
    path.write_text('{"action":"create","action":"destroy"}', encoding="utf-8")

    with pytest.raises(LifecycleError):
        engine.Recover()

    data = {
        "schema_version": 1, "identity": _WireDict(IDENTITY), "fingerprint": PLAN.Fingerprint(),
        "action": "create", "original": [_WireDict(ResourceState("network", "network", "id"))],
        "created": [_WireDict(ResourceState("network", "network", "id"))], "pending": None,
        "operation_id": "a" * 32,
    }
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(LifecycleError):
        engine.Recover()

    data["created"] = []
    data["identity"]["owner_id"] = "foreign-owner"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(LifecycleError):
        engine.Recover()


def test_EmptyPlanConvergesAndStateContainsNoParameters(tmp_path: Path) -> None:
    """An empty plan safely converges; persisted state never gains desired option payloads."""

    engine = LifecycleEngine(DeploymentPlan(IDENTITY, ()), FakeProvider(), tmp_path / "empty.json")

    assert engine.Create().status == engine.Status().status == engine.Destroy().status == "complete"
    assert set(json.loads(engine.statePath.read_text(encoding="utf-8"))) == {
        "schema_version", "identity", "resources",
    }


def test_DifferentOperationCannotBeRecoveredAsOwnCreation(tmp_path: Path) -> None:
    """A concurrent same-stack creation cannot become eligible for another rollback."""

    provider = FakeProvider()
    provider.uncertainCreate = "subnet"
    engine = Engine(tmp_path, provider)

    assert engine.Create().status == "uncertain"

    other = provider.Put(SUBNET)
    provider.resources["subnet"] = ProviderResource(
        other.reference, other.name, labels=(*other.labels, ("flayer-operation", "b" * 32)),
    )

    assert engine.Recover(rollback=True).status == "uncertain"
    assert provider.deleted == []
    assert provider.resources["subnet"].reference.resourceId == "id-subnet"


def test_ChangedOperationLabelBlocksRollbackDeletion(tmp_path: Path) -> None:
    """Even a journaled created locator must retain its exact creation nonce at cleanup."""

    provider = FakeProvider()
    provider.failCreate = "instance"
    provider.failDelete = "subnet"
    engine = Engine(tmp_path, provider)

    assert engine.Create().status == "rollback-incomplete"

    provider.failDelete = None
    item = provider.resources["subnet"]
    labels = tuple((key, "b" * 32 if key == "flayer-operation" else value)
                   for key, value in item.labels)
    provider.resources["subnet"] = ProviderResource(item.reference, item.name, labels=labels)

    with pytest.raises(LifecycleError, match="different creation"):
        engine.Recover()

    assert provider.deleted == []


def test_ConcurrentAcceptedCreateHasForeignNonceAndRemainsUncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A creation response followed by another operation's resource never grants rollback."""

    provider = FakeProvider()
    actualCreate = provider.CreateResource

    def ConcurrentCreate(
        spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource],
        operationId: str,
    ) -> ProviderResource:
        """Replace the observed operation nonce after an apparent successful creation."""

        return actualCreate(spec, identity, dependencies, "c" * 32)

    monkeypatch.setattr(provider, "CreateResource", ConcurrentCreate)
    engine = Engine(tmp_path, provider)

    assert engine.Create().status == "uncertain"
    assert engine.Recover(rollback=True).status == "uncertain"
    assert provider.deleted == []


def test_PlanCountBoundAndMissingOptionalProfile(tmp_path: Path) -> None:
    """The core rejects unbounded graphs and accepts an absent descriptive profile."""

    resources = tuple(ResourceSpec(f"resource-{index}", ResourceKind.NETWORK, f"name-{index}")
                      for index in range(129))

    with pytest.raises(LifecycleError, match="count"):
        DeploymentPlan(IDENTITY, resources)

    path = tmp_path / "plan.toml"
    path.write_text(PlanText("").replace('profile = "generic"\n', 'resources = []\n'), encoding="utf-8")

    assert LoadDeploymentPlan(path).resources == ()


def test_ConcurrentAdoptionRemainsOutsideRollbackEligibility(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resource appearing between preflight and create is adopted and preserved on failure."""

    provider = FakeProvider()
    provider.failCreate = "instance"
    originalFind = provider.FindResource
    networkCalls = 0

    def ConcurrentFind(spec: ResourceSpec, identity: StackIdentity) -> ProviderResource | None:
        """Reveal a concurrent preexisting network only on the second observation."""

        nonlocal networkCalls

        if spec.logicalId == "network":
            networkCalls += 1

            if networkCalls == 2:
                provider.Put(spec, identity)

        return originalFind(spec, identity)

    monkeypatch.setattr(provider, "FindResource", ConcurrentFind)
    engine = Engine(tmp_path, provider)

    assert engine.Create().status == "rolled-back"
    assert set(provider.resources) == {"network"}
    assert provider.deleted == ["subnet"]


def test_ConcurrentPreexistingDependentBlocksUnsafeRollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different operation's dependent resource cannot lose its dependency during rollback."""

    provider = FakeProvider()
    originalCreate = provider.CreateResource

    def ConcurrentDependent(
        spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource],
        operationId: str,
    ) -> ProviderResource:
        """Inject a dependent resource outside this operation after its network was created."""

        resource = originalCreate(spec, identity, dependencies, operationId)

        if spec.logicalId == "network":
            provider.Put(SUBNET, identity)

        return resource

    monkeypatch.setattr(provider, "CreateResource", ConcurrentDependent)
    engine = Engine(tmp_path, provider)

    with pytest.raises(LifecycleError, match="concurrent preexisting"):
        engine.Create()

    with pytest.raises(LifecycleError, match="depends on rollback"):
        engine.Recover(rollback=True)

    assert provider.deleted == []
    assert set(provider.resources) == {"network", "subnet"}


def test_AcceptedCreateWithoutInventoryResultRemainsUncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful command cannot claim a resource when complete inventory shows absence."""

    provider = FakeProvider()

    def InvisibleCreate(
        spec: ResourceSpec, identity: StackIdentity, dependencies: Mapping[str, ProviderResource],
        operationId: str,
    ) -> ProviderResource:
        """Return an accepted result while the simulated inventory remains empty."""

        return ProviderResource(ResourceReference("fake", "folder-test", spec.kind, "accepted-id"),
                                spec.name, labels=spec.OwnershipLabels(identity))

    monkeypatch.setattr(provider, "CreateResource", InvisibleCreate)

    assert Engine(tmp_path, provider).Create().status == "uncertain"
    assert provider.deleted == []


def test_JournalPersistenceFailurePreventsMutationAndCleansTemporaryFile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed write-ahead replacement leaves no submitted cloud mutation."""

    import flayer.core.lifecycle as lifecycle

    provider = FakeProvider()

    def FailedReplace(source: object, target: object) -> None:
        """Inject deterministic inability to commit local mutation intent."""

        raise OSError("Synthetic replace failure")

    monkeypatch.setattr(lifecycle.os, "replace", FailedReplace)

    with pytest.raises(LifecycleError, match="persist operation intent"):
        Engine(tmp_path, provider).Create()

    assert not provider.created
    assert not list(tmp_path.glob("*.tmp"))
    assert not list(tmp_path.glob(".*.tmp"))


def test_JournalDirectorySyncFailureKeepsRecoverableIntent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after journal replacement remains visible and blocks new mutations."""

    import flayer.core.lifecycle as lifecycle

    provider = FakeProvider()
    actualSync = lifecycle._SyncDirectory

    def FailedSync(path: Path) -> None:
        """Inject a filesystem synchronization failure after atomic journal replacement."""

        raise OSError("Synthetic directory failure")

    monkeypatch.setattr(lifecycle, "_SyncDirectory", FailedSync)
    engine = Engine(tmp_path, provider)

    with pytest.raises(LifecycleError, match="persist operation intent"):
        engine.Create()

    assert not provider.created and _JournalPath(engine.statePath).exists()

    monkeypatch.setattr(lifecycle, "_SyncDirectory", actualSync)

    assert engine.Recover().status == "complete"


def test_CompletedOperationWithUnclearableJournalRecoversWithoutDuplication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Failure to clear completed intent does not repeat accepted resource creation."""

    actualUnlink = Path.unlink

    def FailedJournalUnlink(path: Path, missingOk: bool = False) -> None:
        """Keep the journal after creation while allowing locks and temporary files to clean up."""

        if path.name.endswith(".operation.json"):
            raise OSError("Synthetic cleanup failure")

        actualUnlink(path, missing_ok=missingOk)

    provider = FakeProvider()
    engine = Engine(tmp_path, provider)
    monkeypatch.setattr(Path, "unlink", FailedJournalUnlink)

    with pytest.raises(LifecycleError, match="journal requires"):
        engine.Create()

    assert provider.created == ["network", "subnet", "instance"]

    monkeypatch.setattr(Path, "unlink", actualUnlink)

    assert engine.Recover().status == "complete"
    assert provider.created == ["network", "subnet", "instance"]


def test_UnavailableStorageAndUnreleasableLockFailExplicitly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operation lock allocation and cleanup failures never become successful outcomes."""

    actualMkdir = Path.mkdir

    def FailedMkdir(path: Path, parents: bool = False, existOk: bool = False) -> None:
        """Inject unavailable caller-owned local storage."""

        raise OSError("Synthetic directory allocation failure")

    monkeypatch.setattr(Path, "mkdir", FailedMkdir)
    engine = Engine(tmp_path)

    with pytest.raises(LifecycleError, match="storage is unavailable"):
        engine.Status()

    monkeypatch.setattr(Path, "mkdir", actualMkdir)
    actualUnlink = Path.unlink

    def FailedLockUnlink(path: Path, missingOk: bool = False) -> None:
        """Inject failure to release the exclusive operation lock."""

        if path.name.endswith(".operation.lock"):
            raise OSError("Synthetic lock cleanup failure")

        actualUnlink(path, missing_ok=missingOk)

    monkeypatch.setattr(Path, "unlink", FailedLockUnlink)

    with pytest.raises(LifecycleError, match="release the operation lock"):
        engine.Status()

    assert (tmp_path / ".stack.json.operation.lock").exists()


def test_TemporaryJournalCleanupFailureBlocksCloudWork(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed temporary file cleanup remains explicit and cannot submit cloud changes."""

    import flayer.core.lifecycle as lifecycle

    actualUnlink = Path.unlink

    def FailedStream(descriptor: int, mode: str) -> object:
        """Simulate descriptor transfer failure while preserving descriptor cleanup."""

        lifecycle.os.close(descriptor)

        raise OSError("Synthetic stream allocation failure")

    def FailedTemporaryUnlink(path: Path, missingOk: bool = False) -> None:
        """Inject cleanup failure for the incomplete private temporary journal only."""

        if path.suffix == ".tmp":
            raise OSError("Synthetic temporary cleanup failure")

        actualUnlink(path, missing_ok=missingOk)

    provider = FakeProvider()
    monkeypatch.setattr(lifecycle, "_OpenTextStream", FailedStream)
    monkeypatch.setattr(Path, "unlink", FailedTemporaryUnlink)

    with pytest.raises(LifecycleError, match="clean temporary operation"):
        Engine(tmp_path, provider).Create()

    assert provider.created == []
    assert list(tmp_path.glob(".*.tmp"))


def test_RecordedResourceVanishingBetweenPreflightAndCreateBlocksWork(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resource race cannot turn a recorded missing resource into an implicit replacement."""

    provider = FakeProvider()
    provider.Put(NETWORK)
    engine = Engine(tmp_path, provider)
    SaveState(engine.statePath, StackState(IDENTITY, (
        ResourceState("network", "network", "id-network"),
    )), IDENTITY)
    originalFind = provider.FindResource
    calls = 0

    def VanishingFind(spec: ResourceSpec, identity: StackIdentity) -> ProviderResource | None:
        """Remove the recorded network after preflight completed successfully."""

        nonlocal calls

        if spec.logicalId == "network":
            calls += 1

            if calls == 2:
                provider.resources.pop("network")

        return originalFind(spec, identity)

    monkeypatch.setattr(provider, "FindResource", VanishingFind)

    with pytest.raises(LifecycleError, match="missing or replaced"):
        engine.Create()

    assert provider.created == []
    assert _JournalPath(engine.statePath).exists()


@pytest.mark.parametrize('recordedSet', ["original", "created"])
def test_CorruptPendingCreationCannotPromoteRecordedResourceToRollback(
    tmp_path: Path, recordedSet: str
) -> None:
    """A corrupt pending logical ID cannot turn any preexisting locator into a new creation."""

    provider = FakeProvider()
    original = provider.Put(NETWORK)
    provider.resources["network"] = ProviderResource(
        original.reference, original.name, labels=(*original.labels, ("flayer-operation", "a" * 32)),
    )
    engine = Engine(tmp_path, provider)
    locator = ResourceState("network", "network", "id-network")
    SaveState(engine.statePath, StackState(IDENTITY, (locator,)), IDENTITY)
    data: dict[str, object] = {
        "schema_version": 1, "identity": _WireDict(IDENTITY), "fingerprint": PLAN.Fingerprint(),
        "action": "create", "original": [], "created": [], "pending": "network",
        "operation_id": "a" * 32,
    }
    data[recordedSet] = [_WireDict(locator)]
    _JournalPath(engine.statePath).write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(LifecycleError):
        engine.Recover(rollback=True)

    assert provider.deleted == []
    assert "network" in provider.resources


def test_RecoveryDefensivelyRejectsDuplicateEligibilityIfDecoderBypassed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The execution path independently guards against promoting an original resource."""

    import flayer.core.lifecycle as lifecycle

    provider = FakeProvider()
    original = provider.Put(NETWORK)
    provider.resources["network"] = ProviderResource(
        original.reference, original.name, labels=(*original.labels, ("flayer-operation", "a" * 32)),
    )
    locator = ResourceState("network", "network", "id-network")
    journal = lifecycle._Journal(IDENTITY, PLAN.Fingerprint(), "create", (locator,),
                                 pending="network", operation_id="a" * 32)
    monkeypatch.setattr(lifecycle, "_LoadJournal", lambda path, plan: journal)
    engine = Engine(tmp_path, provider)

    with pytest.raises(LifecycleError, match="eligible twice"):
        engine.Recover(rollback=True)

    assert provider.deleted == []
