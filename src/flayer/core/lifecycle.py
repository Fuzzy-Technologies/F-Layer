"""Owned deployment orchestration with durable progress and fail-closed recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import tomllib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast
from uuid import uuid4

from flayer.core.contracts import _WireDict
from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import JsonValue, LifecycleProvider, ResourceSpec

from .contracts import (
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateName,
    ValidateSchemaVersion,
)
from .state import (
    LoadState,
    ParseState,
    ResourceState,
    SaveState,
    StackState,
    _OpenTextStream,
    _ReadOwnedJson,
    _SyncDirectory,
    _ValidatePath,
)

MAX_PLAN_RESOURCES = 128


class LifecycleError(ContractError):
    """An operation is blocked or requires explicit interrupted-operation recovery."""


def CoreKind(kind: ResourceKind) -> str:
    """Bridge provider enum spelling to the portable hyphenated state contract."""

    return kind.value.replace("_", "-")


def ProviderKind(kind: str) -> ResourceKind:
    """Accept only an explicitly recognized portable lifecycle resource kind."""

    try:
        return ResourceKind(kind.replace("-", "_"))

    except ValueError:
        raise LifecycleError("Lifecycle resource kind is unsupported") from None


@dataclass(frozen=True)
class DeploymentPlan:
    """Immutable desired resources with a deterministic dependency order."""

    identity: StackIdentity
    resources: tuple[ResourceSpec, ...]

    def __post_init__(self) -> None:
        """Reject malformed plans, duplicates, unknown dependencies, and cycles offline."""

        if not isinstance(self.identity, StackIdentity) or not isinstance(self.resources, tuple):
            raise LifecycleError("Plan requires an immutable identity and resource tuple")

        if len(self.resources) > MAX_PLAN_RESOURCES:
            raise LifecycleError("Plan resource count exceeds the supported bound")

        if any(not isinstance(resource, ResourceSpec) for resource in self.resources):
            raise LifecycleError("Plan resources must be validated ResourceSpec values")

        identifiers = {resource.logicalId for resource in self.resources}

        if len(identifiers) != len(self.resources):
            raise LifecycleError("Plan logical identifiers must be unique")

        for resource in self.resources:
            if set(resource.dependencies) - identifiers:
                raise LifecycleError("Plan contains an unknown dependency")

        self.OrderedResources()

    def OrderedResources(self) -> tuple[ResourceSpec, ...]:
        """Return a stable topological ordering or reject cyclic dependencies."""

        remaining = list(self.resources)
        result: list[ResourceSpec] = []
        complete: set[str] = set()

        while remaining:
            ready = [item for item in remaining if set(item.dependencies) <= complete]

            if not ready:
                raise LifecycleError("Plan contains a dependency cycle")

            for resource in ready:
                result.append(resource)
                complete.add(resource.logicalId)
                remaining.remove(resource)

        return tuple(result)

    def Fingerprint(self) -> str:
        """Bind recovery to exact intent without persisting desired parameters in state."""

        payload = json.dumps(_WireDict(self), sort_keys=True, separators=(",", ":"))

        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _FreezeValue(value: object) -> JsonValue:
    """Convert TOML collections into immutable provider parameters without coercion."""

    if isinstance(value, dict):
        return tuple((key, _FreezeValue(item)) for key, item in sorted(value.items()))

    if isinstance(value, list):
        return tuple(_FreezeValue(item) for item in value)

    if value is not None and type(value) not in {str, int, bool}:
        raise LifecycleError("Plan parameters require immutable JSON-compatible values")

    return cast(JsonValue, value)


def LoadDeploymentPlan(path: str | Path) -> DeploymentPlan:
    """Load explicit version-one lifecycle TOML without resolving credential material."""

    try:
        with Path(path).open("rb") as stream:
            data = tomllib.load(stream)

        ValidateFields(
            data,
            frozenset({"schema_version", "identity", "resources"}),
            frozenset({"profile"}),
            "deployment plan",
        )
        ValidateSchemaVersion(data["schema_version"])

        if "profile" in data:
            ValidateName(data["profile"], "profile")

        rawResources = data["resources"]

        if not isinstance(rawResources, list):
            raise LifecycleError("Plan resources must be an array of tables")

        resources: list[ResourceSpec] = []

        for item in rawResources:
            table = RequireTable(item, "resources")
            ValidateFields(
                table,
                frozenset({"logical_id", "kind", "name"}),
                frozenset({"parameters", "dependencies"}),
                "resources",
            )
            parameters = RequireTable(table.get("parameters", {}), "parameters")
            dependencies = table.get("dependencies", [])

            if not isinstance(dependencies, list) or any(
                not isinstance(value, str) for value in dependencies
            ):
                raise LifecycleError("Dependencies must be an array of logical identifiers")

            kind = ValidateName(table["kind"], "resources.kind")
            resources.append(ResourceSpec(
                logicalId=ValidateName(table["logical_id"], "resources.logical_id"),
                kind=ProviderKind(kind),
                name=ValidateName(table["name"], "resources.name"),
                parameters=tuple((key, _FreezeValue(value)) for key, value in parameters.items()),
                dependencies=tuple(dependencies),
            ))

        return DeploymentPlan(ParseIdentity(data["identity"]), tuple(resources))

    except (OSError, ValueError, RecursionError):
        raise LifecycleError("Unable to load a valid lifecycle plan") from None


@dataclass(frozen=True)
class LifecycleObservation:
    """Sanitized local ownership and remote existence summary for one logical resource."""

    logicalId: str
    status: str
    resourceId: str | None = None
    providerStatus: str | None = None


@dataclass(frozen=True)
class LifecycleReport:
    """Truthful operation outcome without raw provider commands, errors, or parameters."""

    action: str
    status: str
    resources: tuple[LifecycleObservation, ...] = ()
    recoveryRequired: bool = False

    def ExitCode(self) -> int:
        """Report nonzero whenever an operation failed or is awaiting recovery."""

        return 0 if self.status == "complete" else 1


@dataclass(frozen=True)
class _Journal:
    """Write-ahead mutation intent and the resource set eligible for safe rollback."""

    identity: StackIdentity
    fingerprint: str
    action: str
    original: tuple[ResourceState, ...]
    created: tuple[ResourceState, ...] = ()
    pending: str | None = None
    operationId: str = ""
    schemaVersion: int = 1


def _JournalPath(path: Path) -> Path:
    """Keep recovery progress beside its caller-selected owned snapshot."""

    return path.with_name(f".{path.name}.operation.json")


def _LoadJournal(path: Path, plan: DeploymentPlan) -> _Journal | None:
    """Read a strict journal and block recovery for foreign or changed intent."""

    journalPath = _JournalPath(path)
    _ValidatePath(journalPath)

    try:
        data = RequireTable(_ReadOwnedJson(journalPath), "journal")

        ValidateFields(data, frozenset({
            "schema_version", "identity", "fingerprint", "action", "original", "created", "pending",
            "operation_id",
        }), frozenset(), "journal")
        ValidateSchemaVersion(data["schema_version"])
        identity = ParseIdentity(data["identity"])

        if identity != plan.identity or data["fingerprint"] != plan.Fingerprint():
            raise LifecycleError("Journal ownership or desired plan does not match")

        if not isinstance(data["action"], str) or data["action"] not in {"create", "rollback", "destroy"}:
            raise LifecycleError("Journal action is unsupported")

        operationId = data["operation_id"]

        if not isinstance(operationId, str) or re.fullmatch(r"[0-9a-f]{32}", operationId) is None:
            raise LifecycleError("Journal operation identity is invalid")

        pending = data["pending"]
        logicalIds = {resource.logicalId for resource in plan.resources}

        if pending is not None and (not isinstance(pending, str) or pending not in logicalIds):
            raise LifecycleError("Journal pending resource is invalid")

        snapshots = [ParseState({
            "schema_version": 1, "identity": _WireDict(identity), "resources": data[key],
        }, identity).resources for key in ("original", "created")]

        specs = {resource.logicalId: resource for resource in plan.resources}

        if any(
            resource.logicalId not in logicalIds
            or resource.kind != CoreKind(specs[resource.logicalId].kind)
            for items in snapshots for resource in items
        ):
            raise LifecycleError("Journal includes resources outside the desired plan")

        if {item.logicalId for item in snapshots[0]} & {item.logicalId for item in snapshots[1]}:
            raise LifecycleError("Journal rollback resources overlap preexisting resources")

        StackState(identity, (*snapshots[0], *snapshots[1]))

        if data["action"] == "create" and pending in {
            item.logicalId for items in snapshots for item in items
        }:
            raise LifecycleError("Pending creation must not overlap recorded operation resources")

        if pending is not None and data["action"] in {"rollback", "destroy"}:
            eligible = snapshots[1] if data["action"] == "rollback" else snapshots[0]

            if pending not in {item.logicalId for item in eligible}:
                raise LifecycleError("Journal pending removal is not eligible")

        return _Journal(
            identity, plan.Fingerprint(), data["action"], snapshots[0], snapshots[1],
            pending, operationId=operationId,
        )

    except FileNotFoundError:
        return None

    except (OSError, ValueError, RecursionError):
        raise LifecycleError("Unable to load a valid operation journal") from None


def _WriteJournal(path: Path, journal: _Journal) -> None:
    """Atomically persist write-ahead intent before an external mutation is permitted."""

    journalPath = _JournalPath(path)
    _ValidatePath(journalPath)
    temporaryPath: Path | None = None

    try:
        descriptor, temporaryName = tempfile.mkstemp(
            prefix=f".{path.name}.journal.", suffix=".tmp", dir=path.parent
        )
        temporaryPath = Path(temporaryName)

        with _OpenTextStream(descriptor, "w") as stream:
            json.dump(_WireDict(journal), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporaryPath, journalPath)
        temporaryPath = None
        _SyncDirectory(path.parent)

    except OSError:
        raise LifecycleError("Unable to persist operation intent; recovery may be required") from None

    finally:
        if temporaryPath is not None:
            try:
                temporaryPath.unlink(missing_ok=True)

            except OSError:
                raise LifecycleError("Unable to clean temporary operation intent") from None


def _ClearJournal(path: Path) -> None:
    """Clear durable intent only after the resulting snapshot has been persisted."""

    try:
        _JournalPath(path).unlink(missing_ok=True)
        _SyncDirectory(path.parent)

    except OSError:
        raise LifecycleError("Operation completed but its journal requires local recovery") from None


@contextmanager
def _OperationLock(path: Path) -> Iterator[None]:
    """Serialize complete operations; hard-crash locks require explicit operator inspection."""

    _ValidatePath(path)
    lockPath = path.with_name(f".{path.name}.operation.lock")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lockPath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)

    except OSError:
        raise LifecycleError("Another operation holds the stack lock or storage is unavailable") from None

    try:
        yield

    finally:
        try:
            lockPath.unlink()

        except OSError:
            raise LifecycleError("Unable to release the operation lock") from None


class LifecycleEngine:
    """Compose a scoped provider with durable owned-state lifecycle semantics."""

    def __init__(
        self, plan: DeploymentPlan, provider: LifecycleProvider, statePath: str | Path
    ) -> None:
        """Reject a provider or path that cannot represent the exact desired scope."""

        if not isinstance(plan, DeploymentPlan):
            raise LifecycleError("Lifecycle requires a validated DeploymentPlan")

        if (
            provider.Identity.providerId != plan.identity.provider
            or provider.Identity.scopeId != plan.identity.scopeId
        ):
            raise LifecycleError("Provider identity must match the deployment plan")

        for spec in plan.resources:
            provider.ValidateSpec(spec)

        self.plan = plan
        self.provider = provider
        self.statePath = Path(statePath)
        _ValidatePath(self.statePath)
        self._specs = {resource.logicalId: resource for resource in plan.resources}

    def _State(self) -> StackState:
        """Require exact ownership and reject state incompatible with the current plan."""

        state = LoadState(self.statePath, self.plan.identity) or StackState(self.plan.identity)

        for resource in state.resources:
            spec = self._specs.get(resource.logicalId)

            if spec is None or CoreKind(spec.kind) != resource.kind:
                raise LifecycleError("State contains resources outside the deployment plan")

        return state

    def _Observe(self, spec: ResourceSpec) -> ProviderResource | None:
        """Independently enforce ownership, kind, and scope after adapter discovery."""

        resource = self.provider.FindResource(spec, self.plan.identity)

        if resource is None:
            return None

        expected = spec.OwnershipLabels(self.plan.identity)
        reference = resource.reference

        if (
            reference.providerId != self.plan.identity.provider
            or reference.scopeId != self.plan.identity.scopeId
            or reference.kind != spec.kind
            or not resource.HasLabels(expected)
        ):
            raise LifecycleError("Provider observation violates the ownership boundary")

        return resource

    def _Locator(self, spec: ResourceSpec, resource: ProviderResource) -> ResourceState:
        """Extract only identifiers from a verified scoped provider resource."""

        return ResourceState(spec.logicalId, CoreKind(spec.kind), resource.reference.resourceId)

    def _RequireLocator(self, locator: ResourceState) -> ProviderResource | None:
        """Block deletion if the owned logical resource resolves to a different identifier."""

        reference = ResourceReference(
            self.plan.identity.provider, self.plan.identity.scopeId,
            ProviderKind(locator.kind), locator.resourceId,
        )

        try:
            resource = self.provider.GetResource(reference)

        except ProviderError as error:
            if error.code == ProviderErrorCode.NOT_FOUND:
                return None

            raise

        expected = tuple(sorted({
            **self.plan.identity.OwnershipLabels(), "flayer-resource": locator.logicalId,
        }.items()))

        if resource.reference != reference or not resource.HasLabels(expected):
            raise LifecycleError("Exact resource lookup violates its persisted ownership boundary")

        return resource


    def _Save(self, resources: tuple[ResourceState, ...]) -> None:
        """Persist minimum owned state after every confirmed external resource transition."""

        SaveState(self.statePath, StackState(self.plan.identity, resources), self.plan.identity)

    def _Report(self, action: str, status: str, recovery: bool = False) -> LifecycleReport:
        """Return persisted progress even when the provider could not finish an operation."""

        resources = tuple(LifecycleObservation(item.logicalId, "recorded", item.resourceId)
                          for item in self._State().resources)

        return LifecycleReport(action, status, resources, recovery)

    def Status(self) -> LifecycleReport:
        """Read exact owned remote existence without changing state or creating resources."""

        with _OperationLock(self.statePath):
            state = self._State()
            journal = _LoadJournal(self.statePath, self.plan)
            resources: list[LifecycleObservation] = []

            for locator in state.resources:
                observed = self._RequireLocator(locator)
                resources.append(LifecycleObservation(
                    locator.logicalId, "present" if observed is not None else "missing",
                    locator.resourceId, observed.status if observed is not None else None,
                ))

            missing = any(resource.status == "missing" for resource in resources)
            resources.extend(LifecycleObservation(spec.logicalId, "not-recorded")
                             for spec in self.plan.resources
                             if spec.logicalId not in {item.logicalId for item in state.resources})
            complete = not missing and len(state.resources) == len(self.plan.resources)

            return LifecycleReport(
                "status", "complete" if complete and journal is None else "incomplete",
                tuple(resources), journal is not None,
            )

    def Create(self) -> LifecycleReport:
        """Create missing owned resources and roll back only this operation's creations."""

        with _OperationLock(self.statePath):
            state = self._State()

            if _LoadJournal(self.statePath, self.plan) is not None:
                raise LifecycleError("An interrupted operation requires explicit recovery")

            preexisting: list[ResourceState] = []
            observations: dict[str, ProviderResource] = {}
            recorded = {resource.logicalId: resource for resource in state.resources}

            for spec in self.plan.OrderedResources():
                observed = self._Observe(spec)

                if spec.logicalId in recorded and (
                    observed is None or observed.reference.resourceId != recorded[spec.logicalId].resourceId
                ):
                    raise LifecycleError("Recorded resource is missing or replaced")

                if observed is not None:
                    observations[spec.logicalId] = observed
                    preexisting.append(self._Locator(spec, observed))

            for spec in self.plan.resources:
                if spec.logicalId in observations and not set(spec.dependencies) <= observations.keys():
                    raise LifecycleError("Preexisting resource depends on a missing resource")

            journal = _Journal(
                self.plan.identity, self.plan.Fingerprint(), "create", tuple(preexisting),
                operationId=uuid4().hex,
            )
            _WriteJournal(self.statePath, journal)
            self._Save(tuple(preexisting))

            return self._Create(journal)

    def _Create(self, journal: _Journal) -> LifecycleReport:
        """Persist adoption and each successful creation in dependency order."""

        state = self._State()
        locators = {resource.logicalId: resource for resource in state.resources}
        observed: dict[str, ProviderResource] = {}

        for spec in self.plan.OrderedResources():
            resource = self._Observe(spec)

            if spec.logicalId in locators:
                if resource is None or resource.reference.resourceId != locators[spec.logicalId].resourceId:
                    raise LifecycleError("Recorded resource is missing or replaced; explicit recovery is required")

                observed[spec.logicalId] = resource

                continue

            if resource is not None:
                if set(spec.dependencies) & {item.logicalId for item in journal.created}:
                    raise LifecycleError("A concurrent preexisting resource depends on a new creation")

                locator = self._Locator(spec, resource)
                locators[spec.logicalId] = locator
                journal = replace(journal, original=(*journal.original, locator), pending=None)
                _WriteJournal(self.statePath, journal)
                self._Save(tuple(locators.values()))
                observed[spec.logicalId] = resource

                continue

            journal = replace(journal, action="create", pending=spec.logicalId)
            _WriteJournal(self.statePath, journal)

            try:
                self.provider.CreateResource(
                    spec, self.plan.identity,
                    {key: observed[key] for key in spec.dependencies},
                    journal.operationId,
                )
                resource = self._Observe(spec)

                if resource is None or dict(resource.labels).get("flayer-operation") != journal.operationId:
                    return self._Report("create", "uncertain", True)

            except ProviderError as error:
                if getattr(error, 'outcomeUnknown', True):
                    return self._Report("create", "uncertain", True)

                journal = replace(journal, action="rollback", pending=None)
                _WriteJournal(self.statePath, journal)

                return self._Rollback(journal)

            locator = self._Locator(spec, resource)
            journal = replace(journal, action="create", created=(*journal.created, locator), pending=None)
            _WriteJournal(self.statePath, journal)
            locators[spec.logicalId] = locator
            self._Save(tuple(locators.values()))
            observed[spec.logicalId] = resource

        _ClearJournal(self.statePath)

        return self._Report("create", "complete")

    def _Delete(self, locator: ResourceState, operationId: str | None = None) -> None:
        """Delete an exact verified owned locator, treating confirmed absence as success."""

        observed = self._RequireLocator(locator)

        if observed is None:
            return

        if operationId is not None and dict(observed.labels).get("flayer-operation") != operationId:
            raise LifecycleError("Rollback resource belongs to a different creation operation")

        reference = ResourceReference(
            self.plan.identity.provider, self.plan.identity.scopeId,
            ProviderKind(locator.kind), locator.resourceId,
        )
        self.provider.DeleteResource(reference, self.plan.identity, locator.logicalId, operationId)

        if self._RequireLocator(locator) is not None:
            raise ProviderError(ProviderErrorCode.CONFLICT, "delete_confirmation")

    def _Rollback(self, journal: _Journal) -> LifecycleReport:
        """Remove only confirmed new resources and retain every preexisting locator."""

        createdIds = {resource.logicalId for resource in journal.created}

        for spec in self.plan.resources:
            if spec.logicalId not in createdIds and set(spec.dependencies) & createdIds:
                if self._Observe(spec) is not None:
                    raise LifecycleError("A preexisting resource depends on rollback resources")

        pendingCreated = list(journal.created)

        while pendingCreated:
            locator = pendingCreated[-1]
            current = replace(journal, action="rollback", created=tuple(pendingCreated),
                              pending=locator.logicalId)
            _WriteJournal(self.statePath, current)

            try:
                self._Delete(locator, journal.operationId)

            except ProviderError:
                return self._Report("create", "rollback-incomplete", True)

            pendingCreated.pop()
            self._Save((*journal.original, *pendingCreated))
            journal = replace(journal, action="rollback", created=tuple(pendingCreated), pending=None)
            _WriteJournal(self.statePath, journal)

        self._Save(journal.original)
        _ClearJournal(self.statePath)

        return self._Report("create", "rolled-back")

    def Destroy(self) -> LifecycleReport:
        """Remove only recorded exact-owned resources in reverse dependency order."""

        with _OperationLock(self.statePath):
            state = self._State()

            if _LoadJournal(self.statePath, self.plan) is not None:
                raise LifecycleError("An interrupted operation requires explicit recovery")

            journal = _Journal(
                self.plan.identity, self.plan.Fingerprint(), "destroy", state.resources,
                operationId=uuid4().hex,
            )
            _WriteJournal(self.statePath, journal)

            return self._Destroy(journal)

    def _Destroy(self, journal: _Journal) -> LifecycleReport:
        """Persist every confirmed removal so retry cannot forget partial cleanup."""

        locators = {item.logicalId: item for item in self._State().resources}

        for spec in reversed(self.plan.OrderedResources()):
            locator = locators.get(spec.logicalId)

            if locator is None:
                continue

            current = replace(journal, action="destroy", pending=locator.logicalId)
            _WriteJournal(self.statePath, current)

            try:
                self._Delete(locator)

            except ProviderError:
                return self._Report("destroy", "incomplete", True)

            del locators[spec.logicalId]
            self._Save(tuple(locators.values()))
            _WriteJournal(self.statePath, journal)

        _ClearJournal(self.statePath)

        return self._Report("destroy", "complete")

    def Recover(self, rollback: bool = False) -> LifecycleReport:
        """Explicitly resume durable intent, never recreate an unresolved ambiguous create."""

        with _OperationLock(self.statePath):
            self._State()
            journal = _LoadJournal(self.statePath, self.plan)

            if journal is None:
                raise LifecycleError("No interrupted operation is recorded")

            if journal.action == "destroy":
                if rollback:
                    raise LifecycleError("A partial destroy cannot be rolled back")

                return self._Destroy(journal)

            if journal.action == "rollback":
                return self._Rollback(journal)

            if journal.pending is not None:
                if journal.pending in {item.logicalId for item in (*journal.original, *journal.created)}:
                    raise LifecycleError("Pending creation cannot become rollback eligible twice")

                spec = self._specs[journal.pending]
                resource = self._Observe(spec)

                if resource is None or dict(resource.labels).get("flayer-operation") != journal.operationId:
                    return self._Report("recover", "uncertain", True)

                locator = self._Locator(spec, resource)
                journal = replace(journal, action="create", created=(*journal.created, locator), pending=None)
                _WriteJournal(self.statePath, journal)

            locators = {item.logicalId: item for item in self._State().resources}
            locators.update((item.logicalId, item) for item in (*journal.original, *journal.created))
            self._Save(tuple(locators.values()))

            if rollback:
                journal = replace(journal, action="rollback", pending=None)
                _WriteJournal(self.statePath, journal)

                return self._Rollback(journal)

            return self._Create(journal)
