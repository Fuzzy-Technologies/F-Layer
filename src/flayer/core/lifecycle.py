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
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import cast
from uuid import uuid4

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

        identifiers = {resource.logical_id for resource in self.resources}

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
                complete.add(resource.logical_id)
                remaining.remove(resource)

        return tuple(result)

    def Fingerprint(self) -> str:
        """Bind recovery to exact intent without persisting desired parameters in state."""

        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

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

        raw_resources = data["resources"]

        if not isinstance(raw_resources, list):
            raise LifecycleError("Plan resources must be an array of tables")

        resources: list[ResourceSpec] = []

        for item in raw_resources:
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
                logical_id=ValidateName(table["logical_id"], "resources.logical_id"),
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

    logical_id: str
    status: str
    resource_id: str | None = None
    provider_status: str | None = None


@dataclass(frozen=True)
class LifecycleReport:
    """Truthful operation outcome without raw provider commands, errors, or parameters."""

    action: str
    status: str
    resources: tuple[LifecycleObservation, ...] = ()
    recovery_required: bool = False

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
    operation_id: str = ""
    schema_version: int = 1


def _JournalPath(path: Path) -> Path:
    """Keep recovery progress beside its caller-selected owned snapshot."""

    return path.with_name(f".{path.name}.operation.json")


def _LoadJournal(path: Path, plan: DeploymentPlan) -> _Journal | None:
    """Read a strict journal and block recovery for foreign or changed intent."""

    journal_path = _JournalPath(path)
    _ValidatePath(journal_path)

    try:
        data = RequireTable(_ReadOwnedJson(journal_path), "journal")

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

        operation_id = data["operation_id"]

        if not isinstance(operation_id, str) or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None:
            raise LifecycleError("Journal operation identity is invalid")

        pending = data["pending"]
        logical_ids = {resource.logical_id for resource in plan.resources}

        if pending is not None and (not isinstance(pending, str) or pending not in logical_ids):
            raise LifecycleError("Journal pending resource is invalid")

        snapshots = [ParseState({
            "schema_version": 1, "identity": asdict(identity), "resources": data[key],
        }, identity).resources for key in ("original", "created")]

        specs = {resource.logical_id: resource for resource in plan.resources}

        if any(
            resource.logical_id not in logical_ids
            or resource.kind != CoreKind(specs[resource.logical_id].kind)
            for items in snapshots for resource in items
        ):
            raise LifecycleError("Journal includes resources outside the desired plan")

        if {item.logical_id for item in snapshots[0]} & {item.logical_id for item in snapshots[1]}:
            raise LifecycleError("Journal rollback resources overlap preexisting resources")

        StackState(identity, (*snapshots[0], *snapshots[1]))

        if data["action"] == "create" and pending in {
            item.logical_id for items in snapshots for item in items
        }:
            raise LifecycleError("Pending creation must not overlap recorded operation resources")

        if pending is not None and data["action"] in {"rollback", "destroy"}:
            eligible = snapshots[1] if data["action"] == "rollback" else snapshots[0]

            if pending not in {item.logical_id for item in eligible}:
                raise LifecycleError("Journal pending removal is not eligible")

        return _Journal(
            identity, plan.Fingerprint(), data["action"], snapshots[0], snapshots[1],
            pending, operation_id=operation_id,
        )

    except FileNotFoundError:
        return None

    except (OSError, ValueError, RecursionError):
        raise LifecycleError("Unable to load a valid operation journal") from None


def _WriteJournal(path: Path, journal: _Journal) -> None:
    """Atomically persist write-ahead intent before an external mutation is permitted."""

    journal_path = _JournalPath(path)
    _ValidatePath(journal_path)
    temporary_path: Path | None = None

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.journal.", suffix=".tmp", dir=path.parent
        )
        temporary_path = Path(temporary_name)

        with _OpenTextStream(descriptor, "w") as stream:
            json.dump(asdict(journal), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, journal_path)
        temporary_path = None
        _SyncDirectory(path.parent)

    except OSError:
        raise LifecycleError("Unable to persist operation intent; recovery may be required") from None

    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)

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
    lock_path = path.with_name(f".{path.name}.operation.lock")

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)

    except OSError:
        raise LifecycleError("Another operation holds the stack lock or storage is unavailable") from None

    try:
        yield

    finally:
        try:
            lock_path.unlink()

        except OSError:
            raise LifecycleError("Unable to release the operation lock") from None


class LifecycleEngine:
    """Compose a scoped provider with durable owned-state lifecycle semantics."""

    def __init__(
        self, plan: DeploymentPlan, provider: LifecycleProvider, state_path: str | Path
    ) -> None:
        """Reject a provider or path that cannot represent the exact desired scope."""

        if not isinstance(plan, DeploymentPlan):
            raise LifecycleError("Lifecycle requires a validated DeploymentPlan")

        if (
            provider.Identity.provider_id != plan.identity.provider
            or provider.Identity.scope_id != plan.identity.scope_id
        ):
            raise LifecycleError("Provider identity must match the deployment plan")

        for spec in plan.resources:
            provider.ValidateSpec(spec)

        self.plan = plan
        self.provider = provider
        self.state_path = Path(state_path)
        _ValidatePath(self.state_path)
        self._specs = {resource.logical_id: resource for resource in plan.resources}

    def _State(self) -> StackState:
        """Require exact ownership and reject state incompatible with the current plan."""

        state = LoadState(self.state_path, self.plan.identity) or StackState(self.plan.identity)

        for resource in state.resources:
            spec = self._specs.get(resource.logical_id)

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
            reference.provider_id != self.plan.identity.provider
            or reference.scope_id != self.plan.identity.scope_id
            or reference.kind != spec.kind
            or not resource.HasLabels(expected)
        ):
            raise LifecycleError("Provider observation violates the ownership boundary")

        return resource

    def _Locator(self, spec: ResourceSpec, resource: ProviderResource) -> ResourceState:
        """Extract only identifiers from a verified scoped provider resource."""

        return ResourceState(spec.logical_id, CoreKind(spec.kind), resource.reference.resource_id)

    def _RequireLocator(self, locator: ResourceState) -> ProviderResource | None:
        """Block deletion if the owned logical resource resolves to a different identifier."""

        reference = ResourceReference(
            self.plan.identity.provider, self.plan.identity.scope_id,
            ProviderKind(locator.kind), locator.resource_id,
        )

        try:
            resource = self.provider.GetResource(reference)

        except ProviderError as error:
            if error.code == ProviderErrorCode.NOT_FOUND:
                return None

            raise

        expected = tuple(sorted({
            **self.plan.identity.OwnershipLabels(), "flayer-resource": locator.logical_id,
        }.items()))

        if resource.reference != reference or not resource.HasLabels(expected):
            raise LifecycleError("Exact resource lookup violates its persisted ownership boundary")

        return resource


    def _Save(self, resources: tuple[ResourceState, ...]) -> None:
        """Persist minimum owned state after every confirmed external resource transition."""

        SaveState(self.state_path, StackState(self.plan.identity, resources), self.plan.identity)

    def _Report(self, action: str, status: str, recovery: bool = False) -> LifecycleReport:
        """Return persisted progress even when the provider could not finish an operation."""

        resources = tuple(LifecycleObservation(item.logical_id, "recorded", item.resource_id)
                          for item in self._State().resources)

        return LifecycleReport(action, status, resources, recovery)

    def Status(self) -> LifecycleReport:
        """Read exact owned remote existence without changing state or creating resources."""

        with _OperationLock(self.state_path):
            state = self._State()
            journal = _LoadJournal(self.state_path, self.plan)
            resources: list[LifecycleObservation] = []

            for locator in state.resources:
                observed = self._RequireLocator(locator)
                resources.append(LifecycleObservation(
                    locator.logical_id, "present" if observed is not None else "missing",
                    locator.resource_id, observed.status if observed is not None else None,
                ))

            missing = any(resource.status == "missing" for resource in resources)
            resources.extend(LifecycleObservation(spec.logical_id, "not-recorded")
                             for spec in self.plan.resources
                             if spec.logical_id not in {item.logical_id for item in state.resources})
            complete = not missing and len(state.resources) == len(self.plan.resources)

            return LifecycleReport(
                "status", "complete" if complete and journal is None else "incomplete",
                tuple(resources), journal is not None,
            )

    def Create(self) -> LifecycleReport:
        """Create missing owned resources and roll back only this operation's creations."""

        with _OperationLock(self.state_path):
            state = self._State()

            if _LoadJournal(self.state_path, self.plan) is not None:
                raise LifecycleError("An interrupted operation requires explicit recovery")

            preexisting: list[ResourceState] = []
            observations: dict[str, ProviderResource] = {}
            recorded = {resource.logical_id: resource for resource in state.resources}

            for spec in self.plan.OrderedResources():
                observed = self._Observe(spec)

                if spec.logical_id in recorded and (
                    observed is None or observed.reference.resource_id != recorded[spec.logical_id].resource_id
                ):
                    raise LifecycleError("Recorded resource is missing or replaced")

                if observed is not None:
                    observations[spec.logical_id] = observed
                    preexisting.append(self._Locator(spec, observed))

            for spec in self.plan.resources:
                if spec.logical_id in observations and not set(spec.dependencies) <= observations.keys():
                    raise LifecycleError("Preexisting resource depends on a missing resource")

            journal = _Journal(
                self.plan.identity, self.plan.Fingerprint(), "create", tuple(preexisting),
                operation_id=uuid4().hex,
            )
            _WriteJournal(self.state_path, journal)
            self._Save(tuple(preexisting))

            return self._Create(journal)

    def _Create(self, journal: _Journal) -> LifecycleReport:
        """Persist adoption and each successful creation in dependency order."""

        state = self._State()
        locators = {resource.logical_id: resource for resource in state.resources}
        observed: dict[str, ProviderResource] = {}

        for spec in self.plan.OrderedResources():
            resource = self._Observe(spec)

            if spec.logical_id in locators:
                if resource is None or resource.reference.resource_id != locators[spec.logical_id].resource_id:
                    raise LifecycleError("Recorded resource is missing or replaced; explicit recovery is required")

                observed[spec.logical_id] = resource

                continue

            if resource is not None:
                if set(spec.dependencies) & {item.logical_id for item in journal.created}:
                    raise LifecycleError("A concurrent preexisting resource depends on a new creation")

                locator = self._Locator(spec, resource)
                locators[spec.logical_id] = locator
                journal = replace(journal, original=(*journal.original, locator), pending=None)
                _WriteJournal(self.state_path, journal)
                self._Save(tuple(locators.values()))
                observed[spec.logical_id] = resource

                continue

            journal = replace(journal, action="create", pending=spec.logical_id)
            _WriteJournal(self.state_path, journal)

            try:
                self.provider.CreateResource(
                    spec, self.plan.identity,
                    {key: observed[key] for key in spec.dependencies},
                    journal.operation_id,
                )
                resource = self._Observe(spec)

                if resource is None or dict(resource.labels).get("flayer-operation") != journal.operation_id:
                    return self._Report("create", "uncertain", True)

            except ProviderError as error:
                if getattr(error, "outcome_unknown", True):
                    return self._Report("create", "uncertain", True)

                journal = replace(journal, action="rollback", pending=None)
                _WriteJournal(self.state_path, journal)

                return self._Rollback(journal)

            locator = self._Locator(spec, resource)
            journal = replace(journal, action="create", created=(*journal.created, locator), pending=None)
            _WriteJournal(self.state_path, journal)
            locators[spec.logical_id] = locator
            self._Save(tuple(locators.values()))
            observed[spec.logical_id] = resource

        _ClearJournal(self.state_path)

        return self._Report("create", "complete")

    def _Delete(self, locator: ResourceState, operation_id: str | None = None) -> None:
        """Delete an exact verified owned locator, treating confirmed absence as success."""

        observed = self._RequireLocator(locator)

        if observed is None:
            return

        if operation_id is not None and dict(observed.labels).get("flayer-operation") != operation_id:
            raise LifecycleError("Rollback resource belongs to a different creation operation")

        reference = ResourceReference(
            self.plan.identity.provider, self.plan.identity.scope_id,
            ProviderKind(locator.kind), locator.resource_id,
        )
        self.provider.DeleteResource(reference, self.plan.identity, locator.logical_id, operation_id)

        if self._RequireLocator(locator) is not None:
            raise ProviderError(ProviderErrorCode.CONFLICT, "delete_confirmation")

    def _Rollback(self, journal: _Journal) -> LifecycleReport:
        """Remove only confirmed new resources and retain every preexisting locator."""

        created_ids = {resource.logical_id for resource in journal.created}

        for spec in self.plan.resources:
            if spec.logical_id not in created_ids and set(spec.dependencies) & created_ids:
                if self._Observe(spec) is not None:
                    raise LifecycleError("A preexisting resource depends on rollback resources")

        pending_created = list(journal.created)

        while pending_created:
            locator = pending_created[-1]
            current = replace(journal, action="rollback", created=tuple(pending_created),
                              pending=locator.logical_id)
            _WriteJournal(self.state_path, current)

            try:
                self._Delete(locator, journal.operation_id)

            except ProviderError:
                return self._Report("create", "rollback-incomplete", True)

            pending_created.pop()
            self._Save((*journal.original, *pending_created))
            journal = replace(journal, action="rollback", created=tuple(pending_created), pending=None)
            _WriteJournal(self.state_path, journal)

        self._Save(journal.original)
        _ClearJournal(self.state_path)

        return self._Report("create", "rolled-back")

    def Destroy(self) -> LifecycleReport:
        """Remove only recorded exact-owned resources in reverse dependency order."""

        with _OperationLock(self.state_path):
            state = self._State()

            if _LoadJournal(self.state_path, self.plan) is not None:
                raise LifecycleError("An interrupted operation requires explicit recovery")

            journal = _Journal(
                self.plan.identity, self.plan.Fingerprint(), "destroy", state.resources,
                operation_id=uuid4().hex,
            )
            _WriteJournal(self.state_path, journal)

            return self._Destroy(journal)

    def _Destroy(self, journal: _Journal) -> LifecycleReport:
        """Persist every confirmed removal so retry cannot forget partial cleanup."""

        locators = {item.logical_id: item for item in self._State().resources}

        for spec in reversed(self.plan.OrderedResources()):
            locator = locators.get(spec.logical_id)

            if locator is None:
                continue

            current = replace(journal, action="destroy", pending=locator.logical_id)
            _WriteJournal(self.state_path, current)

            try:
                self._Delete(locator)

            except ProviderError:
                return self._Report("destroy", "incomplete", True)

            del locators[spec.logical_id]
            self._Save(tuple(locators.values()))
            _WriteJournal(self.state_path, journal)

        _ClearJournal(self.state_path)

        return self._Report("destroy", "complete")

    def Recover(self, rollback: bool = False) -> LifecycleReport:
        """Explicitly resume durable intent, never recreate an unresolved ambiguous create."""

        with _OperationLock(self.state_path):
            self._State()
            journal = _LoadJournal(self.state_path, self.plan)

            if journal is None:
                raise LifecycleError("No interrupted operation is recorded")

            if journal.action == "destroy":
                if rollback:
                    raise LifecycleError("A partial destroy cannot be rolled back")

                return self._Destroy(journal)

            if journal.action == "rollback":
                return self._Rollback(journal)

            if journal.pending is not None:
                if journal.pending in {item.logical_id for item in (*journal.original, *journal.created)}:
                    raise LifecycleError("Pending creation cannot become rollback eligible twice")

                spec = self._specs[journal.pending]
                resource = self._Observe(spec)

                if resource is None or dict(resource.labels).get("flayer-operation") != journal.operation_id:
                    return self._Report("recover", "uncertain", True)

                locator = self._Locator(spec, resource)
                journal = replace(journal, action="create", created=(*journal.created, locator), pending=None)
                _WriteJournal(self.state_path, journal)

            locators = {item.logical_id: item for item in self._State().resources}
            locators.update((item.logical_id, item) for item in (*journal.original, *journal.created))
            self._Save(tuple(locators.values()))

            if rollback:
                journal = replace(journal, action="rollback", pending=None)
                _WriteJournal(self.state_path, journal)

                return self._Rollback(journal)

            return self._Create(journal)
