"""Immutable lifecycle requests and explicit, ownership-bound mutation contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, TypeAlias, runtime_checkable

from flayer.core.contracts import StackIdentity, ValidateName

from .contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ProviderIdentity,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)

JsonValue: TypeAlias = str | int | bool | None | tuple["JsonValue", ...]
MAX_PARAMETER_DEPTH = 10
MAX_PARAMETER_VALUES = 2048
LOGICAL_ID_LABEL = "flayer-resource"
SPEC_DIGEST_LABEL = "flayer-spec"
OPERATION_ID_LABEL = "flayer-operation"


def _ValidateValue(value: JsonValue, depth: int, remaining: list[int]) -> None:
    """Bound recursively immutable values before hashing or translating requests."""

    remaining[0] -= 1

    if depth > MAX_PARAMETER_DEPTH or remaining[0] < 0:
        raise ValueError("Resource parameters exceed their structural bounds")

    if isinstance(value, tuple):
        for item in value:
            _ValidateValue(item, depth + 1, remaining)

    elif isinstance(value, str):
        if len(value) > 16384 or "\x00" in value:
            raise ValueError("Resource parameter strings exceed their bounds")

    elif value is not None and type(value) not in {int, bool}:
        raise ValueError("Resource parameters require immutable JSON-compatible values")

    elif type(value) is int and not -(2 ** 63) <= value < 2 ** 63:
        raise ValueError("Resource integer parameters exceed signed 64-bit bounds")


@dataclass(frozen=True, slots=True)
class ResourceSpec:
    """A desired logical resource with immutable options and explicit dependencies."""

    logical_id: str
    kind: ResourceKind
    name: str
    parameters: tuple[tuple[str, JsonValue], ...] = field(default=(), repr=False)
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject malformed, mutable, duplicate or cyclic direct request fields."""

        ValidateName(self.logical_id, "resource.logical_id")
        ValidateName(self.name, "resource.name")

        if not isinstance(self.kind, ResourceKind):
            raise ValueError("Lifecycle kind requires a ResourceKind member")

        if (
            not isinstance(self.parameters, tuple)
            or len(self.parameters) > 128
            or any(
                not isinstance(pair, tuple) or len(pair) != 2
                or not isinstance(pair[0], str) or not pair[0].isidentifier()
                for pair in self.parameters
            )
            or len({pair[0] for pair in self.parameters}) != len(self.parameters)
        ):
            raise ValueError("Resource parameters require unique immutable named pairs")

        remaining = [MAX_PARAMETER_VALUES]

        for _, value in self.parameters:
            _ValidateValue(value, 0, remaining)

        if (
            not isinstance(self.dependencies, tuple)
            or len(self.dependencies) > 128
            or any(not isinstance(value, str) for value in self.dependencies)
            or len(set(self.dependencies)) != len(self.dependencies)
            or self.logical_id in self.dependencies
        ):
            raise ValueError("Resource dependencies require unique immutable logical IDs")

        for logical_id in self.dependencies:
            ValidateName(logical_id, "resource.dependency")

    def OwnershipLabels(self, identity: StackIdentity) -> tuple[tuple[str, str], ...]:
        """Bind one logical resource to the complete stack ownership boundary."""

        labels = identity.OwnershipLabels()
        labels[LOGICAL_ID_LABEL] = self.logical_id
        content = (self.logical_id, self.kind.value, self.name, self.parameters, self.dependencies)
        digest = hashlib.sha256(json.dumps(content, sort_keys=True).encode("utf-8")).hexdigest()
        labels[SPEC_DIGEST_LABEL] = digest[:40]

        return tuple(sorted(labels.items()))


class MutationError(ProviderError):
    """A sanitized mutation failure that distinguishes an uncertain remote outcome."""

    def __init__(
        self, code: ProviderErrorCode, operation: str, outcome_unknown: bool
    ) -> None:
        """Retain only a stable failure category and whether submission may have occurred."""

        if type(outcome_unknown) is not bool:
            raise ValueError("Mutation outcome uncertainty requires a boolean")

        self.outcome_unknown = outcome_unknown
        super().__init__(code, operation)
        self.retryable = self.retryable and not outcome_unknown


@runtime_checkable
class LifecycleProvider(Protocol):
    """Mutation boundary with exact scope, stable reconciliation and owned deletion."""

    @property
    def Identity(self) -> ProviderIdentity:
        """Return the provider and explicit scope used by every observation and command."""

        ...

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Advertise implemented mutation operations independently of account permissions."""

        ...

    def ValidateSpec(self, spec: ResourceSpec) -> None:
        """Reject unsupported resource options without accessing infrastructure."""

        ...

    def FindResource(
        self, spec: ResourceSpec, identity: StackIdentity
    ) -> ProviderResource | None:
        """Find the unique complete ownership-label match or reject ambiguous inventory."""

        ...

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Observe an exact reference with scope validation and sanitized failures."""

        ...

    def CreateResource(
        self, spec: ResourceSpec, identity: StackIdentity,
        dependencies: Mapping[str, ProviderResource], operation_id: str,
    ) -> ProviderResource:
        """Create once from validated owned dependencies; never retry uncertain creation."""

        ...

    def DeleteResource(
        self, reference: ResourceReference, identity: StackIdentity, logical_id: str,
        operation_id: str | None = None,
    ) -> None:
        """Re-read exact scope and complete ownership immediately before deleting by ID."""

        ...
