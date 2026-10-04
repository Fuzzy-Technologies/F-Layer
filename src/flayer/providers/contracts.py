"""Provider-neutral contracts for bounded, read-only infrastructure discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class ResourceKind(StrEnum):
    """Infrastructure resource kinds supported by the discovery contract."""

    INSTANCE = "instance"
    DISK = "disk"
    NETWORK = "network"
    SUBNET = "subnet"
    ADDRESS = "address"
    SECURITY_GROUP = "security_group"


class ProviderCapability(StrEnum):
    """Implemented operations advertised by a provider, independent of permissions."""

    INVENTORY = "inventory"
    RESOURCE_LOOKUP = "resource_lookup"


class ProviderErrorCode(StrEnum):
    """Stable failure categories that never include vendor output or credentials."""

    UNAVAILABLE = "unavailable"
    AUTHENTICATION = "authentication"
    PERMISSION_DENIED = "permission_denied"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    THROTTLED = "throttled"
    CONFLICT = "conflict"
    SCOPE_MISMATCH = "scope_mismatch"
    INVALID_RESPONSE = "invalid_response"
    UNSUPPORTED = "unsupported"
    COMMAND_FAILED = "command_failed"
    INCOMPLETE_INVENTORY = "incomplete_inventory"


class ProviderError(RuntimeError):
    """A sanitized provider failure with a stable code and retry recommendation."""

    def __init__(self, code: ProviderErrorCode, operation: str) -> None:
        """Build an error without retaining external command output or exceptions."""

        self.code = code
        self.operation = operation
        self.retryable = code in {
            ProviderErrorCode.TIMEOUT,
            ProviderErrorCode.THROTTLED,
        }
        super().__init__(f"Provider operation {operation} failed: {code.value}")


def ValidateIdentifier(value: str) -> None:
    """Reject unsafe identifiers without including the rejected value in errors."""

    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(
            "Provider identifiers require 1-128 ASCII letters, digits, dots, underscores or dashes"
        )


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    """Non-secret provider and explicit scope identity; credentials remain external."""

    provider_id: str
    scope_id: str
    authentication_source: str

    def __post_init__(self) -> None:
        """Validate immutable identity fields before they can define a resource scope."""

        ValidateIdentifier(self.provider_id)
        ValidateIdentifier(self.scope_id)
        ValidateIdentifier(self.authentication_source)


@dataclass(frozen=True, slots=True)
class ResourceReference:
    """A resource key bound to one provider, one scope and one resource kind."""

    provider_id: str
    scope_id: str
    kind: ResourceKind
    resource_id: str

    def __post_init__(self) -> None:
        """Reject malformed identities and unrecognized resource kinds."""

        ValidateIdentifier(self.provider_id)
        ValidateIdentifier(self.scope_id)
        ValidateIdentifier(self.resource_id)

        if not isinstance(self.kind, ResourceKind):
            raise ValueError("Resource kind must be a ResourceKind member")


@dataclass(frozen=True, slots=True)
class ProviderResource:
    """A normalized observation, excluding raw vendor payloads and instance metadata."""

    reference: ResourceReference
    name: str
    status: str = "UNKNOWN"
    zone_id: str | None = None
    labels: tuple[tuple[str, str], ...] = ()
    public_addresses: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require immutable labels and endpoint collections from provider adapters."""

        if not isinstance(self.reference, ResourceReference):
            raise ValueError("Provider resources require a validated resource reference")

        if not isinstance(self.name, str) or not isinstance(self.status, str):
            raise ValueError("Resource names and statuses must be strings")

        if self.zone_id is not None:
            ValidateIdentifier(self.zone_id)

        if (
            not isinstance(self.labels, tuple)
            or any(
                not isinstance(label, tuple)
                or len(label) != 2
                or not all(isinstance(value, str) for value in label)
                for label in self.labels
            )
            or len({label[0] for label in self.labels}) != len(self.labels)
        ):
            raise ValueError("Resource labels must be immutable unique string pairs")

        if not isinstance(self.public_addresses, tuple) or not all(
            isinstance(address, str) for address in self.public_addresses
        ):
            raise ValueError("Public addresses must be an immutable string tuple")

    def HasLabels(self, expected: tuple[tuple[str, str], ...]) -> bool:
        """Check all required labels without treating a resource name as ownership."""

        actual = dict(self.labels)

        return bool(expected) and all(actual.get(key) == value for key, value in expected)


@dataclass(frozen=True, slots=True)
class ProviderStatus:
    """A sanitized probe result; unknown authentication differs from a failed probe."""

    identity: ProviderIdentity
    available: bool
    authenticated: bool | None = None
    error_code: ProviderErrorCode | None = None


@runtime_checkable
class CloudProvider(Protocol):
    """Read-only provider boundary consumed by diagnostics and future orchestration."""

    @property
    def Identity(self) -> ProviderIdentity:
        """Return the provider identity and explicit discovery scope."""

        ...

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Advertise implemented operations without promising account authorization."""

        ...

    def CheckAvailability(self) -> ProviderStatus:
        """Probe the local provider adapter without accessing infrastructure."""

        ...

    def CheckAuthentication(self) -> ProviderStatus:
        """Probe read permission to the selected scope without exposing credentials."""

        ...

    def ListResources(self, kind: ResourceKind) -> tuple[ProviderResource, ...]:
        """List a complete resource kind within the provider's explicit scope."""

        ...

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Read one resource and reject any reference or response outside the scope."""

        ...

    def DiscoverInventory(self) -> tuple[ProviderResource, ...]:
        """Return all supported kinds or fail without returning partial inventory."""

        ...
