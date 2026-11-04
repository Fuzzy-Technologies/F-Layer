"""Validated identities shared by desired plans and persisted resource ownership."""

from __future__ import annotations

import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, fields, is_dataclass

SCHEMA_VERSION = 1
MANAGED_BY = "f-layer"
IDENTITY_FIELDS = frozenset({"project", "stack", "provider", "scope_id", "owner_id"})
_NAME_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,62}")


def _WireValue(value: object) -> object:
    """Preserve dictionary keys while serializing owned dataclass fields with stable wire names."""

    if is_dataclass(value) and not isinstance(value, type):
        return _WireDict(value)

    if isinstance(value, tuple):
        return tuple(_WireValue(item) for item in value)

    if isinstance(value, list):
        return [_WireValue(item) for item in value]

    if isinstance(value, dict):
        return {deepcopy(key): _WireValue(item) for key, item in value.items()}

    return deepcopy(value)


def _WireDict(value: object) -> dict[str, object]:
    """Retain the established snake_case JSON and fingerprint contract after Python renaming."""

    if not is_dataclass(value) or isinstance(value, type):
        raise TypeError("Wire serialization requires a dataclass instance")

    return {
        re.sub(r"[A-Z]", lambda match: "_" + match[0].lower(), item.name):
        _WireValue(getattr(value, item.name)) for item in fields(value)
    }


class ContractError(ValueError):
    """An input violates a versioned core contract before any external operation."""


def ValidateName(value: object, label: str) -> str:
    """Require a bounded portable name without coercing invalid input types."""

    if not isinstance(value, str) or _NAME_PATTERN.fullmatch(value) is None:
        raise ContractError(f"{label} must be a lowercase name of 1..63 characters")

    return value


def ValidateIdentifier(value: object, label: str) -> str:
    """Accept opaque provider identifiers without control characters or whitespace."""

    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ContractError(f"{label} must be a nonempty printable ASCII identifier")

    return value


def ValidateSchemaVersion(value: object) -> None:
    """Reject unknown schema versions and booleans masquerading as integers."""

    if type(value) is not int or value != SCHEMA_VERSION:
        raise ContractError(f"schema_version must be the supported integer {SCHEMA_VERSION}")


def ValidateFields(
    data: Mapping[str, object], required: frozenset[str], optional: frozenset[str], label: str
) -> None:
    """Reject missing and unknown fields instead of silently accepting configuration typos."""

    if not isinstance(data, Mapping):
        raise ContractError(f"{label} must be a table")

    if required - data.keys():
        raise ContractError(f"{label} is missing required fields")

    if data.keys() - required - optional:
        raise ContractError(f"{label} contains unknown fields")


def RequireTable(value: object, label: str) -> Mapping[str, object]:
    """Require a string-keyed table at an untrusted decoding boundary."""

    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ContractError(f"{label} must be a table")

    return value


@dataclass(frozen=True)
class StackIdentity:
    """Exact ownership boundary for one provider scope and one managed stack."""

    project: str
    stack: str
    provider: str
    scopeId: str
    ownerId: str

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as decoded configuration."""

        ValidateName(self.project, "identity.project")
        ValidateName(self.stack, "identity.stack")
        ValidateName(self.provider, "identity.provider")
        ValidateIdentifier(self.scopeId, "identity.scope_id")
        ValidateName(self.ownerId, "identity.owner_id")

    def OwnershipLabels(self) -> dict[str, str]:
        """Return explicit labels for provider adapters to attach and verify."""

        return {
            "managed-by": MANAGED_BY,
            "flayer-project": self.project,
            "flayer-stack": self.stack,
            "flayer-owner": self.ownerId,
        }


def ParseIdentity(value: object) -> StackIdentity:
    """Decode a complete identity without defaulting missing ownership information."""

    table = RequireTable(value, "identity")
    ValidateFields(table, IDENTITY_FIELDS, frozenset(), "identity")

    return StackIdentity(
        project=ValidateName(table["project"], "identity.project"),
        stack=ValidateName(table["stack"], "identity.stack"),
        provider=ValidateName(table["provider"], "identity.provider"),
        scopeId=ValidateIdentifier(table["scope_id"], "identity.scope_id"),
        ownerId=ValidateName(table["owner_id"], "identity.owner_id"),
    )
