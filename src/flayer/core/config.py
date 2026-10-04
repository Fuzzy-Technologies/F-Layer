"""Strict TOML desired-state loading without provider defaults or secret material."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .contracts import (
    SCHEMA_VERSION,
    ContractError,
    ParseIdentity,
    RequireTable,
    StackIdentity,
    ValidateFields,
    ValidateName,
    ValidateSchemaVersion,
)

_ENVIRONMENT_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")


class ConfigError(ContractError):
    """Desired configuration cannot be safely parsed or read."""


@dataclass(frozen=True)
class SecretReference:
    """A named credential source; resolution belongs to an authentication adapter."""

    name: str
    source: str
    reference: str

    def __post_init__(self) -> None:
        """Allow environment names and file paths, never inline credential values."""

        ValidateName(self.name, "credentials.name")

        if not isinstance(self.source, str) or self.source not in {"env", "file"}:
            raise ContractError("credentials.source must be env or file")

        if self.source == "env":
            if (
                not isinstance(self.reference, str)
                or _ENVIRONMENT_NAME.fullmatch(self.reference) is None
            ):
                raise ContractError("credentials.reference must be an environment variable name")

        elif (
            not isinstance(self.reference, str)
            or not self.reference.strip()
            or self.reference != self.reference.strip()
            or len(self.reference) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in self.reference)
        ):
            raise ContractError("credentials.reference must be a nonempty file path")


@dataclass(frozen=True)
class DesiredResource:
    """Provider-independent logical resource identity before an external resource exists."""

    logical_id: str
    kind: str
    name: str

    def __post_init__(self) -> None:
        """Reject ambiguous logical identifiers and malformed names."""

        ValidateName(self.logical_id, "resources.logical_id")
        ValidateName(self.kind, "resources.kind")
        ValidateName(self.name, "resources.name")


@dataclass(frozen=True)
class DesiredConfig:
    """Immutable, validated desired intent without observed identifiers or credentials."""

    identity: StackIdentity
    profile: str
    resources: tuple[DesiredResource, ...] = ()
    credentials: tuple[SecretReference, ...] = ()
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Preserve model invariants when callers construct plans directly."""

        ValidateSchemaVersion(self.schema_version)

        if not isinstance(self.identity, StackIdentity):
            raise ContractError("identity must be a StackIdentity")

        ValidateName(self.profile, "profile")

        if not isinstance(self.resources, tuple) or any(
            not isinstance(resource, DesiredResource) for resource in self.resources
        ):
            raise ContractError("resources must be a tuple of DesiredResource values")

        if len({resource.logical_id for resource in self.resources}) != len(self.resources):
            raise ContractError("resources.logical_id values must be unique")

        if not isinstance(self.credentials, tuple) or any(
            not isinstance(credential, SecretReference) for credential in self.credentials
        ):
            raise ContractError("credentials must be a tuple of SecretReference values")

        if len({credential.name for credential in self.credentials}) != len(self.credentials):
            raise ContractError("credentials.name values must be unique")


def _ParseResources(value: object) -> tuple[DesiredResource, ...]:
    """Decode strictly typed logical resource tables."""

    if not isinstance(value, list):
        raise ContractError("resources must be an array of tables")

    resources: list[DesiredResource] = []

    for item in value:
        table = RequireTable(item, "resources")
        ValidateFields(table, frozenset({"logical_id", "kind", "name"}), frozenset(), "resources")
        resources.append(
            DesiredResource(
                logical_id=ValidateName(table["logical_id"], "resources.logical_id"),
                kind=ValidateName(table["kind"], "resources.kind"),
                name=ValidateName(table["name"], "resources.name"),
            )
        )

    return tuple(resources)


def _ParseCredentials(value: object) -> tuple[SecretReference, ...]:
    """Decode references without consulting the environment or reading credential files."""

    if not isinstance(value, list):
        raise ContractError("credentials must be an array of tables")

    credentials: list[SecretReference] = []

    for item in value:
        table = RequireTable(item, "credentials")
        ValidateFields(
            table, frozenset({"name", "source", "reference"}), frozenset(), "credentials"
        )

        if not isinstance(table["source"], str) or not isinstance(table["reference"], str):
            raise ContractError("credentials.source and reference must be strings")

        credentials.append(
            SecretReference(
                name=ValidateName(table["name"], "credentials.name"),
                source=table["source"],
                reference=table["reference"],
            )
        )

    return tuple(credentials)


def ParseConfig(data: Mapping[str, object]) -> DesiredConfig:
    """Validate decoded TOML; unknown fields and schema versions always fail closed."""

    try:
        ValidateFields(
            data,
            frozenset({"schema_version", "identity", "profile"}),
            frozenset({"resources", "credentials"}),
            "configuration",
        )
        ValidateSchemaVersion(data["schema_version"])

        return DesiredConfig(
            identity=ParseIdentity(data["identity"]),
            profile=ValidateName(data["profile"], "profile"),
            resources=_ParseResources(data.get("resources", [])),
            credentials=_ParseCredentials(data.get("credentials", [])),
        )

    except ContractError as error:
        raise ConfigError(str(error)) from error


def LoadConfig(path: str | Path) -> DesiredConfig:
    """Load an explicit TOML path with no implicit local defaults or environment overrides."""

    try:
        with Path(path).open("rb") as stream:
            data = tomllib.load(stream)

    except (OSError, ValueError, RecursionError) as error:
        raise ConfigError("Unable to read a valid TOML configuration") from error

    return ParseConfig(data)
