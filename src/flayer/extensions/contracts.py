"""Typed, versioned extension identities and bounded credential-free contexts."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from flayer.core.contracts import ContractError, StackIdentity, ValidateName
from flayer.profiles.artifacts import ArtifactBundle
from flayer.providers.contracts import CloudProvider, ValidateIdentifier
from flayer.providers.lifecycle import LifecycleProvider

PROVIDER_GROUP = "flayer.providers.v1"
PROFILE_GROUP = "flayer.profiles.v1"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
DISTRIBUTION_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
TARGET_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*"
    r":[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")


class ExtensionError(ContractError):
    """An extension violates discovery, identity, compatibility, or loading policy."""


class ExtensionKind(StrEnum):
    """The two implemented extension contracts; their ABI is encoded in the group."""

    PROVIDER = "provider"
    PROFILE = "profile"


@dataclass(frozen=True, slots=True)
class ExtensionDescriptor:
    """A static identity; external metadata snapshots are not package authenticity proof."""

    kind: ExtensionKind
    plugin_id: str
    distribution: str
    version: str
    group: str
    target: str
    metadata_directory: Path | None = field(default=None, repr=False)
    metadata_sha256: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as statically decoded metadata."""

        if not isinstance(self.kind, ExtensionKind):
            raise ExtensionError("Extension kind must be an ExtensionKind member")

        ValidateName(self.plugin_id, "extension.plugin_id")

        if (
            not isinstance(self.distribution, str) or len(self.distribution) > 128
            or DISTRIBUTION_PATTERN.fullmatch(self.distribution) is None
            or not isinstance(self.version, str) or len(self.version) > 32
            or VERSION_PATTERN.fullmatch(self.version) is None
        ):
            raise ExtensionError("Extension distribution and stable release version are invalid")

        expected_group = PROVIDER_GROUP if self.kind is ExtensionKind.PROVIDER else PROFILE_GROUP

        if self.group != expected_group:
            raise ExtensionError("Extension group uses an unsupported contract version")

        if (
            not isinstance(self.target, str) or len(self.target) > 256
            or TARGET_PATTERN.fullmatch(self.target) is None
        ):
            raise ExtensionError("Extension target must be an exact module:attribute without extras")

        if self.metadata_directory is None:
            if self.distribution != "f-layer" or self.metadata_sha256 is not None:
                raise ExtensionError("Only F-Layer built-ins may omit the metadata snapshot")

        elif (
            not isinstance(self.metadata_directory, Path)
            or not self.metadata_directory.is_absolute()
            or not self.metadata_directory.name.endswith(".dist-info")
            or not isinstance(self.metadata_sha256, str)
            or SHA256_PATTERN.fullmatch(self.metadata_sha256) is None
            or self.distribution == "f-layer"
            or self.target.split(":", 1)[0].split(".", 1)[0] == "flayer"
        ):
            raise ExtensionError("External extensions require a valid non-reserved metadata snapshot")


@dataclass(frozen=True, slots=True)
class ProviderContext:
    """Explicit scope, external CLI authentication reference, and bounded execution limits."""

    scope_id: str
    authentication_reference: str
    command_timeout: float = 45.0
    inventory_limit: int = 10000

    def __post_init__(self) -> None:
        """Reject credential bytes, malformed references, and unbounded execution settings."""

        ValidateIdentifier(self.scope_id)
        ValidateIdentifier(self.authentication_reference)

        if (
            isinstance(self.command_timeout, bool)
            or not isinstance(self.command_timeout, (int, float))
            or not math.isfinite(self.command_timeout)
            or not 0 < self.command_timeout <= 300
            or type(self.inventory_limit) is not int or not 1 <= self.inventory_limit <= 100000
        ):
            raise ExtensionError("Provider context requires bounded timeout and inventory limits")


@dataclass(frozen=True, slots=True)
class ProfileContext:
    """Exact stack ownership context; profile configuration and artifacts stay separate."""

    identity: StackIdentity

    def __post_init__(self) -> None:
        """Require the existing validated immutable ownership contract."""

        if not isinstance(self.identity, StackIdentity):
            raise ExtensionError("Profile context requires a validated StackIdentity")


@runtime_checkable
class ProviderExtension(Protocol):
    """Factory for the existing read-only provider contract, without mandatory mutation."""

    @property
    def Descriptor(self) -> ExtensionDescriptor:
        """Return the exact static identity registered before factory loading."""

        ...

    def CreateProvider(self, context: ProviderContext) -> CloudProvider:
        """Construct a scoped read-only adapter without probing or mutating infrastructure."""

        ...


@runtime_checkable
class LifecycleProviderExtension(ProviderExtension, Protocol):
    """Optional separate factory for the existing owned resource lifecycle contract."""

    def CreateLifecycleProvider(self, context: ProviderContext) -> LifecycleProvider:
        """Construct a mutation-capable adapter without performing provider operations."""

        ...


@runtime_checkable
class CompiledProfile(Protocol):
    """Validated profile adapter that preserves existing artifact and lifecycle boundaries."""

    @property
    def Identity(self) -> StackIdentity:
        """Return the exact identity validated during profile compilation."""

        ...

    def BuildServerBundle(self) -> ArtifactBundle:
        """Generate owned server initialization bytes without writing or deploying them."""

        ...

    def RenderPlan(self, *, user_data_file: str | Path) -> str:
        """Render lifecycle TOML after verifying the exact owned server artifact."""

        ...


@runtime_checkable
class ProfileExtension(Protocol):
    """Compile explicit profile configuration using its own strict versioned schema."""

    @property
    def Descriptor(self) -> ExtensionDescriptor:
        """Return the exact static identity registered before factory loading."""

        ...

    def CompileProfile(
        self, configuration: Mapping[str, object], context: ProfileContext,
    ) -> CompiledProfile:
        """Validate configuration and exact ownership without accessing infrastructure."""

        ...
