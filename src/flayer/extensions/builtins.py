"""Usable extension adapters for the existing Yandex providers and secure gateway."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from flayer import __version__
from flayer.core.contracts import StackIdentity
from flayer.profiles.artifacts import ArtifactBundle
from flayer.providers.contracts import CloudProvider
from flayer.providers.lifecycle import LifecycleProvider

from .contracts import (
    PROFILE_GROUP,
    PROVIDER_GROUP,
    CompiledProfile,
    ExtensionDescriptor,
    ExtensionError,
    ExtensionKind,
    ProfileContext,
    ProfileExtension,
    ProviderContext,
    ProviderExtension,
)

if TYPE_CHECKING:
    from flayer.profiles.gateway import GatewayPlan

YANDEX_READ_ONLY = ExtensionDescriptor(
    ExtensionKind.PROVIDER, "yandex-read-only", "f-layer", __version__, PROVIDER_GROUP,
    "flayer.extensions.builtins:YandexReadOnlyExtension",
)
YANDEX_LIFECYCLE = ExtensionDescriptor(
    ExtensionKind.PROVIDER, "yandex-lifecycle", "f-layer", __version__, PROVIDER_GROUP,
    "flayer.extensions.builtins:YandexLifecycleExtension",
)
SECURE_GATEWAY = ExtensionDescriptor(
    ExtensionKind.PROFILE, "secure-gateway", "f-layer", __version__, PROFILE_GROUP,
    "flayer.extensions.builtins:SecureGatewayExtension",
)


def BuiltinDescriptors() -> tuple[ExtensionDescriptor, ...]:
    """Return static descriptors without importing provider or profile implementations."""

    return (YANDEX_READ_ONLY, YANDEX_LIFECYCLE, SECURE_GATEWAY)


class YandexReadOnlyExtension:
    """Build the real read-only Yandex adapter with an external CLI profile reference."""

    @property
    def Descriptor(self) -> ExtensionDescriptor:
        """Return the immutable built-in identity used by registry lookup."""

        return YANDEX_READ_ONLY

    def CreateProvider(self, context: ProviderContext) -> CloudProvider:
        """Construct a real adapter without running CLI commands or reading credentials."""

        from flayer.providers.yandex import YandexCloudProvider, YandexCloudSettings

        if not isinstance(context, ProviderContext):
            raise ExtensionError("Provider construction requires a validated ProviderContext")

        return YandexCloudProvider(YandexCloudSettings(
            folder_id=context.scope_id, profile=context.authentication_reference,
            command_timeout=context.command_timeout, inventory_limit=context.inventory_limit,
        ))


class YandexLifecycleExtension(YandexReadOnlyExtension):
    """Opt in separately to the existing exact-scope owned resource mutation contract."""

    @property
    def Descriptor(self) -> ExtensionDescriptor:
        """Return the distinct identity that explicitly advertises lifecycle construction."""

        return YANDEX_LIFECYCLE

    def CreateLifecycleProvider(self, context: ProviderContext) -> LifecycleProvider:
        """Construct the real lifecycle adapter without performing provider operations."""

        from flayer.providers.yandex import YandexCloudSettings
        from flayer.providers.yandex_lifecycle import YandexLifecycleProvider

        if not isinstance(context, ProviderContext):
            raise ExtensionError("Provider construction requires a validated ProviderContext")

        return YandexLifecycleProvider(YandexCloudSettings(
            folder_id=context.scope_id, profile=context.authentication_reference,
            command_timeout=context.command_timeout, inventory_limit=context.inventory_limit,
        ))


@dataclass(frozen=True, slots=True)
class _CompiledGateway:
    """Adapt a real compiled gateway while retaining its artifact verification contract."""

    plan: GatewayPlan

    @property
    def Identity(self) -> StackIdentity:
        """Return the exact ownership identity already validated by profile compilation."""

        return self.plan.profile.identity

    def BuildServerBundle(self) -> ArtifactBundle:
        """Generate the real gateway server bundle in memory without storing it."""

        from flayer.profiles.gateway import BuildServerBundle

        return BuildServerBundle(self.plan.profile)

    def RenderPlan(self, *, user_data_file: str | Path) -> str:
        """Preserve gateway verification of the exact exported server artifact."""

        from flayer.profiles.gateway import RenderPlan

        return RenderPlan(self.plan, user_data_file=user_data_file)


class SecureGatewayExtension:
    """Compile the real strict gateway schema through the additive extension boundary."""

    @property
    def Descriptor(self) -> ExtensionDescriptor:
        """Return the immutable built-in profile identity."""

        return SECURE_GATEWAY

    def CompileProfile(
        self, configuration: Mapping[str, object], context: ProfileContext,
    ) -> CompiledProfile:
        """Reject identity disagreement before constructing a real gateway plan."""

        from flayer.profiles.gateway import CompileGateway, ParseGatewayProfile

        if not isinstance(context, ProfileContext):
            raise ExtensionError("Profile compilation requires a validated ProfileContext")

        profile = ParseGatewayProfile(configuration)

        if profile.identity != context.identity:
            raise ExtensionError("Profile configuration does not match its exact ownership context")

        return _CompiledGateway(CompileGateway(profile))


def LoadBuiltin(descriptor: ExtensionDescriptor) -> ProviderExtension | ProfileExtension:
    """Load only an exact known built-in descriptor, rejecting invented built-in targets."""

    if descriptor == YANDEX_READ_ONLY:
        return YandexReadOnlyExtension()

    if descriptor == YANDEX_LIFECYCLE:
        return YandexLifecycleExtension()

    if descriptor == SECURE_GATEWAY:
        return SecureGatewayExtension()

    raise ExtensionError("Extension is not an exact registered F-Layer built-in")
