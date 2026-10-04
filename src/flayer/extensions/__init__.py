"""Additive typed extension contracts, static metadata discovery, and explicit loading."""

from .builtins import BuiltinDescriptors
from .contracts import (
    PROFILE_GROUP,
    PROVIDER_GROUP,
    CompiledProfile,
    ExtensionDescriptor,
    ExtensionError,
    ExtensionKind,
    LifecycleProviderExtension,
    ProfileContext,
    ProfileExtension,
    ProviderContext,
    ProviderExtension,
)
from .discovery import DiscoverExtensions
from .registry import ExtensionRegistry

__all__ = [
    "PROFILE_GROUP", "PROVIDER_GROUP", "BuiltinDescriptors", "CompiledProfile",
    "DiscoverExtensions", "ExtensionDescriptor", "ExtensionError", "ExtensionKind",
    "ExtensionRegistry", "LifecycleProviderExtension", "ProfileContext", "ProfileExtension",
    "ProviderContext", "ProviderExtension",
]
