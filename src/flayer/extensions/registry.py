"""Explicit registry and opt-in loading of metadata-pinned, owned extension sources."""

from __future__ import annotations

import base64
import csv
import hashlib
import importlib.abc
import importlib.util
import io
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import ModuleType

from .builtins import BuiltinDescriptors, LoadBuiltin
from .contracts import (
    ExtensionDescriptor,
    ExtensionError,
    ExtensionKind,
    ProfileExtension,
    ProviderExtension,
)
from .discovery import (
    MAX_EXTENSIONS,
    DiscoverExtensions,
    ReadMetadataFile,
    ReadMetadataSnapshot,
)

MAX_MODULE_BYTES = 1048576
MAX_MODULE_DEPTH = 16
_LOADED_SOURCES: dict[str, tuple[ModuleType, Path, str]] = {}


@dataclass(frozen=True, slots=True)
class _ModuleSource:
    """Verified immutable Python bytes owned by one selected distribution RECORD."""

    name: str
    path: Path
    content: bytes = field(repr=False)
    package: bool = False


class _SnapshotImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Serve only already verified selected-chain imports from immutable source snapshots."""

    def __init__(
        self, sources: tuple[_ModuleSource, ...], created: list[tuple[str, ModuleType]],
    ) -> None:
        """Bind the exact source chain and cleanup receipts for one explicit load attempt."""

        self._sources = {source.name: source for source in sources}
        self._created = created

    def find_spec(
        self, fullname: str, path: Sequence[str] | None, target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        """Honor Python's finder callback only for exact selected source identities."""

        source = self._sources.get(fullname)

        if source is None:
            return None

        return importlib.util.spec_from_file_location(
            fullname, source.path, loader=self,
            submodule_search_locations=[str(source.path.parent)] if source.package else None,
        )

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        """Honor Python's loader callback with the standard module construction behavior."""

        return None

    def exec_module(self, module: ModuleType) -> None:
        """Execute selected verified bytes and register exact module-object provenance."""

        source = self._sources[module.__name__]
        self._created.append((source.name, module))
        exec(compile(source.content, str(source.path), "exec"), module.__dict__)
        _LOADED_SOURCES[source.name] = (
            module, source.path, hashlib.sha256(source.content).hexdigest(),
        )
        _RequireReceipt(source, module)


def _ReadSources(descriptor: ExtensionDescriptor) -> tuple[_ModuleSource, ...]:
    """Validate exact metadata and every parent/target source before any plugin execution."""

    directory = descriptor.metadata_directory

    if directory is None:
        raise ExtensionError("External loading requires a selected metadata directory")

    contents, digest = ReadMetadataSnapshot(directory)

    if digest != descriptor.metadata_sha256 or descriptor not in DiscoverExtensions((directory,)):
        raise ExtensionError("Selected extension metadata changed after discovery")

    records: dict[str, tuple[str, str]] = {}

    try:
        for row in csv.reader(io.StringIO(contents[2].decode("utf-8")), strict=True):
            if (
                len(row) != 3 or not row[0] or row[0] in records
                or PurePosixPath(row[0]).is_absolute() or "\\" in row[0]
            ):
                raise ExtensionError("Distribution RECORD contains malformed or duplicate paths")

            records[row[0]] = (row[1], row[2])

    except (UnicodeError, csv.Error):
        raise ExtensionError("Distribution RECORD is malformed") from None

    module = descriptor.target.split(":", 1)[0]
    parts = module.split(".")

    if len(parts) > MAX_MODULE_DEPTH:
        raise ExtensionError("Extension import target exceeds the supported package depth")

    sources: list[_ModuleSource] = []

    for index in range(1, len(parts) + 1):
        stem = "/".join(parts[:index])
        candidates: tuple[str, ...] = (stem + "/__init__.py",)

        if index == len(parts):
            candidates += (stem + ".py",)

        matches = tuple(candidate for candidate in candidates if candidate in records)

        if len(matches) != 1:
            raise ExtensionError("Extension target and parent packages require exact RECORD ownership")

        relative = matches[0]
        path = directory.parent / relative

        try:
            if path.resolve() != path or not path.is_relative_to(directory.parent):
                raise ExtensionError("Extension source cannot redirect outside its selected installation")

        except (OSError, RuntimeError):
            raise ExtensionError("Unable to resolve exact non-redirected extension source") from None

        content = ReadMetadataFile(path, MAX_MODULE_BYTES)
        source_digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")

        if records[relative] != ("sha256=" + source_digest, str(len(content))):
            raise ExtensionError("Extension source does not match its exact RECORD hash and size")

        sources.append(_ModuleSource(
            ".".join(parts[:index]), path, content, relative.endswith("/__init__.py"),
        ))

    return tuple(sources)


def _LoadFactory(descriptor: ExtensionDescriptor) -> ProviderExtension | ProfileExtension:
    """Execute verified selected sources directly, rejecting ambient module shadowing."""

    sources = _ReadSources(descriptor)

    for source in sources:
        existing = sys.modules.get(source.name)

        if existing is not None:
            _RequireReceipt(source, existing)

    created: list[tuple[str, ModuleType]] = []
    importer = _SnapshotImporter(sources, created)
    sys.meta_path.insert(0, importer)

    try:
        for source in sources:
            existing = sys.modules.get(source.name)

            if existing is not None:
                _RequireReceipt(source, existing)

                continue

            spec = importer.find_spec(source.name, None)

            if spec is None:
                raise ExtensionError("Unable to construct the selected extension module")

            module = importlib.util.module_from_spec(spec)
            sys.modules[source.name] = module
            importer.exec_module(module)

            if "." in source.name:
                parent_name, _, child_name = source.name.rpartition(".")
                setattr(sys.modules[parent_name], child_name, module)

        factory: object = sys.modules[sources[-1].name]

        for attribute in descriptor.target.split(":", 1)[1].split("."):
            factory = getattr(factory, attribute)

        if not callable(factory):
            raise ExtensionError("Selected entry-point target is not a callable factory")

        return _ValidateExtension(factory(), descriptor)

    except (Exception, SystemExit):
        for name, module in reversed(created):
            if sys.modules.get(name) is module:
                del sys.modules[name]

            receipt = _LOADED_SOURCES.get(name)

            if receipt is not None and receipt[0] is module:
                del _LOADED_SOURCES[name]

            if "." in name:
                parent_name, _, child_name = name.rpartition(".")
                parent = sys.modules.get(parent_name)

                if parent is not None and parent.__dict__.get(child_name) is module:
                    del parent.__dict__[child_name]

        raise ExtensionError("Selected extension factory failed to load") from None

    finally:
        if importer in sys.meta_path:
            sys.meta_path.remove(importer)


def _RequireReceipt(source: _ModuleSource, module: ModuleType) -> None:
    """Reject cached code unless this loader executed this exact verified byte snapshot."""

    receipt = _LOADED_SOURCES.get(source.name)

    if (
        receipt is None or receipt[0] is not module or receipt[1] != source.path
        or receipt[2] != hashlib.sha256(source.content).hexdigest()
        or sys.modules.get(source.name) is not module
        or module.__dict__.get("__file__") != str(source.path)
        or getattr(module.__dict__.get("__spec__"), "origin", None) != str(source.path)
    ):
        raise ExtensionError("An unverified cached module shadows the selected extension source")


def _ValidateExtension(
    loaded: object, descriptor: ExtensionDescriptor,
) -> ProviderExtension | ProfileExtension:
    """Check exact identity and callable protocol before a factory transaction commits."""

    expected = ProviderExtension if descriptor.kind is ExtensionKind.PROVIDER else ProfileExtension
    method = "CreateProvider" if descriptor.kind is ExtensionKind.PROVIDER else "CompileProfile"

    try:
        if (
            not isinstance(loaded, expected) or loaded.Descriptor != descriptor
            or not callable(getattr(loaded, method, None))
        ):
            raise ExtensionError("Loaded extension does not match its declared identity and contract")

    except (Exception, SystemExit):
        raise ExtensionError("Loaded extension does not match its declared identity and contract") from None

    return loaded


class ExtensionRegistry:
    """A bounded explicit catalog; neither construction nor lookup imports external code."""

    def __init__(
        self, descriptors: Sequence[ExtensionDescriptor] = (), *, include_builtins: bool = True,
    ) -> None:
        """Validate complete registration before publishing any catalog entries."""

        if type(include_builtins) is not bool or not isinstance(descriptors, (tuple, list)):
            raise ExtensionError("Registry requires explicit bounded descriptor registration")

        entries = (*BuiltinDescriptors(), *descriptors) if include_builtins else tuple(descriptors)

        if len(entries) > MAX_EXTENSIONS:
            raise ExtensionError("Registry exceeds its extension bound")

        registered: dict[tuple[ExtensionKind, str], ExtensionDescriptor] = {}

        for descriptor in entries:
            if not isinstance(descriptor, ExtensionDescriptor):
                raise ExtensionError("Registry accepts only validated ExtensionDescriptor objects")

            identity = (descriptor.kind, descriptor.plugin_id)

            if identity in registered:
                raise ExtensionError("Duplicate extension identity would shadow a registered extension")

            if descriptor.metadata_directory is None and descriptor not in BuiltinDescriptors():
                raise ExtensionError("Registry rejects invented or incompatible built-in identities")

            registered[identity] = descriptor

        self._descriptors = registered
        self._loaded: dict[ExtensionDescriptor, ProviderExtension | ProfileExtension] = {}

    def Descriptors(self) -> tuple[ExtensionDescriptor, ...]:
        """Return immutable descriptors in deterministic kind and identifier order."""

        return tuple(sorted(self._descriptors.values(), key=lambda item: (item.kind.value, item.plugin_id)))

    def Get(self, kind: ExtensionKind, plugin_id: str) -> ExtensionDescriptor:
        """Select one registered identity without imports or capability probes."""

        if not isinstance(kind, ExtensionKind) or not isinstance(plugin_id, str):
            raise ExtensionError("Registry lookup requires an exact extension kind and identifier")

        descriptor = self._descriptors.get((kind, plugin_id))

        if descriptor is None:
            raise ExtensionError("Extension identity is not registered")

        return descriptor

    def Load(
        self, descriptor: ExtensionDescriptor, *, allowed: Sequence[ExtensionDescriptor] = (),
    ) -> ProviderExtension | ProfileExtension:
        """Load an exact registered factory; external code requires an exact descriptor pin."""

        if (
            not isinstance(descriptor, ExtensionDescriptor)
            or self.Get(descriptor.kind, descriptor.plugin_id) != descriptor
            or not isinstance(allowed, (tuple, list)) or len(allowed) > MAX_EXTENSIONS
            or any(not isinstance(item, ExtensionDescriptor) for item in allowed)
            or len(set(allowed)) != len(allowed)
        ):
            raise ExtensionError("Loading requires an exact registered descriptor and bounded unique pins")

        if descriptor.metadata_directory is not None and descriptor not in allowed:
            raise ExtensionError("External loading requires an explicit exact descriptor allowlist")

        if descriptor in self._loaded:
            return self._loaded[descriptor]

        loaded = (
            _ValidateExtension(LoadBuiltin(descriptor), descriptor)
            if descriptor.metadata_directory is None else _LoadFactory(descriptor)
        )
        self._loaded[descriptor] = loaded

        return loaded
