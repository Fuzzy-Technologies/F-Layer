"""Deterministic static discovery, pinned loading, and usable built-in extension contracts."""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.metadata
import os
import py_compile
import sys
import tomllib
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import ModuleType

import pytest

from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LoadDeploymentPlan
from flayer.extensions import (
    PROVIDER_GROUP,
    BuiltinDescriptors,
    CompiledProfile,
    DiscoverExtensions,
    ExtensionDescriptor,
    ExtensionError,
    ExtensionKind,
    ExtensionRegistry,
    LifecycleProviderExtension,
    ProfileContext,
    ProfileExtension,
    ProviderContext,
    ProviderExtension,
)
from flayer.extensions.discovery import MAX_METADATA_BYTES, ReadMetadataFile
from flayer.profiles.artifacts import WriteArtifactBundle
from flayer.providers.contracts import CloudProvider, ProviderCapability
from flayer.providers.lifecycle import LifecycleProvider

PROJECT_ROOT = Path(__file__).resolve().parents[2]
IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")


def WriteRecord(directory: Path, sources: tuple[Path, ...]) -> None:
    """Record exact synthetic installed sources without creating or installing a package."""

    rows = []

    for source in sources:
        content = source.read_bytes()
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        rows.append(f"{source.relative_to(directory.parent).as_posix()},sha256={digest},{len(content)}")

    (directory / "RECORD").write_text("\n".join(rows) + "\n", encoding="utf-8")


def Metadata(
    tmp_path: Path, *, entries: str | None = None, source: str | None = None,
) -> Path:
    """Build exact fixture metadata and source with a factory execution sentinel."""

    directory = tmp_path / "example_plugin-1.2.3.dist-info"
    package = tmp_path / "example_plugin"
    directory.mkdir()
    package.mkdir()
    (directory / "METADATA").write_text("Metadata-Version: 2.1\nName: example-plugin\nVersion: 1.2.3\n")
    (directory / "entry_points.txt").write_text(entries or (
        f"[{PROVIDER_GROUP}]\nexample = example_plugin.plugin:Plugin\n"
    ))
    parent = package / "__init__.py"
    parent.write_text('"""Synthetic plugin package with no discovery-time execution."""\n')
    plugin = package / "plugin.py"
    plugin.write_text(source or (
        '"""Synthetic provider factory loaded only after exact opt-in."""\n'
        "from pathlib import Path\n"
        "from flayer.extensions import DiscoverExtensions\n"
        "Path(__file__).parent.joinpath('executed.txt').write_text('executed')\n\n"
        "class Plugin:\n"
        '    """A fixture provider extension with a real constructible adapter."""\n\n'
        "    @property\n"
        "    def Descriptor(self):\n"
        '        """Return the exact selected metadata snapshot."""\n\n'
        "        directory = Path(__file__).parent.parent / 'example_plugin-1.2.3.dist-info'\n\n"
        "        return DiscoverExtensions((directory,))[0]\n\n"
        "    def CreateProvider(self, context):\n"
        '        """Construct a real read-only provider without probing infrastructure."""\n\n'
        "        from flayer.extensions.builtins import YandexReadOnlyExtension\n\n"
        "        return YandexReadOnlyExtension().CreateProvider(context)\n"
    ))
    WriteRecord(directory, (parent, plugin))

    return directory


@pytest.fixture(autouse=True)
def isolated_plugin_modules() -> None:
    """Remove only synthetic fixture modules so plugin tests never share execution state."""

    for name in ("example_plugin.plugin", "example_plugin"):
        sys.modules.pop(name, None)


def test_DiscoveryCannotExecuteCodeOrInstalledFinders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Discovery is explicit bounded metadata parsing, even with executable plugin source."""

    directory = Metadata(tmp_path)

    def RejectFinder(*arguments: object, **keywords: object) -> None:
        """Fail if discovery accidentally invokes ambient distribution enumeration."""

        raise AssertionError("Static discovery called an installed metadata finder")

    monkeypatch.setattr(importlib.metadata, "distributions", RejectFinder)
    descriptors = DiscoverExtensions((directory,))
    registry = ExtensionRegistry(descriptors)

    assert len(descriptors) == 1, "Explicit metadata failed to discover its one entry point"
    assert len(registry.Descriptors()) == 4, "External registration discarded built-in descriptors"
    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Discovery executed plugin code"
    assert "example_plugin" not in sys.modules, "Discovery imported a plugin parent package"
    assert descriptors[0].distribution == "example-plugin", "Distribution identity was not canonical"

    with pytest.raises(FrozenInstanceError):
        descriptors[0].version = "1.2.4"  # type: ignore[misc]


@pytest.mark.parametrize("entries", [
    f"[{PROVIDER_GROUP}]\nexample = example_plugin.plugin:Plugin [extra]\n",
    f"[{PROVIDER_GROUP}]\nexample = example_plugin.plugin\n",
    f"[{PROVIDER_GROUP}]\nExample = example_plugin.plugin:Plugin\n",
    f"[{PROVIDER_GROUP}]\nexample = flayer.providers.yandex:YandexCloudProvider\n",
    "[flayer.providers.v2]\nexample = example_plugin.plugin:Plugin\n",
    "[flayer.unknown.v1]\nexample = example_plugin.plugin:Plugin\n",
    f"[{PROVIDER_GROUP}]\nexample = example_plugin.plugin:Plugin\nexample = example_plugin:Other\n",
    f"[{PROVIDER_GROUP}]\nexample = example_plugin.plugin:Plugin\n[{PROVIDER_GROUP}]\n",
    f"[DEFAULT]\nexample = example_plugin.plugin:Plugin\n[{PROVIDER_GROUP}]\n",
    "missing section and delimiter",
])
def test_MalformedAndIncompatibleEntryPointsFailClosed(tmp_path: Path, entries: str) -> None:
    """Malformed names, targets, duplicates, reserved namespace, and ABI versions never register."""

    directory = Metadata(tmp_path, entries=entries)

    with pytest.raises(ExtensionError):
        DiscoverExtensions((directory,))

    assert "example_plugin" not in sys.modules, "Rejected entry points executed parent code"


@pytest.mark.parametrize("metadata", [
    "Name: example-plugin\nVersion: 1.2.3\nVersion: 1.2.4\n",
    "Name: example-plugin\nName: other\nVersion: 1.2.3\n",
    "Name: example-plugin\nVersion: 1.2.3rc1\n",
    "Name: example-plugin\nVersion: 01.2.3\n",
    "Name: f-layer\nVersion: 1.2.3\n",
    "Name: example-plugin\n",
])
def test_InvalidDistributionMetadataFailsClosed(tmp_path: Path, metadata: str) -> None:
    """Identity and exact stable version must be present and unambiguous before registry use."""

    directory = Metadata(tmp_path)
    (directory / "METADATA").write_text(metadata)

    with pytest.raises(ExtensionError):
        DiscoverExtensions((directory,))


def test_UnrelatedEntryPointsStayUnloadedAndEmptyDiscoveryIsValid(tmp_path: Path) -> None:
    """Other ecosystems are ignored without resolving their target modules."""

    directory = Metadata(tmp_path, entries="[unrelated.group]\nname = arbitrary:Callable\n")

    assert DiscoverExtensions((directory,)) == (), "Discovery interpreted an unrelated group"
    assert DiscoverExtensions(()) == (), "An explicit empty metadata selection should remain valid"


def test_MetadataSelectionAndFileBoundsFailClosed(tmp_path: Path) -> None:
    """Discovery cannot expand to duplicate, relative, redirected, or oversized sources."""

    directory = Metadata(tmp_path)

    for selected in ((directory, directory), (Path("relative.dist-info"),), (directory,) * 129):
        with pytest.raises(ExtensionError):
            DiscoverExtensions(selected)

    redirected = tmp_path / "redirected.dist-info"
    redirected.symlink_to(directory, target_is_directory=True)

    with pytest.raises(ExtensionError):
        DiscoverExtensions((redirected,))

    (directory / "entry_points.txt").write_bytes(b"x" * (MAX_METADATA_BYTES + 1))

    with pytest.raises(ExtensionError):
        DiscoverExtensions((directory,))

    (directory / "entry_points.txt").unlink()
    (directory / "entry_points.txt").symlink_to(directory / "METADATA")

    with pytest.raises(ExtensionError):
        DiscoverExtensions((directory,))

    with pytest.raises(ExtensionError):
        ReadMetadataFile(tmp_path / "absent")


def test_LoopedMetadataParentPathsAreSanitized(tmp_path: Path) -> None:
    """Malformed path resolution cannot leak local path details from a symlink loop."""

    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    with pytest.raises(ExtensionError) as error:
        DiscoverExtensions((loop / "example.dist-info",))

    assert str(tmp_path) not in str(error.value), "Malformed metadata path leaked local path details"


def test_DuplicateRegistryIdentitiesAndInventedBuiltinsAreRejected(tmp_path: Path) -> None:
    """Registration cannot replace a built-in or a previously selected external identity."""

    external = DiscoverExtensions((Metadata(tmp_path),))[0]

    with pytest.raises(ExtensionError, match="Duplicate"):
        ExtensionRegistry((external, external))

    with pytest.raises(ExtensionError, match="Duplicate"):
        ExtensionRegistry((replace(external, plugin_id="yandex-read-only"),))

    with pytest.raises(ExtensionError, match="invented"):
        ExtensionRegistry((replace(BuiltinDescriptors()[0], plugin_id="invented"),))

    with pytest.raises(ExtensionError):
        ExtensionRegistry((external,) * 257, include_builtins=False)


def test_ExternalLoadRequiresExactPinAndUsesOwnedSource(tmp_path: Path) -> None:
    """Exact opted-in loading executes a verified factory without ambient path resolution."""

    descriptor = DiscoverExtensions((Metadata(tmp_path),))[0]
    registry = ExtensionRegistry((descriptor,))

    with pytest.raises(ExtensionError, match="allowlist"):
        registry.Load(descriptor)

    with pytest.raises(ExtensionError, match="allowlist"):
        registry.Load(descriptor, allowed=(replace(descriptor, version="1.2.4"),))

    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Unpinned load executed code"

    extension = registry.Load(descriptor, allowed=(descriptor,))

    assert isinstance(extension, ProviderExtension), "Loaded factory lost its typed provider contract"

    provider = extension.CreateProvider(ProviderContext("example-folder", "external-profile"))

    assert isinstance(provider, CloudProvider), "External factory did not construct a usable provider"
    assert (tmp_path / "example_plugin/executed.txt").read_text() == "executed"
    assert registry.Load(descriptor, allowed=(descriptor,)) is extension, "Factory was executed twice"
    assert sys.modules["example_plugin.plugin"].__file__ == str(tmp_path / "example_plugin/plugin.py")


def test_AmbientModuleShadowingIsRejectedBeforeExecution(tmp_path: Path) -> None:
    """A preloaded same-name package cannot replace the metadata-selected source origin."""

    descriptor = DiscoverExtensions((Metadata(tmp_path),))[0]
    foreign = ModuleType("example_plugin")
    foreign.__file__ = str(tmp_path / "foreign.py")
    sys.modules["example_plugin"] = foreign

    with pytest.raises(ExtensionError, match="shadows"):
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Shadowed load executed code"


def test_SameOriginPreloadedCodeRequiresAnExecutedSnapshotReceipt(tmp_path: Path) -> None:
    """Truthful file and spec paths alone cannot authorize stale ambient cached code."""

    directory = Metadata(tmp_path)
    descriptor = DiscoverExtensions((directory,))[0]
    source = tmp_path / "example_plugin/plugin.py"
    module = ModuleType("example_plugin.plugin")
    module.__file__ = str(source)
    module.__spec__ = importlib.util.spec_from_file_location(module.__name__, source)
    sys.modules[module.__name__] = module

    with pytest.raises(ExtensionError, match="unverified"):
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Stale ambient cache executed code"


def test_ParentImportsUseVerifiedSnapshotsInsteadOfStaleBytecode(tmp_path: Path) -> None:
    """A parent importing its target cannot bypass RECORD-pinned in-memory source execution."""

    directory = Metadata(tmp_path)
    parent = tmp_path / "example_plugin/__init__.py"
    plugin = tmp_path / "example_plugin/plugin.py"
    selected_source = plugin.read_text()
    stale_source = selected_source.replace("'executed'", "'obsolete'")

    assert len(stale_source) == len(selected_source), "Stale bytecode fixture must preserve source size"

    plugin.write_text(stale_source)
    timestamp = plugin.stat()
    py_compile.compile(str(plugin), doraise=True)
    plugin.write_text(selected_source)
    os.utime(plugin, ns=(timestamp.st_atime_ns, timestamp.st_mtime_ns))
    parent.write_text(
        '"""Synthetic parent importing a selected child before the explicit load loop."""\n'
        "from . import plugin\n"
    )
    WriteRecord(directory, (parent, plugin))
    descriptor = DiscoverExtensions((directory,))[0]
    registry = ExtensionRegistry((descriptor,))
    loaded = registry.Load(descriptor, allowed=(descriptor,))

    assert loaded.Descriptor == descriptor, "Parent-triggered loading lost its selected identity"
    assert (tmp_path / "example_plugin/executed.txt").read_text() == "executed", (
        "Parent import executed stale bytecode instead of the verified source snapshot"
    )
    assert all(type(finder).__name__ != "_SnapshotImporter" for finder in sys.meta_path), (
        "Selected snapshot importer remained installed after loading"
    )


def test_LoaderOwnedModuleReceiptsPermitExactReuseAndRejectSourceDrift(tmp_path: Path) -> None:
    """Separate registries may reuse loader-owned exact code, while changed bytes need a fresh process."""

    directory = Metadata(tmp_path)
    descriptor = DiscoverExtensions((directory,))[0]
    ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))
    reused = ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert reused.Descriptor == descriptor, "Exact loader-owned source reuse was rejected"

    plugin = tmp_path / "example_plugin/plugin.py"
    plugin.write_text(plugin.read_text() + "\nchanged = True\n")
    WriteRecord(directory, (tmp_path / "example_plugin/__init__.py", plugin))
    changed_descriptor = DiscoverExtensions((directory,))[0]

    with pytest.raises(ExtensionError, match="unverified"):
        ExtensionRegistry((changed_descriptor,)).Load(changed_descriptor, allowed=(changed_descriptor,))


@pytest.mark.parametrize("filename", ["METADATA", "entry_points.txt", "RECORD"])
def test_MetadataDriftInvalidatesLoadConsent(tmp_path: Path, filename: str) -> None:
    """Exact loading pins the full static metadata snapshot, not only a package version string."""

    directory = Metadata(tmp_path)
    descriptor = DiscoverExtensions((directory,))[0]
    file = directory / filename
    file.write_bytes(file.read_bytes() + b"\n")

    with pytest.raises(ExtensionError, match="changed"):
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Drifted metadata executed code"


@pytest.mark.parametrize("change", ["content", "parent", "missing", "duplicate", "escape", "weak-hash", "ambiguous"])
def test_SourceOwnershipAndIntegrityAreRequiredBeforeExecution(tmp_path: Path, change: str) -> None:
    """Every target and parent source must be selected, regular, and bound by exact RECORD hashes."""

    directory = Metadata(tmp_path)
    parent = tmp_path / "example_plugin/__init__.py"
    plugin = tmp_path / "example_plugin/plugin.py"

    if change == "missing":
        WriteRecord(directory, (plugin,))

    elif change == "duplicate":
        record = directory / "RECORD"
        record.write_text(record.read_text() * 2)

    elif change == "escape":
        foreign = tmp_path / "foreign.py"
        foreign.write_bytes(plugin.read_bytes())
        plugin.unlink()
        plugin.symlink_to(foreign)

    elif change == "weak-hash":
        record = directory / "RECORD"
        record.write_text(record.read_text().replace("sha256=", "md5="))

    elif change == "ambiguous":
        package = tmp_path / "example_plugin/plugin"
        package.mkdir()
        alternative = package / "__init__.py"
        alternative.write_bytes(plugin.read_bytes())
        WriteRecord(directory, (parent, plugin, alternative))

    descriptor = DiscoverExtensions((directory,))[0]

    if change in {"content", "parent"}:
        changed = plugin if change == "content" else parent
        changed.write_text(changed.read_text() + "\nraise RuntimeError('changed source')\n")

    with pytest.raises(ExtensionError):
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert not (tmp_path / "example_plugin/executed.txt").exists(), "Unverified source executed code"


@pytest.mark.parametrize("source", [
    '"""An intentionally broken opted-in fixture."""\nraise RuntimeError("untrusted failure")\n',
    '"""A noncallable fixture target."""\nPlugin = 1\n',
    '"""An intentionally wrong fixture contract."""\n'
    'class Plugin:\n    """No extension methods are implemented."""\n',
    '"""An identity-mismatched fixture contract."""\n'
    'class Plugin:\n    """Expose a malformed identity."""\n\n'
    '    Descriptor = None\n\n'
    '    def CreateProvider(self, context):\n'
    '        """Provide a fixture method for structural checks."""\n\n'
    '        return None\n',
])
def test_LoadFailuresAreSanitizedAndContractsFailClosed(tmp_path: Path, source: str) -> None:
    """Wrong factories, runtime failures, identities, and extension contracts are rejected."""

    descriptor = DiscoverExtensions((Metadata(tmp_path, source=source),))[0]

    with pytest.raises(ExtensionError) as error:
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert "untrusted failure" not in str(error.value), "External exception details leaked"
    assert "example_plugin" not in sys.modules, "Rejected factory retained its created parent module"
    assert "example_plugin.plugin" not in sys.modules, "Rejected factory retained its created target module"


def test_FailureCleanupCannotInvokePackageAttributeHooks(tmp_path: Path) -> None:
    """Cleanup uses module dictionaries and removes owned modules despite hostile attribute hooks."""

    directory = Metadata(tmp_path, source=(
        '"""An intentionally failing child fixture."""\n'
        'raise RuntimeError("ordinary-child-failure")\n'
    ))
    parent = tmp_path / "example_plugin/__init__.py"
    parent.write_text(
        '"""A parent with an attribute hook that cleanup must never invoke."""\n'
        "def __getattr__(name):\n"
        '    """Expose an intentional sensitive fixture failure."""\n\n'
        '    raise RuntimeError("synthetic-sensitive-marker")\n'
    )
    WriteRecord(directory, (parent, tmp_path / "example_plugin/plugin.py"))
    descriptor = DiscoverExtensions((directory,))[0]

    with pytest.raises(ExtensionError) as error:
        ExtensionRegistry((descriptor,)).Load(descriptor, allowed=(descriptor,))

    assert "synthetic-sensitive-marker" not in str(error.value), "Cleanup invoked an external hook"
    assert "example_plugin" not in sys.modules, "Failed loading retained its created parent module"
    assert "example_plugin.plugin" not in sys.modules, "Failed loading retained its created child module"
    assert all(type(finder).__name__ != "_SnapshotImporter" for finder in sys.meta_path), (
        "Failed loading retained its temporary selected-chain importer"
    )


@pytest.mark.parametrize("values", [
    {"kind": "provider"}, {"plugin_id": "Upper"}, {"distribution": "Upper"},
    {"version": "1.0"}, {"group": "flayer.providers.v2"}, {"target": "plugin:Factory [extra]"},
    {"metadata_sha256": "a" * 64}, {"distribution": "third-party"},
])
def test_DescriptorConstructionCannotBypassValidation(values: dict[str, object]) -> None:
    """Direct construction receives the same strict validation as metadata discovery."""

    arguments: dict[str, object] = {
        "kind": ExtensionKind.PROVIDER, "plugin_id": "example", "distribution": "f-layer",
        "version": "1.2.3", "group": PROVIDER_GROUP, "target": "flayer.example:Factory",
    }
    arguments.update(values)

    with pytest.raises(ValueError):
        ExtensionDescriptor(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize("values", [
    {"scope_id": b"credential-bytes"}, {"authentication_reference": b"credential-bytes"},
    {"command_timeout": True}, {"command_timeout": float("inf")}, {"command_timeout": 301},
    {"inventory_limit": True}, {"inventory_limit": 0}, {"inventory_limit": 100001},
])
def test_ProviderContextRejectsCredentialBytesAndUnboundedLimits(values: dict[str, object]) -> None:
    """Context stores identifiers and bounded limits rather than resolved credential payloads."""

    arguments: dict[str, object] = {"scope_id": "folder", "authentication_reference": "profile"}
    arguments.update(values)

    with pytest.raises(ValueError):
        ProviderContext(**arguments)  # type: ignore[arg-type]


def test_BuiltinProvidersKeepReadOnlyAndLifecycleCapabilitiesSeparate() -> None:
    """Built-in descriptors construct real adapters while read-only consumers need no mutations."""

    registry = ExtensionRegistry()
    context = ProviderContext("example-folder", "external-profile")
    read_only = registry.Load(registry.Get(ExtensionKind.PROVIDER, "yandex-read-only"))
    lifecycle = registry.Load(registry.Get(ExtensionKind.PROVIDER, "yandex-lifecycle"))

    assert isinstance(read_only, ProviderExtension), "Read-only extension lost its provider factory"
    assert not isinstance(read_only, LifecycleProviderExtension), "Read-only factory requires mutation"

    provider = read_only.CreateProvider(context)

    assert ProviderCapability.CREATE_RESOURCE not in provider.Capabilities, "Read-only provider mutates"
    assert not hasattr(provider, "CreateResource"), "Read-only construction selected lifecycle adapter"
    assert isinstance(lifecycle, LifecycleProviderExtension), "Lifecycle extension lost optional factory"

    mutation_provider = lifecycle.CreateLifecycleProvider(context)

    assert isinstance(mutation_provider, LifecycleProvider), "Lifecycle extension did not return real adapter"
    assert ProviderCapability.CREATE_RESOURCE in mutation_provider.Capabilities
    assert provider.Identity.scope_id == mutation_provider.Identity.scope_id == "example-folder"


def test_BuiltinGatewayCompilesExportsAndRendersRealOwnedPlan(tmp_path: Path) -> None:
    """The profile adapter provides a useful end-to-end artifact workflow on the existing core."""

    configuration = tomllib.loads((PROJECT_ROOT / "examples/secure-gateway.toml").read_text())
    registry = ExtensionRegistry()
    extension = registry.Load(registry.Get(ExtensionKind.PROFILE, "secure-gateway"))

    assert isinstance(extension, ProfileExtension), "Profile descriptor did not return a profile factory"

    compiled = extension.CompileProfile(configuration, ProfileContext(IDENTITY))

    assert isinstance(compiled, CompiledProfile), "Compiled profile lost artifact or plan methods"
    assert compiled.Identity == IDENTITY, "Compilation changed the exact ownership boundary"

    bundle = compiled.BuildServerBundle()
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    server_file = directory / bundle.files[0].name
    plan_path = tmp_path / "plan.toml"
    plan_path.write_text(compiled.RenderPlan(user_data_file=server_file))
    plan = LoadDeploymentPlan(plan_path)

    assert plan.identity == IDENTITY, "Rendered plan discarded profile ownership"
    assert len(plan.resources) == 6, "Adapter did not preserve the real gateway resource graph"

    altered = copy.deepcopy(configuration)
    identity = altered["identity"]

    assert isinstance(identity, dict), "Fixture identity must remain a TOML table"

    identity["stack"] = "other"

    with pytest.raises(ExtensionError, match="ownership"):
        extension.CompileProfile(altered, ProfileContext(IDENTITY))

    server_file.write_bytes(b"changed")

    with pytest.raises(ValueError):
        compiled.RenderPlan(user_data_file=server_file)


def test_RegistryLookupAndInvalidContextsFailBeforeOperations() -> None:
    """Unknown identities, malformed pins, and unvalidated context cannot trigger provider calls."""

    registry = ExtensionRegistry()

    with pytest.raises(ExtensionError):
        registry.Get(ExtensionKind.PROVIDER, "unknown")

    with pytest.raises(ExtensionError):
        registry.Get("provider", "yandex-read-only")  # type: ignore[arg-type]

    descriptor = registry.Get(ExtensionKind.PROVIDER, "yandex-read-only")

    with pytest.raises(ExtensionError):
        registry.Load(replace(descriptor, version="99.0.0"))

    with pytest.raises(ExtensionError):
        registry.Load(descriptor, allowed=(descriptor, descriptor))

    with pytest.raises(ExtensionError):
        ProfileContext(None)  # type: ignore[arg-type]

    provider_extension = registry.Load(descriptor)

    assert isinstance(provider_extension, ProviderExtension)

    with pytest.raises(ExtensionError):
        provider_extension.CreateProvider(None)  # type: ignore[arg-type]

    lifecycle_extension = registry.Load(registry.Get(ExtensionKind.PROVIDER, "yandex-lifecycle"))

    assert isinstance(lifecycle_extension, LifecycleProviderExtension)

    with pytest.raises(ExtensionError):
        lifecycle_extension.CreateLifecycleProvider(None)  # type: ignore[arg-type]

    profile_extension = registry.Load(registry.Get(ExtensionKind.PROFILE, "secure-gateway"))

    assert isinstance(profile_extension, ProfileExtension)

    with pytest.raises(ExtensionError):
        profile_extension.CompileProfile({}, None)  # type: ignore[arg-type]
