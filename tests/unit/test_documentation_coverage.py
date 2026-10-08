"""Prove repository coverage, installed parity, and generated reachability fail closed."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import build_api_reference, documentation_coverage, documentation_gates

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_SOURCE = '"""Fixture package contract."""\n'


@pytest.fixture
def coverage_project(tmp_path: Path) -> Path:
    """Create a Git-tracked project with the actual explicit coverage rules."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "docs/site").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / documentation_coverage.MANIFEST_PATH,
                    tmp_path / documentation_coverage.MANIFEST_PATH)
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    return tmp_path


def Track(project_root: Path, source_path: str, content: str) -> Path:
    """Add one deterministic fixture file to the accountable Git index."""

    path = project_root / source_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", source_path], cwd=project_root, check=True)

    return path


def PackageFixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Construct matching source and installed roots without executing package code."""

    project_root = tmp_path / "repository"
    installed_root = tmp_path / "installed"
    (project_root / "src/flayer").mkdir(parents=True)
    (installed_root / "flayer").mkdir(parents=True)
    (project_root / "src/flayer/__init__.py").write_text(MODULE_SOURCE)
    (installed_root / "flayer/__init__.py").write_text(MODULE_SOURCE)
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", project_root)

    return project_root, installed_root


def test_NewPublicModuleAndCliAreAutomaticallyDiscovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Include future modules and the established underscored CLI entry point."""

    project_root, installed_root = PackageFixture(tmp_path, monkeypatch)
    source = MODULE_SOURCE + '\ndef Main() -> int:\n    """Return without mutation."""\n\n    return 0\n'

    for name in ("__main__.py", "future.py", "_internal.py"):
        (project_root / "src/flayer" / name).write_text(source)
        (installed_root / "flayer" / name).write_text(source)

    modules = build_api_reference.DiscoverModules(installed_root)

    assert [item.name for item in modules] == ["flayer", "flayer.__main__", "flayer.future"]
    assert modules[1].symbols == ("flayer.__main__.Main",)
    definitions = build_api_reference.DiscoverDefinitions(installed_root)
    assert any(item.symbol == "flayer._internal.Main" and item.disposition == "source-only"
               for item in definitions), "Private definitions must have accountable omissions"


@pytest.mark.parametrize("name", ["_private.py", "__main__.py", "future.py", "py.typed", "data.json"])
def test_SourceOnlyWheelOmissionsFailForEveryPackageFile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    """No private, executable, typing, or resource file may disappear during packaging."""

    project_root, installed_root = PackageFixture(tmp_path, monkeypatch)
    (project_root / "src/flayer" / name).write_text(MODULE_SOURCE)

    with pytest.raises(ValueError, match="package inventory differs"):
        build_api_reference.DiscoverModules(installed_root)


@pytest.mark.parametrize("change", ["extra", "bytes"])
def test_PrivateInstalledExtraAndDriftFail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Private installed files receive the same parity checks as public modules."""

    project_root, installed_root = PackageFixture(tmp_path, monkeypatch)
    (installed_root / "flayer/_private.py").write_text(MODULE_SOURCE)

    if change == "bytes":
        (project_root / "src/flayer/_private.py").write_text(MODULE_SOURCE + "# Source drift\n")

    with pytest.raises(ValueError, match="inventory differs|differs from current source"):
        build_api_reference.DiscoverModules(installed_root)


def test_DefinitionInventoryDistinguishesCallableAndPrivateImplementation() -> None:
    """Document callable protocol surfaces without exposing helpers and constructors."""

    syntax = ast.parse(
        MODULE_SOURCE + 'class Probe:\n    """A callable contract."""\n'
        '    def __call__(self) -> bool:\n        """Inspect safely."""\n\n        return True\n'
        '    def __init__(self) -> None:\n        """Initialize safely."""\n\n        pass\n'
        '    def _Internal(self) -> None:\n        """Private behavior."""\n\n        pass\n'
    )
    definitions = documentation_coverage.InventoryDefinitions("src/flayer/future.py", syntax)
    dispositions = {item.symbol: item.disposition for item in definitions}

    assert dispositions["flayer.future.Probe.__call__"] == "generated-api"
    assert dispositions["flayer.future.Probe.__init__"] == "source-only"
    assert dispositions["flayer.future.Probe._Internal"] == "source-only"


def test_UnclassifiedFileFailsClosed(coverage_project: Path) -> None:
    """A new unsupported file type requires a reviewable coverage rule."""

    Track(coverage_project, "unknown.bin", "Fixture")

    with pytest.raises(ValueError, match="exactly one coverage rule: unknown.bin"):
        documentation_coverage.InventoryFiles(coverage_project)


def test_OverlappingOrEmptyRationaleRulesFailClosed(coverage_project: Path) -> None:
    """Ambiguous category or empty rationale cannot silently relax accountability."""

    manifest = coverage_project / documentation_coverage.MANIFEST_PATH
    original = manifest.read_text()
    manifest.write_text(original + '\n[[rules]]\npatterns = ["README.md"]\n'
                        'category = "markdown"\nreason = "Duplicate"\n')

    with pytest.raises(ValueError, match="exactly one coverage rule: README.md"):
        documentation_coverage.InventoryFiles(coverage_project)

    manifest.write_text(original.replace('reason = "Canonical repository Markdown is copied into navigable documentation."',
                                        'reason = ""'))

    with pytest.raises(ValueError, match="rationale"):
        documentation_coverage.InventoryFiles(coverage_project)


def test_FutureKnownCategoriesNeedNoHardcodedFileCounts(coverage_project: Path) -> None:
    """Future API, tools, tests, guides, and examples classify through explicit rules."""

    names = ["src/flayer/extensions/contract.py", "src/flayer/_private.py", "tools/future.py",
             "tests/contract/test_future.py", "docs/adr/0999-future.md", "examples/future.toml"]

    for name in names:
        Track(coverage_project, name, MODULE_SOURCE if name.endswith(".py") else "Fixture")

    inventory = {item.source_path: item for item in documentation_coverage.InventoryFiles(coverage_project)}

    assert inventory[names[0]].disposition == "generated-api"
    assert inventory[names[1]].disposition == "source-only"
    assert inventory[names[4]].disposition == "rendered-markdown"
    assert all(inventory[name].reason for name in names), "Every new file must retain its rationale"


def test_AllMarkdownIncludesPoliciesTemplatesAndEntryPoints(
    coverage_project: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generated repository routes cover Markdown outside selected docs folders."""

    names = ["AGENTS.md", "DEVELOPMENT_PROTOCOL.md", "CONTRIBUTING.md", "SECURITY.md",
             "docs/README.md", "docs/site/README.md", "docs/adr/0000-template.md",
             ".github/pull_request_template.md"]

    for name in names:
        Track(coverage_project, name, "# Fixture\n")

    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", coverage_project)
    content_root = coverage_project / "_build/content/en"
    content_root.mkdir(parents=True)
    navigation = build_api_reference.WriteEngineeringContent(content_root)
    routes = {route for item in navigation for route in item.values()}

    assert all(documentation_coverage.MarkdownPage(name) in routes for name in names)
    assert all((content_root / documentation_coverage.MarkdownPage(name)).is_file() for name in names)


def test_CopiedMarkdownRoutesAndNonpageSourceReferences(
    coverage_project: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve fragments and resolve repository links without copying config as pages."""

    Track(coverage_project, "docs/adr/README.md", "# Decisions\n")
    Track(coverage_project, "pyproject.toml", "# Configuration\n")
    source_path = coverage_project / "README.md"
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", coverage_project)
    generated = build_api_reference.RewriteRepositoryLinks(
        "[Decisions](docs/adr/#decisions) [Config](pyproject.toml)", source_path, "repository/README.md",
    )

    assert "(docs/adr/README.md#decisions)" in generated
    assert "blob/develop/pyproject.toml)" in generated


@pytest.mark.parametrize("locale", ["ru", "zh-CN"])
def test_LocaleOverlayLinksRemainSourceReferences(
    coverage_project: Path, monkeypatch: pytest.MonkeyPatch, locale: str,
) -> None:
    """Review links must not invent canonical routes for separately rendered locale drafts."""

    source_path = Track(coverage_project, "docs/i18n/review-snapshot.md", "# Review\n")
    Track(coverage_project, "docs/site/content/en/guide/index.md", "# Guide\n")
    locale_path = f"docs/site/content/{locale}/guide/index.md"
    Track(coverage_project, locale_path, "# Guide\n")
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", coverage_project)
    generated = build_api_reference.RewriteRepositoryLinks(
        f"[English](../site/content/en/guide/index.md#guide) "
        f"[Draft](../site/content/{locale}/guide/index.md#guide)",
        source_path, "repository/docs/i18n/review-snapshot.md",
    )

    assert "(../../../guide/index.md#guide)" in generated
    assert f"({documentation_coverage.SOURCE_URL}{locale_path}#guide)" in generated, (
        "Locale overlays are source references in canonical repository pages, not missing local pages"
    )


def test_ExistingButOrphanedMarkdownFailsReachability(coverage_project: Path) -> None:
    """An artifact's existence alone cannot establish navigable documentation."""

    site_root = coverage_project / "_build/site"
    Track(coverage_project, "docs/adr/0000-template.md", "# Template\n")
    inventory = documentation_coverage.InventoryFiles(coverage_project)

    for item in inventory:
        if item.page_path is not None:
            artifact = documentation_gates.HtmlPage(item.page_path, site_root)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("<h1>Fixture</h1>")

    (site_root / "en/coverage").mkdir(parents=True)
    (site_root / "en/coverage/index.html").write_text("<h1>Coverage</h1>")
    (site_root / "en/index.html").write_text('<a href="repository/">Readme</a>'
                                            '<a href="coverage/">Coverage</a>')
    diagnostics = documentation_gates.CheckMarkdownReachability(coverage_project, site_root)

    assert diagnostics == ("Unreachable classified documentation page: docs/adr/0000-template.md",)


def test_InventoryWritesEveryTrackedDisposition(coverage_project: Path) -> None:
    """Generated JSON and human-readable inventory have the same accountable files."""

    Track(coverage_project, "tests/unit/test_future.py", MODULE_SOURCE)
    build_root = coverage_project / "_build"
    build_root.mkdir()
    documentation_coverage.WriteInventory(coverage_project, build_root, ())
    payload = json.loads((build_root / "repository-coverage.json").read_text())
    classified = {item["source_path"]: item for item in payload["files"]}

    assert set(classified) == set(documentation_coverage.TrackedFiles(coverage_project))
    assert classified["tests/unit/test_future.py"]["disposition"] == "source-only"
    assert (build_root / "content/en/coverage/index.md").is_file()


def test_ConditionalDefinitionsAreInventoriedWithoutChangingScope() -> None:
    """Module/class conditionals and exception handlers cannot hide defined symbols."""

    syntax = ast.parse(
        MODULE_SOURCE + 'if TYPE_CHECKING:\n'
        '    def Conditional() -> None:\n        """A conditional surface."""\n\n        pass\n'
        'try:\n'
        '    class Protocol:\n        """A conditional protocol."""\n'
        '        if True:\n'
        '            def Inspect(self) -> None:\n                """Inspect safely."""\n\n                pass\n'
        'except ImportError:\n'
        '    def _Fallback() -> None:\n        """A private fallback."""\n\n        pass\n'
    )
    definitions = documentation_coverage.InventoryDefinitions("src/flayer/future.py", syntax)
    dispositions = {item.symbol: item.disposition for item in definitions}

    assert dispositions == {
        "flayer.future.Conditional": "generated-api",
        "flayer.future.Protocol": "generated-api",
        "flayer.future.Protocol.Inspect": "generated-api",
        "flayer.future._Fallback": "source-only",
    }, "Control-flow definitions must retain their actual static parent scope"


def test_LocaleOverlaysAndWireExamplesHaveAccountableCategories(coverage_project: Path) -> None:
    """Draft localization and JSON wire fixtures cannot disappear from file evidence."""

    names = ["docs/site/content/ru/index.md", "docs/site/content/ru/assets/theme.css",
             "examples/agent-request.json"]

    for name in names:
        Track(coverage_project, name, "Fixture")

    inventory = {item.source_path: item for item in documentation_coverage.InventoryFiles(coverage_project)}

    assert inventory[names[0]].disposition == "locale-overlay"
    assert inventory[names[0]].page_path == "ru/index.md"
    assert "approval is never inferred" in inventory[names[0]].reason
    assert inventory[names[1]].category == "asset"
    assert inventory[names[2]].category == "examples"


def test_ReservedAndDuplicateRoutesFailClosed(coverage_project: Path) -> None:
    """Authored pages cannot overwrite the generated coverage inventory."""

    Track(coverage_project, "docs/site/content/en/coverage/index.md", "# Conflict\n")

    with pytest.raises(ValueError, match="Duplicate or reserved documentation route"):
        documentation_coverage.InventoryFiles(coverage_project)


def test_ReadmeAndIndexArtifactCollisionFailsClosed(coverage_project: Path) -> None:
    """Different Markdown names cannot overwrite the same MkDocs index artifact."""

    Track(coverage_project, "docs/new/README.md", "# First\n")
    Track(coverage_project, "docs/new/index.md", "# Second\n")

    with pytest.raises(ValueError, match="Duplicate or reserved documentation route"):
        documentation_coverage.InventoryFiles(coverage_project)


def test_UntrackedPackageAndCanonicalInputsCannotEnterArtifacts(coverage_project: Path) -> None:
    """Git provenance must include files copied into the wheel and generated site."""

    Track(coverage_project, "src/flayer/__init__.py", MODULE_SOURCE)
    package_file = coverage_project / "src/flayer/untracked.py"
    package_file.write_text(MODULE_SOURCE)
    site_file = coverage_project / "docs/site/content/en/untracked.md"
    site_file.parent.mkdir(parents=True)
    site_file.write_text("# Untracked\n")
    cache_file = coverage_project / "src/flayer/__pycache__/ignored.pyc"
    cache_file.parent.mkdir()
    cache_file.write_bytes(b"Fixture")
    diagnostics = documentation_coverage.CheckBuildInputs(coverage_project)

    assert diagnostics == (
        "Untracked documentation build input: src/flayer/untracked.py",
        "Untracked documentation build input: docs/site/content/en/untracked.md",
    ), "Untracked copied inputs must fail while bytecode remains disposable"


def test_FreshAssemblyDiscardsRestoredLocaleSiblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Previously restored fallback pages cannot contaminate newly verified publication."""

    build_root = tmp_path / "owned-build"
    (build_root / "rendered-en").mkdir(parents=True)
    (build_root / "rendered-en/index.html").write_text("Fresh English")
    (build_root / "site/ru").mkdir(parents=True)
    (build_root / "site/ru/index.html").write_text("Stale translation")
    monkeypatch.setattr(build_api_reference, "BUILD_ROOT", build_root)
    site_root = build_api_reference.AssembleSite(build_root)

    assert (site_root / "en/index.html").read_text() == "Fresh English"
    assert not (site_root / "ru").exists(), "Restored siblings must be discarded before fallback generation"


def test_FreshAssemblyRejectsUnownedOrAbsentOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assembly cannot erase another directory or manufacture a strict build result."""

    monkeypatch.setattr(build_api_reference, "BUILD_ROOT", tmp_path / "owned")

    with pytest.raises(ValueError, match="unowned or redirected"):
        build_api_reference.AssembleSite(tmp_path)

    (tmp_path / "owned").mkdir()

    with pytest.raises(ValueError, match="absent or.*redirected"):
        build_api_reference.AssembleSite(tmp_path / "owned")


def test_WheelInstallUsesOwnedTargetWithoutMutatingTools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selected tooling environments cannot receive project code or ambient package state."""

    build_root = tmp_path / "owned-build"
    build_root.mkdir()
    calls: list[tuple[str, ...]] = []

    def RecordCommand(command: object, **options: object) -> str:
        """Capture bounded install and metadata commands without performing installation."""

        assert isinstance(command, list)
        calls.append(tuple(str(part) for part in command))

        return ""

    monkeypatch.setattr(build_api_reference, "BUILD_ROOT", build_root)
    monkeypatch.setattr(build_api_reference, "RunCommand", RecordCommand)
    installed_root = build_api_reference.InstallWheel(
        tmp_path / "tools/bin/python", tmp_path / "f_layer.whl", build_root,
    )
    install = calls[0]

    assert installed_root == build_root / "installed"
    assert "--no-index" in install and "--no-deps" in install
    assert install[install.index("--target") + 1] == str(installed_root)
    assert "--force-reinstall" not in install, "The tooling environment must remain unchanged"
    assert "distributions(path=" in calls[1][-1], "Metadata verification must use only the installed target"


def test_WheelInstallRejectsRestoredOrUnownedTarget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previously restored target must fail before pip can overlay unaccounted files."""

    build_root = tmp_path / "owned-build"
    installed_root = build_root / "installed"
    installed_root.mkdir(parents=True)
    sentinel = installed_root / "stale.txt"
    sentinel.write_text("Keep evidence")
    monkeypatch.setattr(build_api_reference, "BUILD_ROOT", build_root)

    with pytest.raises(ValueError, match="target already exists"):
        build_api_reference.InstallWheel(tmp_path / "python", tmp_path / "fixture.whl", build_root)

    with pytest.raises(ValueError, match="unowned or redirected"):
        build_api_reference.InstallWheel(tmp_path / "python", tmp_path / "fixture.whl", tmp_path)

    assert sentinel.read_text() == "Keep evidence", "Refusal must preserve restored output for diagnosis"
