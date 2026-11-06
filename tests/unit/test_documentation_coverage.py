"""Prove repository coverage, installed parity, and generated reachability fail closed."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools import build_api_reference as buildApiReference
from tools import documentation_coverage as documentationCoverage
from tools import documentation_gates as documentationGates

PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODULE_SOURCE = '"""Fixture package contract."""\n'


@pytest.fixture(name='coverageProject')
def CoverageProjectFixture(tmp_path: Path) -> Path:
    """Create a Git-tracked project with the actual explicit coverage rules."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "docs/site").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / documentationCoverage.MANIFEST_PATH,
                    tmp_path / documentationCoverage.MANIFEST_PATH)
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    return tmp_path


def Track(projectRoot: Path, sourcePath: str, content: str) -> Path:
    """Add one deterministic fixture file to the accountable Git index."""

    path = projectRoot / sourcePath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", sourcePath], cwd=projectRoot, check=True)

    return path


def PackageFixture(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """Construct matching source and installed roots without executing package code."""

    projectRoot = tmpPath / "repository"
    installedRoot = tmpPath / "installed"
    (projectRoot / "src/flayer").mkdir(parents=True)
    (installedRoot / "flayer").mkdir(parents=True)
    (projectRoot / "src/flayer/__init__.py").write_text(MODULE_SOURCE)
    (installedRoot / "flayer/__init__.py").write_text(MODULE_SOURCE)
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", projectRoot)

    return projectRoot, installedRoot


def test_NewPublicModuleAndCliAreAutomaticallyDiscovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Include future modules and the established underscored CLI entry point."""

    projectRoot, installedRoot = PackageFixture(tmp_path, monkeypatch)
    source = MODULE_SOURCE + '\ndef Main() -> int:\n    """Return without mutation."""\n\n    return 0\n'

    for name in ("__main__.py", "future.py", "_internal.py"):
        (projectRoot / "src/flayer" / name).write_text(source)
        (installedRoot / "flayer" / name).write_text(source)

    modules = buildApiReference.DiscoverModules(installedRoot)

    assert [item.name for item in modules] == ["flayer", "flayer.__main__", "flayer.future"]
    assert modules[1].symbols == ("flayer.__main__.Main",)

    definitions = buildApiReference.DiscoverDefinitions(installedRoot)

    assert any(item.symbol == "flayer._internal.Main" and item.disposition == "source-only"
               for item in definitions), "Private definitions must have accountable omissions"


@pytest.mark.parametrize("name", ["_private.py", "__main__.py", "future.py", "py.typed", "data.json"])
def test_SourceOnlyWheelOmissionsFailForEveryPackageFile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str,
) -> None:
    """No private, executable, typing, or resource file may disappear during packaging."""

    projectRoot, installedRoot = PackageFixture(tmp_path, monkeypatch)
    (projectRoot / "src/flayer" / name).write_text(MODULE_SOURCE)

    with pytest.raises(ValueError, match="package inventory differs"):
        buildApiReference.DiscoverModules(installedRoot)


@pytest.mark.parametrize("change", ["extra", "bytes"])
def test_PrivateInstalledExtraAndDriftFail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Private installed files receive the same parity checks as public modules."""

    projectRoot, installedRoot = PackageFixture(tmp_path, monkeypatch)
    (installedRoot / "flayer/_private.py").write_text(MODULE_SOURCE)

    if change == "bytes":
        (projectRoot / "src/flayer/_private.py").write_text(MODULE_SOURCE + "# Source drift\n")

    with pytest.raises(ValueError, match="inventory differs|differs from current source"):
        buildApiReference.DiscoverModules(installedRoot)


def test_DefinitionInventoryDistinguishesCallableAndPrivateImplementation() -> None:
    """Document callable protocol surfaces without exposing helpers and constructors."""

    syntax = ast.parse(
        MODULE_SOURCE + 'class Probe:\n    """A callable contract."""\n'
        '    def __call__(self) -> bool:\n        """Inspect safely."""\n\n        return True\n'
        '    def __init__(self) -> None:\n        """Initialize safely."""\n\n        pass\n'
        '    def _Internal(self) -> None:\n        """Private behavior."""\n\n        pass\n'
    )
    definitions = documentationCoverage.InventoryDefinitions("src/flayer/future.py", syntax)
    dispositions = {item.symbol: item.disposition for item in definitions}

    assert dispositions["flayer.future.Probe.__call__"] == "generated-api"
    assert dispositions["flayer.future.Probe.__init__"] == "source-only"
    assert dispositions["flayer.future.Probe._Internal"] == "source-only"


def test_UnclassifiedFileFailsClosed(coverageProject: Path) -> None:
    """A new unsupported file type requires a reviewable coverage rule."""

    Track(coverageProject, "unknown.bin", "Fixture")

    with pytest.raises(ValueError, match="exactly one coverage rule: unknown.bin"):
        documentationCoverage.InventoryFiles(coverageProject)


def test_OverlappingOrEmptyRationaleRulesFailClosed(coverageProject: Path) -> None:
    """Ambiguous category or empty rationale cannot silently relax accountability."""

    manifest = coverageProject / documentationCoverage.MANIFEST_PATH
    original = manifest.read_text()
    manifest.write_text(original + '\n[[rules]]\npatterns = ["README.md"]\n'
                        'category = "markdown"\nreason = "Duplicate"\n')

    with pytest.raises(ValueError, match="exactly one coverage rule: README.md"):
        documentationCoverage.InventoryFiles(coverageProject)

    manifest.write_text(original.replace('reason = "Canonical repository Markdown is copied into navigable documentation."',
                                        'reason = ""'))

    with pytest.raises(ValueError, match="rationale"):
        documentationCoverage.InventoryFiles(coverageProject)


def test_FutureKnownCategoriesNeedNoHardcodedFileCounts(coverageProject: Path) -> None:
    """Future API, tools, tests, guides, and examples classify through explicit rules."""

    names = ["src/flayer/extensions/contract.py", "src/flayer/_private.py", "tools/future.py",
             "tests/contract/test_future.py", "docs/adr/0999-future.md", "examples/future.toml"]

    for name in names:
        Track(coverageProject, name, MODULE_SOURCE if name.endswith(".py") else "Fixture")

    inventory = {item.sourcePath: item for item in documentationCoverage.InventoryFiles(coverageProject)}

    assert inventory[names[0]].disposition == "generated-api"
    assert inventory[names[1]].disposition == "source-only"
    assert inventory[names[4]].disposition == "rendered-markdown"
    assert all(inventory[name].reason for name in names), "Every new file must retain its rationale"


def test_AllMarkdownIncludesPoliciesTemplatesAndEntryPoints(
    coverageProject: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generated repository routes cover Markdown outside selected docs folders."""

    names = ["AGENTS.md", "DEVELOPMENT_PROTOCOL.md", "CONTRIBUTING.md", "SECURITY.md",
             "docs/README.md", "docs/site/README.md", "docs/adr/0000-template.md",
             ".github/pull_request_template.md"]

    for name in names:
        Track(coverageProject, name, "# Fixture\n")

    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", coverageProject)
    contentRoot = coverageProject / "_build/content/en"
    contentRoot.mkdir(parents=True)
    navigation = buildApiReference.WriteEngineeringContent(contentRoot)
    routes = {route for item in navigation for route in item.values()}

    assert all(documentationCoverage.MarkdownPage(name) in routes for name in names)
    assert all((contentRoot / documentationCoverage.MarkdownPage(name)).is_file() for name in names)


def test_CopiedMarkdownRoutesAndNonpageSourceReferences(
    coverageProject: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve fragments and resolve repository links without copying config as pages."""

    Track(coverageProject, "docs/adr/README.md", "# Decisions\n")
    Track(coverageProject, "pyproject.toml", "# Configuration\n")
    sourcePath = coverageProject / "README.md"
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", coverageProject)
    generated = buildApiReference.RewriteRepositoryLinks(
        "[Decisions](docs/adr/#decisions) [Config](pyproject.toml)", sourcePath, "repository/README.md",
    )

    assert "(docs/adr/README.md#decisions)" in generated
    assert "blob/develop/pyproject.toml)" in generated


@pytest.mark.parametrize("locale", ["ru", "zh-CN"])
def test_LocaleOverlayLinksRemainSourceReferences(
    coverageProject: Path, monkeypatch: pytest.MonkeyPatch, locale: str,
) -> None:
    """Review links must not invent canonical routes for separately rendered locale drafts."""

    sourcePath = Track(coverageProject, "docs/i18n/review-snapshot.md", "# Review\n")
    Track(coverageProject, "docs/site/content/en/guide/index.md", "# Guide\n")
    localePath = f"docs/site/content/{locale}/guide/index.md"
    Track(coverageProject, localePath, "# Guide\n")
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", coverageProject)
    generated = buildApiReference.RewriteRepositoryLinks(
        f"[English](../site/content/en/guide/index.md#guide) "
        f"[Draft](../site/content/{locale}/guide/index.md#guide)",
        sourcePath, "repository/docs/i18n/review-snapshot.md",
    )

    assert "(../../../guide/index.md#guide)" in generated
    assert f"({documentationCoverage.SOURCE_URL}{localePath}#guide)" in generated, (
        "Locale overlays are source references in canonical repository pages, not missing local pages"
    )


def test_ExistingButOrphanedMarkdownFailsReachability(coverageProject: Path) -> None:
    """An artifact's existence alone cannot establish navigable documentation."""

    siteRoot = coverageProject / "_build/site"
    Track(coverageProject, "docs/adr/0000-template.md", "# Template\n")
    inventory = documentationCoverage.InventoryFiles(coverageProject)

    for item in inventory:
        if item.pagePath is not None:
            artifact = documentationGates.HtmlPage(item.pagePath, siteRoot)
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("<h1>Fixture</h1>")

    (siteRoot / "en/coverage").mkdir(parents=True)
    (siteRoot / "en/coverage/index.html").write_text("<h1>Coverage</h1>")
    (siteRoot / "en/index.html").write_text('<a href="repository/">Readme</a>'
                                            '<a href="coverage/">Coverage</a>')
    diagnostics = documentationGates.CheckMarkdownReachability(coverageProject, siteRoot)

    assert diagnostics == ("Unreachable classified documentation page: docs/adr/0000-template.md",)


def test_InventoryWritesEveryTrackedDisposition(coverageProject: Path) -> None:
    """Generated JSON and human-readable inventory have the same accountable files."""

    Track(coverageProject, "tests/unit/test_future.py", MODULE_SOURCE)
    buildRoot = coverageProject / "_build"
    buildRoot.mkdir()
    documentationCoverage.WriteInventory(coverageProject, buildRoot, ())
    payload = json.loads((buildRoot / "repository-coverage.json").read_text())
    classified = {item["source_path"]: item for item in payload["files"]}

    assert set(classified) == set(documentationCoverage.TrackedFiles(coverageProject))
    assert classified["tests/unit/test_future.py"]["disposition"] == "source-only"
    assert (buildRoot / "content/en/coverage/index.md").is_file()


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
    definitions = documentationCoverage.InventoryDefinitions("src/flayer/future.py", syntax)
    dispositions = {item.symbol: item.disposition for item in definitions}

    assert dispositions == {
        "flayer.future.Conditional": "generated-api",
        "flayer.future.Protocol": "generated-api",
        "flayer.future.Protocol.Inspect": "generated-api",
        "flayer.future._Fallback": "source-only",
    }, "Control-flow definitions must retain their actual static parent scope"


def test_LocaleOverlaysAndWireExamplesHaveAccountableCategories(coverageProject: Path) -> None:
    """Draft localization and JSON wire fixtures cannot disappear from file evidence."""

    names = ["docs/site/content/ru/index.md", "docs/site/content/ru/assets/theme.css",
             "examples/agent-request.json"]

    for name in names:
        Track(coverageProject, name, "Fixture")

    inventory = {item.sourcePath: item for item in documentationCoverage.InventoryFiles(coverageProject)}

    assert inventory[names[0]].disposition == "locale-overlay"
    assert inventory[names[0]].pagePath == "ru/index.md"
    assert "approval is never inferred" in inventory[names[0]].reason
    assert inventory[names[1]].category == "asset"
    assert inventory[names[2]].category == "examples"


def test_ReservedAndDuplicateRoutesFailClosed(coverageProject: Path) -> None:
    """Authored pages cannot overwrite the generated coverage inventory."""

    Track(coverageProject, "docs/site/content/en/coverage/index.md", "# Conflict\n")

    with pytest.raises(ValueError, match="Duplicate or reserved documentation route"):
        documentationCoverage.InventoryFiles(coverageProject)


def test_ReadmeAndIndexArtifactCollisionFailsClosed(coverageProject: Path) -> None:
    """Different Markdown names cannot overwrite the same MkDocs index artifact."""

    Track(coverageProject, "docs/new/README.md", "# First\n")
    Track(coverageProject, "docs/new/index.md", "# Second\n")

    with pytest.raises(ValueError, match="Duplicate or reserved documentation route"):
        documentationCoverage.InventoryFiles(coverageProject)


def test_UntrackedPackageAndCanonicalInputsCannotEnterArtifacts(coverageProject: Path) -> None:
    """Git provenance must include files copied into the wheel and generated site."""

    Track(coverageProject, "src/flayer/__init__.py", MODULE_SOURCE)
    packageFile = coverageProject / "src/flayer/untracked.py"
    packageFile.write_text(MODULE_SOURCE)
    siteFile = coverageProject / "docs/site/content/en/untracked.md"
    siteFile.parent.mkdir(parents=True)
    siteFile.write_text("# Untracked\n")
    cacheFile = coverageProject / "src/flayer/__pycache__/ignored.pyc"
    cacheFile.parent.mkdir()
    cacheFile.write_bytes(b"Fixture")
    diagnostics = documentationCoverage.CheckBuildInputs(coverageProject)

    assert diagnostics == (
        "Untracked documentation build input: src/flayer/untracked.py",
        "Untracked documentation build input: docs/site/content/en/untracked.md",
    ), "Untracked copied inputs must fail while bytecode remains disposable"


def test_FreshAssemblyDiscardsRestoredLocaleSiblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Previously restored fallback pages cannot contaminate newly verified publication."""

    buildRoot = tmp_path / "owned-build"
    (buildRoot / "rendered-en").mkdir(parents=True)
    (buildRoot / "rendered-en/index.html").write_text("Fresh English")
    (buildRoot / "site/ru").mkdir(parents=True)
    (buildRoot / "site/ru/index.html").write_text("Stale translation")
    monkeypatch.setattr(buildApiReference, "BUILD_ROOT", buildRoot)
    siteRoot = buildApiReference.AssembleSite(buildRoot)

    assert (siteRoot / "en/index.html").read_text() == "Fresh English"
    assert not (siteRoot / "ru").exists(), "Restored siblings must be discarded before fallback generation"


def test_FreshAssemblyRejectsUnownedOrAbsentOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Assembly cannot erase another directory or manufacture a strict build result."""

    monkeypatch.setattr(buildApiReference, "BUILD_ROOT", tmp_path / "owned")

    with pytest.raises(ValueError, match="unowned or redirected"):
        buildApiReference.AssembleSite(tmp_path)

    (tmp_path / "owned").mkdir()

    with pytest.raises(ValueError, match="absent or.*redirected"):
        buildApiReference.AssembleSite(tmp_path / "owned")


def test_WheelInstallUsesOwnedTargetWithoutMutatingTools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selected tooling environments cannot receive project code or ambient package state."""

    buildRoot = tmp_path / "owned-build"
    buildRoot.mkdir()
    calls: list[tuple[str, ...]] = []

    def RecordCommand(command: object, **options: object) -> str:
        """Capture bounded install and metadata commands without performing installation."""

        assert isinstance(command, list)

        calls.append(tuple(str(part) for part in command))

        return ""

    monkeypatch.setattr(buildApiReference, "BUILD_ROOT", buildRoot)
    monkeypatch.setattr(buildApiReference, "RunCommand", RecordCommand)
    installedRoot = buildApiReference.InstallWheel(
        tmp_path / "tools/bin/python", tmp_path / "f_layer.whl", buildRoot,
    )
    install = calls[0]

    assert installedRoot == buildRoot / "installed"
    assert "--no-index" in install and "--no-deps" in install
    assert install[install.index("--target") + 1] == str(installedRoot)
    assert "--force-reinstall" not in install, "The tooling environment must remain unchanged"
    assert "distributions(path=" in calls[1][-1], "Metadata verification must use only the installed target"


def test_WheelInstallRejectsRestoredOrUnownedTarget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previously restored target must fail before pip can overlay unaccounted files."""

    buildRoot = tmp_path / "owned-build"
    installedRoot = buildRoot / "installed"
    installedRoot.mkdir(parents=True)
    sentinel = installedRoot / "stale.txt"
    sentinel.write_text("Keep evidence")
    monkeypatch.setattr(buildApiReference, "BUILD_ROOT", buildRoot)

    with pytest.raises(ValueError, match="target already exists"):
        buildApiReference.InstallWheel(tmp_path / "python", tmp_path / "fixture.whl", buildRoot)

    with pytest.raises(ValueError, match="unowned or redirected"):
        buildApiReference.InstallWheel(tmp_path / "python", tmp_path / "fixture.whl", tmp_path)

    assert sentinel.read_text() == "Keep evidence", "Refusal must preserve restored output for diagnosis"
