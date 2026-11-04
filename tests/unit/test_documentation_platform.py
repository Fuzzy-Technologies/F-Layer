"""Exercise static documentation discovery and publication failure contracts."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as elementTree
from pathlib import Path

import pytest

from tools import build_api_reference as buildApiReference
from tools import documentation_gates as documentationGates
from tools.locale_documentation import CanonicalHash, CanonicalUnit, ValidateLocales

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("locale", ["en", "ru", "zh-CN"])
def test_OverviewCardsRenderMarkdownInsideHtml(locale: str) -> None:
    """Render the real landing cards so missing HTML Markdown support cannot regress."""

    markdown = pytest.importorskip("markdown")
    yaml = pytest.importorskip("yaml")
    config = yaml.load((PROJECT_ROOT / "docs/site/mkdocs.yml").read_text(), Loader=yaml.BaseLoader)
    extensions = [entry for entry in config["markdown_extensions"] if isinstance(entry, str)]
    source = (PROJECT_ROOT / f"docs/site/content/{locale}/index.md").read_text(encoding="utf-8")
    rendered = elementTree.fromstring("<main>" + markdown.markdown(source, extensions=extensions) + "</main>")
    cards = rendered.find(".//div[@class='grid cards']/ul")

    assert cards is not None, "Landing cards must render as a list, not raw Markdown text"
    assert len(cards.findall("li")) == 4, "Every getting-started scenario must remain a distinct card"

    for card in cards:
        assert card.find(".//strong") is not None, "Card titles must render with emphasis"
        assert card.find(".//a[@href]") is not None, "Card links must become usable navigation"


@pytest.fixture(name='localeProject')
def LocaleProjectFixture(tmp_path: Path) -> Path:
    """Copy only the local source necessary for blueprint locale validation."""

    shutil.copytree(PROJECT_ROOT / "docs", tmp_path / "docs")
    (tmp_path / "src/flayer").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / "src/flayer/__init__.py", tmp_path / "src/flayer/__init__.py")

    return tmp_path


def test_CanonicalHashPreservesBlueprintVector() -> None:
    """Protect the upstream hash payload from naming-only port drift."""

    unit = CanonicalUnit(
        identifier="symbol:sampleproject.Greet", kind="symbol",
        sourcePath="sampleproject.py", signature="def Greet(name: str) -> str",
        body="Return a greeting without side effects.",
    )

    assert CanonicalHash(unit) == (
        "sha256:6adc80348e45ec52d8824eef057947727452d80bf0204e6e1953f290ca377a79"
    ), "House-style port must preserve the corporate blueprint's exact hash scheme"


def test_UnreviewedLocalesRemainHonest(localeProject: Path) -> None:
    """Missing and draft registry entries never claim synthetic human reviews."""

    report = ValidateLocales(localeProject)

    assert not report.diagnostics, "Canonical missing states and terminology must validate"
    assert all(state in {"missing", "approved"} for states in report.states.values()
               for state in states.values()), "Authored review and missing fallback remain distinct"


def test_CanonicalSourceDriftFails(localeProject: Path) -> None:
    """A changed English unit cannot reuse the prior registered source hash."""

    page = localeProject / "docs/site/content/en/architecture.md"
    page.write_text(page.read_text(encoding="utf-8") + "\nChanged contract.\n", encoding="utf-8")
    report = ValidateLocales(localeProject)

    assert any("canonical source drift" in item for item in report.diagnostics)


def test_ApprovalWithoutRequiredReviewsFails(localeProject: Path) -> None:
    """Approved translations fail validation when their required reviews are removed."""

    registry = localeProject / "docs/i18n/units.toml"
    content = re.sub(
        r"\n\[\[units\.translations\.ru\.reviews\]\].*?(?=\n\[|\Z)",
        "", registry.read_text(), flags=re.DOTALL,
    )
    registry.write_text(content)
    report = ValidateLocales(localeProject)

    assert any("approved state lacks review roles" in item for item in report.diagnostics)


def test_RenderedFragmentsAreExact(tmp_path: Path) -> None:
    """Reject an existing page link whose generated fragment does not exist."""

    (tmp_path / "index.html").write_text('<a href="api/#missing">API</a>')
    (tmp_path / "api").mkdir()
    (tmp_path / "api/index.html").write_text('<h1 id="actual">API</h1>')
    diagnostics = documentationGates.CheckRenderedLinks(tmp_path)

    assert diagnostics == ("index.html: missing anchor api/#missing",)


def test_PublicRouteResolvesToArtifact(tmp_path: Path) -> None:
    """Resolve publication-prefixed canonical URLs inside the disposable site."""

    (tmp_path / "en").mkdir()
    (tmp_path / "en/index.html").write_text('<h1 id="reference">Reference</h1>')
    (tmp_path / "index.html").write_text(
        '<a href="https://fuzzy-technologies.github.io/F-Layer/en/#reference">English</a>'
    )

    assert not documentationGates.CheckRenderedLinks(tmp_path)


def test_RenderedLinksCannotEscapeSite(tmp_path: Path) -> None:
    """Decoded traversal URLs must fail instead of reading outside build ownership."""

    (tmp_path / "index.html").write_text('<a href="%2e%2e/private.html">Invalid</a>')

    assert "escapes the generated site" in documentationGates.CheckRenderedLinks(tmp_path)[0]


def test_SourceLinksFailForMissingTargets(tmp_path: Path) -> None:
    """Repository-local Markdown target validation catches source drift early."""

    (tmp_path / "README.md").write_text("[Broken](docs/missing.md)")
    (tmp_path / "docs").mkdir()

    assert documentationGates.CheckSourceLinks(tmp_path) == (
        "README.md: missing source target docs/missing.md",
    )


def test_GeneratedHtmlMustRemainUntracked(tmp_path: Path) -> None:
    """Git-tracked generated artifacts fail the disposable-output policy gate."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "_build").mkdir()
    (tmp_path / "_build/index.html").write_text("Generated")
    subprocess.run(["git", "add", "_build/index.html"], cwd=tmp_path, check=True)

    assert documentationGates.CheckGeneratedPolicy(tmp_path) == (
        "Generated output must remain untracked: _build/index.html",
    )


def test_StaticModuleDiscoveryNeverExecutesCode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that raises on import is still documented safely through syntax."""

    source = ('"""A static contract fixture."""\n'
              'raise RuntimeError("Runtime import is prohibited")\n\n'
              'def Inspect() -> str:\n    """Return a fixture contract."""\n    return "safe"\n')
    installed = tmp_path / "installed/flayer"
    repository = tmp_path / "repository/src/flayer"
    installed.mkdir(parents=True)
    repository.mkdir(parents=True)
    (installed / "__init__.py").write_text(source)
    (repository / "__init__.py").write_text(source)
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", tmp_path / "repository")
    modules = buildApiReference.DiscoverModules(tmp_path / "installed")

    assert [module.name for module in modules] == ["flayer"]
    assert modules[0].symbols == ("flayer.Inspect",)



def test_DynamicApiUnitsAreExplicitlyMissing(
    localeProject: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An API contract without a catalog stays missing instead of gaining invented approval."""

    from tools import generated_localization as generatedLocalization

    unit = CanonicalUnit("symbol:flayer.state.State", "symbol", "src/flayer/state.py",
                         "class State", "Track fixture state.")
    buildRoot = localeProject / "_build/api-reference"
    buildRoot.mkdir(parents=True)
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", localeProject)
    monkeypatch.setattr(generatedLocalization, "DiscoverGeneratedUnits", lambda root: {unit.identifier: unit})
    monkeypatch.setattr(generatedLocalization, "LoadTranslations", lambda root, units: {"ru": {}, "zh-CN": {}})
    module = buildApiReference.ModuleSource(
        "flayer.state", localeProject / unit.sourcePath, unit.sourcePath, ("flayer.state.State",),
    )
    buildApiReference.WriteApiLocaleInventory((module,), buildRoot)
    report = json.loads((buildRoot / "api-locales.json").read_text(encoding="utf-8"))

    assert report["states"] == {unit.identifier: {"ru": "missing", "zh-CN": "missing"}}
    assert report["sourceHashes"] == {unit.identifier: CanonicalHash(unit)}


def test_ImportGuardBlocksRuntimeExecution(tmp_path: Path) -> None:
    """The subprocess startup guard independently rejects project package imports."""

    guard = tmp_path / "guard"
    buildApiReference.WriteImportGuard(guard)
    environment = {**os.environ, "PYTHONPATH": str(guard)}
    result = subprocess.run([sys.executable, "-c", "import flayer"], cwd=tmp_path,
                            env=environment, capture_output=True, text=True, check=False)

    assert result.returncode != 0, "Runtime imports must fail during API discovery"
    assert "API discovery attempted to import flayer" in result.stderr


def test_BuildRootRejectsUnownedDirectory(tmp_path: Path) -> None:
    """The clean builder cannot remove directories outside its exact ownership."""

    sentinel = tmp_path / "keep.txt"
    sentinel.write_text("Keep")

    with pytest.raises(ValueError, match="unowned or redirected"):
        buildApiReference.RecreateBuildRoot(tmp_path)

    assert sentinel.read_text() == "Keep"


def test_EnvironmentCreationCannotRestoreStaleOutput(tmp_path: Path) -> None:
    """A restored artifact must fail before stale content can contaminate publication."""

    (tmp_path / "environment").mkdir()
    buildApiReference.VerifyBuildWorkspace(tmp_path)
    (tmp_path / "content/en").mkdir(parents=True)

    with pytest.raises(ValueError, match="environment creation restored generated output"):
        buildApiReference.VerifyBuildWorkspace(tmp_path)



def test_GeneratedDirectoryLinksPreserveSourceLabels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated site normalization preserves canonical policy files and link labels."""

    directory = tmp_path / "docs/adr"
    directory.mkdir(parents=True)
    (directory / "README.md").write_text("# Decisions")
    sourcePath = tmp_path / "DEVELOPMENT_PROTOCOL.md"
    canonical = "[docs/adr/](docs/adr/)"
    sourcePath.write_text(canonical)
    monkeypatch.setattr(buildApiReference, "PROJECT_ROOT", tmp_path)

    assert buildApiReference.RewriteDirectoryLinks(canonical, sourcePath) == (
        "[docs/adr/](docs/adr/README.md)"
    )
    assert sourcePath.read_text() == canonical, "Generated link adaptation cannot edit policy"


def test_GeneratedApiNavigationPreservesAuthoredGuides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed API generation cannot silently discard configured user navigation."""

    contentRoot = tmp_path / "source"
    (contentRoot / "api").mkdir(parents=True)
    (contentRoot / "api/index.md").write_text("# API")
    (contentRoot / "guide.md").write_text("# Guide")
    configPath = tmp_path / "source.yml"
    configPath.write_text(
        "docs_dir: source\nsite_dir: site\nnav:\n"
        "  - User guide:\n      - Get started: guide.md\n"
        "  - API reference: api/index.md\n\nplugins:\n  - search\n",
    )
    buildRoot = tmp_path / "build"
    buildRoot.mkdir()
    monkeypatch.setattr(buildApiReference, "SOURCE_CONTENT", contentRoot)
    monkeypatch.setattr(buildApiReference, "SOURCE_CONFIG", configPath)
    monkeypatch.setattr(buildApiReference, "WriteEngineeringContent", lambda root: [])
    generated = buildApiReference.WriteBuildContent((), buildRoot).read_text()

    assert "  - User guide:\n      - Get started: guide.md\n" in generated
    assert '  - API reference: [{"Index": "api/index.md"}]' in generated
    assert "  - Engineering guides: []" in generated


def test_LocaleFallbacksExposeMissingState(tmp_path: Path) -> None:
    """Language routes announce missing reviews and link the canonical reference."""

    buildApiReference.WriteLocaleFallbacks(tmp_path)

    for locale in ("ru", "zh-CN"):
        page = (tmp_path / locale / "index.html").read_text(encoding="utf-8")

        assert 'lang="' + locale + '"' in page
        assert "<strong>missing</strong>" in page
        assert '../en/' in page
