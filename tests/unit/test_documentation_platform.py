"""Exercise static documentation discovery and publication failure contracts."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as element_tree
from pathlib import Path

import pytest

from tools import build_api_reference, documentation_gates
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
    rendered = element_tree.fromstring("<main>" + markdown.markdown(source, extensions=extensions) + "</main>")
    cards = rendered.find(".//div[@class='grid cards']/ul")

    assert cards is not None, "Landing cards must render as a list, not raw Markdown text"
    assert len(cards.findall("li")) == 4, "Every getting-started scenario must remain a distinct card"

    for card in cards:
        assert card.find(".//strong") is not None, "Card titles must render with emphasis"
        assert card.find(".//a[@href]") is not None, "Card links must become usable navigation"


@pytest.fixture
def locale_project(tmp_path: Path) -> Path:
    """Copy only the local source necessary for blueprint locale validation."""

    shutil.copytree(PROJECT_ROOT / "docs", tmp_path / "docs")
    (tmp_path / "src/flayer").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / "src/flayer/__init__.py", tmp_path / "src/flayer/__init__.py")

    return tmp_path


def test_CanonicalHashPreservesBlueprintVector() -> None:
    """Protect the upstream hash payload from naming-only port drift."""

    unit = CanonicalUnit(
        identifier="symbol:sampleproject.Greet", kind="symbol",
        source_path="sampleproject.py", signature="def Greet(name: str) -> str",
        body="Return a greeting without side effects.",
    )

    assert CanonicalHash(unit) == (
        "sha256:6adc80348e45ec52d8824eef057947727452d80bf0204e6e1953f290ca377a79"
    ), "House-style port must preserve the corporate blueprint's exact hash scheme"


def test_UnreviewedLocalesRemainHonest(locale_project: Path) -> None:
    """Missing and draft registry entries never claim synthetic human reviews."""

    report = ValidateLocales(locale_project)

    assert not report.diagnostics, "Canonical missing states and terminology must validate"
    assert all(state in {"missing", "approved"} for states in report.states.values()
               for state in states.values()), "Authored review and missing fallback remain distinct"


def test_CanonicalSourceDriftFails(locale_project: Path) -> None:
    """A changed English unit cannot reuse the prior registered source hash."""

    page = locale_project / "docs/site/content/en/architecture.md"
    page.write_text(page.read_text(encoding="utf-8") + "\nChanged contract.\n", encoding="utf-8")
    report = ValidateLocales(locale_project)

    assert any("canonical source drift" in item for item in report.diagnostics)


def test_ApprovalWithoutHumanReviewFails(locale_project: Path) -> None:
    """Automation cannot convert an untranslated unit into an approved translation."""

    registry = locale_project / "docs/i18n/units.toml"
    registry.write_text(registry.read_text().replace('state = "missing"',
                                                   'state = "approved"', 1))
    report = ValidateLocales(locale_project)

    assert any("approved state lacks review roles" in item for item in report.diagnostics)


def test_RenderedFragmentsAreExact(tmp_path: Path) -> None:
    """Reject an existing page link whose generated fragment does not exist."""

    (tmp_path / "index.html").write_text('<a href="api/#missing">API</a>')
    (tmp_path / "api").mkdir()
    (tmp_path / "api/index.html").write_text('<h1 id="actual">API</h1>')
    diagnostics = documentation_gates.CheckRenderedLinks(tmp_path)

    assert diagnostics == ("index.html: missing anchor api/#missing",)


def test_PublicRouteResolvesToArtifact(tmp_path: Path) -> None:
    """Resolve publication-prefixed canonical URLs inside the disposable site."""

    (tmp_path / "en").mkdir()
    (tmp_path / "en/index.html").write_text('<h1 id="reference">Reference</h1>')
    (tmp_path / "index.html").write_text(
        '<a href="https://fuzzy-technologies.github.io/F-Layer/en/#reference">English</a>'
    )

    assert not documentation_gates.CheckRenderedLinks(tmp_path)


def test_RenderedLinksCannotEscapeSite(tmp_path: Path) -> None:
    """Decoded traversal URLs must fail instead of reading outside build ownership."""

    (tmp_path / "index.html").write_text('<a href="%2e%2e/private.html">Invalid</a>')

    assert "escapes the generated site" in documentation_gates.CheckRenderedLinks(tmp_path)[0]


def test_SourceLinksFailForMissingTargets(tmp_path: Path) -> None:
    """Repository-local Markdown target validation catches source drift early."""

    (tmp_path / "README.md").write_text("[Broken](docs/missing.md)")
    (tmp_path / "docs").mkdir()

    assert documentation_gates.CheckSourceLinks(tmp_path) == (
        "README.md: missing source target docs/missing.md",
    )


def test_GeneratedHtmlMustRemainUntracked(tmp_path: Path) -> None:
    """Git-tracked generated artifacts fail the disposable-output policy gate."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    (tmp_path / "_build").mkdir()
    (tmp_path / "_build/index.html").write_text("Generated")
    subprocess.run(["git", "add", "_build/index.html"], cwd=tmp_path, check=True)

    assert documentation_gates.CheckGeneratedPolicy(tmp_path) == (
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
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", tmp_path / "repository")
    modules = build_api_reference.DiscoverModules(tmp_path / "installed")

    assert [module.name for module in modules] == ["flayer"]
    assert modules[0].symbols == ("flayer.Inspect",)



def test_DynamicApiUnitsAreExplicitlyMissing(
    locale_project: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Integrated modules receive stable hashes with no invented translation reviews."""

    source = ('"""An additional module contract."""\n'
              'class State:\n    """Track fixture state."""\n'
              '    def Inspect(self) -> str:\n        """Return fixture state."""\n'
              '        return "safe"\n')
    module_path = locale_project / "src/flayer/state.py"
    module_path.write_text(source, encoding="utf-8")
    build_root = locale_project / "_build/api-reference"
    build_root.mkdir(parents=True)
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", locale_project)
    module = build_api_reference.ModuleSource(
        "flayer.state", module_path, "src/flayer/state.py",
        ("flayer.state.State", "flayer.state.State.Inspect"),
    )
    build_api_reference.WriteApiLocaleInventory((module,), build_root)
    report = ValidateLocales(locale_project, build_root / "api-locales-project.toml")

    assert not report.diagnostics
    assert set(report.states) == {"symbol:flayer.state.State", "symbol:flayer.state.State.Inspect"}
    assert all(state == "missing" for states in report.states.values() for state in states.values())
    assert "reviews" not in (build_root / "api-units.toml").read_text(encoding="utf-8")


def test_ImportGuardBlocksRuntimeExecution(tmp_path: Path) -> None:
    """The subprocess startup guard independently rejects project package imports."""

    guard = tmp_path / "guard"
    build_api_reference.WriteImportGuard(guard)
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
        build_api_reference.RecreateBuildRoot(tmp_path)

    assert sentinel.read_text() == "Keep"


def test_EnvironmentCreationCannotRestoreStaleOutput(tmp_path: Path) -> None:
    """A restored artifact must fail before stale content can contaminate publication."""

    (tmp_path / "environment").mkdir()
    build_api_reference.VerifyBuildWorkspace(tmp_path)
    (tmp_path / "content/en").mkdir(parents=True)

    with pytest.raises(ValueError, match="environment creation restored generated output"):
        build_api_reference.VerifyBuildWorkspace(tmp_path)



def test_GeneratedDirectoryLinksPreserveSourceLabels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Generated site normalization preserves canonical policy files and link labels."""

    directory = tmp_path / "docs/adr"
    directory.mkdir(parents=True)
    (directory / "README.md").write_text("# Decisions")
    source_path = tmp_path / "DEVELOPMENT_PROTOCOL.md"
    canonical = "[docs/adr/](docs/adr/)"
    source_path.write_text(canonical)
    monkeypatch.setattr(build_api_reference, "PROJECT_ROOT", tmp_path)

    assert build_api_reference.RewriteDirectoryLinks(canonical, source_path) == (
        "[docs/adr/](docs/adr/README.md)"
    )
    assert source_path.read_text() == canonical, "Generated link adaptation cannot edit policy"


def test_GeneratedApiNavigationPreservesAuthoredGuides(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed API generation cannot silently discard configured user navigation."""

    content_root = tmp_path / "source"
    (content_root / "api").mkdir(parents=True)
    (content_root / "api/index.md").write_text("# API")
    (content_root / "guide.md").write_text("# Guide")
    config_path = tmp_path / "source.yml"
    config_path.write_text(
        "docs_dir: source\nsite_dir: site\nnav:\n"
        "  - User guide:\n      - Get started: guide.md\n"
        "  - API reference: api/index.md\n\nplugins:\n  - search\n",
    )
    build_root = tmp_path / "build"
    build_root.mkdir()
    monkeypatch.setattr(build_api_reference, "SOURCE_CONTENT", content_root)
    monkeypatch.setattr(build_api_reference, "SOURCE_CONFIG", config_path)
    monkeypatch.setattr(build_api_reference, "WriteEngineeringContent", lambda root: [])
    generated = build_api_reference.WriteBuildContent((), build_root).read_text()

    assert "  - User guide:\n      - Get started: guide.md\n" in generated
    assert '  - API reference: [{"Index": "api/index.md"}]' in generated
    assert "  - Engineering guides: []" in generated


def test_LocaleFallbacksExposeMissingState(tmp_path: Path) -> None:
    """Language routes announce missing reviews and link the canonical reference."""

    build_api_reference.WriteLocaleFallbacks(tmp_path)

    for locale in ("ru", "zh-CN"):
        page = (tmp_path / locale / "index.html").read_text(encoding="utf-8")
        assert 'lang="' + locale + '"' in page
        assert "<strong>missing</strong>" in page
        assert '../en/' in page
