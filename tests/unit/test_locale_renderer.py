"""Protect honest draft rendering, stale fallbacks, and exact localized routes."""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from tools import locale_renderer
from tools.locale_documentation import (
    CanonicalHash,
    CanonicalUnit,
    DiscoverCanonicalUnits,
    ValidateLocales,
)
from tools.markdown_tables import AlignMarkdown

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def locale_project(tmp_path: Path) -> Path:
    """Copy canonical documents and metadata into an isolated locale project."""

    shutil.copytree(PROJECT_ROOT / "docs", tmp_path / "docs")
    (tmp_path / "src/flayer").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / "src/flayer/__init__.py", tmp_path / "src/flayer/__init__.py")

    return tmp_path


def test_ApprovedPagesRecordActualAiReview(locale_project: Path) -> None:
    """Approved authored pages identify AI provenance without invented human reviews."""

    registry = tomllib.loads((locale_project / "docs/i18n/units.toml").read_text())
    report = ValidateLocales(locale_project)

    assert not report.diagnostics, "Actual reviewed sources must pass the locale contract"

    for record in registry["units"]:
        for translation in record["translations"].values():
            if translation["state"] == "approved":
                assert translation["basedOnSourceHash"] == record["sourceHash"]
                assert {review["role"] for review in translation["reviews"]} == {
                    "editorial", "technical",
                }
                assert all(review["reviewerType"] == "ai" and review["reviewer"] == "AIna-Dev"
                           for review in translation["reviews"])

            else:
                assert "reviews" not in translation, "Missing translations have no reviews"


def test_RefreshingCanonicalHashCannotHideStaleDraft(locale_project: Path) -> None:
    """Updating the English registry cannot silently bless an outdated translated draft."""

    page = locale_project / "docs/site/content/en/guide/cli.md"
    body = page.read_text() + "\nAdditional canonical evidence.\n"
    page.write_text(body)
    registry = locale_project / "docs/i18n/units.toml"
    content = registry.read_text()
    record = next(item for item in tomllib.loads(content)["units"] if item["id"] == "page:guide.cli")
    current_hash = CanonicalHash(CanonicalUnit(record["id"], "page", record["sourcePath"], "", body))
    content = content.replace(f'sourceHash = "{record["sourceHash"]}"',
                              f'sourceHash = "{current_hash}"')
    registry.write_text(content)
    report = ValidateLocales(locale_project)

    assert report.states[record["id"]] == {"ru": "stale", "zh-CN": "stale"}
    assert any("set state=stale" in item for item in report.diagnostics)

    section = re.search(r'\[\[units\]\]\nid = "page:guide.cli".*?(?=\n\[\[units\]\]|\Z)',
                        content, re.DOTALL)
    assert section is not None, "The fixture CLI unit must exist"
    registry.write_text(content.replace(section[0], section[0].replace('state = "approved"',
                                                                      'state = "stale"')))

    assert not ValidateLocales(locale_project).diagnostics, "Explicit stale state must permit fallback"


def test_TranslationsCannotEscapeTheirLocale(locale_project: Path) -> None:
    """A tracked translation cannot be confused with canonical or other locale source."""

    registry = locale_project / "docs/i18n/units.toml"
    registry.write_text(registry.read_text().replace('path = "docs/site/content/ru/architecture.md"',
                                                     'path = "docs/site/content/en/architecture.md"'))

    assert any("inside its locale" in item for item in ValidateLocales(locale_project).diagnostics)


def test_LocalizedConfigPreservesEnvironmentTagAndExactRoutes(tmp_path: Path) -> None:
    """Translation of navigation must preserve installed-source guards and module routes."""

    config = ('docs_dir: source\nsite_dir: site\nsite_url: https://example.com/en/\n'
              'theme:\n  language: en\nnav:\n  - Overview: index.md\n'
              '  - API reference: [{"Index": "api/index.md"}, {"flayer": "api/flayer.md"}]\n'
              'plugins:\n  - mkdocstrings:\n      paths: [!ENV FLAYER_INSTALLED_PACKAGES]\n')
    localized = locale_renderer.LocalizeConfig(config, "ru", tmp_path / "ru", tmp_path / "site",
                                              {"Overview": "Localized overview"}, "https://example.com")

    assert '"Localized overview": index.md' in localized
    assert '"flayer": "api/flayer.md"' in localized
    assert "!ENV FLAYER_INSTALLED_PACKAGES" in localized
    assert "site_url: https://example.com/ru/" in localized

    chinese = locale_renderer.LocalizeConfig(config, "zh-CN", tmp_path / "zh-CN",
                                            tmp_path / "chinese-site", {}, "https://example.com")
    assert "  language: zh\n" in chinese, "Material uses zh for Simplified Chinese UI templates"
    assert "site_url: https://example.com/zh-CN/" in chinese


def test_PreparedPagesRetainApprovedProvenanceAndFallbackNotices(locale_project: Path) -> None:
    """Localized prose and absent API pages render with distinct honest states."""

    project = tomllib.loads((locale_project / "docs/i18n/project.toml").read_text())
    registry = tomllib.loads((locale_project / project["unitManifest"]).read_text())
    notices = tomllib.loads((locale_project / "docs/i18n/fallbacks.toml").read_text())
    build_root = locale_project / "_build/api-reference"
    shutil.copytree(locale_project / "docs/site/content/en", build_root / "content/en")
    restored_locale = build_root / "content/ru"
    restored_locale.mkdir()
    (restored_locale / "stale-generated-page.md").write_text("Stale restored output")
    content_root, evidence = locale_renderer._PrepareLocale(
        locale_project, build_root, "ru", project, registry, ValidateLocales(locale_project).states,
        notices["ru"], "https://fuzzy-technologies.github.io/F-Layer",
    )

    assert evidence["guide/cli.md"]["state"] == "approved"
    assert evidence["api/index.md"]["renderedContent"] == "english-fallback"
    approved_page = (content_root / "guide/cli.md").read_text()
    assert '<aside hidden data-translation-state="approved"' in approved_page
    assert 'class="fl-translation-notice"' not in approved_page
    assert "Черновик перевода" not in approved_page
    assert 'data-translation-state="missing"' in (content_root / "api/index.md").read_text()
    assert not (content_root / "stale-generated-page.md").exists(), "Stale generated inputs must be replaced"
    status = (content_root / "translation-status/index.md").read_text()
    assert AlignMarkdown(status) == status, "Generated status tables must retain content padding"


def test_StaleTranslationRendersCurrentEnglishInsteadOfOldProse(locale_project: Path) -> None:
    """An explicitly stale page remains buildable while displaying canonical English."""

    project = tomllib.loads((locale_project / "docs/i18n/project.toml").read_text())
    registry = tomllib.loads((locale_project / project["unitManifest"]).read_text())
    notices = tomllib.loads((locale_project / "docs/i18n/fallbacks.toml").read_text())
    states = ValidateLocales(locale_project).states
    states["page:guide.cli"]["ru"] = "stale"
    build_root = locale_project / "_build/api-reference"
    shutil.copytree(locale_project / "docs/site/content/en", build_root / "content/en")
    content_root, evidence = locale_renderer._PrepareLocale(
        locale_project, build_root, "ru", project, registry, states, notices["ru"],
        "https://fuzzy-technologies.github.io/F-Layer",
    )
    page = (content_root / "guide/cli.md").read_text()

    assert "# CLI and diagnostic results" in page
    assert 'data-translation-state="stale"' in page
    assert evidence["guide/cli.md"]["renderedContent"] == "english-fallback"


def test_UnregisteredLocalePageFails(locale_project: Path) -> None:
    """Unregistered translations cannot bypass per-unit state or source-basis review."""

    (locale_project / "docs/site/content/ru/unregistered.md").write_text("# Unexpected overlay")

    assert any("lacks explicit unit state" in item for item in ValidateLocales(locale_project).diagnostics)


def test_UntrackedOverlayCannotEnterReproducibleSite(locale_project: Path) -> None:
    """Locale rendering requires reproducible tracked translation inputs."""

    subprocess.run(["git", "init", "--quiet", str(locale_project)], check=True)
    registry = tomllib.loads((locale_project / "docs/i18n/units.toml").read_text())

    with pytest.raises(ValueError, match="Untracked locale overlay"):
        locale_renderer.VerifyTrackedTranslations(locale_project, registry)


def test_RenderedLocaleMustExposeBannerAndReachability(tmp_path: Path) -> None:
    """A generated overlay must have the promised state and be reachable from locale entry."""

    locale_root = tmp_path / "ru"
    locale_root.mkdir()
    (locale_root / "index.html").write_text('<a href="guide/">Guide</a>')
    (locale_root / "guide").mkdir()
    page = locale_root / "guide/index.html"
    page.write_text('<aside data-translation-state="draft" data-documentation-unit="page:guide">')
    evidence = {"guide/index.md": {"state": "draft", "unitId": "page:guide"}}
    locale_renderer.VerifyRenderedLocale(tmp_path, "ru", evidence)
    (locale_root / "index.html").write_text("<h1>Entry</h1>")

    with pytest.raises(ValueError, match="Unreachable locale pages"):
        locale_renderer.VerifyRenderedLocale(tmp_path, "ru", evidence)

    page.write_text('<aside data-translation-state="approved">')

    with pytest.raises(ValueError, match="Missing actual review-state banner"):
        locale_renderer.VerifyRenderedLocale(tmp_path, "ru", evidence)


def test_LocalizedExamplesRemainExactCanonicalCode() -> None:
    """Translated user guides never alter commands, API identifiers, or Python examples."""

    for canonical_path in (PROJECT_ROOT / "docs/site/content/en/guide").glob("*.md"):
        canonical_blocks = re.findall(r"^```.*?^```", canonical_path.read_text(), re.MULTILINE | re.DOTALL)

        for locale in ("ru", "zh-CN"):
            localized_path = PROJECT_ROOT / "docs/site/content" / locale / "guide" / canonical_path.name
            translated_blocks = re.findall(r"^```.*?^```", localized_path.read_text(),
                                           re.MULTILINE | re.DOTALL)
            assert translated_blocks == canonical_blocks, "Code examples must preserve canonical contracts"


def test_RendererRejectsUnownedBuildRoot(locale_project: Path, tmp_path: Path) -> None:
    """Locale fallback replacement is confined to the verified owned generated site."""

    with pytest.raises(ValueError, match="owned verified canonical"):
        locale_renderer.RenderLocaleSites(locale_project, tmp_path / "unowned", tmp_path / "config",
                                         tmp_path / "python", {})


def test_FallbackLinksPreserveLocalizedLabelsAndCanonicalAnchors(tmp_path: Path) -> None:
    """A missing translation still links to the exact local fallback route and fragment."""

    source = tmp_path / "content/ru/guide/configuration.md"
    canonical_root = tmp_path / "content/en"
    text = "[API](../../en/api/index.md#flayer) ![Brand](../../en/assets/brand.svg)"

    assert locale_renderer.RewriteFallbackLinks(text, source, canonical_root) == (
        "[API](../api/index.md#flayer) ![Brand](../assets/brand.svg)"
    ), "Locale routing must preserve labels, fragments, and existing generated fallback targets"


def test_ApiLocaleInventoryIncludesCallableAndConditionalContracts(locale_project: Path) -> None:
    """Disposable API locale units match supported callable and conditional public anchors."""

    source = ('"""A fixture package contract."""\n'
              'if True:\n'
              '    class Callback:\n'
              '        """A public callable contract."""\n'
              '        def __call__(self) -> str:\n'
              '            """Return a fixture value."""\n\n'
              '            return "safe"\n'
              '        def __init__(self) -> None:\n'
              '            """Initialize a source-only fixture hook."""\n\n'
              '            pass\n'
              '        if True:\n'
              '            def Inspect(self) -> str:\n'
              '                """Return a public conditional fixture value."""\n\n'
              '                def Nested() -> str:\n'
              '                    """Return a source-only implementation value."""\n\n'
              '                    return "safe"\n\n'
              '                return Nested()\n')
    (locale_project / "src/flayer/__init__.py").write_text(source)
    project = tomllib.loads((locale_project / "docs/i18n/project.toml").read_text())
    units = DiscoverCanonicalUnits(locale_project, project)
    symbol_ids = {unit.identifier for unit in units if unit.kind == "symbol"}

    assert symbol_ids == {"symbol:flayer.Callback", "symbol:flayer.Callback.__call__",
                          "symbol:flayer.Callback.Inspect"}, "Locale units must match public API scopes"


@pytest.mark.parametrize("manifest_value", [None, '["human"]', '["robot"]', '"ai"'])
def test_AiReviewRequiresExplicitProjectAuthority(locale_project: Path, manifest_value: str | None) -> None:
    """AI records fail under the unchanged human-only default or invalid authority."""

    manifest = locale_project / "docs/i18n/project.toml"
    replacement = "" if manifest_value is None else f"reviewerTypes = {manifest_value}"
    manifest.write_text(manifest.read_text().replace('reviewerTypes = ["human", "ai"]', replacement))

    assert ValidateLocales(locale_project).diagnostics, "AI approval requires explicit valid opt-in"


@pytest.mark.parametrize("change", ["translation", "hash", "identity", "role"])
def test_AiApprovalCannotSurviveChangedEvidence(locale_project: Path, change: str) -> None:
    """Changed localized bytes or missing review evidence cannot retain valid approval."""

    registry = locale_project / "docs/i18n/units.toml"
    content = registry.read_text()

    if change == "translation":
        page = locale_project / "docs/site/content/ru/guide/cli.md"
        page.write_text(page.read_text() + "\nUnreviewed translated change.\n")

    elif change == "hash":
        content = re.sub(r'^reviewedTranslationHash = .*\n', "", content, count=1, flags=re.MULTILINE)

    elif change == "identity":
        content = content.replace('reviewerType = "ai"', 'reviewerType = "robot"', 1)

    else:
        content = content.replace('role = "editorial"', 'role = "technical"', 1)

    registry.write_text(content)
    report = ValidateLocales(locale_project)

    assert report.diagnostics, "Changed review evidence must block approval"

    if change == "translation":
        assert report.states["page:guide.cli"]["ru"] == "stale"
