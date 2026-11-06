"""Protect honest draft rendering, stale fallbacks, and exact localized routes."""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from tools import locale_renderer as localeRenderer
from tools.locale_documentation import (
    CanonicalHash,
    CanonicalUnit,
    DiscoverCanonicalUnits,
    ValidateLocales,
)
from tools.markdown_tables import AlignMarkdown

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(name='localeProject')
def LocaleProjectFixture(tmp_path: Path) -> Path:
    """Copy canonical documents and metadata into an isolated locale project."""

    shutil.copytree(PROJECT_ROOT / "docs", tmp_path / "docs")
    (tmp_path / "src/flayer").mkdir(parents=True)
    shutil.copyfile(PROJECT_ROOT / "src/flayer/__init__.py", tmp_path / "src/flayer/__init__.py")

    return tmp_path


def test_ApprovedPagesRecordActualAiReview(localeProject: Path) -> None:
    """Approved authored pages identify AI provenance without invented human reviews."""

    registry = tomllib.loads((localeProject / "docs/i18n/units.toml").read_text())
    report = ValidateLocales(localeProject)

    assert not report.diagnostics, "Actual reviewed sources must pass the locale contract"

    for record in registry["units"]:
        expectedReviewer = "Codex" if record["id"] in {
            "page:development", "page:guide.configuration", "page:guide.first-deployment", "page:guide.cli",
        } else "AIna-Dev"

        for translation in record["translations"].values():
            if translation["state"] == "approved":
                assert translation["basedOnSourceHash"] == record["sourceHash"]
                assert {review["role"] for review in translation["reviews"]} == {
                    "editorial", "technical",
                }
                assert all(review["reviewerType"] == "ai" and review["reviewer"] == expectedReviewer
                           for review in translation["reviews"])

            else:
                assert "reviews" not in translation, "Missing translations have no reviews"


def test_RefreshingCanonicalHashCannotHideStaleDraft(localeProject: Path) -> None:
    """Updating the English registry cannot silently bless an outdated translated draft."""

    page = localeProject / "docs/site/content/en/guide/cli.md"
    body = page.read_text() + "\nAdditional canonical evidence.\n"
    page.write_text(body)
    registry = localeProject / "docs/i18n/units.toml"
    content = registry.read_text()
    record = next(item for item in tomllib.loads(content)["units"] if item["id"] == "page:guide.cli")
    currentHash = CanonicalHash(CanonicalUnit(record["id"], "page", record["sourcePath"], "", body))
    content = content.replace(f'sourceHash = "{record["sourceHash"]}"',
                              f'sourceHash = "{currentHash}"')
    registry.write_text(content)
    report = ValidateLocales(localeProject)

    assert report.states[record["id"]] == {"ru": "stale", "zh-CN": "stale"}
    assert any("set state=stale" in item for item in report.diagnostics)

    section = re.search(r'\[\[units\]\]\nid = "page:guide.cli".*?(?=\n\[\[units\]\]|\Z)',
                        content, re.DOTALL)

    assert section is not None, "The fixture CLI unit must exist"

    registry.write_text(content.replace(section[0], section[0].replace('state = "approved"',
                                                                      'state = "stale"')))

    assert not ValidateLocales(localeProject).diagnostics, "Explicit stale state must permit fallback"


def test_TranslationsCannotEscapeTheirLocale(localeProject: Path) -> None:
    """A tracked translation cannot be confused with canonical or other locale source."""

    registry = localeProject / "docs/i18n/units.toml"
    registry.write_text(registry.read_text().replace('path = "docs/site/content/ru/architecture.md"',
                                                     'path = "docs/site/content/en/architecture.md"'))

    assert any("inside its locale" in item for item in ValidateLocales(localeProject).diagnostics)


def test_LocalizedConfigPreservesEnvironmentTagAndExactRoutes(tmp_path: Path) -> None:
    """Translation of navigation must preserve installed-source guards and module routes."""

    config = ('docs_dir: source\nsite_dir: site\nsite_url: https://example.com/en/\n'
              'theme:\n  language: en\nnav:\n  - Overview: index.md\n'
              '  - API reference: [{"Index": "api/index.md"}, {"flayer": "api/flayer.md"}]\n'
              'plugins:\n  - mkdocstrings:\n      paths: [!ENV FLAYER_INSTALLED_PACKAGES]\n')
    localized = localeRenderer.LocalizeConfig(config, "ru", tmp_path / "ru", tmp_path / "site",
                                              {"Overview": "Localized overview"}, "https://example.com")

    assert '"Localized overview": index.md' in localized
    assert '"flayer": "api/flayer.md"' in localized
    assert "!ENV FLAYER_INSTALLED_PACKAGES" in localized
    assert "site_url: https://example.com/ru/" in localized

    chinese = localeRenderer.LocalizeConfig(config, "zh-CN", tmp_path / "zh-CN",
                                            tmp_path / "chinese-site", {}, "https://example.com")

    assert "  language: zh\n" in chinese, "Material uses zh for Simplified Chinese UI templates"
    assert "site_url: https://example.com/zh-CN/" in chinese


def test_PreparedPagesRetainApprovedProvenanceAndFallbackNotices(localeProject: Path) -> None:
    """Localized prose and absent API pages render with distinct honest states."""

    project = tomllib.loads((localeProject / "docs/i18n/project.toml").read_text())
    registry = tomllib.loads((localeProject / project["unitManifest"]).read_text())
    notices = tomllib.loads((localeProject / "docs/i18n/fallbacks.toml").read_text())
    states = ValidateLocales(localeProject).states
    states["page:api"]["ru"] = "missing"

    for record in registry["units"]:
        if record["id"] == "page:api":
            record["translations"]["ru"] = {"state": "missing"}

    buildRoot = localeProject / "_build/api-reference"
    shutil.copytree(localeProject / "docs/site/content/en", buildRoot / "content/en")
    restoredLocale = buildRoot / "content/ru"
    restoredLocale.mkdir()
    (restoredLocale / "stale-generated-page.md").write_text("Stale restored output")
    contentRoot, evidence = localeRenderer._PrepareLocale(
        localeProject, buildRoot, "ru", project, registry, states,
        notices["ru"], "https://fuzzy-technologies.github.io/F-Layer",
    )

    assert evidence["guide/cli.md"]["state"] == "approved"
    assert evidence["api/index.md"]["renderedContent"] == "english-fallback"

    approvedPage = (contentRoot / "guide/cli.md").read_text()

    assert '<aside hidden data-translation-state="approved"' in approvedPage
    assert 'class="fl-translation-notice"' not in approvedPage
    assert "Черновик перевода" not in approvedPage
    assert 'data-translation-state="missing"' in (contentRoot / "api/index.md").read_text()
    assert not (contentRoot / "stale-generated-page.md").exists(), "Stale generated inputs must be replaced"

    status = (contentRoot / "translation-status/index.md").read_text()

    assert AlignMarkdown(status) == status, "Generated status tables must retain content padding"


def test_StaleTranslationRendersCurrentEnglishInsteadOfOldProse(localeProject: Path) -> None:
    """An explicitly stale page remains buildable while displaying canonical English."""

    project = tomllib.loads((localeProject / "docs/i18n/project.toml").read_text())
    registry = tomllib.loads((localeProject / project["unitManifest"]).read_text())
    notices = tomllib.loads((localeProject / "docs/i18n/fallbacks.toml").read_text())
    states = ValidateLocales(localeProject).states
    states["page:guide.cli"]["ru"] = "stale"
    buildRoot = localeProject / "_build/api-reference"
    shutil.copytree(localeProject / "docs/site/content/en", buildRoot / "content/en")
    contentRoot, evidence = localeRenderer._PrepareLocale(
        localeProject, buildRoot, "ru", project, registry, states, notices["ru"],
        "https://fuzzy-technologies.github.io/F-Layer",
    )
    page = (contentRoot / "guide/cli.md").read_text()

    assert "# CLI and diagnostic results" in page
    assert 'data-translation-state="stale"' in page
    assert evidence["guide/cli.md"]["renderedContent"] == "english-fallback"


def test_UnregisteredLocalePageFails(localeProject: Path) -> None:
    """Unregistered translations cannot bypass per-unit state or source-basis review."""

    (localeProject / "docs/site/content/ru/unregistered.md").write_text("# Unexpected overlay")

    assert any("lacks explicit unit state" in item for item in ValidateLocales(localeProject).diagnostics)


def test_UntrackedOverlayCannotEnterReproducibleSite(localeProject: Path) -> None:
    """Locale rendering requires reproducible tracked translation inputs."""

    subprocess.run(["git", "init", "--quiet", str(localeProject)], check=True)
    registry = tomllib.loads((localeProject / "docs/i18n/units.toml").read_text())

    with pytest.raises(ValueError, match="Untracked locale overlay"):
        localeRenderer.VerifyTrackedTranslations(localeProject, registry)


def test_RenderedLocaleMustExposeBannerAndReachability(tmp_path: Path) -> None:
    """A generated overlay must have the promised state and be reachable from locale entry."""

    localeRoot = tmp_path / "ru"
    localeRoot.mkdir()
    (localeRoot / "index.html").write_text('<a href="guide/">Guide</a>')
    (localeRoot / "guide").mkdir()
    page = localeRoot / "guide/index.html"
    page.write_text('<aside data-translation-state="draft" data-documentation-unit="page:guide">')
    evidence = {"guide/index.md": {"state": "draft", "unitId": "page:guide"}}
    localeRenderer.VerifyRenderedLocale(tmp_path, "ru", evidence)
    (localeRoot / "index.html").write_text("<h1>Entry</h1>")

    with pytest.raises(ValueError, match="Unreachable locale pages"):
        localeRenderer.VerifyRenderedLocale(tmp_path, "ru", evidence)

    page.write_text('<aside data-translation-state="approved">')

    with pytest.raises(ValueError, match="Missing actual review-state banner"):
        localeRenderer.VerifyRenderedLocale(tmp_path, "ru", evidence)


def test_LocalizedExamplesRemainExactCanonicalCode() -> None:
    """Translated user guides never alter commands, API identifiers, or Python examples."""

    for canonicalPath in (PROJECT_ROOT / "docs/site/content/en/guide").glob("*.md"):
        canonicalBlocks = re.findall(r"^```.*?^```", canonicalPath.read_text(), re.MULTILINE | re.DOTALL)

        for locale in ("ru", "zh-CN"):
            localizedPath = PROJECT_ROOT / "docs/site/content" / locale / "guide" / canonicalPath.name
            translatedBlocks = re.findall(r"^```.*?^```", localizedPath.read_text(),
                                           re.MULTILINE | re.DOTALL)

            assert translatedBlocks == canonicalBlocks, "Code examples must preserve canonical contracts"


def test_RendererRejectsUnownedBuildRoot(localeProject: Path, tmp_path: Path) -> None:
    """Locale fallback replacement is confined to the verified owned generated site."""

    with pytest.raises(ValueError, match="owned verified canonical"):
        localeRenderer.RenderLocaleSites(localeProject, tmp_path / "unowned", tmp_path / "config",
                                         tmp_path / "python", {})


def test_FallbackLinksPreserveLocalizedLabelsAndCanonicalAnchors(tmp_path: Path) -> None:
    """A missing translation still links to the exact local fallback route and fragment."""

    source = tmp_path / "content/ru/guide/configuration.md"
    canonicalRoot = tmp_path / "content/en"
    text = "[API](../../en/api/index.md#flayer) ![Brand](../../en/assets/brand.svg)"

    assert localeRenderer.RewriteFallbackLinks(text, source, canonicalRoot) == (
        "[API](../api/index.md#flayer) ![Brand](../assets/brand.svg)"
    ), "Locale routing must preserve labels, fragments, and existing generated fallback targets"


@pytest.mark.parametrize("locale", ["ru", "zh-CN"])
def test_PreparedAuthoredPagesRouteRepositoryGuidesWithinTheirLocale(
    localeProject: Path, locale: str,
) -> None:
    """Root and nested authored overlays resolve their real source links into local generated pages."""

    project = tomllib.loads((localeProject / "docs/i18n/project.toml").read_text())
    registry = tomllib.loads((localeProject / project["unitManifest"]).read_text())
    notices = tomllib.loads((localeProject / "docs/i18n/fallbacks.toml").read_text())
    buildRoot = localeProject / "_build/api-reference"
    shutil.copytree(localeProject / "docs/site/content/en", buildRoot / "content/en")
    contentRoot, _ = localeRenderer._PrepareLocale(
        localeProject, buildRoot, locale, project, registry, ValidateLocales(localeProject).states,
        notices[locale], "https://fuzzy-technologies.github.io/F-Layer",
    )
    destinations = {
        "architecture.md": ["repository/docs/architecture/reference.md",
                            "repository/docs/architecture/README.md", "repository/docs/adr/README.md",
                            "repository/docs/development/documentation-coverage.md"],
        "development.md": ["repository/docs/development/PYTHON_CODE_STYLE.md"],
        "documentation.md": ["repository/docs/development/documentation-coverage.md",
                             "repository/docs/adr/0004-documentation-platform.md"],
        "guide/index.md": ["../repository/docs/architecture/amneziawg.md",
                           "../repository/docs/architecture/vless-reality.md",
                           "../repository/docs/development/vpn-release-acceptance.md"],
    }

    for source, targets in destinations.items():
        rendered = contentRoot / source
        body = rendered.read_text()

        for target in targets:
            assert f"]({target})" in body, f"{locale}/{source} lost local destination {target}"
            assert (rendered.parent / target).resolve().is_relative_to(contentRoot)


def test_RepositoryOverlayLinksKeepQueryFragmentAndExplicitSourceFiles(tmp_path: Path) -> None:
    """Mapping repository Markdown does not drop query/anchor data or confuse files with pages."""

    root = tmp_path / "project"
    source = root / "docs/site/content/ru/guide/index.md"
    canonical = root / "docs/site/content/en"
    body = ("[Схема](../../../../architecture/reference.md?view=compact#composition) "
            "[Настройки](../../../../../pyproject.toml) "
            "[Облако](https://yandex.cloud/ru/docs/cli/quickstart)")
    mapped = localeRenderer.RewriteFallbackLinks(body, source, canonical, root)

    assert "[Схема](../repository/docs/architecture/reference.md?view=compact#composition)" in mapped
    assert "[Настройки](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/pyproject.toml)" in mapped
    assert "[Облако](https://yandex.cloud/ru/docs/cli/quickstart)" in mapped


def test_ApiLocaleInventoryIncludesCallableAndConditionalContracts(localeProject: Path) -> None:
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
    (localeProject / "src/flayer/__init__.py").write_text(source)
    project = tomllib.loads((localeProject / "docs/i18n/project.toml").read_text())
    units = DiscoverCanonicalUnits(localeProject, project)
    symbolIds = {unit.identifier for unit in units if unit.kind == "symbol"}

    assert symbolIds == {"symbol:flayer.Callback", "symbol:flayer.Callback.__call__",
                          "symbol:flayer.Callback.Inspect"}, "Locale units must match public API scopes"


@pytest.mark.parametrize('manifestValue', [None, '["human"]', '["robot"]', '"ai"'])
def test_AiReviewRequiresExplicitProjectAuthority(localeProject: Path, manifestValue: str | None) -> None:
    """AI records fail under the unchanged human-only default or invalid authority."""

    manifest = localeProject / "docs/i18n/project.toml"
    replacement = "" if manifestValue is None else f"reviewerTypes = {manifestValue}"
    manifest.write_text(manifest.read_text().replace('reviewerTypes = ["human", "ai"]', replacement))

    assert ValidateLocales(localeProject).diagnostics, "AI approval requires explicit valid opt-in"


@pytest.mark.parametrize("change", ["translation", "hash", "identity", "role", "reviewer", "timestamp", "source-hash"])
def test_AiApprovalCannotSurviveChangedEvidence(localeProject: Path, change: str) -> None:
    """Changed localized bytes or missing review evidence cannot retain valid approval."""

    registry = localeProject / "docs/i18n/units.toml"
    content = registry.read_text()

    if change == "translation":
        page = localeProject / "docs/site/content/ru/guide/cli.md"
        page.write_text(page.read_text() + "\nUnreviewed translated change.\n")

    elif change == "hash":
        content = re.sub(r'^reviewedTranslationHash = .*\n', "", content, count=1, flags=re.MULTILINE)

    elif change == "identity":
        content = content.replace('reviewerType = "ai"', 'reviewerType = "robot"', 1)

    elif change == "reviewer":
        content = re.sub(r'^reviewer = .*$', 'reviewer = ""', content, count=1, flags=re.MULTILINE)

    elif change == "timestamp":
        content = re.sub(r'^reviewedAt = .*$', 'reviewedAt = "invalid"', content, count=1, flags=re.MULTILINE)

    elif change == "source-hash":
        content = re.sub(r'^reviewedSourceHash = .*$', 'reviewedSourceHash = "sha256:' + "0" * 64 + '"',
                         content, count=1, flags=re.MULTILINE)

    else:
        content = content.replace('role = "editorial"', 'role = "technical"', 1)

    registry.write_text(content)
    report = ValidateLocales(localeProject)

    assert report.diagnostics, "Changed review evidence must block approval"

    if change == "translation":
        assert report.states["page:guide.cli"]["ru"] == "stale"
