"""Protect complete generated translations, review provenance, and untouched source code."""

from __future__ import annotations

import json
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest

from tools import documentation_coverage, generated_localization
from tools.locale_documentation import CanonicalHash, CanonicalUnit


@pytest.fixture
def generated_project(tmp_path: Path) -> Path:
    """Create a tracked miniature repository with prose and a static public API."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    sources = {
        "docs/site/repository-coverage.toml": (
            'schemaVersion = 1\n[[rules]]\npatterns = ["*.md"]\ncategory = "markdown"\n'
            'reason = "Canonical prose."\n[[rules]]\npatterns = ["*.toml"]\ncategory = "locale"\n'
            'reason = "Translation registry."\n[[rules]]\npatterns = ["src/*.py"]\n'
            'category = "package"\nreason = "Public API."\n'
        ),
        "docs/i18n/project.toml": 'reviewerTypes = ["human", "ai"]\n',
        "docs/guide.md": "# Setup\n\nExplain the supported setup.\n\n## Operation\n\nUse the explicit command.\n",
        "src/flayer/__init__.py": (
            '"""Canonical module description."""\n'
            'raise RuntimeError("Runtime import must never happen")\n\n'
            'def Inspect() -> str:\n    """Canonical callable description."""\n'
            '    return "unchanged"\n'
        ),
    }

    for name, body in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    return tmp_path


def ReviewRecord(unit: CanonicalUnit, body: str) -> dict[str, Any]:
    """Construct attributable fixture evidence independently of production validators."""

    return {"schemaVersion": 1, "id": unit.identifier, "sourcePath": unit.source_path,
            "sourceHash": CanonicalHash(unit), "body": body,
            "reviewedTranslationHash": generated_localization.TextHash(body),
            "reviewer": "Fixture reviewer", "reviewerType": "ai",
            "reviewedAt": "2026-10-09T07:00:00Z", "reviewRoles": ["editorial", "technical"]}


def WriteCatalog(root: Path, unit: CanonicalUnit, body: str) -> Path:
    """Track one fixture catalog using the documented page-record schema."""

    path = root / "docs/i18n/generated/ru/fixture.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    record = ReviewRecord(unit, body)
    path.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in record.items()) + "\n",
                    encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=root, check=True)

    return path


def test_GeneratedDiscoveryIncludesActualNarrativesAndSourceBoundSymbols(generated_project: Path) -> None:
    """Prose, module docstrings, and supported definitions are translation units without imports."""

    units = generated_localization.DiscoverGeneratedUnits(generated_project)

    assert {"repository:docs/guide.md", "module:flayer", "symbol:flayer.Inspect"} <= units.keys()
    assert units["symbol:flayer.Inspect"].signature == "def Inspect() -> str"
    assert any(identifier.startswith("coverage:") for identifier in units)


def test_GeneratedCatalogReviewBindsBothExactSourceAndTranslation(generated_project: Path) -> None:
    """Changing source signatures or translated bytes invalidates a previous review."""

    unit = generated_localization.DiscoverGeneratedUnits(generated_project)["symbol:flayer.Inspect"]
    record = ReviewRecord(unit, "Reviewed callable description.")

    assert generated_localization.ValidateTranslation(unit, record, ["human", "ai"]).state == "approved"
    changed = CanonicalUnit(unit.identifier, unit.kind, unit.source_path, "def Inspect() -> int", unit.body)
    assert generated_localization.ValidateTranslation(changed, record, ["human", "ai"]).state == "stale"
    record["body"] += " Changed afterward."
    assert generated_localization.ValidateTranslation(unit, record, ["human", "ai"]).state == "stale"


@pytest.mark.parametrize("change", ["reviewer", "roles", "timezone", "authority", "copied-source"])
def test_GeneratedReviewRequiresActualAttributionAndAuthority(generated_project: Path, change: str) -> None:
    """Incomplete reviews and copied English cannot acquire approved translation status."""

    unit = generated_localization.DiscoverGeneratedUnits(generated_project)["symbol:flayer.Inspect"]
    record = ReviewRecord(unit, "Reviewed description.")
    authority = ["human", "ai"]

    if change == "reviewer":
        record["reviewer"] = ""

    elif change == "roles":
        record["reviewRoles"] = ["editorial"]

    elif change == "timezone":
        record["reviewedAt"] = "2026-10-09T07:00:00"

    elif change == "authority":
        authority = ["human"]

    else:
        record["body"] = unit.body

    with pytest.raises(ValueError):
        generated_localization.ValidateTranslation(unit, record, authority)


def test_GeneratedCatalogCannotAlterRunnableExamples() -> None:
    """Translated prose cannot change commands, source code, or their ordering."""

    unit = CanonicalUnit("repository:guide.md", "page", "guide.md", "",
                         "# Guide\n\n```bash\nflayer check\n```\n")
    record = ReviewRecord(unit, "# Reviewed guide\n\n```bash\nflayer destroy\n```\n")

    with pytest.raises(ValueError, match="changed code examples"):
        generated_localization.ValidateTranslation(unit, record, ["ai"])


@pytest.mark.parametrize("change", ["labels", "node", "arrow", "direction", "state-id",
                                     "extra-edge", "caption-injection", "language", "command"])
def test_DiagramTranslationPreservesTopologyAndExecutableExamples(change: str) -> None:
    """Visible diagram prose can change, but nodes, aliases, edges, and shell commands cannot."""

    source = ('# Diagram\n\n```mermaid\nflowchart TD\n'
              '    Input["Explicit input"] --> Config["Configuration"]\n```\n\n'
              '```mermaid\nstateDiagram-v2\n    state "Planned" as Planned\n'
              '    state "Complete" as Complete\n'
              '    Planned --> Complete: operation finished\n```\n\n'
              '```bash\nflayer status\n```\n')
    translated = source.replace("# Diagram", "# Схема").replace('"Explicit input"', '"Ввод"')
    translated = translated.replace('"Configuration"', '"配置"').replace('"Planned"', '"План готов"')
    translated = translated.replace('"Complete"', '"Завершено"').replace("operation finished", "操作完成")
    substitutions = {
        "node": ('Config["配置"]', 'Changed["配置"]'),
        "arrow": ("Input[\"Ввод\"] -->", "Input[\"Ввод\"] ---"),
        "direction": ("flowchart TD", "flowchart LR"),
        "state-id": ('"План готов" as Planned', '"План готов" as Changed'),
        "extra-edge": ("操作完成", "操作完成\n    Complete --> Planned"),
        "caption-injection": ("操作完成", "操作完成; Complete --> Planned"),
        "language": ("```mermaid", "```bash"),
        "command": ("flayer status", "flayer destroy"),
    }

    if change in substitutions:
        translated = translated.replace(*substitutions[change])

    unit = CanonicalUnit("repository:diagram.md", "page", "diagram.md", "", source)
    record = ReviewRecord(unit, translated)

    if change == "labels":
        assert generated_localization.ValidateTranslation(unit, record, ["ai"]).state == "approved"

    else:
        with pytest.raises(ValueError, match="changed code examples"):
            generated_localization.ValidateTranslation(unit, record, ["ai"])


def test_TrackedCatalogsDoNotConcealNewMissingContracts(generated_project: Path) -> None:
    """Approved catalog entries never imply coverage of newly discovered source units."""

    units = generated_localization.DiscoverGeneratedUnits(generated_project)
    unit = units["symbol:flayer.Inspect"]
    WriteCatalog(generated_project, unit, "Reviewed callable description.")
    translations = generated_localization.LoadTranslations(generated_project, units)
    states = generated_localization.TranslationStates(units, translations)

    assert states[unit.identifier] == {"ru": "approved", "zh-CN": "missing"}

    with pytest.raises(ValueError, match="Documentation translation is incomplete"):
        generated_localization.RequireComplete(states)


def test_UntrackedAndUnknownCatalogsFailClosed(generated_project: Path) -> None:
    """Local files and unknown source identities cannot enter reproducible translations."""

    units = generated_localization.DiscoverGeneratedUnits(generated_project)
    path = WriteCatalog(generated_project, units["symbol:flayer.Inspect"], "Reviewed description.")
    subprocess.run(["git", "rm", "--cached", str(path)], cwd=generated_project, check=True,
                   capture_output=True)

    with pytest.raises(ValueError, match="Untracked or redirected"):
        generated_localization.LoadTranslations(generated_project, units)

    subprocess.run(["git", "add", "."], cwd=generated_project, check=True)
    path.write_text(path.read_text().replace("symbol:flayer.Inspect", "symbol:flayer.Invented"))

    with pytest.raises(ValueError, match="Unknown or repeated"):
        generated_localization.LoadTranslations(generated_project, units)


def test_TranslatedHeadingsKeepCanonicalLinksAndRejectOmittedSections() -> None:
    """Translation preserves exact English section anchors and cannot omit source sections."""

    pytest.importorskip("markdown")
    canonical = "# Setup\n\n## Runtime options\n\n## Runtime options\n"
    target = "# Installation\n\n## Supported settings\n\n## Repeated settings\n"
    result = generated_localization.CanonicalHeadingAnchors(canonical, target)

    assert "# Installation {#setup}" in result
    assert "## Supported settings {#runtime-options}" in result
    assert "## Repeated settings {#runtime-options_1}" in result

    with pytest.raises(ValueError, match="preserve every heading"):
        generated_localization.CanonicalHeadingAnchors(canonical, "# Incomplete guide\n")


def test_GriffeChangesOnlyDocumentationObjects(generated_project: Path, tmp_path: Path) -> None:
    """Real static extraction localizes prose while preserving code and avoiding runtime imports."""

    griffe = pytest.importorskip("griffe")
    from tools.translated_docstrings import TranslatedDocstrings

    overlay = tmp_path / "overlay.json"
    overlay.write_text(json.dumps({"flayer.Inspect": "Reviewed callable description."}))
    module = griffe.load("flayer", search_paths=[generated_project / "src"], allow_inspection=False,
                         extensions=griffe.Extensions(TranslatedDocstrings(str(overlay))))

    assert module["Inspect"].docstring.value == "Reviewed callable description."
    assert '"""Canonical callable description."""' in module["Inspect"].source
    assert 'return "unchanged"' in module["Inspect"].source


def test_CoverageLocalizationKeepsExactFilePathsAndMachineDispositions(generated_project: Path) -> None:
    """Coverage is rendered from the real inventory while only natural-language cells change."""

    files = documentation_coverage.InventoryFiles(generated_project)
    localized = documentation_coverage.RenderInventory(files, [], lambda value: "Reviewed " + value)

    assert "[docs/guide.md](../repository/docs/guide.md)" in localized
    assert "`rendered-markdown`" in localized
    assert "Reviewed Canonical prose." in localized


def test_MkdocsLoadsTheExactLocaleExtensionWithoutImportingRuntime(
    generated_project: Path, tmp_path: Path,
) -> None:
    """A one-page strict build proves the actual handler loads reviewed prose and keeps API anchors."""

    pytest.importorskip("mkdocstrings_handlers.python")
    import sys

    content = tmp_path / "content"
    content.mkdir()
    (content / "index.md").write_text("# API\n\n::: flayer\n", encoding="utf-8")
    module_path = generated_project / "src/flayer/__init__.py"
    module_path.write_text(module_path.read_text() + (
        '\nclass Client:\n    """Canonical class description."""\n'
        '    def __init__(self) -> None:\n        """Canonical constructor description."""\n'
        '        self.value = 1\n'
    ))
    overlay = tmp_path / "overlay.json"
    overlay.write_text(json.dumps({"flayer": "Reviewed module description.",
                                   "flayer.Inspect": "Reviewed callable description.",
                                   "flayer.Client": "Reviewed class description.",
                                   "flayer.Client.__init__": "Reviewed constructor description."}))
    project_root = Path(__file__).resolve().parents[2]
    extension = project_root / "tools/translated_docstrings.py"
    templates = generated_localization.WriteApiTemplates(project_root, tmp_path, "ru")
    config = tmp_path / "mkdocs.yml"
    config.write_text(
        "site_name: Fixture\nstrict: true\ntheme:\n  name: material\n  language: ru\n"
        f"docs_dir: {json.dumps(str(content))}\n"
        f"site_dir: {json.dumps(str(tmp_path / 'site'))}\n"
        "plugins:\n  - mkdocstrings:\n"
        f"      custom_templates: {json.dumps(str(templates))}\n"
        "      handlers:\n        python:\n"
        f"          paths: [{json.dumps(str(generated_project / 'src'))}]\n"
        "          options:\n            extensions: "
        + json.dumps([{str(extension): {"translations_path": str(overlay)}}]) + "\n"
        "            allow_inspection: false\n            show_source: true\n"
        "            merge_init_into_class: true\n",
        encoding="utf-8",
    )
    process = subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict", "-f", str(config)],
                             capture_output=True, text=True)

    assert process.returncode == 0, process.stdout + process.stderr
    rendered = (tmp_path / "site/index.html").read_text(encoding="utf-8")
    assert "Reviewed callable description." in rendered
    assert "Reviewed class description." in rendered
    assert "Reviewed constructor description." in rendered
    labels = tomllib.loads((project_root / "docs/i18n/api-labels.toml").read_text())["ru"]
    assert labels["Source code in"] in rendered
    assert "Source code in" not in rendered
    assert 'id="flayer.Inspect"' in rendered
    assert "Runtime import must never happen" in (generated_project / "src/flayer/__init__.py").read_text()


def test_ApprovedMarkerCannotSubstituteForRenderedApiProse(tmp_path: Path) -> None:
    """An approved flag and translated source listing do not prove localized API narrative."""

    pytest.importorskip("markdown")
    unit = CanonicalUnit("symbol:flayer.Inspect", "symbol", "src/flayer/__init__.py", "def Inspect()", "English.")
    entry = generated_localization.ValidateTranslation(unit, ReviewRecord(unit, "Reviewed prose."), ["ai"])
    page = tmp_path / "ru/api/modules/flayer/index.html"
    page.parent.mkdir(parents=True)
    page.write_text('<aside data-translation-state="approved"></aside><pre>Reviewed prose.</pre><p>English.</p>')

    with pytest.raises(ValueError, match="was not rendered"):
        generated_localization.VerifyApiProse(tmp_path, "ru", {unit.identifier: unit}, {unit.identifier: entry})

    page.write_text('<p>Reviewed prose.</p><pre>English.</pre>')
    generated_localization.VerifyApiProse(tmp_path, "ru", {unit.identifier: unit}, {unit.identifier: entry})


def test_NestedPublicConstructorsRemainTranslationRequirements(generated_project: Path) -> None:
    """Nested class prose must not disappear while private and function-local classes stay source-only."""

    path = generated_project / "src/flayer/__init__.py"
    path.write_text(path.read_text() + (
        '\nclass Outer:\n    """Public outer class."""\n'
        '    class Inner:\n        """Public nested class."""\n'
        '        def __init__(self) -> None:\n            """Rendered nested constructor."""\n'
        '            pass\n'
        '    class _Private:\n        def __init__(self) -> None:\n'
        '            """Private constructor."""\n            pass\n'
    ))
    units = generated_localization.DiscoverGeneratedUnits(generated_project)

    assert "symbol:flayer.Outer.Inner.__init__" in units
    assert not any("_Private" in identifier for identifier in units)
