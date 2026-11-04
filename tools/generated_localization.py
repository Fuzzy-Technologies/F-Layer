"""Validate reviewed translations for generated API and repository documentation."""

from __future__ import annotations

import ast
import hashlib
import html.parser
import importlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from tools import documentation_coverage as documentationCoverage
from tools.locale_documentation import CanonicalHash, CanonicalUnit, _AuthoredUnits, _NodeUnit

CATALOG_ROOT = "docs/i18n/generated"
LOCALES = ("ru", "zh-CN")
CODE_FENCE = re.compile(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$")


@dataclass(frozen=True)
class ReviewedTranslation:
    """A translation bound to one source contract and its exact reviewed bytes."""

    body: str
    state: str
    sourceHash: str
    translationHash: str
    reviewerType: str


def TextHash(body: str) -> str:
    """Hash normalized UTF-8 text without changing meaningful whitespace."""

    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def DiscoverGeneratedUnits(projectRoot: Path) -> dict[str, CanonicalUnit]:
    """Inventory canonical engineering prose and public API contracts statically."""

    units = {}

    for item in documentationCoverage.InventoryFiles(projectRoot):
        path = projectRoot / item.sourcePath

        if (item.disposition == "rendered-markdown"
                and not item.sourcePath.startswith(documentationCoverage.SOURCE_CONTENT_PREFIX)):
            identifier = "repository:" + item.sourcePath
            units[identifier] = CanonicalUnit(identifier, "page", item.sourcePath, "",
                                               path.read_text(encoding="utf-8"))

        elif item.disposition == "generated-api":
            module = documentationCoverage.ModuleName(item.sourcePath)
            identifier = "module:" + module
            syntax = ast.parse(path.read_text(encoding="utf-8"))
            units[identifier] = CanonicalUnit(identifier, "symbol", item.sourcePath, "",
                                               ast.get_docstring(syntax, clean=False) or "")

            for unit in _AuthoredUnits(module, path, projectRoot):
                units[unit.identifier] = unit

            units.update(RenderedConstructors(syntax, module, item.sourcePath, units))

    for message in CoverageMessages(projectRoot):
        identifier = "coverage:" + TextHash(message).removeprefix("sha256:")
        units[identifier] = CanonicalUnit(identifier, "page", "tools/documentation_coverage.py", "", message)

    return units


def RenderedConstructors(
    syntax: ast.Module, module: str, sourcePath: str, knownUnits: Mapping[str, CanonicalUnit],
) -> dict[str, CanonicalUnit]:
    """Include merged constructor prose only inside statically discovered public classes."""

    result = {}

    def Visit(node: ast.AST, parent: str) -> None:
        """Follow conditional and nested class scopes without entering function-local classes."""

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        if isinstance(node, ast.ClassDef):
            parent += "." + node.name

            if "symbol:" + parent not in knownUnits:
                return

            for member in node.body:
                if (isinstance(member, ast.FunctionDef) and member.name == "__init__"
                        and ast.get_docstring(member)):
                    identifier = f"symbol:{parent}.__init__"
                    result[identifier] = _NodeUnit(identifier, sourcePath, member)

        for child in ast.iter_child_nodes(node):
            Visit(child, parent)

    Visit(syntax, module)

    return result


def CoverageMessages(projectRoot: Path) -> tuple[str, ...]:
    """Collect every rendered coverage sentence from the canonical renderer itself."""

    messages: set[str] = set()
    files = documentationCoverage.InventoryFiles(projectRoot)
    definitions: list[documentationCoverage.DefinitionCoverage] = []

    for item in files:
        if item.category == "package":
            syntax = ast.parse((projectRoot / item.sourcePath).read_text(encoding="utf-8"))
            definitions.extend(documentationCoverage.InventoryDefinitions(item.sourcePath, syntax))

    def Collect(message: str) -> str:
        """Retain one canonical sentence while exercising the actual coverage renderer."""

        messages.add(message)

        return message

    documentationCoverage.RenderInventory(files, definitions, Collect)

    return tuple(sorted(messages))


def RenderCoverage(
    projectRoot: Path, translations: Mapping[str, ReviewedTranslation],
) -> tuple[str, str]:
    """Translate inventory prose only when every message has current attributable review."""

    messages = CoverageMessages(projectRoot)
    entries = {message: translations.get("coverage:" + TextHash(message).removeprefix("sha256:"))
               for message in messages}
    states = [entry.state if entry else "missing" for entry in entries.values()]
    state = ("approved" if all(value == "approved" for value in states)
             else "stale" if "stale" in states else "missing")
    files = documentationCoverage.InventoryFiles(projectRoot)
    definitions: list[documentationCoverage.DefinitionCoverage] = []

    for item in files:
        if item.category == "package":
            syntax = ast.parse((projectRoot / item.sourcePath).read_text(encoding="utf-8"))
            definitions.extend(documentationCoverage.InventoryDefinitions(item.sourcePath, syntax))

    def Translate(message: str) -> str:
        """Use translated prose only for a completely reviewed coverage page."""

        entry = entries[message]

        return entry.body if state == "approved" and entry else message

    return documentationCoverage.RenderInventory(files, definitions, Translate), state


def CatalogEntries(path: Path) -> tuple[dict[str, Any], ...]:
    """Read one page catalog or a collection of API contracts without implicit defaults."""

    payload = tomllib.loads(path.read_text(encoding="utf-8"))

    if payload.get("schemaVersion") != 1:
        raise ValueError(f"Generated translation catalog requires schemaVersion 1: {path.name}")

    if "units" in payload:
        records = payload["units"]

        if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
            raise ValueError(f"Generated translation catalog requires table records: {path.name}")

        return tuple(records)

    return (payload,)


def ValidateTranslation(
    unit: CanonicalUnit, record: Mapping[str, Any], reviewerTypes: Sequence[str],
) -> ReviewedTranslation:
    """Reject malformed reviews and classify source or translated-byte drift as stale."""

    body = record.get("body")
    reviewerType = record.get("reviewerType")

    if (not isinstance(body, str) or not body.strip() or body == unit.body
            or record.get("sourcePath") != unit.sourcePath
            or reviewerType not in reviewerTypes
            or not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip()
            or set(record.get("reviewRoles", ())) != {"editorial", "technical"}):
        raise ValueError(f"Generated translation lacks attributable complete review: {unit.identifier}")

    try:
        reviewedAt = datetime.fromisoformat(record["reviewedAt"].replace("Z", "+00:00"))

    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError(f"Generated translation lacks review timestamp: {unit.identifier}") from error

    if reviewedAt.tzinfo is None:
        raise ValueError(f"Generated translation review requires timezone: {unit.identifier}")

    for field in ("sourceHash", "reviewedTranslationHash"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(record.get(field, ""))):
            raise ValueError(f"Generated translation lacks {field}: {unit.identifier}")

    sourceHash = CanonicalHash(unit)
    translationHash = TextHash(body)
    state = "approved"

    if (record["sourceHash"] != sourceHash
            or record["reviewedTranslationHash"] != translationHash):
        state = "stale"

    sourceCode = [DiagramStructure(match.group(0)) for match in CODE_FENCE.finditer(unit.body)]
    translatedCode = [DiagramStructure(match.group(0)) for match in CODE_FENCE.finditer(body)]

    if sourceCode != translatedCode:
        raise ValueError(f"Generated translation changed code examples: {unit.identifier}")

    return ReviewedTranslation(body, state, sourceHash, translationHash, str(reviewerType))


def DiagramStructure(fence: str) -> str:
    """Permit diagram-label translation while preserving topology and every executable example."""

    if not re.match(r"^(?:`{3,}|~{3,})mermaid\n", fence):
        return fence

    # Only quoted node labels, explicit state aliases, and transition captions are prose.
    # Everything outside those positions, including identifiers and arrows, stays exact.
    prose = r"[\w ,.!?():/—–+\-]+"
    normalized = re.sub(rf'(\b[A-Za-z_]\w*\["){prose}("\])', r"\1<label>\2", fence)
    normalized = re.sub(rf'(?m)^(\s*state "){prose}(" as [A-Za-z_]\w*)$',
                        r"\1<label>\2", normalized)
    node = r"(?:[A-Za-z_]\w*|\[\*\])"
    normalized = re.sub(rf"(?m)^(\s*{node} --> {node}: ){prose}$", r"\1<label>", normalized)

    return normalized


def LoadTranslations(
    projectRoot: Path, units: Mapping[str, CanonicalUnit],
) -> dict[str, dict[str, ReviewedTranslation]]:
    """Read tracked catalogs and reject duplicates, unknown source IDs, or forged reviews."""

    root = projectRoot / CATALOG_ROOT
    results: dict[str, dict[str, ReviewedTranslation]] = {locale: {} for locale in LOCALES}

    if not root.exists():
        return results

    project = tomllib.loads((projectRoot / "docs/i18n/project.toml").read_text(encoding="utf-8"))
    reviewerTypes = project.get("reviewerTypes", ["human"])
    tracked = set(documentationCoverage.TrackedFiles(projectRoot))

    for locale in LOCALES:
        for path in sorted((root / locale).rglob("*.toml")):
            if (path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
                    or path.relative_to(projectRoot).as_posix() not in tracked):
                raise ValueError(f"Untracked or redirected generated translation: {locale}/{path.name}")

            for record in CatalogEntries(path):
                identifier = record.get("id", "repository:" + record.get("sourcePath", ""))

                if identifier not in units or identifier in results[locale]:
                    raise ValueError(f"Unknown or repeated generated translation: {locale}:{identifier}")

                results[locale][identifier] = ValidateTranslation(units[identifier], record,
                                                                 reviewerTypes)

    return results


def CanonicalHeadingAnchors(canonical: str, translated: str) -> str:
    """Retain canonical heading URLs so translated links target the same document sections."""

    slugify = importlib.import_module("markdown.extensions.toc").slugify

    def Headings(body: str) -> list[tuple[int, str, str]]:
        """Locate authored ATX headings without interpreting fenced source code."""

        result = []
        fence = ""

        for index, line in enumerate(body.splitlines()):
            marker = re.match(r"^\s*(`{3,}|~{3,})", line)

            if marker:
                fence = "" if fence and marker[1].startswith(fence[0]) else marker[1]
                continue

            match = re.match(r"^(#{1,6})\s+(.+?)\s*#*\s*$", line)

            if not fence and match:
                result.append((index, match[1], match[2]))

        return result

    original = Headings(canonical)
    target = Headings(translated)

    if [entry[1] for entry in original] != [entry[1] for entry in target]:
        raise ValueError("Repository translation must preserve every heading and its level")

    lines = translated.splitlines()
    used: dict[str, int] = {}

    for source, destination in zip(original, target, strict=True):
        explicit = re.search(r"\s*\{#([^}]+)\}\s*$", source[2])
        anchor = explicit[1] if explicit else slugify(re.sub(r"[`*_]", "", source[2]), "-")
        count = used.get(anchor, 0)
        used[anchor] = count + 1
        anchor = anchor + f"_{count}" if count else anchor
        line = re.sub(r"\s*\{#[^}]+\}\s*$", "", lines[destination[0]])
        lines[destination[0]] = line + " {#" + anchor + "}"

    return "\n".join(lines) + ("\n" if translated.endswith("\n") else "")


def TranslationStates(
    units: Mapping[str, CanonicalUnit], translations: Mapping[str, Mapping[str, ReviewedTranslation]],
) -> dict[str, dict[str, str]]:
    """Report every discovered source independently of available catalog records."""

    return {identifier: {locale: translations[locale][identifier].state
                         if identifier in translations[locale] else "missing"
                         for locale in LOCALES} for identifier in units}


def RequireComplete(states: Mapping[str, Mapping[str, str]]) -> None:
    """Block release publication whenever any discovered narrative lacks current review."""

    incomplete = [f"{locale}:{identifier} ({state})" for identifier, locales in states.items()
                  for locale, state in locales.items() if state != "approved"]

    if incomplete:
        raise ValueError("Documentation translation is incomplete:\n" + "\n".join(incomplete))


def WriteApiOverlay(
    projectRoot: Path, buildRoot: Path, locale: str,
    translations: Mapping[str, ReviewedTranslation], units: Mapping[str, CanonicalUnit],
) -> tuple[Path, Path]:
    """Write validated prose for static Griffe extraction while leaving wheel source intact."""

    target = buildRoot / f"api-docstrings-{locale}.json"
    completeSources = {unit.sourcePath for unit in units.values() if unit.kind == "symbol"}

    for identifier, unit in units.items():
        if unit.kind == "symbol" and (identifier not in translations or translations[identifier].state != "approved"):
            completeSources.discard(unit.sourcePath)

    payload = {identifier.split(":", 1)[1]: entry.body
               for identifier, entry in translations.items()
               if identifier.startswith(("symbol:", "module:")) and entry.state == "approved"
               and units[identifier].sourcePath in completeSources}
    target.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    extension = projectRoot / "tools/translated_docstrings.py"

    return extension, target


class _ProseParser(html.parser.HTMLParser):
    """Read displayed narrative while excluding verbatim source listings."""

    def __init__(self) -> None:
        """Initialize an isolated HTML text collector."""

        super().__init__(convert_charrefs=True)
        self.preDepth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Respect HTMLParser's callback name and track literal source blocks."""

        if tag == "pre":
            self.preDepth += 1

        elif tag in {"p", "div", "br", "li", "td", "th"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        """Separate prose blocks while keeping inline markup text contiguous."""

        if tag == "pre":
            self.preDepth -= 1

        elif tag in {"p", "div", "li", "td", "th"}:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        """Collect visible text outside original Python source listings."""

        if not self.preDepth:
            self.parts.append(data)

    def Text(self) -> str:
        """Return normalized displayed text for exact translation comparisons."""

        return " ".join("".join(self.parts).split())


def VerifyApiProse(
    siteRoot: Path, locale: str, units: Mapping[str, CanonicalUnit],
    translations: Mapping[str, ReviewedTranslation],
) -> None:
    """Require reviewed prose in real API output, not only an approved-state marker."""

    markdown = importlib.import_module("markdown")

    apiUnits = {identifier: unit for identifier, unit in units.items() if unit.kind == "symbol"}
    completeSources = {unit.sourcePath for unit in apiUnits.values()}

    for identifier, unit in apiUnits.items():
        if identifier not in translations or translations[identifier].state != "approved":
            completeSources.discard(unit.sourcePath)

    displayed: dict[str, str] = {}

    for sourcePath in sorted(completeSources):
        module = documentationCoverage.ModuleName(sourcePath)
        page = siteRoot / locale / "api/modules" / module.replace(".", "-") / "index.html"
        parser = _ProseParser()
        parser.feed(page.read_text(encoding="utf-8"))
        displayed[sourcePath] = parser.Text()

    for identifier, unit in apiUnits.items():
        if unit.sourcePath not in completeSources:
            continue

        expected = _ProseParser()
        expected.feed(markdown.markdown(translations[identifier].body))

        if expected.Text() not in displayed[unit.sourcePath]:
            raise ValueError(f"Reviewed API translation was not rendered: {locale}:{identifier}")


def WriteApiTemplates(projectRoot: Path, buildRoot: Path, locale: str) -> Path:
    """Localize the pinned handler's interface labels without copying its source templates."""

    handler = importlib.import_module("mkdocstrings_handlers.python")

    if handler.__file__ is None:
        raise ValueError("Installed API handler has no template source path")

    handlerRoot = Path(handler.__file__).parent
    source = (handlerRoot / "templates/material/_base/languages/en.html.jinja").read_text(encoding="utf-8")
    expected = set(re.findall(r'^\s*"([^"\n]+)"\s*:', source, re.MULTILINE))
    labels = tomllib.loads((projectRoot / "docs/i18n/api-labels.toml").read_text(encoding="utf-8"))[locale]

    if not expected or set(labels) != expected or any(not isinstance(value, str) or not value for value in labels.values()):
        raise ValueError("API interface translations do not match the pinned handler's label inventory")

    root = buildRoot / "locale-templates" / locale
    language = "zh" if locale == "zh-CN" else locale
    destination = root / "python/material/languages" / f"{language}.html.jinja"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("{% macro t(key) %}{{ " + json.dumps(labels, ensure_ascii=False)
                           + "[key] }}{% endmacro %}\n", encoding="utf-8")

    return root
