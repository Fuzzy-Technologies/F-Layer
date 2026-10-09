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

from tools import documentation_coverage
from tools.locale_documentation import CanonicalHash, CanonicalUnit, _AuthoredUnits, _NodeUnit

CATALOG_ROOT = "docs/i18n/generated"
LOCALES = ("ru", "zh-CN")
CODE_FENCE = re.compile(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*$")


@dataclass(frozen=True)
class ReviewedTranslation:
    """A translation bound to one source contract and its exact reviewed bytes."""

    body: str
    state: str
    source_hash: str
    translation_hash: str
    reviewer_type: str


def TextHash(body: str) -> str:
    """Hash normalized UTF-8 text without changing meaningful whitespace."""

    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def DiscoverGeneratedUnits(project_root: Path) -> dict[str, CanonicalUnit]:
    """Inventory canonical engineering prose and public API contracts statically."""

    units = {}

    for item in documentation_coverage.InventoryFiles(project_root):
        path = project_root / item.source_path

        if (item.disposition == "rendered-markdown"
                and not item.source_path.startswith(documentation_coverage.SOURCE_CONTENT_PREFIX)):
            identifier = "repository:" + item.source_path
            units[identifier] = CanonicalUnit(identifier, "page", item.source_path, "",
                                               path.read_text(encoding="utf-8"))

        elif item.disposition == "generated-api":
            module = documentation_coverage.ModuleName(item.source_path)
            identifier = "module:" + module
            syntax = ast.parse(path.read_text(encoding="utf-8"))
            units[identifier] = CanonicalUnit(identifier, "symbol", item.source_path, "",
                                               ast.get_docstring(syntax, clean=False) or "")

            for unit in _AuthoredUnits(module, path, project_root):
                units[unit.identifier] = unit

            units.update(RenderedConstructors(syntax, module, item.source_path, units))

    for message in CoverageMessages(project_root):
        identifier = "coverage:" + TextHash(message).removeprefix("sha256:")
        units[identifier] = CanonicalUnit(identifier, "page", "tools/documentation_coverage.py", "", message)

    return units


def RenderedConstructors(
    syntax: ast.Module, module: str, source_path: str, known_units: Mapping[str, CanonicalUnit],
) -> dict[str, CanonicalUnit]:
    """Include merged constructor prose only inside statically discovered public classes."""

    result = {}

    def Visit(node: ast.AST, parent: str) -> None:
        """Follow conditional and nested class scopes without entering function-local classes."""

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return

        if isinstance(node, ast.ClassDef):
            parent += "." + node.name

            if "symbol:" + parent not in known_units:
                return

            for member in node.body:
                if (isinstance(member, ast.FunctionDef) and member.name == "__init__"
                        and ast.get_docstring(member)):
                    identifier = f"symbol:{parent}.__init__"
                    result[identifier] = _NodeUnit(identifier, source_path, member)

        for child in ast.iter_child_nodes(node):
            Visit(child, parent)

    Visit(syntax, module)

    return result


def CoverageMessages(project_root: Path) -> tuple[str, ...]:
    """Collect every rendered coverage sentence from the canonical renderer itself."""

    messages: set[str] = set()
    files = documentation_coverage.InventoryFiles(project_root)
    definitions: list[documentation_coverage.DefinitionCoverage] = []

    for item in files:
        if item.category == "package":
            syntax = ast.parse((project_root / item.source_path).read_text(encoding="utf-8"))
            definitions.extend(documentation_coverage.InventoryDefinitions(item.source_path, syntax))

    def Collect(message: str) -> str:
        """Retain one canonical sentence while exercising the actual coverage renderer."""

        messages.add(message)

        return message

    documentation_coverage.RenderInventory(files, definitions, Collect)

    return tuple(sorted(messages))


def RenderCoverage(
    project_root: Path, translations: Mapping[str, ReviewedTranslation],
) -> tuple[str, str]:
    """Translate inventory prose only when every message has current attributable review."""

    messages = CoverageMessages(project_root)
    entries = {message: translations.get("coverage:" + TextHash(message).removeprefix("sha256:"))
               for message in messages}
    states = [entry.state if entry else "missing" for entry in entries.values()]
    state = ("approved" if all(value == "approved" for value in states)
             else "stale" if "stale" in states else "missing")
    files = documentation_coverage.InventoryFiles(project_root)
    definitions: list[documentation_coverage.DefinitionCoverage] = []

    for item in files:
        if item.category == "package":
            syntax = ast.parse((project_root / item.source_path).read_text(encoding="utf-8"))
            definitions.extend(documentation_coverage.InventoryDefinitions(item.source_path, syntax))

    def Translate(message: str) -> str:
        """Use translated prose only for a completely reviewed coverage page."""

        entry = entries[message]

        return entry.body if state == "approved" and entry else message

    return documentation_coverage.RenderInventory(files, definitions, Translate), state


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
    unit: CanonicalUnit, record: Mapping[str, Any], reviewer_types: Sequence[str],
) -> ReviewedTranslation:
    """Reject malformed reviews and classify source or translated-byte drift as stale."""

    body = record.get("body")
    reviewer_type = record.get("reviewerType")

    if (not isinstance(body, str) or not body.strip() or body == unit.body
            or record.get("sourcePath") != unit.source_path
            or reviewer_type not in reviewer_types
            or not isinstance(record.get("reviewer"), str) or not record["reviewer"].strip()
            or set(record.get("reviewRoles", ())) != {"editorial", "technical"}):
        raise ValueError(f"Generated translation lacks attributable complete review: {unit.identifier}")

    try:
        reviewed_at = datetime.fromisoformat(record["reviewedAt"].replace("Z", "+00:00"))

    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError(f"Generated translation lacks review timestamp: {unit.identifier}") from error

    if reviewed_at.tzinfo is None:
        raise ValueError(f"Generated translation review requires timezone: {unit.identifier}")

    for field in ("sourceHash", "reviewedTranslationHash"):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(record.get(field, ""))):
            raise ValueError(f"Generated translation lacks {field}: {unit.identifier}")

    source_hash = CanonicalHash(unit)
    translation_hash = TextHash(body)
    state = "approved"

    if (record["sourceHash"] != source_hash
            or record["reviewedTranslationHash"] != translation_hash):
        state = "stale"

    source_code = [DiagramStructure(match.group(0)) for match in CODE_FENCE.finditer(unit.body)]
    translated_code = [DiagramStructure(match.group(0)) for match in CODE_FENCE.finditer(body)]

    if source_code != translated_code:
        raise ValueError(f"Generated translation changed code examples: {unit.identifier}")

    return ReviewedTranslation(body, state, source_hash, translation_hash, str(reviewer_type))


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
    project_root: Path, units: Mapping[str, CanonicalUnit],
) -> dict[str, dict[str, ReviewedTranslation]]:
    """Read tracked catalogs and reject duplicates, unknown source IDs, or forged reviews."""

    root = project_root / CATALOG_ROOT
    results: dict[str, dict[str, ReviewedTranslation]] = {locale: {} for locale in LOCALES}

    if not root.exists():
        return results

    project = tomllib.loads((project_root / "docs/i18n/project.toml").read_text(encoding="utf-8"))
    reviewer_types = project.get("reviewerTypes", ["human"])
    tracked = set(documentation_coverage.TrackedFiles(project_root))

    for locale in LOCALES:
        for path in sorted((root / locale).rglob("*.toml")):
            if (path.is_symlink() or not path.resolve().is_relative_to(root.resolve())
                    or path.relative_to(project_root).as_posix() not in tracked):
                raise ValueError(f"Untracked or redirected generated translation: {locale}/{path.name}")

            for record in CatalogEntries(path):
                identifier = record.get("id", "repository:" + record.get("sourcePath", ""))

                if identifier not in units or identifier in results[locale]:
                    raise ValueError(f"Unknown or repeated generated translation: {locale}:{identifier}")

                results[locale][identifier] = ValidateTranslation(units[identifier], record,
                                                                 reviewer_types)

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
    project_root: Path, build_root: Path, locale: str,
    translations: Mapping[str, ReviewedTranslation], units: Mapping[str, CanonicalUnit],
) -> tuple[Path, Path]:
    """Write validated prose for static Griffe extraction while leaving wheel source intact."""

    target = build_root / f"api-docstrings-{locale}.json"
    complete_sources = {unit.source_path for unit in units.values() if unit.kind == "symbol"}

    for identifier, unit in units.items():
        if unit.kind == "symbol" and (identifier not in translations or translations[identifier].state != "approved"):
            complete_sources.discard(unit.source_path)

    payload = {identifier.split(":", 1)[1]: entry.body
               for identifier, entry in translations.items()
               if identifier.startswith(("symbol:", "module:")) and entry.state == "approved"
               and units[identifier].source_path in complete_sources}
    target.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    extension = project_root / "tools/translated_docstrings.py"

    return extension, target


class _ProseParser(html.parser.HTMLParser):
    """Read displayed narrative while excluding verbatim source listings."""

    def __init__(self) -> None:
        """Initialize an isolated HTML text collector."""

        super().__init__(convert_charrefs=True)
        self.pre_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Respect HTMLParser's callback name and track literal source blocks."""

        if tag == "pre":
            self.pre_depth += 1

        elif tag in {"p", "div", "br", "li", "td", "th"}:
            self.parts.append(" ")

    def handle_endtag(self, tag: str) -> None:
        """Separate prose blocks while keeping inline markup text contiguous."""

        if tag == "pre":
            self.pre_depth -= 1

        elif tag in {"p", "div", "li", "td", "th"}:
            self.parts.append(" ")

    def handle_data(self, data: str) -> None:
        """Collect visible text outside original Python source listings."""

        if not self.pre_depth:
            self.parts.append(data)

    def Text(self) -> str:
        """Return normalized displayed text for exact translation comparisons."""

        return " ".join("".join(self.parts).split())


def VerifyApiProse(
    site_root: Path, locale: str, units: Mapping[str, CanonicalUnit],
    translations: Mapping[str, ReviewedTranslation],
) -> None:
    """Require reviewed prose in real API output, not only an approved-state marker."""

    markdown = importlib.import_module("markdown")

    api_units = {identifier: unit for identifier, unit in units.items() if unit.kind == "symbol"}
    complete_sources = {unit.source_path for unit in api_units.values()}

    for identifier, unit in api_units.items():
        if identifier not in translations or translations[identifier].state != "approved":
            complete_sources.discard(unit.source_path)

    displayed: dict[str, str] = {}

    for source_path in sorted(complete_sources):
        module = documentation_coverage.ModuleName(source_path)
        page = site_root / locale / "api/modules" / module.replace(".", "-") / "index.html"
        parser = _ProseParser()
        parser.feed(page.read_text(encoding="utf-8"))
        displayed[source_path] = parser.Text()

    for identifier, unit in api_units.items():
        if unit.source_path not in complete_sources:
            continue

        expected = _ProseParser()
        expected.feed(markdown.markdown(translations[identifier].body))

        if expected.Text() not in displayed[unit.source_path]:
            raise ValueError(f"Reviewed API translation was not rendered: {locale}:{identifier}")


def WriteApiTemplates(project_root: Path, build_root: Path, locale: str) -> Path:
    """Localize the pinned handler's interface labels without copying its source templates."""

    handler = importlib.import_module("mkdocstrings_handlers.python")

    if handler.__file__ is None:
        raise ValueError("Installed API handler has no template source path")

    handler_root = Path(handler.__file__).parent
    source = (handler_root / "templates/material/_base/languages/en.html.jinja").read_text(encoding="utf-8")
    expected = set(re.findall(r'^\s*"([^"\n]+)"\s*:', source, re.MULTILINE))
    labels = tomllib.loads((project_root / "docs/i18n/api-labels.toml").read_text(encoding="utf-8"))[locale]

    if not expected or set(labels) != expected or any(not isinstance(value, str) or not value for value in labels.values()):
        raise ValueError("API interface translations do not match the pinned handler's label inventory")

    root = build_root / "locale-templates" / locale
    language = "zh" if locale == "zh-CN" else locale
    destination = root / "python/material/languages" / f"{language}.html.jinja"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("{% macro t(key) %}{{ " + json.dumps(labels, ensure_ascii=False)
                           + "[key] }}{% endmacro %}\n", encoding="utf-8")

    return root
