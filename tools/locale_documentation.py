# Project: F-Layer by Fuzzy Technologies
# Maintainer: Fuzzy Technologies contributors
# Ported from the Fuzzy Technologies documentation blueprint; naming only is adapted.
# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Validate multilingual documentation identity, review state, and source drift.

The validator reads only tracked UTF-8 source and TOML metadata. It never
imports the documented package, accesses the network, changes review state, or treats a
generated site as canonical documentation.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_MANIFEST = PROJECT_ROOT / "docs" / "i18n" / "project.toml"
HASH_SCHEME = "fuzzy-doc-unit-v1"
HASH_FORMAT = re.compile(r"^sha256:[0-9a-f]{64}$")
PAGE_ID_FORMAT = re.compile(r"^page:[a-z0-9]+(?:[.-][a-z0-9]+)*$")
SYMBOL_ID_FORMAT = re.compile(
    r"^symbol:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$"
)
CONCEPT_ID_FORMAT = re.compile(
    r"^concept:[a-z0-9]+(?:[.-][a-z0-9]+)*$"
)
LOCALE_FORMAT = re.compile(r"^[a-z]{2,3}(?:-[A-Z][A-Za-z0-9]{1,7})?$")
TRANSLATION_STATES = frozenset(
    {"missing", "draft", "review", "approved", "stale", "retired"}
)
REVIEW_CLASSES = frozenset({"editorial", "technical", "mathematical"})
REVIEW_ROLES = {
    "editorial": frozenset({"editorial"}),
    "technical": frozenset({"editorial", "technical"}),
    "mathematical": frozenset({"editorial", "mathematical"}),
}


@dataclass(frozen=True)
class CanonicalUnit:
    """Canonical English page or Python symbol discovered without imports.

    Attributes:
        identifier: Stable manifest identifier.
        kind: Unit kind, either `page` or `symbol`.
        sourcePath: Project-relative canonical source path.
        signature: Public symbol signature, or an empty string for a page.
        body: Canonical English Markdown page or Python docstring.
    """

    identifier: str
    kind: str
    source_path: str
    signature: str
    body: str


@dataclass(frozen=True)
class ValidationReport:
    """Deterministic multilingual-validation result and computed states.

    Attributes:
        diagnostics: Sorted actionable contract violations.
        states: Computed translation state keyed by unit ID and locale.
    """

    diagnostics: tuple[str, ...]
    states: dict[str, dict[str, str]]


def _Relative(path: Path, project_root: Path) -> str:
    """Return a stable project-relative diagnostic path."""

    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()

    except ValueError:
        return path.as_posix()


def _ReadCanonicalText(path: Path) -> str:
    """Read UTF-8 text, reject a byte-order mark, and normalize newlines."""

    content = path.read_bytes()

    if content.startswith(b"\xef\xbb\xbf"):
        raise ValueError(f"{path}: UTF-8 byte-order marks are not allowed")

    return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def CanonicalHash(unit: CanonicalUnit) -> str:
    """Return the versioned SHA-256 digest for one canonical English unit."""

    signature_bytes = unit.signature.encode()
    body_bytes = unit.body.encode()
    payload = (
        f"{HASH_SCHEME}\n"
        f"id:{unit.identifier}\n"
        f"kind:{unit.kind}\n"
        f"signature-length:{len(signature_bytes)}\n"
    ).encode()
    payload += signature_bytes
    payload += f"\nbody-length:{len(body_bytes)}\n".encode()
    payload += body_bytes

    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _PageIdentifier(path: Path, content_root: Path) -> str:
    """Derive the default stable page ID for a newly discovered English page."""

    relative_path = path.relative_to(content_root).with_suffix("")
    parts = list(relative_path.parts)

    if parts[-1] == "index":
        parts.pop()

    return "page:" + (".".join(parts) if parts else "index")


def _FunctionSignature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Return a stable public function or method signature from syntax."""

    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    signature = f"{prefix} {node.name}({ast.unparse(node.args)})"

    if node.returns is not None:
        signature += f" -> {ast.unparse(node.returns)}"

    return signature


def _ClassSignature(node: ast.ClassDef) -> str:
    """Return a stable public class signature from syntax."""

    arguments = [ast.unparse(base) for base in node.bases]
    arguments.extend(
        f"{keyword.arg}={ast.unparse(keyword.value)}"
        for keyword in node.keywords
        if keyword.arg is not None
    )
    suffix = f"({', '.join(arguments)})" if arguments else ""
    public_fields = []

    for member in node.body:
        if (
            isinstance(member, ast.AnnAssign)
            and isinstance(member.target, ast.Name)
            and not member.target.id.startswith("_")
        ):
            field = f"{member.target.id}: {ast.unparse(member.annotation)}"

            if member.value is not None:
                field += f" = {ast.unparse(member.value)}"

            public_fields.append(field)

        elif isinstance(member, ast.Assign):
            for target in member.targets:
                if isinstance(target, ast.Name) and not target.id.startswith("_"):
                    public_fields.append(f"{target.id} = {ast.unparse(member.value)}")

    fields = f"; public-fields: {'; '.join(public_fields)}" if public_fields else ""

    return f"class {node.name}{suffix}{fields}"


def _IsPropertySetter(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a method only supplies a property setter or deleter."""

    return any(
        isinstance(decorator, ast.Attribute)
        and decorator.attr in {"setter", "deleter"}
        for decorator in node.decorator_list
    )


def _NodeUnit(
    identifier: str,
    source_path: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> CanonicalUnit:
    """Build one canonical symbol unit from an authored syntax node."""

    signature = (
        _ClassSignature(node)
        if isinstance(node, ast.ClassDef)
        else _FunctionSignature(node)
    )

    return CanonicalUnit(
        identifier=identifier,
        kind="symbol",
        source_path=source_path,
        signature=signature,
        body=ast.get_docstring(node, clean=False) or "",
    )


def _FindModulePath(module_name: str, project_root: Path) -> Path:
    """Resolve a project-owned module path without importing the package."""

    relative_path = Path(*module_name.split("."))
    module_path = project_root / relative_path.with_suffix(".py")

    if module_path.is_file():
        return module_path

    package_path = project_root / relative_path / "__init__.py"

    if package_path.is_file():
        return package_path

    raise ValueError(f"cannot resolve project module {module_name}")


def _FindTopLevelNode(path: Path, name: str):
    """Return one named top-level public definition from a Python source."""

    syntax = ast.parse(_ReadCanonicalText(path), filename=str(path))

    for node in syntax.body:
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ) and node.name == name:
            return node

    raise ValueError(f"{path}: cannot find public definition {name}")


def _AuthoredUnits(
    module_name: str,
    source_path: Path,
    project_root: Path,
) -> tuple[CanonicalUnit, ...]:
    """Return public authored definitions and class members as symbol units."""

    relative_path = _Relative(source_path, project_root)
    syntax = ast.parse(_ReadCanonicalText(source_path), filename=str(source_path))
    units = []
    seen_symbols = set()

    def Visit(nodes: list[ast.stmt], parent: str, class_scope: bool) -> None:
        """Discover conditional public definitions while excluding function-local helpers."""

        for node in nodes:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                statements = []

                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.stmt):
                        statements.append(child)

                    elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                        statements.extend(child.body)

                Visit(statements, parent, class_scope)
                continue

            if node.name.startswith("_") and not (class_scope and node.name == "__call__"):
                continue

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _IsPropertySetter(node):
                continue

            symbol_name = f"{parent}.{node.name}"

            if symbol_name not in seen_symbols:
                units.append(_NodeUnit(f"symbol:{symbol_name}", relative_path, node))
                seen_symbols.add(symbol_name)

            if isinstance(node, ast.ClassDef):
                Visit(node.body, symbol_name, True)

    Visit(syntax.body, module_name, False)

    return tuple(units)


def _LiteralExports(syntax: ast.Module, source_path: Path) -> tuple[str, ...]:
    """Return the literal package export contract from `__all__`."""

    for node in syntax.body:
        if not isinstance(node, ast.Assign):
            continue

        if not any(
            isinstance(target, ast.Name) and target.id == "__all__"
            for target in node.targets
        ):
            continue

        exports = ast.literal_eval(node.value)

        if not isinstance(exports, (list, tuple)) or not all(
            isinstance(name, str) for name in exports
        ):
            raise ValueError(f"{source_path}: __all__ must be a literal string sequence")

        if len(exports) != len(set(exports)):
            raise ValueError(f"{source_path}: __all__ contains duplicate names")

        return tuple(exports)

    raise ValueError(f"{source_path}: missing literal __all__")


def _ExportUnits(
    module_name: str,
    source_path: Path,
    project_root: Path,
) -> tuple[CanonicalUnit, ...]:
    """Return root-package aliases bound to their authored English contracts."""

    syntax = ast.parse(_ReadCanonicalText(source_path), filename=str(source_path))
    export_targets = {}

    for node in syntax.body:
        if not isinstance(node, ast.ImportFrom) or not node.module:
            continue

        for imported_name in node.names:
            public_name = imported_name.asname or imported_name.name
            export_targets[public_name] = (node.module, imported_name.name)

    units = []

    for public_name in _LiteralExports(syntax, source_path):
        if public_name not in export_targets:
            raise ValueError(f"{source_path}: export {public_name} has no static import target")

        target_module, target_name = export_targets[public_name]
        target_path = _FindModulePath(target_module, project_root)
        target_node = _FindTopLevelNode(target_path, target_name)
        units.append(
            _NodeUnit(
                f"symbol:{module_name}.{public_name}",
                _Relative(target_path, project_root),
                target_node,
            )
        )

    return tuple(units)


def DiscoverCanonicalUnits(
    project_root: Path,
    project_manifest: dict,
    known_page_ids: dict[str, str] | None = None,
) -> tuple[CanonicalUnit, ...]:
    """Discover every active canonical English page and public API symbol."""

    content_root = project_root / project_manifest["contentRoot"] / "en"
    known_page_ids = known_page_ids or {}
    units = []

    for page_path in sorted(content_root.rglob("*.md")):
        relative_path = _Relative(page_path, project_root)
        units.append(
            CanonicalUnit(
                identifier=known_page_ids.get(
                    relative_path,
                    _PageIdentifier(page_path, content_root),
                ),
                kind="page",
                source_path=relative_path,
                signature="",
                body=_ReadCanonicalText(page_path),
            )
        )

    coverage_path = project_root / project_manifest["apiCoverageManifest"]
    coverage = tomllib.loads(_ReadCanonicalText(coverage_path))
    exclusions = {
        exclusion.get("symbol") for exclusion in coverage.get("exclusions", ())
    }

    for surface in coverage.get("surfaces", ()):
        module_name = surface.get("module", "")
        source_path = project_root / surface.get("source", "")
        mode = surface.get("mode", "")
        package_name = module_name.partition(".")[0]

        if package_name not in project_manifest["packageNames"]:
            raise ValueError(
                f"{coverage_path}: module {module_name!r} is outside declared "
                f"packageNames {project_manifest['packageNames']!r}"
            )

        if mode == "authored":
            surface_units = _AuthoredUnits(module_name, source_path, project_root)

        elif mode == "exports":
            surface_units = _ExportUnits(module_name, source_path, project_root)

        else:
            raise ValueError(f"{coverage_path}: invalid surface mode {mode!r}")

        units.extend(
            unit
            for unit in surface_units
            if unit.identifier.removeprefix("symbol:") not in exclusions
        )

    identifiers = [unit.identifier for unit in units]

    if len(identifiers) != len(set(identifiers)):
        duplicate_ids = sorted(
            identifier
            for identifier in set(identifiers)
            if identifiers.count(identifier) > 1
        )
        raise ValueError(f"duplicate discovered unit IDs: {', '.join(duplicate_ids)}")

    return tuple(sorted(units, key=lambda unit: unit.identifier))


def _LoadProjectManifest(path: Path) -> dict:
    """Load and validate the reusable multilingual project manifest."""

    manifest = tomllib.loads(_ReadCanonicalText(path))

    if manifest.get("schemaVersion") != 1:
        raise ValueError(f"{path}: schemaVersion must be 1")

    required_text = (
        "projectId",
        "projectName",
        "sourceLocale",
        "contentRoot",
        "unitManifest",
        "buildRoot",
        "apiCoverageManifest",
        "publicationPath",
    )

    for field_name in required_text:
        if not isinstance(manifest.get(field_name), str) or not manifest[field_name]:
            raise ValueError(f"{path}: {field_name} must be a non-empty string")

    locales = manifest.get("locales")

    if manifest["sourceLocale"] != "en":
        raise ValueError(f"{path}: sourceLocale must be 'en'")

    if (
        not isinstance(locales, list)
        or len(locales) < 2
        or locales[0] != manifest["sourceLocale"]
        or len(locales) != len(set(locales))
        or not all(isinstance(locale, str) and LOCALE_FORMAT.fullmatch(locale) for locale in locales)
    ):
        raise ValueError(
            f"{path}: locales must be a unique list beginning with sourceLocale "
            "and containing at least one target locale"
        )

    package_names = manifest.get("packageNames")

    if (
        not isinstance(package_names, list)
        or not package_names
        or not all(isinstance(name, str) and name.strip() for name in package_names)
    ):
        raise ValueError(f"{path}: packageNames must be a non-empty string list")

    publication_path = manifest["publicationPath"]

    if (
        not publication_path.startswith("/")
        or (publication_path != "/" and publication_path.endswith("/"))
        or ".." in Path(publication_path).parts
    ):
        raise ValueError(
            f"{path}: publicationPath must be an absolute URL path without a trailing slash"
        )

    branding = manifest.get("branding")

    if not isinstance(branding, dict):
        raise TypeError(f"{path}: branding must be a table")

    for field_name in ("organization", "assetRoot"):
        if not isinstance(branding.get(field_name), str) or not branding[field_name].strip():
            raise ValueError(f"{path}: branding.{field_name} must be a non-empty string")

    glossaries = manifest.get("glossaries", {})

    target_locales = set(locales[1:])

    if set(glossaries) != target_locales:
        raise ValueError(
            f"{path}: glossaries must match target locales "
            f"{', '.join(sorted(target_locales))}"
        )

    return manifest


def _ValidTimestamp(value) -> bool:
    """Return whether a value is a timezone-aware ISO-8601 timestamp."""

    if not isinstance(value, str) or not value.endswith("Z"):
        return False

    try:
        parsed_value = datetime.fromisoformat(value)

    except ValueError:
        return False

    return parsed_value.utcoffset() is not None


def _ValidateGlossaries(
    project_root: Path,
    project_manifest: dict,
) -> tuple[str, ...]:
    """Return deterministic cross-locale glossary integrity violations."""

    diagnostics = []
    concept_sets = {}
    english_terms = {}

    target_locales = tuple(project_manifest["locales"][1:])

    for locale in target_locales:
        glossary_path = project_root / project_manifest["glossaries"][locale]
        glossary_label = _Relative(glossary_path, project_root)

        try:
            glossary = tomllib.loads(_ReadCanonicalText(glossary_path))

        except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
            diagnostics.append(f"{glossary_label}: cannot load glossary: {error}")
            continue

        if glossary.get("schemaVersion") != 1:
            diagnostics.append(f"{glossary_label}: schemaVersion must be 1")

        if glossary.get("locale") != locale:
            diagnostics.append(f"{glossary_label}: locale must be {locale}")

        concept_ids = []

        for index, term in enumerate(glossary.get("terms", ())):
            term_label = f"{glossary_label}:terms[{index}]"
            identifier = term.get("id", "")
            english = term.get("english", "")
            preferred = term.get("preferred", "")
            avoid = term.get("avoid", ())
            references = term.get("references", ())

            if not CONCEPT_ID_FORMAT.fullmatch(identifier):
                diagnostics.append(f"{term_label}: invalid concept ID {identifier!r}")

            concept_ids.append(identifier)

            if not isinstance(english, str) or not english.strip():
                diagnostics.append(f"{term_label}: english must be non-empty")

            if not isinstance(preferred, str) or not preferred.strip():
                diagnostics.append(f"{term_label}: preferred must be non-empty")

            if not isinstance(avoid, list) or not all(
                isinstance(value, str) and value.strip() for value in avoid
            ):
                diagnostics.append(f"{term_label}: avoid must be a string list")

            elif preferred in avoid:
                diagnostics.append(f"{term_label}: preferred term cannot be prohibited")

            if not isinstance(references, list) or not references:
                diagnostics.append(f"{term_label}: at least one reference is required")

            else:
                for reference in references:
                    reference_path = project_root / reference

                    if not isinstance(reference, str) or not reference_path.is_file():
                        diagnostics.append(
                            f"{term_label}: missing reference {reference!r}"
                        )

            if identifier in english_terms and english_terms[identifier] != english:
                diagnostics.append(
                    f"{term_label}: canonical English term differs across locales"
                )

            english_terms[identifier] = english

        if len(concept_ids) != len(set(concept_ids)):
            diagnostics.append(f"{glossary_label}: duplicate concept IDs")

        concept_sets[locale] = frozenset(concept_ids)

    if len(concept_sets) == len(target_locales) and len(set(concept_sets.values())) > 1:
        diagnostics.append("docs/i18n/glossaries: target locale concept IDs must match")

    return tuple(diagnostics)


def _TranslationDiagnostic(
    unit_id: str,
    locale: str,
    source_path: str,
    translation_path: str,
    expected_hash: str,
    actual_hash: str,
    action: str,
) -> str:
    """Format one complete stale-translation diagnostic."""

    return (
        f"unit={unit_id} locale={locale} source={source_path} "
        f"translation={translation_path or '<missing>'} "
        f"expected={expected_hash or '<missing>'} actual={actual_hash} "
        f"action={action}"
    )


def ValidateLocales(
    project_root: Path = PROJECT_ROOT,
    project_manifest_path: Path | None = None,
) -> ValidationReport:
    """Validate canonical inventory, source hashes, review state, and glossaries."""

    project_manifest_path = project_manifest_path or project_root / "docs" / "i18n" / "project.toml"
    diagnostics = []
    states = {}

    try:
        project_manifest = _LoadProjectManifest(project_manifest_path)
        reviewer_types = project_manifest.get("reviewerTypes", ["human"])

        if (not isinstance(reviewer_types, list) or not reviewer_types
                or any(item not in {"human", "ai"} for item in reviewer_types)):
            raise ValueError("reviewerTypes must explicitly select human and/or ai")

        target_locales = tuple(project_manifest["locales"][1:])
        unit_manifest_path = project_root / project_manifest["unitManifest"]
        unit_manifest = tomllib.loads(_ReadCanonicalText(unit_manifest_path))
        known_page_ids = {
            record.get("sourcePath", ""): record.get("id", "")
            for record in unit_manifest.get("units", ())
            if record.get("kind") == "page"
        }
        discovered_units = DiscoverCanonicalUnits(
            project_root,
            project_manifest,
            known_page_ids,
        )

    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        SyntaxError,
        tomllib.TOMLDecodeError,
    ) as error:
        return ValidationReport((str(error),), {})

    unit_manifest_label = _Relative(unit_manifest_path, project_root)

    if unit_manifest.get("schemaVersion") != 1:
        diagnostics.append(f"{unit_manifest_label}: schemaVersion must be 1")

    discovered_by_id = {unit.identifier: unit for unit in discovered_units}
    records = unit_manifest.get("units", ())
    records_by_id = {}
    active_source_paths = {}

    for index, record in enumerate(records):
        identifier = record.get("id", "")
        record_label = f"{unit_manifest_label}:units[{index}]"

        if identifier in records_by_id:
            diagnostics.append(f"{record_label}: duplicate unit ID {identifier}")

        records_by_id[identifier] = record

        if record.get("kind") == "page":
            source_path = record.get("sourcePath", "")
            prior_id = active_source_paths.get(source_path)

            if prior_id:
                diagnostics.append(
                    f"{record_label}: sourcePath {source_path!r} is already owned by {prior_id}"
                )

            active_source_paths[source_path] = identifier

    missing_ids = sorted(set(discovered_by_id) - set(records_by_id))
    unexpected_ids = sorted(set(records_by_id) - set(discovered_by_id))

    for identifier in missing_ids:
        unit = discovered_by_id[identifier]
        diagnostics.append(
            f"{unit_manifest_label}: missing canonical unit {identifier} "
            f"source={unit.source_path} action=add exactly one manifest record"
        )

    for identifier in unexpected_ids:
        diagnostics.append(
            f"{unit_manifest_label}: unknown or retired-unmarked unit {identifier} "
            "action=remove it or implement an explicit retired-unit contract"
        )

    for identifier in sorted(set(discovered_by_id) & set(records_by_id)):
        unit = discovered_by_id[identifier]
        record = records_by_id[identifier]
        record_label = f"{unit_manifest_label}:{identifier}"
        current_hash = CanonicalHash(unit)
        recorded_hash = record.get("sourceHash", "")
        source_path = record.get("sourcePath", "")
        review_class = record.get("reviewClass", "")

        identifier_format = PAGE_ID_FORMAT if unit.kind == "page" else SYMBOL_ID_FORMAT

        if not identifier_format.fullmatch(identifier):
            diagnostics.append(f"{record_label}: invalid stable ID")

        if record.get("kind") != unit.kind:
            diagnostics.append(f"{record_label}: kind must be {unit.kind}")

        if source_path != unit.source_path:
            diagnostics.append(
                f"{record_label}: sourcePath={source_path!r} actual={unit.source_path!r} "
                "action=preserve the stable ID and update its canonical source path"
            )

        if not HASH_FORMAT.fullmatch(recorded_hash):
            diagnostics.append(f"{record_label}: invalid sourceHash {recorded_hash!r}")

        elif recorded_hash != current_hash:
            diagnostics.append(
                f"{record_label}: canonical source drift expected={recorded_hash} "
                f"actual={current_hash} source={unit.source_path} "
                "action=review the English change and refresh sourceHash"
            )

        if review_class not in REVIEW_CLASSES:
            diagnostics.append(f"{record_label}: invalid reviewClass {review_class!r}")

        translations = record.get("translations", {})
        unexpected_locales = sorted(set(translations) - set(target_locales))

        for locale in unexpected_locales:
            diagnostics.append(f"{record_label}: unsupported locale {locale}")

        states[identifier] = {}

        for locale in target_locales:
            translation = translations.get(locale)

            if not isinstance(translation, dict):
                diagnostics.append(f"{record_label}: missing {locale} translation state")
                states[identifier][locale] = "invalid"
                continue

            state = translation.get("state", "")
            translation_path = translation.get("path", "")
            reviews = translation.get("reviews", ())

            if state not in TRANSLATION_STATES:
                diagnostics.append(f"{record_label}: invalid {locale} state {state!r}")
                states[identifier][locale] = "invalid"
                continue

            states[identifier][locale] = state

            if state == "missing":
                if translation_path or reviews:
                    diagnostics.append(
                        f"{record_label}: {locale} missing state cannot carry a path or reviews"
                    )

                continue

            if state == "retired":
                diagnostics.append(
                    f"{record_label}: active canonical unit cannot have retired {locale} state"
                )
                continue

            resolved_translation = project_root / translation_path

            if unit.kind == "page" and translation_path:
                locale_root = (project_root / project_manifest["contentRoot"] / locale).resolve()

                if not resolved_translation.resolve().is_relative_to(locale_root):
                    diagnostics.append(
                        f"{record_label}: {locale} translation path must remain inside its locale"
                    )

            if not translation_path or not resolved_translation.is_file():
                diagnostics.append(
                    _TranslationDiagnostic(
                        identifier,
                        locale,
                        unit.source_path,
                        translation_path,
                        recorded_hash,
                        current_hash,
                        "add the locale file or use state=missing",
                    )
                )

            based_on_hash = translation.get("basedOnSourceHash", "")

            if not HASH_FORMAT.fullmatch(based_on_hash):
                diagnostics.append(f"{record_label}: {locale} invalid basedOnSourceHash")

            elif based_on_hash != current_hash:
                states[identifier][locale] = "stale"

                if state != "stale":
                    diagnostics.append(
                        _TranslationDiagnostic(
                            identifier, locale, unit.source_path, translation_path,
                            based_on_hash, current_hash,
                            "set state=stale until the translation is updated against current English",
                        )
                    )

            if state != "approved":
                continue

            required_roles = REVIEW_ROLES.get(review_class, frozenset())
            reviewed_roles = set()
            mismatched_review_hash = False

            if not isinstance(reviews, list):
                diagnostics.append(f"{record_label}: {locale} reviews must be a list")
                reviews = ()

            for review_index, review in enumerate(reviews):
                review_label = f"{record_label}:{locale}:reviews[{review_index}]"

                if not isinstance(review, dict):
                    diagnostics.append(f"{review_label}: review must be a table")
                    continue

                role = review.get("role", "")
                review_hash = review.get("reviewedSourceHash", "")
                reviewer_type = review.get("reviewerType", "human")

                if reviewer_type not in reviewer_types:
                    diagnostics.append(f"{review_label}: reviewerType is not authorized by the project")

                if reviewer_type == "ai":
                    translation_hash = review.get("reviewedTranslationHash", "")
                    actual_translation_hash = ""

                    if resolved_translation.is_file():
                        actual_translation_hash = "sha256:" + hashlib.sha256(
                            _ReadCanonicalText(resolved_translation).encode("utf-8"),
                        ).hexdigest()

                    if (not HASH_FORMAT.fullmatch(translation_hash)
                            or translation_hash != actual_translation_hash):
                        mismatched_review_hash = True
                        diagnostics.append(f"{review_label}: reviewedTranslationHash does not match")

                if role in reviewed_roles:
                    diagnostics.append(f"{review_label}: duplicate review role {role}")

                reviewed_roles.add(role)

                if not isinstance(review.get("reviewer"), str) or not review["reviewer"].strip():
                    diagnostics.append(f"{review_label}: reviewer must be non-empty")

                if not _ValidTimestamp(review.get("reviewedAt")):
                    diagnostics.append(f"{review_label}: reviewedAt must be a UTC timestamp")

                if review_hash != current_hash:
                    mismatched_review_hash = True

            missing_roles = sorted(required_roles - reviewed_roles)

            if missing_roles:
                diagnostics.append(
                    f"{record_label}: {locale} approved state lacks review roles "
                    f"{', '.join(missing_roles)}"
                )

            if recorded_hash != current_hash or mismatched_review_hash:
                states[identifier][locale] = "stale"
                diagnostics.append(
                    _TranslationDiagnostic(
                        identifier,
                        locale,
                        unit.source_path,
                        translation_path,
                        recorded_hash,
                        current_hash,
                        "set state=stale and obtain new accountable authorized reviews",
                    )
                )

    for locale in target_locales:
        locale_root = project_root / project_manifest["contentRoot"] / locale
        declared_paths = {
            (project_root / record["translations"][locale]["path"]).resolve()
            for record in records
            if isinstance(record.get("translations", {}).get(locale), dict)
            and record["translations"][locale].get("path")
        }

        for page_path in locale_root.rglob("*.md"):
            if page_path.resolve() not in declared_paths:
                diagnostics.append(
                    f"{_Relative(page_path, project_root)}: locale page lacks explicit unit state"
                )

    diagnostics.extend(_ValidateGlossaries(project_root, project_manifest))

    return ValidationReport(tuple(sorted(set(diagnostics))), states)


def _WriteReport(report: ValidationReport, output_path: Path) -> None:
    """Write deterministic machine-readable validation evidence."""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": 1,
        "status": "pass" if not report.diagnostics else "fail",
        "diagnostics": list(report.diagnostics),
        "states": report.states,
    }
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def ParseArguments(arguments=None):
    """Parse locale-documentation validator arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "inventory"))
    parser.add_argument("--project-root", dest="project_root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--project-manifest", dest="project_manifest", type=Path)
    parser.add_argument("--output", type=Path)

    return parser.parse_args(arguments)


def Main(arguments=None):
    """Run deterministic locale validation or print canonical inventory."""

    options = ParseArguments(arguments)
    project_manifest_path = options.project_manifest or (
        options.project_root / "docs" / "i18n" / "project.toml"
    )

    if options.command == "inventory":
        try:
            project_manifest = _LoadProjectManifest(project_manifest_path)
            unit_manifest_path = options.project_root / project_manifest["unitManifest"]
            known_page_ids = {}

            if unit_manifest_path.is_file():
                unit_manifest = tomllib.loads(_ReadCanonicalText(unit_manifest_path))
                known_page_ids = {
                    record.get("sourcePath", ""): record.get("id", "")
                    for record in unit_manifest.get("units", ())
                    if record.get("kind") == "page"
                }

            units = DiscoverCanonicalUnits(
                options.project_root,
                project_manifest,
                known_page_ids,
            )

        except (
            OSError,
            UnicodeError,
            TypeError,
            ValueError,
            SyntaxError,
            tomllib.TOMLDecodeError,
        ) as error:
            print(error, file=sys.stderr)
            return 1

        for unit in units:
            print(
                json.dumps(
                    {
                        "id": unit.identifier,
                        "kind": unit.kind,
                        "sourcePath": unit.source_path,
                        "sourceHash": CanonicalHash(unit),
                    },
                    sort_keys=True,
                )
            )

        return 0

    report = ValidateLocales(options.project_root, project_manifest_path)

    if options.output:
        _WriteReport(report, options.output)

    if report.diagnostics:
        for diagnostic in report.diagnostics:
            print(diagnostic, file=sys.stderr)

        return 1

    print("Multilingual documentation validation: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
