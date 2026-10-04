"""Classify every Git-tracked file and every installed package definition explicitly."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import subprocess
import sys
import tomllib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.markdown_tables import AlignMarkdown  # noqa: E402

MANIFEST_PATH = "docs/site/repository-coverage.toml"
SOURCE_CONTENT_PREFIX = "docs/site/content/en/"
SOURCE_URL = "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/"
CALLABLE_METHODS = frozenset({"__call__"})


@dataclass(frozen=True)
class FileCoverage:
    """A repository file's documentation disposition and accountable reason."""

    source_path: str
    category: str
    disposition: str
    reason: str
    page_path: str | None = None


@dataclass(frozen=True)
class DefinitionCoverage:
    """A static package definition's API or implementation-only disposition."""

    symbol: str
    disposition: str
    reason: str


def TrackedFiles(project_root: Path) -> tuple[str, ...]:
    """Read the exact Git index inventory without relying on directory enumeration."""

    result = subprocess.run(["git", "ls-files", "-z"], cwd=project_root,
                            capture_output=True, text=True, check=True)

    return tuple(sorted(set(filter(None, result.stdout.split("\0")))))


def ModuleName(source_path: str) -> str:
    """Translate one package Python path into its static import name."""

    parts = list(Path(source_path).relative_to("src").with_suffix("").parts)

    if parts[-1] == "__init__":
        parts.pop()

    return ".".join(parts)


def PublicModule(source_path: str) -> bool:
    """Include the explicit executable entry point and nonprivate package paths."""

    module_name = ModuleName(source_path)

    return module_name == "flayer.__main__" or all(
        not part.startswith("_") for part in module_name.split(".")
    )


def MarkdownPage(source_path: str) -> str:
    """Preserve canonical routes and place other Markdown under repository routes."""

    if source_path.startswith(SOURCE_CONTENT_PREFIX):
        return source_path.removeprefix(SOURCE_CONTENT_PREFIX)

    relative = source_path.removeprefix(".github/")

    if relative != source_path:
        relative = "github/" + relative

    return "repository/" + relative


def MarkdownArtifact(page_path: str) -> Path:
    """Map Markdown to MkDocs directory routes, including README index semantics."""

    relative = Path(page_path)

    if relative.name in {"index.md", "README.md"}:
        return relative.parent / "index.html"

    return relative.with_suffix("") / "index.html"


def InventoryFiles(project_root: Path) -> tuple[FileCoverage, ...]:
    """Fail closed on missing, ambiguous, malformed, or unsupported coverage rules."""

    manifest = tomllib.loads((project_root / MANIFEST_PATH).read_text(encoding="utf-8"))

    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("rules"), list):
        raise ValueError("Repository coverage manifest must use schemaVersion 1 and rules")

    rules = manifest["rules"]
    valid_categories = {"markdown", "package", "typing", "tests", "tools", "examples",
                        "workflow", "template", "locale", "asset", "configuration", "license"}

    for rule in rules:
        if (not isinstance(rule, dict) or rule.get("category") not in valid_categories
                or not isinstance(rule.get("reason"), str) or not rule["reason"].strip()
                or not isinstance(rule.get("patterns"), list) or not rule["patterns"]
                or any(not isinstance(pattern, str) or not pattern for pattern in rule["patterns"])):
            raise ValueError("Repository coverage rule requires patterns, category, and rationale")

    inventory = []
    page_owners: dict[str, str] = {}

    for source_path in TrackedFiles(project_root):
        matches = [rule for rule in rules if any(
            fnmatch.fnmatchcase(source_path, pattern) for pattern in rule["patterns"]
        )]

        if len(matches) != 1:
            raise ValueError(f"Repository file requires exactly one coverage rule: {source_path}")

        if not (project_root / source_path).is_file():
            raise ValueError(f"Tracked coverage file is absent: {source_path}")

        rule = matches[0]
        category = rule["category"]
        page_path = None
        disposition = "source-only"
        reason = rule["reason"]

        if category == "markdown":
            if source_path.startswith("docs/site/content/") and not source_path.startswith(
                SOURCE_CONTENT_PREFIX
            ):
                disposition = "locale-overlay"
                page_path = source_path.removeprefix("docs/site/content/")
                reason = ("Locale overlay rendered with explicit review state by the locale renderer; "
                          "human approval is never inferred.")

            else:
                disposition = "rendered-markdown"
                page_path = MarkdownPage(source_path)

        elif category == "package":
            if PublicModule(source_path):
                disposition = "generated-api"
                page_path = "api/modules/" + ModuleName(source_path).replace(".", "-") + ".md"

            else:
                reason = "Private package module: implementation detail outside the supported API."

        if page_path is not None:
            artifact = MarkdownArtifact(page_path).as_posix()

            if artifact == "coverage/index.html" or artifact in page_owners:
                raise ValueError(f"Duplicate or reserved documentation route: {page_path}")

            page_owners[artifact] = source_path

        inventory.append(FileCoverage(source_path, category, disposition, reason, page_path))

    return tuple(inventory)


def CheckBuildInputs(project_root: Path) -> tuple[str, ...]:
    """Reject untracked package or canonical site files that could enter built artifacts."""

    tracked = set(TrackedFiles(project_root))
    diagnostics = []

    for source_root in (project_root / "src/flayer", project_root / SOURCE_CONTENT_PREFIX):
        for path in sorted(source_root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue

            relative = path.relative_to(project_root).as_posix()

            if relative not in tracked:
                diagnostics.append(f"Untracked documentation build input: {relative}")

    return tuple(diagnostics)


def InventoryDefinitions(source_path: str, syntax: ast.Module) -> tuple[DefinitionCoverage, ...]:
    """Record defined public symbols, callable protocols, and all omitted definitions."""

    module_name = ModuleName(source_path)
    module_public = PublicModule(source_path)
    definitions = []
    seen_symbols: set[str] = set()

    def Visit(nodes: list[ast.stmt], parent: str, public_parent: bool, scope: str) -> None:
        """Classify definition scopes without promoting nested implementation helpers."""

        for node in nodes:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                nested_statements = []

                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.stmt):
                        nested_statements.append(child)

                    elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                        nested_statements.extend(child.body)

                Visit(nested_statements, parent, public_parent, scope)
                continue

            symbol = parent + "." + node.name
            is_public = (public_parent and scope != "function" and (
                not node.name.startswith("_") or (scope == "class" and node.name in CALLABLE_METHODS)
            ))
            disposition = "generated-api" if is_public else "source-only"
            reason = ("Public definition receives an exact rendered API anchor." if is_public else
                      "Private, special-method, or nested implementation definition; inspect source.")

            if symbol not in seen_symbols:
                definitions.append(DefinitionCoverage(symbol, disposition, reason))
                seen_symbols.add(symbol)

            if is_public and not ast.get_docstring(node):
                raise ValueError(f"Public symbol lacks a docstring: {symbol}")

            Visit(node.body, symbol, is_public,
                  "class" if isinstance(node, ast.ClassDef) else "function")

    Visit(syntax.body, module_name, module_public, "module")

    return tuple(definitions)


def CheckRepositoryCoverage(project_root: Path) -> tuple[str, ...]:
    """Expose manifest validation as deterministic documentation diagnostics."""

    try:
        InventoryFiles(project_root)

    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        return (f"Repository documentation coverage: {error}",)

    return ()


def WriteInventory(
    project_root: Path, build_root: Path, definitions: Sequence[DefinitionCoverage],
) -> None:
    """Write machine evidence and a navigable, explicitly scoped file inventory."""

    files = InventoryFiles(project_root)
    payload = {"schemaVersion": 1, "files": [asdict(item) for item in files],
               "definitions": [asdict(item) for item in definitions]}
    (build_root / "repository-coverage.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    lines = ["# Repository documentation coverage", "",
             "Every Git-tracked file has one explicit classification. API pages document",
             "supported definitions; private helpers, tests, tools, configuration, assets,",
             "and workflows remain source-only with a reason. This is file accountability,",
             "not a claim that every source file is a public API or a reviewed translation.", "",
             "[Coverage contract](../repository/docs/development/documentation-coverage.md)", "",
             "| File | Disposition | Reason |", "| --- | --- | --- |"]

    for item in files:
        target = "../" + item.page_path if item.page_path else SOURCE_URL + item.source_path

        if item.disposition == "locale-overlay":
            target = SOURCE_URL + item.source_path

        lines.append(f"| [{item.source_path}]({target}) | {item.disposition} | {item.reason} |")

    lines.extend(["", "## Defined package symbols", "",
                  "Imported aliases, constants, fields, and inherited methods are represented",
                  "by their defining module or class; they do not receive duplicate anchor requirements.",
                  "", "| Symbol | Disposition | Reason |", "| --- | --- | --- |"])

    for definition in definitions:
        lines.append(f"| `{definition.symbol}` | {definition.disposition} | {definition.reason} |")

    coverage_root = build_root / "content/en/coverage"
    coverage_root.mkdir(parents=True, exist_ok=True)
    (coverage_root / "index.md").write_text(AlignMarkdown("\n".join(lines) + "\n"), encoding="utf-8")


def Main(arguments: Sequence[str] | None = None) -> int:
    """Validate repository coverage without installing tools or importing runtime code."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    options = parser.parse_args(arguments)
    diagnostics = CheckRepositoryCoverage(options.project_root)

    if diagnostics:
        print("\n".join(diagnostics))

        return 1

    print(f"Repository documentation coverage: PASS ({len(InventoryFiles(options.project_root))} files)")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
