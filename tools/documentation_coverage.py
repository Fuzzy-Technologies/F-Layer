"""Classify every Git-tracked file and every installed package definition explicitly."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from flayer.core.contracts import _WireDict

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

    sourcePath: str
    category: str
    disposition: str
    reason: str
    pagePath: str | None = None


@dataclass(frozen=True)
class DefinitionCoverage:
    """A static package definition's API or implementation-only disposition."""

    symbol: str
    disposition: str
    reason: str


def TrackedFiles(projectRoot: Path) -> tuple[str, ...]:
    """Read the exact Git index inventory without relying on directory enumeration."""

    result = subprocess.run(["git", "ls-files", "-z"], cwd=projectRoot,
                            capture_output=True, text=True, check=True)

    return tuple(sorted(set(filter(None, result.stdout.split("\0")))))


def ModuleName(sourcePath: str) -> str:
    """Translate one package Python path into its static import name."""

    parts = list(Path(sourcePath).relative_to("src").with_suffix("").parts)

    if parts[-1] == "__init__":
        parts.pop()

    return ".".join(parts)


def PublicModule(sourcePath: str) -> bool:
    """Include the explicit executable entry point and nonprivate package paths."""

    moduleName = ModuleName(sourcePath)

    return moduleName == "flayer.__main__" or all(
        not part.startswith("_") for part in moduleName.split(".")
    )


def MarkdownPage(sourcePath: str) -> str:
    """Preserve canonical routes and place other Markdown under repository routes."""

    if sourcePath.startswith(SOURCE_CONTENT_PREFIX):
        return sourcePath.removeprefix(SOURCE_CONTENT_PREFIX)

    relative = sourcePath.removeprefix(".github/")

    if relative != sourcePath:
        relative = "github/" + relative

    return "repository/" + relative


def MarkdownArtifact(pagePath: str) -> Path:
    """Map Markdown to MkDocs directory routes, including README index semantics."""

    relative = Path(pagePath)

    if relative.name in {"index.md", "README.md"}:
        return relative.parent / "index.html"

    return relative.with_suffix("") / "index.html"


def InventoryFiles(projectRoot: Path) -> tuple[FileCoverage, ...]:
    """Fail closed on missing, ambiguous, malformed, or unsupported coverage rules."""

    manifest = tomllib.loads((projectRoot / MANIFEST_PATH).read_text(encoding="utf-8"))

    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("rules"), list):
        raise ValueError("Repository coverage manifest must use schemaVersion 1 and rules")

    rules = manifest["rules"]
    validCategories = {"markdown", "package", "typing", "tests", "tools", "examples",
                        "workflow", "template", "locale", "asset", "configuration", "license"}

    for rule in rules:
        if (not isinstance(rule, dict) or rule.get("category") not in validCategories
                or not isinstance(rule.get("reason"), str) or not rule["reason"].strip()
                or not isinstance(rule.get("patterns"), list) or not rule["patterns"]
                or any(not isinstance(pattern, str) or not pattern for pattern in rule["patterns"])):
            raise ValueError("Repository coverage rule requires patterns, category, and rationale")

    inventory = []
    pageOwners: dict[str, str] = {}

    for sourcePath in TrackedFiles(projectRoot):
        matches = [rule for rule in rules if any(
            fnmatch.fnmatchcase(sourcePath, pattern) for pattern in rule["patterns"]
        )]

        if len(matches) != 1:
            raise ValueError(f"Repository file requires exactly one coverage rule: {sourcePath}")

        if not (projectRoot / sourcePath).is_file():
            raise ValueError(f"Tracked coverage file is absent: {sourcePath}")

        rule = matches[0]
        category = rule["category"]
        pagePath = None
        disposition = "source-only"
        reason = rule["reason"]

        if category == "markdown":
            if sourcePath.startswith("docs/site/content/") and not sourcePath.startswith(
                SOURCE_CONTENT_PREFIX
            ):
                disposition = "locale-overlay"
                pagePath = sourcePath.removeprefix("docs/site/content/")
                reason = ("Locale overlay rendered with explicit review state by the locale renderer; "
                          "human approval is never inferred.")

            else:
                disposition = "rendered-markdown"
                pagePath = MarkdownPage(sourcePath)

        elif category == "package":
            if PublicModule(sourcePath):
                disposition = "generated-api"
                pagePath = "api/modules/" + ModuleName(sourcePath).replace(".", "-") + ".md"

            else:
                reason = "Private package module: implementation detail outside the supported API."

        if pagePath is not None:
            artifact = MarkdownArtifact(pagePath).as_posix()

            if artifact == "coverage/index.html" or artifact in pageOwners:
                raise ValueError(f"Duplicate or reserved documentation route: {pagePath}")

            pageOwners[artifact] = sourcePath

        inventory.append(FileCoverage(sourcePath, category, disposition, reason, pagePath))

    return tuple(inventory)


def CheckBuildInputs(projectRoot: Path) -> tuple[str, ...]:
    """Reject untracked package or canonical site files that could enter built artifacts."""

    tracked = set(TrackedFiles(projectRoot))
    diagnostics = []

    for sourceRoot in (projectRoot / "src/flayer", projectRoot / SOURCE_CONTENT_PREFIX):
        for path in sorted(sourceRoot.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue

            relative = path.relative_to(projectRoot).as_posix()

            if relative not in tracked:
                diagnostics.append(f"Untracked documentation build input: {relative}")

    return tuple(diagnostics)


def InventoryDefinitions(sourcePath: str, syntax: ast.Module) -> tuple[DefinitionCoverage, ...]:
    """Record defined public symbols, callable protocols, and all omitted definitions."""

    moduleName = ModuleName(sourcePath)
    modulePublic = PublicModule(sourcePath)
    definitions = []
    seenSymbols: set[str] = set()

    def Visit(nodes: list[ast.stmt], parent: str, publicParent: bool, scope: str) -> None:
        """Classify definition scopes without promoting nested implementation helpers."""

        for node in nodes:
            if not isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                nestedStatements = []

                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.stmt):
                        nestedStatements.append(child)

                    elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                        nestedStatements.extend(child.body)

                Visit(nestedStatements, parent, publicParent, scope)
                continue

            symbol = parent + "." + node.name
            isPublic = (publicParent and scope != "function" and (
                not node.name.startswith("_") or (scope == "class" and node.name in CALLABLE_METHODS)
            ))
            disposition = "generated-api" if isPublic else "source-only"
            reason = ("Public definition receives an exact rendered API anchor." if isPublic else
                      "Private, special-method, or nested implementation definition; inspect source.")

            if symbol not in seenSymbols:
                definitions.append(DefinitionCoverage(symbol, disposition, reason))
                seenSymbols.add(symbol)

            if isPublic and not ast.get_docstring(node):
                raise ValueError(f"Public symbol lacks a docstring: {symbol}")

            Visit(node.body, symbol, isPublic,
                  "class" if isinstance(node, ast.ClassDef) else "function")

    Visit(syntax.body, moduleName, modulePublic, "module")

    return tuple(definitions)


def CheckRepositoryCoverage(projectRoot: Path) -> tuple[str, ...]:
    """Expose manifest validation as deterministic documentation diagnostics."""

    try:
        InventoryFiles(projectRoot)

    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        return (f"Repository documentation coverage: {error}",)

    return ()


def WriteInventory(
    projectRoot: Path, buildRoot: Path, definitions: Sequence[DefinitionCoverage],
) -> None:
    """Write machine evidence and a navigable, explicitly scoped file inventory."""

    files = InventoryFiles(projectRoot)
    payload = {"schemaVersion": 1, "files": [_WireDict(item) for item in files],
               "definitions": [_WireDict(item) for item in definitions]}
    (buildRoot / "repository-coverage.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    coverageRoot = buildRoot / "content/en/coverage"
    coverageRoot.mkdir(parents=True, exist_ok=True)
    (coverageRoot / "index.md").write_text(RenderInventory(files, definitions), encoding="utf-8")


def RenderInventory(
    files: Sequence[FileCoverage], definitions: Sequence[DefinitionCoverage],
    translate: Callable[[str], str] = str,
) -> str:
    """Render exact coverage evidence using locale prose without changing identifiers or URLs."""

    lines = ["# " + translate("Repository documentation coverage"), "",
             translate("Every Git-tracked file has one explicit classification. API pages document "
                       "supported definitions; private helpers, tests, tools, configuration, assets, "
                       "and workflows remain source-only with a reason. This is file accountability, "
                       "not a claim that every source file is a public API or a reviewed translation."), "",
             "[" + translate("Coverage contract") + "]"
             "(../repository/docs/development/documentation-coverage.md)", "",
             f"| {translate('File')} | {translate('Disposition')} | {translate('Reason')} |",
             "| --- | --- | --- |"]

    for item in files:
        target = "../" + item.pagePath if item.pagePath else SOURCE_URL + item.sourcePath

        if item.disposition == "locale-overlay":
            target = SOURCE_URL + item.sourcePath

        lines.append(f"| [{item.sourcePath}]({target}) | `{item.disposition}` | {translate(item.reason)} |")

    lines.extend(["", "## " + translate("Defined package symbols"), "",
                  translate("Imported aliases, constants, fields, and inherited methods are represented "
                            "by their defining module or class; they do not receive duplicate anchor requirements."),
                  "", f"| {translate('Symbol')} | {translate('Disposition')} | {translate('Reason')} |",
                  "| --- | --- | --- |"])

    for definition in definitions:
        lines.append(f"| `{definition.symbol}` | `{definition.disposition}` | {translate(definition.reason)} |")

    return AlignMarkdown("\n".join(lines) + "\n")


def Main(arguments: Sequence[str] | None = None) -> int:
    """Validate repository coverage without installing tools or importing runtime code."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1], dest='projectRoot')
    options = parser.parse_args(arguments)
    diagnostics = CheckRepositoryCoverage(options.project_root)

    if diagnostics:
        print("\n".join(diagnostics))

        return 1

    print(f"Repository documentation coverage: PASS ({len(InventoryFiles(options.project_root))} files)")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
