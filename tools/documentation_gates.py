"""Validate documentation paths, exact rendered anchors, and generated-output policy."""

from __future__ import annotations

import argparse
import html.parser
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import documentation_coverage as documentationCoverage  # noqa: E402
from tools.markdown_tables import CheckMarkdownTables  # noqa: E402

PUBLIC_ORIGIN = "https://fuzzy-technologies.github.io"
PUBLIC_PATH = "/F-Layer"
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")


class ModuleContract(Protocol):
    """Installed-module metadata required by the rendered API coverage gate."""

    @property
    def name(self) -> str:
        """Return the module import path."""

    @property
    def sourcePath(self) -> str:
        """Return the repository source path."""

    @property
    def symbols(self) -> tuple[str, ...]:
        """Return all authored public definition anchors."""


class PageParser(html.parser.HTMLParser):
    """Collect navigational links, assets, and exact HTML identifier anchors."""

    def __init__(self) -> None:
        """Initialize a fresh page parser."""

        super().__init__(convert_charrefs=True)
        self.anchors: set[str] = set()
        self.targets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect anchor and URL attributes from HTML tags."""

        values = dict(attrs)
        identifier = values.get("id")

        if identifier:
            self.anchors.add(identifier)

        key = "href" if tag in {"a", "link"} else "src"
        target = values.get(key)

        if target:
            self.targets.append(target)


def ParsePage(path: Path) -> PageParser:
    """Read one generated HTML page into a deterministic parsed index."""

    parser = PageParser()
    parser.feed(path.read_text(encoding="utf-8"))

    return parser


def LocalTarget(pagePath: Path, target: str, siteRoot: Path) -> tuple[Path, str] | None:
    """Resolve a local URL and reject targets outside the published site boundary."""

    parsed = urlsplit(target)

    if parsed.scheme or parsed.netloc:
        if f"{parsed.scheme}://{parsed.netloc}" != PUBLIC_ORIGIN:
            return None

        if not (parsed.path == PUBLIC_PATH or parsed.path.startswith(PUBLIC_PATH + "/")):
            return None

        targetPath = parsed.path.removeprefix(PUBLIC_PATH)

    else:
        targetPath = parsed.path

    targetPath = unquote(targetPath)

    if targetPath.startswith("/"):
        if targetPath == PUBLIC_PATH or targetPath.startswith(PUBLIC_PATH + "/"):
            targetPath = targetPath.removeprefix(PUBLIC_PATH)

        resolved = (siteRoot / targetPath.lstrip("/")).resolve()

    else:
        resolved = (pagePath.parent / targetPath).resolve() if targetPath else pagePath.resolve()

    if not resolved.is_relative_to(siteRoot.resolve()):
        raise ValueError(f"URL escapes the generated site: {target}")

    if resolved.is_dir():
        resolved /= "index.html"

    return resolved, unquote(parsed.fragment)


def CheckRenderedLinks(siteRoot: Path) -> tuple[str, ...]:
    """Validate every generated local URL and its exact fragment identifier."""

    pages = {path.resolve(): ParsePage(path) for path in sorted(siteRoot.rglob("*.html"))}
    diagnostics = []

    for pagePath, page in pages.items():
        for target in page.targets:
            try:
                resolved = LocalTarget(pagePath, target, siteRoot)

            except ValueError as error:
                diagnostics.append(f"{pagePath.relative_to(siteRoot)}: {error}")
                continue

            if resolved is None:
                continue

            targetPath, fragment = resolved

            if not targetPath.is_file():
                diagnostics.append(f"{pagePath.relative_to(siteRoot)}: missing target {target}")

            elif fragment and targetPath.suffix == ".html":
                targetPage = pages.get(targetPath)

                if targetPage is None or fragment not in targetPage.anchors:
                    diagnostics.append(f"{pagePath.relative_to(siteRoot)}: missing anchor {target}")

    return tuple(sorted(set(diagnostics)))


def CheckSourceLinks(projectRoot: Path) -> tuple[str, ...]:
    """Reject broken repository-local Markdown and asset targets in authored docs."""

    try:
        paths = [projectRoot / name for name in documentationCoverage.TrackedFiles(projectRoot)
                 if name.endswith(".md")]

    except subprocess.CalledProcessError:
        paths = [*projectRoot.glob("*.md"), *sorted((projectRoot / "docs").rglob("*.md"))]
    diagnostics = []

    for path in paths:
        for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1)
            parsed = urlsplit(target)

            if parsed.scheme or parsed.netloc or not parsed.path:
                continue

            resolved = (path.parent / unquote(parsed.path)).resolve()

            if not resolved.is_relative_to(projectRoot.resolve()) or not resolved.exists():
                diagnostics.append(f"{path.relative_to(projectRoot)}: missing source target {target}")

    return tuple(sorted(set(diagnostics)))


def CheckGeneratedPolicy(projectRoot: Path) -> tuple[str, ...]:
    """Fail if disposable build output or generated site HTML is tracked by Git."""

    result = subprocess.run(["git", "ls-files", "-z"], cwd=projectRoot,
                            capture_output=True, text=True, check=True)
    diagnostics = []

    for name in result.stdout.split("\0"):
        if name.startswith("_build/") or (
            name.startswith("docs/site/") and name.endswith(".html")
        ):
            diagnostics.append(f"Generated output must remain untracked: {name}")

    return tuple(diagnostics)


def CheckApiCoverage(siteRoot: Path, modules: Sequence[ModuleContract]) -> tuple[str, ...]:
    """Require installed module/public-symbol anchors and branch-specific source links."""

    diagnostics = []

    for module in modules:
        pagePath = siteRoot / "en" / "api" / "modules" / module.name.replace(".", "-")
        pagePath /= "index.html"

        if not pagePath.is_file():
            diagnostics.append(f"Missing generated module page: {module.name}")
            continue

        page = ParsePage(pagePath)

        for symbol in (module.name, *module.symbols):
            if symbol not in page.anchors:
                diagnostics.append(f"Missing generated API anchor: {symbol}")

        expectedSource = (
            "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/" + module.sourcePath
        )

        if expectedSource not in page.targets:
            diagnostics.append(f"Missing develop source link: {module.name}")

    for name in ("en/index.html", "en/objects.inv", "en/search/search_index.json",
                 "ru/index.html", "zh-CN/index.html"):
        if not (siteRoot / name).is_file():
            diagnostics.append(f"Missing generated site artifact: {name}")

    return tuple(diagnostics)


def HtmlPage(pagePath: str, siteRoot: Path) -> Path:
    """Map one Markdown route to its directory-URL HTML artifact."""

    return siteRoot / "en" / documentationCoverage.MarkdownArtifact(pagePath)


def CheckMarkdownReachability(projectRoot: Path, siteRoot: Path) -> tuple[str, ...]:
    """Require every canonical Markdown artifact to be reachable from English entry."""

    diagnostics = []
    pages = {path.resolve(): ParsePage(path) for path in sorted(siteRoot.rglob("*.html"))}
    entry = (siteRoot / "en/index.html").resolve()
    pending = [entry]
    reached: set[Path] = set()

    while pending:
        pagePath = pending.pop()

        if pagePath in reached or pagePath not in pages:
            continue

        reached.add(pagePath)

        for target in pages[pagePath].targets:
            try:
                local = LocalTarget(pagePath, target, siteRoot)

            except ValueError:
                continue

            if local is not None and local[0].suffix == ".html":
                pending.append(local[0])

    for item in documentationCoverage.InventoryFiles(projectRoot):
        if item.disposition not in {"rendered-markdown", "generated-api"} or item.pagePath is None:
            continue

        expected = HtmlPage(item.pagePath, siteRoot).resolve()

        if not expected.is_file():
            diagnostics.append(f"Missing classified documentation page: {item.sourcePath}")

        elif expected not in reached:
            diagnostics.append(f"Unreachable classified documentation page: {item.sourcePath}")

    coveragePage = (siteRoot / "en/coverage/index.html").resolve()

    if coveragePage not in reached:
        diagnostics.append("Repository coverage inventory is not reachable from English entry")

    return tuple(diagnostics)


def CheckAll(
    projectRoot: Path, siteRoot: Path, modules: Sequence[ModuleContract] = (),
) -> tuple[str, ...]:
    """Run the complete deterministic documentation policy and rendered gate."""

    return tuple(sorted(set((
        *CheckSourceLinks(projectRoot), *CheckGeneratedPolicy(projectRoot),
        *documentationCoverage.CheckRepositoryCoverage(projectRoot),
        *CheckMarkdownReachability(projectRoot, siteRoot),
        *CheckMarkdownTables(projectRoot),
        *CheckRenderedLinks(siteRoot), *CheckApiCoverage(siteRoot, modules),
    ))))


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run source and generated-site checks without accessing the network."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1], dest='projectRoot')
    parser.add_argument("--site-root", type=Path, dest='siteRoot')
    options = parser.parse_args(arguments)
    diagnostics = [*CheckSourceLinks(options.projectRoot), *CheckGeneratedPolicy(options.projectRoot),
                   *CheckMarkdownTables(options.projectRoot),
                   *documentationCoverage.CheckRepositoryCoverage(options.projectRoot)]

    if options.siteRoot:
        diagnostics.extend(CheckRenderedLinks(options.siteRoot.resolve()))
        diagnostics.extend(CheckMarkdownReachability(options.projectRoot, options.siteRoot.resolve()))

    if diagnostics:
        print("\n".join(diagnostics))

        return 1

    print("Documentation quality gates: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
