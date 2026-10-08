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

from tools import documentation_coverage  # noqa: E402
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
    def source_path(self) -> str:
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


def LocalTarget(page_path: Path, target: str, site_root: Path) -> tuple[Path, str] | None:
    """Resolve a local URL and reject targets outside the published site boundary."""

    parsed = urlsplit(target)

    if parsed.scheme or parsed.netloc:
        if f"{parsed.scheme}://{parsed.netloc}" != PUBLIC_ORIGIN:
            return None

        if not (parsed.path == PUBLIC_PATH or parsed.path.startswith(PUBLIC_PATH + "/")):
            return None

        target_path = parsed.path.removeprefix(PUBLIC_PATH)

    else:
        target_path = parsed.path

    target_path = unquote(target_path)

    if target_path.startswith("/"):
        if target_path == PUBLIC_PATH or target_path.startswith(PUBLIC_PATH + "/"):
            target_path = target_path.removeprefix(PUBLIC_PATH)

        resolved = (site_root / target_path.lstrip("/")).resolve()

    else:
        resolved = (page_path.parent / target_path).resolve() if target_path else page_path.resolve()

    if not resolved.is_relative_to(site_root.resolve()):
        raise ValueError(f"URL escapes the generated site: {target}")

    if resolved.is_dir():
        resolved /= "index.html"

    return resolved, unquote(parsed.fragment)


def CheckRenderedLinks(site_root: Path) -> tuple[str, ...]:
    """Validate every generated local URL and its exact fragment identifier."""

    pages = {path.resolve(): ParsePage(path) for path in sorted(site_root.rglob("*.html"))}
    diagnostics = []

    for page_path, page in pages.items():
        for target in page.targets:
            try:
                resolved = LocalTarget(page_path, target, site_root)

            except ValueError as error:
                diagnostics.append(f"{page_path.relative_to(site_root)}: {error}")
                continue

            if resolved is None:
                continue

            target_path, fragment = resolved

            if not target_path.is_file():
                diagnostics.append(f"{page_path.relative_to(site_root)}: missing target {target}")

            elif fragment and target_path.suffix == ".html":
                target_page = pages.get(target_path)

                if target_page is None or fragment not in target_page.anchors:
                    diagnostics.append(f"{page_path.relative_to(site_root)}: missing anchor {target}")

    return tuple(sorted(set(diagnostics)))


def CheckSourceLinks(project_root: Path) -> tuple[str, ...]:
    """Reject broken repository-local Markdown and asset targets in authored docs."""

    try:
        paths = [project_root / name for name in documentation_coverage.TrackedFiles(project_root)
                 if name.endswith(".md")]

    except subprocess.CalledProcessError:
        paths = [*project_root.glob("*.md"), *sorted((project_root / "docs").rglob("*.md"))]
    diagnostics = []

    for path in paths:
        for match in MARKDOWN_LINK.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1)
            parsed = urlsplit(target)

            if parsed.scheme or parsed.netloc or not parsed.path:
                continue

            resolved = (path.parent / unquote(parsed.path)).resolve()

            if not resolved.is_relative_to(project_root.resolve()) or not resolved.exists():
                diagnostics.append(f"{path.relative_to(project_root)}: missing source target {target}")

    return tuple(sorted(set(diagnostics)))


def CheckGeneratedPolicy(project_root: Path) -> tuple[str, ...]:
    """Fail if disposable build output or generated site HTML is tracked by Git."""

    result = subprocess.run(["git", "ls-files", "-z"], cwd=project_root,
                            capture_output=True, text=True, check=True)
    diagnostics = []

    for name in result.stdout.split("\0"):
        if name.startswith("_build/") or (
            name.startswith("docs/site/") and name.endswith(".html")
        ):
            diagnostics.append(f"Generated output must remain untracked: {name}")

    return tuple(diagnostics)


def CheckApiCoverage(site_root: Path, modules: Sequence[ModuleContract]) -> tuple[str, ...]:
    """Require installed module/public-symbol anchors and branch-specific source links."""

    diagnostics = []

    for module in modules:
        page_path = site_root / "en" / "api" / "modules" / module.name.replace(".", "-")
        page_path /= "index.html"

        if not page_path.is_file():
            diagnostics.append(f"Missing generated module page: {module.name}")
            continue

        page = ParsePage(page_path)

        for symbol in (module.name, *module.symbols):
            if symbol not in page.anchors:
                diagnostics.append(f"Missing generated API anchor: {symbol}")

        expected_source = (
            "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/" + module.source_path
        )

        if expected_source not in page.targets:
            diagnostics.append(f"Missing develop source link: {module.name}")

    for name in ("en/index.html", "en/objects.inv", "en/search/search_index.json",
                 "ru/index.html", "zh-CN/index.html"):
        if not (site_root / name).is_file():
            diagnostics.append(f"Missing generated site artifact: {name}")

    return tuple(diagnostics)


def HtmlPage(page_path: str, site_root: Path) -> Path:
    """Map one Markdown route to its directory-URL HTML artifact."""

    return site_root / "en" / documentation_coverage.MarkdownArtifact(page_path)


def CheckMarkdownReachability(project_root: Path, site_root: Path) -> tuple[str, ...]:
    """Require every canonical Markdown artifact to be reachable from English entry."""

    diagnostics = []
    pages = {path.resolve(): ParsePage(path) for path in sorted(site_root.rglob("*.html"))}
    entry = (site_root / "en/index.html").resolve()
    pending = [entry]
    reached: set[Path] = set()

    while pending:
        page_path = pending.pop()

        if page_path in reached or page_path not in pages:
            continue

        reached.add(page_path)

        for target in pages[page_path].targets:
            try:
                local = LocalTarget(page_path, target, site_root)

            except ValueError:
                continue

            if local is not None and local[0].suffix == ".html":
                pending.append(local[0])

    for item in documentation_coverage.InventoryFiles(project_root):
        if item.disposition not in {"rendered-markdown", "generated-api"} or item.page_path is None:
            continue

        expected = HtmlPage(item.page_path, site_root).resolve()

        if not expected.is_file():
            diagnostics.append(f"Missing classified documentation page: {item.source_path}")

        elif expected not in reached:
            diagnostics.append(f"Unreachable classified documentation page: {item.source_path}")

    coverage_page = (site_root / "en/coverage/index.html").resolve()

    if coverage_page not in reached:
        diagnostics.append("Repository coverage inventory is not reachable from English entry")

    return tuple(diagnostics)


def CheckAll(
    project_root: Path, site_root: Path, modules: Sequence[ModuleContract] = (),
) -> tuple[str, ...]:
    """Run the complete deterministic documentation policy and rendered gate."""

    return tuple(sorted(set((
        *CheckSourceLinks(project_root), *CheckGeneratedPolicy(project_root),
        *documentation_coverage.CheckRepositoryCoverage(project_root),
        *CheckMarkdownReachability(project_root, site_root),
        *CheckMarkdownTables(project_root),
        *CheckRenderedLinks(site_root), *CheckApiCoverage(site_root, modules),
    ))))


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run source and generated-site checks without accessing the network."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--site-root", type=Path)
    options = parser.parse_args(arguments)
    diagnostics = [*CheckSourceLinks(options.project_root), *CheckGeneratedPolicy(options.project_root),
                   *CheckMarkdownTables(options.project_root),
                   *documentation_coverage.CheckRepositoryCoverage(options.project_root)]

    if options.site_root:
        diagnostics.extend(CheckRenderedLinks(options.site_root.resolve()))
        diagnostics.extend(CheckMarkdownReachability(options.project_root, options.site_root.resolve()))

    if diagnostics:
        print("\n".join(diagnostics))

        return 1

    print("Documentation quality gates: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
