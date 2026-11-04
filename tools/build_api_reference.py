"""Build strict F-Layer documentation from statically discovered installed source."""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import documentation_coverage as documentationCoverage  # noqa: E402
from tools import documentation_gates as documentationGates
from tools import generated_localization as generatedLocalization
from tools.locale_documentation import (  # noqa: E402
    CanonicalHash,
    ValidateLocales,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BUILD_ROOT = PROJECT_ROOT / "_build" / "api-reference"
REQUIREMENTS_PATH = PROJECT_ROOT / "docs" / "requirements-api.txt"
SOURCE_CONTENT = PROJECT_ROOT / "docs" / "site" / "content" / "en"
SOURCE_CONFIG = PROJECT_ROOT / "docs" / "site" / "mkdocs.yml"
PUBLIC_ROOT = "https://fuzzy-technologies.github.io/F-Layer"


@dataclass(frozen=True)
class ModuleSource:
    """A public installed module and its corresponding repository source."""

    name: str
    installedPath: Path
    sourcePath: str
    symbols: tuple[str, ...]


def RunCommand(
    command: Sequence[str | Path],
    *,
    cwd: Path = PROJECT_ROOT,
    environment: Mapping[str, str] | None = None,
) -> str:
    """Run a deterministic subprocess and preserve its diagnostic failure."""

    result = subprocess.run(
        [str(part) for part in command], cwd=cwd, env=environment,
        capture_output=True, text=True, check=False,
    )

    if result.returncode:
        raise RuntimeError(f"Command failed: {command[0]}\n{result.stdout}{result.stderr}")

    return result.stdout.strip()


def RecreateBuildRoot(buildRoot: Path) -> None:
    """Replace only the owned build root and reject symlink redirection."""

    if buildRoot != BUILD_ROOT or buildRoot.is_symlink() or buildRoot.parent.is_symlink():
        raise ValueError("Refusing to replace an unowned or redirected build directory")

    if buildRoot.exists():
        shutil.rmtree(buildRoot)

    buildRoot.mkdir(parents=True)


def EnvironmentPython(environmentRoot: Path) -> Path:
    """Return the platform interpreter path inside a virtual environment."""

    return environmentRoot / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def LockedVersions() -> dict[str, str]:
    """Read every exact documentation distribution pin from the committed lock."""

    pins: dict[str, str] = {}

    for line in REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue

        name, separator, version = line.partition("==")

        if not separator or not re.fullmatch(r"[\w.-]+", version):
            raise ValueError(f"Documentation dependency is not exactly pinned: {line}")

        pins[name] = version

    return pins


def VerifyEnvironment(environmentPython: Path) -> dict[str, str]:
    """Require the selected environment to contain the complete exact lock."""

    pins = LockedVersions()
    code = (
        "import importlib.metadata as m, json; "
        f"print(json.dumps({{name: m.version(name) for name in {tuple(pins)!r}}}))"
    )
    versions: dict[str, str] = json.loads(RunCommand([environmentPython, "-c", code]))

    if versions != pins:
        mismatched = [name for name in pins if versions.get(name) != pins[name]]
        raise ValueError(f"Documentation lock mismatch: {', '.join(mismatched)}")

    return versions


def VerifyBuildWorkspace(buildRoot: Path) -> None:
    """Reject stale generated output restored unexpectedly by environment creation."""

    unexpected = [path for path in buildRoot.iterdir() if path.name != "environment"]

    if unexpected:
        raise ValueError(
            "Documentation environment creation restored generated output in the clean build root; "
            "use --environment-python with a verified environment outside _build/api-reference"
        )


def WriteImportGuard(guardRoot: Path) -> None:
    """Fail if documentation discovery attempts to import the runtime package."""

    guardRoot.mkdir()
    (guardRoot / "sitecustomize.py").write_text(
        '"""Generated documentation import guard."""\n'
        "import sys\n\n"
        "class FLayerImportGuard:\n"
        '    """Prevent runtime package execution during static discovery."""\n'
        "    def find_spec(self, fullname, path=None, target=None):\n"
        '        """Reject F-Layer imports and delegate all other discovery."""\n\n'
        '        if fullname == "flayer" or fullname.startswith("flayer."):\n'
        '            raise RuntimeError("API discovery attempted to import flayer")\n'
        "\n        return None\n\n"
        "sys.meta_path.insert(0, FLayerImportGuard())\n",
        encoding="utf-8",
    )


def DiscoverModules(installedRoot: Path) -> tuple[ModuleSource, ...]:
    """Require exact package parity and discover supported surfaces without imports."""

    installedFiles = {path.relative_to(installedRoot).as_posix(): path
                       for path in (installedRoot / "flayer").rglob("*")
                       if path.is_file() and "__pycache__" not in path.parts
                       and path.suffix not in {".pyc", ".pyo"}}
    sourceFiles = {path.relative_to(PROJECT_ROOT / "src").as_posix(): path
                    for path in (PROJECT_ROOT / "src/flayer").rglob("*")
                    if path.is_file() and "__pycache__" not in path.parts
                    and path.suffix not in {".pyc", ".pyo"}}

    if installedFiles.keys() != sourceFiles.keys():
        missing = sorted(sourceFiles.keys() - installedFiles.keys())
        unexpected = sorted(installedFiles.keys() - sourceFiles.keys())
        raise ValueError(f"Installed wheel package inventory differs: missing={missing}, unexpected={unexpected}")

    for relative, path in installedFiles.items():
        if sourceFiles[relative].read_bytes() != path.read_bytes():
            raise ValueError(f"Installed wheel differs from current source: src/{relative}")

    installedPaths = {name: path for name, path in installedFiles.items() if path.suffix == ".py"}
    modules = []

    for relative, path in sorted(installedPaths.items()):
        sourcePath = "src/" + relative

        syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        definitions = documentationCoverage.InventoryDefinitions(sourcePath, syntax)

        if not documentationCoverage.PublicModule(sourcePath):
            continue

        moduleName = documentationCoverage.ModuleName(sourcePath)

        if not ast.get_docstring(syntax):
            raise ValueError(f"Public module lacks an English docstring: {moduleName}")

        symbols = tuple(item.symbol for item in definitions if item.disposition == "generated-api")
        modules.append(ModuleSource(moduleName, path, sourcePath, symbols))

    if not modules:
        raise ValueError("Installed flayer package has no discoverable modules")

    return tuple(modules)


def DiscoverDefinitions(installedRoot: Path) -> tuple[documentationCoverage.DefinitionCoverage, ...]:
    """Inventory private and public installed definitions for accountable omissions."""

    definitions: list[documentationCoverage.DefinitionCoverage] = []

    for path in sorted((installedRoot / "flayer").rglob("*.py")):
        sourcePath = "src/" + path.relative_to(installedRoot).as_posix()
        syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        definitions.extend(documentationCoverage.InventoryDefinitions(sourcePath, syntax))

    return tuple(definitions)


def WriteApiLocaleInventory(modules: tuple[ModuleSource, ...], buildRoot: Path) -> None:
    """Record actual source-bound API reviews instead of manufacturing missing states."""

    units = generatedLocalization.DiscoverGeneratedUnits(PROJECT_ROOT)
    translations = generatedLocalization.LoadTranslations(PROJECT_ROOT, units)
    sourcePaths = {module.sourcePath for module in modules}
    apiUnits = {identifier: unit for identifier, unit in units.items()
                 if unit.kind == "symbol" and unit.sourcePath in sourcePaths}
    states = generatedLocalization.TranslationStates(apiUnits, translations)
    payload = {"status": "pass", "states": states,
               "sourceHashes": {identifier: CanonicalHash(unit) for identifier, unit in apiUnits.items()}}
    (buildRoot / "api-locales.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def RewriteDirectoryLinks(content: str, sourcePath: Path) -> str:
    """Resolve repository README directory links in generated Markdown only."""

    def Rewrite(match: re.Match[str]) -> str:
        """Replace only a local URL target whose directory owns a README page."""

        target = match.group(1)
        directory = (sourcePath.parent / target).resolve()

        if (target.endswith("/") and directory.is_relative_to(PROJECT_ROOT)
                and (directory / "README.md").is_file()):
            start = match.start(1) - match.start()
            end = match.end(1) - match.start()
            original = match.group(0)

            return original[:start] + target + "README.md" + original[end:]

        return match.group(0)

    return documentationGates.MARKDOWN_LINK.sub(Rewrite, content)


def RewriteRepositoryLinks(content: str, sourcePath: Path, pagePath: str) -> str:
    """Route copied Markdown locally and retain source links for nonpage files."""

    def Rewrite(match: re.Match[str]) -> str:
        """Resolve one source-relative link against the complete repository page map."""

        target = match.group(1)
        parsed = urlsplit(target)

        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)

        resolved = (sourcePath.parent / unquote(parsed.path)).resolve()

        if not resolved.is_relative_to(PROJECT_ROOT):
            raise ValueError(f"Repository link escapes project: {target}")

        if resolved.is_dir() and (resolved / "README.md").is_file():
            resolved /= "README.md"

        relative = resolved.relative_to(PROJECT_ROOT).as_posix()

        if (relative.startswith("docs/site/content/")
                and not relative.startswith(documentationCoverage.SOURCE_CONTENT_PREFIX)):
            rewritten = documentationCoverage.SOURCE_URL + relative

        elif resolved.suffix == ".md":
            destination = documentationCoverage.MarkdownPage(relative)
            rewritten = os.path.relpath(destination, Path(pagePath).parent).replace(os.sep, "/")

        elif relative.startswith(documentationCoverage.SOURCE_CONTENT_PREFIX):
            destination = relative.removeprefix(documentationCoverage.SOURCE_CONTENT_PREFIX)
            rewritten = os.path.relpath(destination, Path(pagePath).parent).replace(os.sep, "/")

        else:
            rewritten = documentationCoverage.SOURCE_URL + relative

        if parsed.fragment:
            rewritten += "#" + parsed.fragment

        original = match.group(0)
        start = match.start(1) - match.start()
        end = match.end(1) - match.start()

        return original[:start] + rewritten + original[end:]

    return documentationGates.MARKDOWN_LINK.sub(Rewrite, content)


def WriteEngineeringContent(contentRoot: Path) -> list[dict[str, str]]:
    """Render every classified canonical Markdown file, including policies and templates."""

    navigation = []

    for item in documentationCoverage.InventoryFiles(PROJECT_ROOT):
        if item.disposition != "rendered-markdown" or item.pagePath is None:
            continue

        canonicalRoute = item.sourcePath.startswith(documentationCoverage.SOURCE_CONTENT_PREFIX)
        sourcePath = PROJECT_ROOT / item.sourcePath
        destination = contentRoot / item.pagePath
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = RewriteRepositoryLinks(sourcePath.read_text(encoding="utf-8"),
                                         sourcePath, item.pagePath)

        if canonicalRoute:
            destination.write_text(content, encoding="utf-8")
            continue

        sourceLink = documentationCoverage.SOURCE_URL + item.sourcePath
        destination.write_text(content + f"\n[Repository source]({sourceLink})\n",
                               encoding="utf-8")
        heading = next((line.removeprefix("# ").strip() for line in content.splitlines()
                        if line.startswith("# ")), sourcePath.stem)
        navigation.append({heading + " (" + item.sourcePath + ")": item.pagePath})

    return navigation


def WriteBuildContent(modules: tuple[ModuleSource, ...], buildRoot: Path) -> Path:
    """Copy canonical pages and add a module page for each installed public module."""

    contentRoot = buildRoot / "content" / "en"
    shutil.copytree(SOURCE_CONTENT, contentRoot)
    moduleRoot = contentRoot / "api" / "modules"
    moduleRoot.mkdir()
    links = []
    moduleNavigation = []

    for module in modules:
        pageName = module.name.replace(".", "-")
        sourceUrl = (
            "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/" + module.sourcePath
        )
        page = (
            f"# {module.name}\n\n[Module source]({sourceUrl})\n\n"
            f"::: {module.name}\n    options:\n      filters: [\"!^_(?!_call__$)\"]\n"
        )
        (moduleRoot / f"{pageName}.md").write_text(page, encoding="utf-8")
        links.append(f"- [{module.name}](modules/{pageName}.md)")
        moduleNavigation.append({module.name: f"api/modules/{pageName}.md"})

    indexPath = contentRoot / "api" / "index.md"
    with indexPath.open("a", encoding="utf-8") as index:
        index.write("\n## Installed modules\n\n" + "\n".join(links) + "\n")

    config = SOURCE_CONFIG.read_text(encoding="utf-8")
    config = re.sub(r"^docs_dir:.*$", f"docs_dir: {json.dumps(str(contentRoot))}",
                    config, flags=re.MULTILINE)
    config = re.sub(r"^site_dir:.*$", f"site_dir: {json.dumps(str(buildRoot / 'rendered-en'))}",
                    config, flags=re.MULTILINE)
    engineeringNavigation = WriteEngineeringContent(contentRoot)
    apiNavigation = json.dumps([{"Index": "api/index.md"}, *moduleNavigation])
    navigationMarker = "  - API reference: api/index.md"

    if config.count(navigationMarker) != 1:
        raise ValueError("Authored navigation must contain exactly one API reference entry")

    config = config.replace(navigationMarker, "  - API reference: " + apiNavigation)
    config = re.sub(
        r"(?m)^plugins:",
        "  - Repository coverage: coverage/index.md\n  - Engineering guides: " + json.dumps(engineeringNavigation) + "\n\nplugins:",
        config, count=1,
    )
    configPath = buildRoot / "mkdocs.yml"
    configPath.write_text(config, encoding="utf-8")

    return configPath


def AssembleSite(buildRoot: Path) -> Path:
    """Replace owned publication output with only the freshly rendered English tree."""

    if buildRoot != BUILD_ROOT or buildRoot.is_symlink() or buildRoot.parent.is_symlink():
        raise ValueError("Refusing to assemble an unowned or redirected documentation site")

    renderedRoot = buildRoot / "rendered-en"
    siteRoot = buildRoot / "site"

    if renderedRoot.is_symlink() or siteRoot.is_symlink() or not renderedRoot.is_dir():
        raise ValueError("Fresh English output is absent or the generated site is redirected")

    if siteRoot.exists():
        shutil.rmtree(siteRoot)

    siteRoot.mkdir()
    renderedRoot.rename(siteRoot / "en")

    return siteRoot


def WriteLocaleFallbacks(siteRoot: Path) -> None:
    """Expose clear unavailable-translation routes with canonical English navigation."""

    notices = tomllib.loads((PROJECT_ROOT / "docs/i18n/fallbacks.toml").read_text(encoding="utf-8"))

    for locale, notice in notices.items():
        title = notice["title"]
        body = notice["body"]
        pageRoot = siteRoot / locale
        pageRoot.mkdir()
        page = (
            f'<!doctype html><html lang="{locale}"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)} · F-Layer</title>'
            '<link rel="stylesheet" href="../en/assets/stylesheets/flayer.css"></head>'
            '<body class="fl-fallback"><main>'
            '<img class="fl-brand-lockup" src="../en/assets/brand/flayer-horizontal.svg" '
            'alt="F-Layer by Fuzzy Technologies">'
            f'<h1>{html.escape(title)}</h1><p>{html.escape(body)}</p>'
            '<p>Translation status: <strong>missing</strong>. No approved translation is claimed.</p>'
            '<nav aria-label="Languages"><a href="../en/">English documentation</a>'
            '<a href="../ru/">Russian</a><a href="../zh-CN/">Simplified Chinese</a></nav>'
            '</main></body></html>\n'
        )
        (pageRoot / "index.html").write_text(page, encoding="utf-8")

    (siteRoot / "index.html").write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="refresh" content="0;url=en/">'
        '<title>F-Layer documentation</title></head><body>'
        '<a href="en/">Open F-Layer documentation</a></body></html>\n', encoding="utf-8",
    )
    (siteRoot / ".nojekyll").touch()


def InstallWheel(environmentPython: Path, wheelPath: Path, buildRoot: Path) -> Path:
    """Install only the built wheel into a clean owned target, without mutating tools."""

    if buildRoot != BUILD_ROOT or buildRoot.is_symlink() or buildRoot.parent.is_symlink():
        raise ValueError("Refusing to install a wheel into an unowned or redirected build root")

    installedRoot = buildRoot / "installed"

    if installedRoot.exists():
        raise ValueError("Fresh installed-wheel target already exists in the clean build root")

    RunCommand([environmentPython, "-m", "pip", "install", "--no-index", "--no-deps",
                "--disable-pip-version-check", "--target", installedRoot, wheelPath], cwd=buildRoot)
    code = (
        "import importlib.metadata as m\n"
        f"distributions = tuple(m.distributions(path=[{str(installedRoot)!r}]))\n\n"
        "assert len(distributions) == 1, 'Expected one installed wheel distribution'\n"
        "assert distributions[0].metadata['Name'] == 'f-layer', 'Unexpected wheel distribution'"
    )
    RunCommand([environmentPython, "-c", code], cwd=buildRoot)

    return installedRoot


def BuildReference(environmentPython: Path | None = None) -> tuple[Path, dict[str, str], Path]:
    """Build, verify, and record evidence for a clean installed-wheel reference."""

    documentationCoverage.InventoryFiles(PROJECT_ROOT)
    inputDiagnostics = documentationCoverage.CheckBuildInputs(PROJECT_ROOT)

    if inputDiagnostics:
        raise ValueError("\n".join(inputDiagnostics))

    RecreateBuildRoot(BUILD_ROOT)

    if environmentPython is None:
        RunCommand([sys.executable, "-m", "venv", BUILD_ROOT / "environment"])
        environmentPython = EnvironmentPython(BUILD_ROOT / "environment")
        VerifyBuildWorkspace(BUILD_ROOT)
        RunCommand([environmentPython, "-m", "pip", "install", "--disable-pip-version-check",
                    "--requirement", REQUIREMENTS_PATH])

    VerifyBuildWorkspace(BUILD_ROOT)
    versions = VerifyEnvironment(environmentPython)
    artifactRoot = BUILD_ROOT / "artifacts"
    RunCommand([environmentPython, "-m", "build", "--no-isolation", "--wheel",
                "--outdir", artifactRoot, PROJECT_ROOT], cwd=BUILD_ROOT)
    wheels = list(artifactRoot.glob("*.whl"))

    if len(wheels) != 1:
        raise ValueError("Expected exactly one built F-Layer wheel")

    wheelPath = wheels[0]
    installedRoot = InstallWheel(environmentPython, wheelPath, BUILD_ROOT)
    modules = DiscoverModules(installedRoot)
    definitions = DiscoverDefinitions(installedRoot)
    locales = ValidateLocales(PROJECT_ROOT)

    if locales.diagnostics:
        raise ValueError("\n".join(locales.diagnostics))

    WriteApiLocaleInventory(modules, BUILD_ROOT)
    configPath = WriteBuildContent(modules, BUILD_ROOT)
    documentationCoverage.WriteInventory(PROJECT_ROOT, BUILD_ROOT, definitions)
    guardRoot = BUILD_ROOT / "import-guard"
    WriteImportGuard(guardRoot)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(guardRoot)
    environment["FLAYER_INSTALLED_PACKAGES"] = str(installedRoot)
    RunCommand([environmentPython, "-m", "mkdocs", "build", "--strict", "--config-file",
                configPath], cwd=BUILD_ROOT, environment=environment)
    siteRoot = AssembleSite(BUILD_ROOT)
    WriteLocaleFallbacks(siteRoot)
    diagnostics = documentationGates.CheckAll(PROJECT_ROOT, siteRoot, modules)

    if diagnostics:
        raise ValueError("\n".join(diagnostics))

    evidence = {
        "discovery": "static-installed-wheel", "runtimeImports": "blocked",
        "wheelInstallIsolation": "fresh-owned-target",
        "sourceRevision": RunCommand(["git", "rev-parse", "HEAD"]),
        "sourceDirty": bool(RunCommand(["git", "status", "--porcelain", "--untracked-files=no"])),
        "documentationPackages": versions,
        "wheel": {"name": wheelPath.name, "sha256": hashlib.sha256(wheelPath.read_bytes()).hexdigest()},
        "modules": [module.name for module in modules],
        "repositoryCoverage": {"status": "pass", "inventory": "repository-coverage.json",
                               "files": len(documentationCoverage.InventoryFiles(PROJECT_ROOT)),
                               "definitions": len(definitions)},
        "sourceWheelPackageParity": "exact-excluding-bytecode",
        "renderedMarkdownReachability": "pass",
        "authoredLocales": {"status": "pass", "states": locales.states},
        "renderedLinksAndAnchors": "pass", "generatedHtmlTracked": False,
    }
    (BUILD_ROOT / "build-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )

    return environmentPython, environment, configPath


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run a strict build and optionally serve the same verified configuration."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-python", type=Path,
                        help="Use a provisioned exact-lock environment without downloading tools.", dest='environmentPython')
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--dev-addr", default="127.0.0.1:8000", dest='devAddr')
    options = parser.parse_args(arguments)
    environmentPython, environment, configPath = BuildReference(options.environment_python)
    print(f"Documentation build: PASS ({BUILD_ROOT / 'site'})")

    if options.serve:
        RunCommand([environmentPython, "-m", "mkdocs", "serve", "--strict", "--config-file",
                    configPath, "--dev-addr", options.dev_addr], cwd=BUILD_ROOT,
                   environment=environment)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
