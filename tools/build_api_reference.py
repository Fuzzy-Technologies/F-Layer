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

from tools import documentation_coverage, documentation_gates, generated_localization  # noqa: E402
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
    installed_path: Path
    source_path: str
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


def RecreateBuildRoot(build_root: Path) -> None:
    """Replace only the owned build root and reject symlink redirection."""

    if build_root != BUILD_ROOT or build_root.is_symlink() or build_root.parent.is_symlink():
        raise ValueError("Refusing to replace an unowned or redirected build directory")

    if build_root.exists():
        shutil.rmtree(build_root)

    build_root.mkdir(parents=True)


def EnvironmentPython(environment_root: Path) -> Path:
    """Return the platform interpreter path inside a virtual environment."""

    return environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


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


def VerifyEnvironment(environment_python: Path) -> dict[str, str]:
    """Require the selected environment to contain the complete exact lock."""

    pins = LockedVersions()
    code = (
        "import importlib.metadata as m, json; "
        f"print(json.dumps({{name: m.version(name) for name in {tuple(pins)!r}}}))"
    )
    versions: dict[str, str] = json.loads(RunCommand([environment_python, "-c", code]))

    if versions != pins:
        mismatched = [name for name in pins if versions.get(name) != pins[name]]
        raise ValueError(f"Documentation lock mismatch: {', '.join(mismatched)}")

    return versions


def VerifyBuildWorkspace(build_root: Path) -> None:
    """Reject stale generated output restored unexpectedly by environment creation."""

    unexpected = [path for path in build_root.iterdir() if path.name != "environment"]

    if unexpected:
        raise ValueError(
            "Documentation environment creation restored generated output in the clean build root; "
            "use --environment-python with a verified environment outside _build/api-reference"
        )


def WriteImportGuard(guard_root: Path) -> None:
    """Fail if documentation discovery attempts to import the runtime package."""

    guard_root.mkdir()
    (guard_root / "sitecustomize.py").write_text(
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


def DiscoverModules(installed_root: Path) -> tuple[ModuleSource, ...]:
    """Require exact package parity and discover supported surfaces without imports."""

    installed_files = {path.relative_to(installed_root).as_posix(): path
                       for path in (installed_root / "flayer").rglob("*")
                       if path.is_file() and "__pycache__" not in path.parts
                       and path.suffix not in {".pyc", ".pyo"}}
    source_files = {path.relative_to(PROJECT_ROOT / "src").as_posix(): path
                    for path in (PROJECT_ROOT / "src/flayer").rglob("*")
                    if path.is_file() and "__pycache__" not in path.parts
                    and path.suffix not in {".pyc", ".pyo"}}

    if installed_files.keys() != source_files.keys():
        missing = sorted(source_files.keys() - installed_files.keys())
        unexpected = sorted(installed_files.keys() - source_files.keys())
        raise ValueError(f"Installed wheel package inventory differs: missing={missing}, unexpected={unexpected}")

    for relative, path in installed_files.items():
        if source_files[relative].read_bytes() != path.read_bytes():
            raise ValueError(f"Installed wheel differs from current source: src/{relative}")

    installed_paths = {name: path for name, path in installed_files.items() if path.suffix == ".py"}
    modules = []

    for relative, path in sorted(installed_paths.items()):
        source_path = "src/" + relative

        syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        definitions = documentation_coverage.InventoryDefinitions(source_path, syntax)

        if not documentation_coverage.PublicModule(source_path):
            continue

        module_name = documentation_coverage.ModuleName(source_path)

        if not ast.get_docstring(syntax):
            raise ValueError(f"Public module lacks an English docstring: {module_name}")

        symbols = tuple(item.symbol for item in definitions if item.disposition == "generated-api")
        modules.append(ModuleSource(module_name, path, source_path, symbols))

    if not modules:
        raise ValueError("Installed flayer package has no discoverable modules")

    return tuple(modules)


def DiscoverDefinitions(installed_root: Path) -> tuple[documentation_coverage.DefinitionCoverage, ...]:
    """Inventory private and public installed definitions for accountable omissions."""

    definitions: list[documentation_coverage.DefinitionCoverage] = []

    for path in sorted((installed_root / "flayer").rglob("*.py")):
        source_path = "src/" + path.relative_to(installed_root).as_posix()
        syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        definitions.extend(documentation_coverage.InventoryDefinitions(source_path, syntax))

    return tuple(definitions)


def WriteApiLocaleInventory(modules: tuple[ModuleSource, ...], build_root: Path) -> None:
    """Record actual source-bound API reviews instead of manufacturing missing states."""

    units = generated_localization.DiscoverGeneratedUnits(PROJECT_ROOT)
    translations = generated_localization.LoadTranslations(PROJECT_ROOT, units)
    source_paths = {module.source_path for module in modules}
    api_units = {identifier: unit for identifier, unit in units.items()
                 if unit.kind == "symbol" and unit.source_path in source_paths}
    states = generated_localization.TranslationStates(api_units, translations)
    payload = {"status": "pass", "states": states,
               "sourceHashes": {identifier: CanonicalHash(unit) for identifier, unit in api_units.items()}}
    (build_root / "api-locales.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def RewriteDirectoryLinks(content: str, source_path: Path) -> str:
    """Resolve repository README directory links in generated Markdown only."""

    def Rewrite(match: re.Match[str]) -> str:
        """Replace only a local URL target whose directory owns a README page."""

        target = match.group(1)
        directory = (source_path.parent / target).resolve()

        if (target.endswith("/") and directory.is_relative_to(PROJECT_ROOT)
                and (directory / "README.md").is_file()):
            start = match.start(1) - match.start()
            end = match.end(1) - match.start()
            original = match.group(0)

            return original[:start] + target + "README.md" + original[end:]

        return match.group(0)

    return documentation_gates.MARKDOWN_LINK.sub(Rewrite, content)


def RewriteRepositoryLinks(content: str, source_path: Path, page_path: str) -> str:
    """Route copied Markdown locally and retain source links for nonpage files."""

    def Rewrite(match: re.Match[str]) -> str:
        """Resolve one source-relative link against the complete repository page map."""

        target = match.group(1)
        parsed = urlsplit(target)

        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)

        resolved = (source_path.parent / unquote(parsed.path)).resolve()

        if not resolved.is_relative_to(PROJECT_ROOT):
            raise ValueError(f"Repository link escapes project: {target}")

        if resolved.is_dir() and (resolved / "README.md").is_file():
            resolved /= "README.md"

        relative = resolved.relative_to(PROJECT_ROOT).as_posix()

        if (relative.startswith("docs/site/content/")
                and not relative.startswith(documentation_coverage.SOURCE_CONTENT_PREFIX)):
            rewritten = documentation_coverage.SOURCE_URL + relative

        elif resolved.suffix == ".md":
            destination = documentation_coverage.MarkdownPage(relative)
            rewritten = os.path.relpath(destination, Path(page_path).parent).replace(os.sep, "/")

        elif relative.startswith(documentation_coverage.SOURCE_CONTENT_PREFIX):
            destination = relative.removeprefix(documentation_coverage.SOURCE_CONTENT_PREFIX)
            rewritten = os.path.relpath(destination, Path(page_path).parent).replace(os.sep, "/")

        else:
            rewritten = documentation_coverage.SOURCE_URL + relative

        if parsed.fragment:
            rewritten += "#" + parsed.fragment

        original = match.group(0)
        start = match.start(1) - match.start()
        end = match.end(1) - match.start()

        return original[:start] + rewritten + original[end:]

    return documentation_gates.MARKDOWN_LINK.sub(Rewrite, content)


def WriteEngineeringContent(content_root: Path) -> list[dict[str, str]]:
    """Render every classified canonical Markdown file, including policies and templates."""

    navigation = []

    for item in documentation_coverage.InventoryFiles(PROJECT_ROOT):
        if item.disposition != "rendered-markdown" or item.page_path is None:
            continue

        canonical_route = item.source_path.startswith(documentation_coverage.SOURCE_CONTENT_PREFIX)
        source_path = PROJECT_ROOT / item.source_path
        destination = content_root / item.page_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = RewriteRepositoryLinks(source_path.read_text(encoding="utf-8"),
                                         source_path, item.page_path)

        if canonical_route:
            destination.write_text(content, encoding="utf-8")
            continue

        source_link = documentation_coverage.SOURCE_URL + item.source_path
        destination.write_text(content + f"\n[Repository source]({source_link})\n",
                               encoding="utf-8")
        heading = next((line.removeprefix("# ").strip() for line in content.splitlines()
                        if line.startswith("# ")), source_path.stem)
        navigation.append({heading + " (" + item.source_path + ")": item.page_path})

    return navigation


def WriteBuildContent(modules: tuple[ModuleSource, ...], build_root: Path) -> Path:
    """Copy canonical pages and add a module page for each installed public module."""

    content_root = build_root / "content" / "en"
    shutil.copytree(SOURCE_CONTENT, content_root)
    module_root = content_root / "api" / "modules"
    module_root.mkdir()
    links = []
    module_navigation = []

    for module in modules:
        page_name = module.name.replace(".", "-")
        source_url = (
            "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/" + module.source_path
        )
        page = (
            f"# {module.name}\n\n[Module source]({source_url})\n\n"
            f"::: {module.name}\n    options:\n      filters: [\"!^_(?!_call__$)\"]\n"
        )
        (module_root / f"{page_name}.md").write_text(page, encoding="utf-8")
        links.append(f"- [{module.name}](modules/{page_name}.md)")
        module_navigation.append({module.name: f"api/modules/{page_name}.md"})

    index_path = content_root / "api" / "index.md"
    with index_path.open("a", encoding="utf-8") as index:
        index.write("\n## Installed modules\n\n" + "\n".join(links) + "\n")

    config = SOURCE_CONFIG.read_text(encoding="utf-8")
    config = re.sub(r"^docs_dir:.*$", f"docs_dir: {json.dumps(str(content_root))}",
                    config, flags=re.MULTILINE)
    config = re.sub(r"^site_dir:.*$", f"site_dir: {json.dumps(str(build_root / 'rendered-en'))}",
                    config, flags=re.MULTILINE)
    engineering_navigation = WriteEngineeringContent(content_root)
    api_navigation = json.dumps([{"Index": "api/index.md"}, *module_navigation])
    navigation_marker = "  - API reference: api/index.md"

    if config.count(navigation_marker) != 1:
        raise ValueError("Authored navigation must contain exactly one API reference entry")

    config = config.replace(navigation_marker, "  - API reference: " + api_navigation)
    config = re.sub(
        r"(?m)^plugins:",
        "  - Repository coverage: coverage/index.md\n  - Engineering guides: " + json.dumps(engineering_navigation) + "\n\nplugins:",
        config, count=1,
    )
    config_path = build_root / "mkdocs.yml"
    config_path.write_text(config, encoding="utf-8")

    return config_path


def AssembleSite(build_root: Path) -> Path:
    """Replace owned publication output with only the freshly rendered English tree."""

    if build_root != BUILD_ROOT or build_root.is_symlink() or build_root.parent.is_symlink():
        raise ValueError("Refusing to assemble an unowned or redirected documentation site")

    rendered_root = build_root / "rendered-en"
    site_root = build_root / "site"

    if rendered_root.is_symlink() or site_root.is_symlink() or not rendered_root.is_dir():
        raise ValueError("Fresh English output is absent or the generated site is redirected")

    if site_root.exists():
        shutil.rmtree(site_root)

    site_root.mkdir()
    rendered_root.rename(site_root / "en")

    return site_root


def WriteLocaleFallbacks(site_root: Path) -> None:
    """Expose clear unavailable-translation routes with canonical English navigation."""

    notices = tomllib.loads((PROJECT_ROOT / "docs/i18n/fallbacks.toml").read_text(encoding="utf-8"))

    for locale, notice in notices.items():
        title = notice["title"]
        body = notice["body"]
        page_root = site_root / locale
        page_root.mkdir()
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
        (page_root / "index.html").write_text(page, encoding="utf-8")

    (site_root / "index.html").write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="refresh" content="0;url=en/">'
        '<title>F-Layer documentation</title></head><body>'
        '<a href="en/">Open F-Layer documentation</a></body></html>\n', encoding="utf-8",
    )
    (site_root / ".nojekyll").touch()


def InstallWheel(environment_python: Path, wheel_path: Path, build_root: Path) -> Path:
    """Install only the built wheel into a clean owned target, without mutating tools."""

    if build_root != BUILD_ROOT or build_root.is_symlink() or build_root.parent.is_symlink():
        raise ValueError("Refusing to install a wheel into an unowned or redirected build root")

    installed_root = build_root / "installed"

    if installed_root.exists():
        raise ValueError("Fresh installed-wheel target already exists in the clean build root")

    RunCommand([environment_python, "-m", "pip", "install", "--no-index", "--no-deps",
                "--disable-pip-version-check", "--target", installed_root, wheel_path], cwd=build_root)
    code = (
        "import importlib.metadata as m\n"
        f"distributions = tuple(m.distributions(path=[{str(installed_root)!r}]))\n\n"
        "assert len(distributions) == 1, 'Expected one installed wheel distribution'\n"
        "assert distributions[0].metadata['Name'] == 'f-layer', 'Unexpected wheel distribution'"
    )
    RunCommand([environment_python, "-c", code], cwd=build_root)

    return installed_root


def BuildReference(environment_python: Path | None = None) -> tuple[Path, dict[str, str], Path]:
    """Build, verify, and record evidence for a clean installed-wheel reference."""

    documentation_coverage.InventoryFiles(PROJECT_ROOT)
    input_diagnostics = documentation_coverage.CheckBuildInputs(PROJECT_ROOT)

    if input_diagnostics:
        raise ValueError("\n".join(input_diagnostics))

    RecreateBuildRoot(BUILD_ROOT)

    if environment_python is None:
        RunCommand([sys.executable, "-m", "venv", BUILD_ROOT / "environment"])
        environment_python = EnvironmentPython(BUILD_ROOT / "environment")
        VerifyBuildWorkspace(BUILD_ROOT)
        RunCommand([environment_python, "-m", "pip", "install", "--disable-pip-version-check",
                    "--requirement", REQUIREMENTS_PATH])

    VerifyBuildWorkspace(BUILD_ROOT)
    versions = VerifyEnvironment(environment_python)
    artifact_root = BUILD_ROOT / "artifacts"
    RunCommand([environment_python, "-m", "build", "--no-isolation", "--wheel",
                "--outdir", artifact_root, PROJECT_ROOT], cwd=BUILD_ROOT)
    wheels = list(artifact_root.glob("*.whl"))

    if len(wheels) != 1:
        raise ValueError("Expected exactly one built F-Layer wheel")

    wheel_path = wheels[0]
    installed_root = InstallWheel(environment_python, wheel_path, BUILD_ROOT)
    modules = DiscoverModules(installed_root)
    definitions = DiscoverDefinitions(installed_root)
    locales = ValidateLocales(PROJECT_ROOT)

    if locales.diagnostics:
        raise ValueError("\n".join(locales.diagnostics))

    WriteApiLocaleInventory(modules, BUILD_ROOT)
    config_path = WriteBuildContent(modules, BUILD_ROOT)
    documentation_coverage.WriteInventory(PROJECT_ROOT, BUILD_ROOT, definitions)
    guard_root = BUILD_ROOT / "import-guard"
    WriteImportGuard(guard_root)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(guard_root)
    environment["FLAYER_INSTALLED_PACKAGES"] = str(installed_root)
    RunCommand([environment_python, "-m", "mkdocs", "build", "--strict", "--config-file",
                config_path], cwd=BUILD_ROOT, environment=environment)
    site_root = AssembleSite(BUILD_ROOT)
    WriteLocaleFallbacks(site_root)
    diagnostics = documentation_gates.CheckAll(PROJECT_ROOT, site_root, modules)

    if diagnostics:
        raise ValueError("\n".join(diagnostics))

    evidence = {
        "discovery": "static-installed-wheel", "runtimeImports": "blocked",
        "wheelInstallIsolation": "fresh-owned-target",
        "sourceRevision": RunCommand(["git", "rev-parse", "HEAD"]),
        "sourceDirty": bool(RunCommand(["git", "status", "--porcelain", "--untracked-files=no"])),
        "documentationPackages": versions,
        "wheel": {"name": wheel_path.name, "sha256": hashlib.sha256(wheel_path.read_bytes()).hexdigest()},
        "modules": [module.name for module in modules],
        "repositoryCoverage": {"status": "pass", "inventory": "repository-coverage.json",
                               "files": len(documentation_coverage.InventoryFiles(PROJECT_ROOT)),
                               "definitions": len(definitions)},
        "sourceWheelPackageParity": "exact-excluding-bytecode",
        "renderedMarkdownReachability": "pass",
        "authoredLocales": {"status": "pass", "states": locales.states},
        "renderedLinksAndAnchors": "pass", "generatedHtmlTracked": False,
    }
    (BUILD_ROOT / "build-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )

    return environment_python, environment, config_path


def Main(arguments: Sequence[str] | None = None) -> int:
    """Run a strict build and optionally serve the same verified configuration."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-python", type=Path,
                        help="Use a provisioned exact-lock environment without downloading tools.")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--dev-addr", default="127.0.0.1:8000")
    options = parser.parse_args(arguments)
    environment_python, environment, config_path = BuildReference(options.environment_python)
    print(f"Documentation build: PASS ({BUILD_ROOT / 'site'})")

    if options.serve:
        RunCommand([environment_python, "-m", "mkdocs", "serve", "--strict", "--config-file",
                    config_path, "--dev-addr", options.dev_addr], cwd=BUILD_ROOT,
                   environment=environment)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
