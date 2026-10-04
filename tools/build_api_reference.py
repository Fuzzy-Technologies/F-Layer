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

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import documentation_gates  # noqa: E402
from tools.locale_documentation import (  # noqa: E402
    CanonicalHash,
    DiscoverCanonicalUnits,
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
    """Inventory installed public modules without importing any project code."""

    modules = []

    for path in sorted((installed_root / "flayer").rglob("*.py")):
        relative = path.relative_to(installed_root)
        parts = list(relative.with_suffix("").parts)

        if parts[-1] == "__init__":
            parts.pop()

        if any(part.startswith("_") for part in parts):
            continue

        module_name = ".".join(parts)
        syntax = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        symbols = []

        if not ast.get_docstring(syntax):
            raise ValueError(f"Public module lacks an English docstring: {module_name}")

        for node in syntax.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue

                if not ast.get_docstring(node):
                    raise ValueError(f"Public symbol lacks a docstring: {module_name}.{node.name}")

                symbol_name = f"{module_name}.{node.name}"
                symbols.append(symbol_name)

                if isinstance(node, ast.ClassDef):
                    seen_members: set[str] = set()

                    for member in node.body:
                        if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue

                        if member.name.startswith("_") or member.name in seen_members:
                            continue

                        if not ast.get_docstring(member):
                            raise ValueError(f"Public method lacks a docstring: {symbol_name}.{member.name}")

                        seen_members.add(member.name)
                        symbols.append(f"{symbol_name}.{member.name}")

        source_path = f"src/{relative.as_posix()}"

        if (PROJECT_ROOT / source_path).read_bytes() != path.read_bytes():
            raise ValueError(f"Installed wheel differs from current source: {source_path}")

        modules.append(ModuleSource(module_name, path, source_path, tuple(symbols)))

    if not modules:
        raise ValueError("Installed flayer package has no discoverable modules")

    return tuple(modules)


def WriteApiLocaleInventory(modules: tuple[ModuleSource, ...], build_root: Path) -> None:
    """Validate dynamic API units with unchanged hashes and explicitly missing locales."""

    coverage_path = build_root / "api-coverage.toml"
    coverage_text = "schemaVersion = 1\n"

    for module in modules:
        coverage_text += (
            f'\n[[surfaces]]\nmodule = "{module.name}"\n'
            f'source = "{module.source_path}"\nmode = "authored"\n'
        )

    coverage_path.write_text(coverage_text, encoding="utf-8")
    project = tomllib.loads((PROJECT_ROOT / "docs/i18n/project.toml").read_text())
    project["contentRoot"] = "_build/api-reference/api-locales-content"
    project["apiCoverageManifest"] = "_build/api-reference/api-coverage.toml"
    project["unitManifest"] = "_build/api-reference/api-units.toml"
    units = DiscoverCanonicalUnits(PROJECT_ROOT, project)
    unit_text = "schemaVersion = 1\n"

    for unit in units:
        unit_text += (
            f'\n[[units]]\nid = "{unit.identifier}"\nkind = "{unit.kind}"\n'
            f'sourcePath = "{unit.source_path}"\nsourceHash = "{CanonicalHash(unit)}"\n'
            'reviewClass = "technical"\n\n[units.translations.ru]\nstate = "missing"\n'
            '\n[units.translations.zh-CN]\nstate = "missing"\n'
        )

    (build_root / "api-units.toml").write_text(unit_text, encoding="utf-8")
    original = (PROJECT_ROOT / "docs/i18n/project.toml").read_text(encoding="utf-8")
    original = original.replace('contentRoot = "docs/site/content"',
                                f'contentRoot = "{project["contentRoot"]}"')
    original = original.replace('apiCoverageManifest = "docs/site/api-coverage.toml"',
                                f'apiCoverageManifest = "{project["apiCoverageManifest"]}"')
    original = original.replace('unitManifest = "docs/i18n/units.toml"',
                                f'unitManifest = "{project["unitManifest"]}"')
    manifest_path = build_root / "api-locales-project.toml"
    manifest_path.write_text(original, encoding="utf-8")
    report = ValidateLocales(PROJECT_ROOT, manifest_path)

    if report.diagnostics:
        raise ValueError("\n".join(report.diagnostics))

    (build_root / "api-locales.json").write_text(
        json.dumps({"status": "pass", "states": report.states}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
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


def WriteEngineeringContent(content_root: Path) -> list[dict[str, str]]:
    """Render current repository architecture and decisions with relative links intact."""

    navigation = []
    documentation_root = PROJECT_ROOT / "docs"

    for folder in ("architecture", "adr", "development", "releases"):
        source_root = documentation_root / folder

        for source_path in sorted(source_root.rglob("*.md")):
            relative = source_path.relative_to(PROJECT_ROOT)
            destination = content_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = RewriteDirectoryLinks(source_path.read_text(encoding="utf-8"), source_path)
            source_link = (
                "https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/"
                + relative.as_posix()
            )
            destination.write_text(content + f"\n[Repository source]({source_link})\n",
                                   encoding="utf-8")
            heading = next((line.removeprefix("# ").strip() for line in content.splitlines()
                            if line.startswith("# ")), source_path.stem)
            navigation.append({heading: relative.as_posix()})

    for name in ("AGENTS.md", "DEVELOPMENT_PROTOCOL.md", "CHANGELOG.md", "docs/RELEASE_WORKFLOW.md"):
        source_path = PROJECT_ROOT / name
        destination = content_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            RewriteDirectoryLinks(source_path.read_text(encoding="utf-8"), source_path),
            encoding="utf-8",
        )
        navigation.append({source_path.stem.replace("_", " ").title(): name})

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
            f"::: {module.name}\n"
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
    config = re.sub(r"^site_dir:.*$", f"site_dir: {json.dumps(str(build_root / 'site' / 'en'))}",
                    config, flags=re.MULTILINE)
    engineering_navigation = WriteEngineeringContent(content_root)
    api_navigation = json.dumps([{"Index": "api/index.md"}, *module_navigation])
    navigation_marker = "  - API reference: api/index.md"

    if config.count(navigation_marker) != 1:
        raise ValueError("Authored navigation must contain exactly one API reference entry")

    config = config.replace(navigation_marker, "  - API reference: " + api_navigation)
    config = re.sub(
        r"(?m)^plugins:",
        "  - Engineering guides: " + json.dumps(engineering_navigation) + "\n\nplugins:",
        config, count=1,
    )
    config_path = build_root / "mkdocs.yml"
    config_path.write_text(config, encoding="utf-8")

    return config_path


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


def BuildReference(environment_python: Path | None = None) -> tuple[Path, dict[str, str], Path]:
    """Build, verify, and record evidence for a clean installed-wheel reference."""

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
    RunCommand([environment_python, "-m", "pip", "install", "--no-deps", "--force-reinstall",
                "--disable-pip-version-check", wheel_path], cwd=BUILD_ROOT)
    installed_root = Path(RunCommand([
        environment_python, "-c", "import importlib.metadata as m; print(m.distribution('f-layer').locate_file(''))",
    ], cwd=BUILD_ROOT))
    modules = DiscoverModules(installed_root)
    locales = ValidateLocales(PROJECT_ROOT)

    if locales.diagnostics:
        raise ValueError("\n".join(locales.diagnostics))

    WriteApiLocaleInventory(modules, BUILD_ROOT)
    config_path = WriteBuildContent(modules, BUILD_ROOT)
    guard_root = BUILD_ROOT / "import-guard"
    WriteImportGuard(guard_root)
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(guard_root)
    environment["FLAYER_INSTALLED_PACKAGES"] = str(installed_root)
    RunCommand([environment_python, "-m", "mkdocs", "build", "--strict", "--config-file",
                config_path], cwd=BUILD_ROOT, environment=environment)
    site_root = BUILD_ROOT / "site"
    WriteLocaleFallbacks(site_root)
    diagnostics = documentation_gates.CheckAll(PROJECT_ROOT, site_root, modules)

    if diagnostics:
        raise ValueError("\n".join(diagnostics))

    evidence = {
        "discovery": "static-installed-wheel", "runtimeImports": "blocked",
        "sourceRevision": RunCommand(["git", "rev-parse", "HEAD"]),
        "sourceDirty": bool(RunCommand(["git", "status", "--porcelain", "--untracked-files=no"])),
        "documentationPackages": versions,
        "wheel": {"name": wheel_path.name, "sha256": hashlib.sha256(wheel_path.read_bytes()).hexdigest()},
        "modules": [module.name for module in modules],
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
