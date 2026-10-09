"""Render localized documentation and explicit English fallbacks from verified content."""

from __future__ import annotations

import hashlib
import html
import json
import posixpath
import re
import shutil
import subprocess
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

from tools import documentation_coverage, documentation_gates, generated_localization
from tools.locale_documentation import ValidateLocales
from tools.markdown_tables import AlignMarkdown


def _LocalizeNavigation(value: Any, labels: Mapping[str, str]) -> Any:
    """Translate navigation labels while preserving every route and module identifier."""

    if isinstance(value, list):
        return [_LocalizeNavigation(item, labels) for item in value]

    if isinstance(value, dict):
        return {labels.get(key, key): _LocalizeNavigation(item, labels)
                for key, item in value.items()}

    return value


def LocalizeConfig(
    config: str, locale: str, content_root: Path, site_root: Path,
    labels: Mapping[str, str], publication_root: str,
) -> str:
    """Adapt the verified canonical configuration without loading its environment tags."""

    config = re.sub(r"(?m)^docs_dir:.*$", f"docs_dir: {json.dumps(str(content_root))}", config)
    config = re.sub(r"(?m)^site_dir:.*$", f"site_dir: {json.dumps(str(site_root))}", config)
    config = re.sub(r"(?m)^site_url:.*$", f"site_url: {publication_root}/{locale}/", config)
    config = re.sub(r"(?m)^edit_uri:.*$", f"edit_uri: edit/develop/docs/site/content/{locale}/",
                    config)
    theme_locale = "zh" if locale == "zh-CN" else locale
    config = re.sub(r"(?m)^  language:.*$", f"  language: {theme_locale}", config)
    lines = config.splitlines()
    in_navigation = False

    for index, line in enumerate(lines):
        if line == "nav:":
            in_navigation = True
            continue

        if in_navigation and line and not line.startswith(" "):
            in_navigation = False

        if not in_navigation:
            continue

        match = re.fullmatch(r"(\s+- )([^:]+):(.*)", line)

        if not match:
            continue

        prefix, title, destination = match.groups()

        if destination.strip().startswith("["):
            destination = " " + json.dumps(
                _LocalizeNavigation(json.loads(destination), labels), ensure_ascii=False,
            )

        lines[index] = f"{prefix}{json.dumps(labels.get(title, title), ensure_ascii=False)}:{destination}"

    return "\n".join(lines) + "\n"


def TranslationBanner(
    state: str, unit_id: str, canonical_url: str, notices: Mapping[str, Any],
    rendered_source_hash: str,
) -> str:
    """Expose the actual computed review state and a link to current canonical English."""

    if state == "approved":
        return (
            f'<aside hidden data-translation-state="approved" '
            f'data-documentation-unit="{html.escape(unit_id)}" '
            f'data-rendered-source-sha256="{rendered_source_hash}"></aside>\n\n'
        )

    message = notices["states"][state]

    return (
        f'<aside class="fl-translation-notice" data-translation-state="{html.escape(state)}" '
        f'data-documentation-unit="{html.escape(unit_id)}" '
        f'data-rendered-source-sha256="{rendered_source_hash}">\n'
        f'<strong>{html.escape(message["title"])}</strong> '
        f'<a href="{html.escape(canonical_url)}">{html.escape(notices["canonicalLink"])}</a>'
        f' <details><summary>{html.escape(notices["statusLink"])}</summary>'
        f'<p>{html.escape(message["body"])} '
        f'<a href="{html.escape(notices["statusUrl"])}">'
        f'{html.escape(notices["statusLink"])}</a></p></details>\n</aside>\n\n'
    )


def _PageRoute(relative_path: Path) -> str:
    """Map an authored Markdown path to MkDocs directory URLs."""

    if relative_path.name in {"index.md", "README.md"}:
        return relative_path.parent.as_posix().removeprefix(".").strip("/")

    return relative_path.with_suffix("").as_posix()


def RewriteFallbackLinks(
    body: str, translation_path: Path, canonical_root: Path, project_root: Path | None = None,
) -> str:
    """Map actual authored and repository source targets onto the current locale's routes."""

    locale_root = translation_path

    while locale_root.name not in {"ru", "zh-CN"}:
        locale_root = locale_root.parent

        if locale_root == locale_root.parent:
            raise ValueError("Translation source must belong to a configured locale")

    source_parent = translation_path.parent.relative_to(locale_root).as_posix()

    def Rewrite(match: re.Match[str]) -> str:
        """Preserve labels and fragments while remapping canonical source destinations."""

        target = match.group(1)
        parsed = urlsplit(target)

        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)

        resolved = (translation_path.parent / unquote(parsed.path)).resolve()

        if resolved.is_relative_to(canonical_root.resolve()):
            destination = resolved.relative_to(canonical_root).as_posix()

        elif resolved.is_relative_to(locale_root.resolve()):
            destination = resolved.relative_to(locale_root).as_posix()

        elif project_root and resolved.is_relative_to(project_root.resolve()):
            if resolved.is_dir() and (resolved / "README.md").is_file():
                resolved /= "README.md"

            source_path = resolved.relative_to(project_root).as_posix()
            destination = (documentation_coverage.MarkdownPage(source_path)
                           if resolved.suffix == ".md"
                           else documentation_coverage.SOURCE_URL + source_path)

        else:
            return match.group(0)

        route = urlsplit(destination)
        local_path = route.path if route.scheme else posixpath.relpath(route.path, source_parent)
        rewritten = urlunsplit((route.scheme, route.netloc, local_path, parsed.query, parsed.fragment))
        start, end = match.span(1)
        original = match.group(0)

        return original[:start - match.start()] + rewritten + original[end - match.start():]

    return documentation_gates.MARKDOWN_LINK.sub(Rewrite, body)


def _PrepareLocale(
    project_root: Path, build_root: Path, locale: str, project: Mapping[str, Any],
    registry: Mapping[str, Any], states: Mapping[str, Mapping[str, str]],
    notices: dict[str, Any], publication_root: str,
    generated_units: Mapping[str, Any] | None = None,
    generated_translations: Mapping[str, generated_localization.ReviewedTranslation] | None = None,
) -> tuple[Path, dict[str, dict[str, str]]]:
    """Overlay tracked translations onto disposable canonical source with visible state."""

    generated_units = generated_units or {}
    generated_translations = generated_translations or {}
    canonical_root = build_root / "content/en"
    content_root = build_root / "content" / locale

    if content_root.is_symlink() or content_root.parent.is_symlink():
        raise ValueError(f"Refusing redirected generated locale source: {locale}")

    if content_root.exists():
        shutil.rmtree(content_root)

    shutil.copytree(canonical_root, content_root)
    records = {Path(record["sourcePath"]).relative_to(Path(project["contentRoot"]) / "en"): record
               for record in registry["units"] if record["kind"] == "page"}
    evidence: dict[str, dict[str, str]] = {}
    notices["statusUrl"] = f"{publication_root}/{locale}/translation-status/"

    for canonical_path in sorted(canonical_root.rglob("*.md")):
        relative_path = canonical_path.relative_to(canonical_root)
        record = records.get(relative_path)
        unit_id = record["id"] if record else f"generated:{relative_path.as_posix()}"
        state = states[unit_id][locale] if record else "missing"
        route = _PageRoute(relative_path)
        canonical_url = f"{publication_root}/en/{route + '/' if route else ''}"
        body = canonical_path.read_text(encoding="utf-8")

        if record and state in {"draft", "review", "approved"}:
            translation_path = project_root / record["translations"][locale]["path"]
            body = RewriteFallbackLinks(
                translation_path.read_text(encoding="utf-8"), translation_path,
                project_root / project["contentRoot"] / "en", project_root,
            )

        elif not record:
            repository_id = "repository:" + relative_path.as_posix().removeprefix("repository/")

            if relative_path.as_posix().startswith("repository/github/"):
                repository_id = repository_id.replace("repository:github/", "repository:.github/", 1)

            if repository_id in generated_units:
                from tools.build_api_reference import RewriteRepositoryLinks

                unit_id = repository_id
                translation = generated_translations.get(unit_id)
                state = translation.state if translation else "missing"

                if translation and state == "approved":
                    unit = generated_units[unit_id]
                    body = generated_localization.CanonicalHeadingAnchors(unit.body, translation.body)
                    body = RewriteRepositoryLinks(body, project_root / unit.source_path,
                                                  relative_path.as_posix())

            elif relative_path.as_posix() == "coverage/index.md" and generated_units:
                body, state = generated_localization.RenderCoverage(project_root, generated_translations)
                unit_id = "generated:coverage/index.md"

            elif relative_path.parts[:2] == ("api", "modules"):
                module_id = "module:" + relative_path.stem.replace("-", ".")
                module = generated_units.get(module_id)

                if module:
                    unit_id = module_id
                    related = [identifier for identifier, unit in generated_units.items()
                               if unit.kind == "symbol" and unit.source_path == module.source_path]
                    review_states = [generated_translations[identifier].state
                                     if identifier in generated_translations else "missing"
                                     for identifier in related]
                    state = ("approved" if all(value == "approved" for value in review_states)
                             else "stale" if "stale" in review_states else "missing")
                    body = body.replace("[Module source]", f"[{notices.get('moduleSource', 'Module source')}]")

        rendered_source_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        (content_root / relative_path).write_text(
            TranslationBanner(state, unit_id, canonical_url, notices, rendered_source_hash) + body,
            encoding="utf-8",
        )
        evidence[relative_path.as_posix()] = {
            "unitId": unit_id, "state": state,
            "renderedContent": "translation" if state in {"draft", "review", "approved"}
            else "english-fallback", "canonicalUrl": canonical_url,
            "renderedSourceSha256": rendered_source_hash,
        }

    status_lines = [f'# {notices["statusTitle"]}', "", notices["statusBody"], "",
                    f'| {notices["pageLabel"]} | {notices["stateLabel"]} |', "| --- | --- |"]

    for page_name, entry in evidence.items():
        status_lines.append(
            f'| [{page_name}](../{page_name}) | '
            f'{notices["states"][entry["state"]]["title"]} (`{entry["state"]}`) |'
        )

    status_root = content_root / "translation-status"
    status_root.mkdir()
    (status_root / "index.md").write_text(
        AlignMarkdown("\n".join(status_lines) + "\n"), encoding="utf-8",
    )

    return content_root, evidence


def RenderLocaleSites(
    project_root: Path, build_root: Path, config_path: Path, environment_python: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Build every locale strictly using the canonical guarded installed-wheel environment."""

    expected_root = project_root / "_build/api-reference"

    if (build_root.resolve() != expected_root.resolve() or build_root.is_symlink()
            or (build_root / "site").is_symlink() or not (build_root / "site/en/index.html").is_file()):
        raise ValueError("Locale rendering requires the owned verified canonical build root")

    report = ValidateLocales(project_root)

    if report.diagnostics:
        raise ValueError("\n".join(report.diagnostics))

    project = tomllib.loads((project_root / "docs/i18n/project.toml").read_text(encoding="utf-8"))
    registry = tomllib.loads((project_root / project["unitManifest"]).read_text(encoding="utf-8"))
    VerifyTrackedTranslations(project_root, registry)
    generated_units = generated_localization.DiscoverGeneratedUnits(project_root)
    generated_translations = generated_localization.LoadTranslations(project_root, generated_units)
    locale_data = tomllib.loads((project_root / "docs/i18n/fallbacks.toml").read_text(encoding="utf-8"))
    canonical_config = config_path.read_text(encoding="utf-8")
    publication_root = "https://fuzzy-technologies.github.io" + project["publicationPath"]
    result: dict[str, Any] = {}

    for locale in project["locales"][1:]:
        site_root = build_root / "site" / locale
        staged_root = build_root / "rendered-locales" / locale

        if site_root.is_symlink():
            raise ValueError(f"Refusing redirected generated locale directory: {locale}")

        if staged_root.is_symlink() or staged_root.parent.is_symlink():
            raise ValueError(f"Refusing redirected locale staging directory: {locale}")

        if staged_root.exists():
            shutil.rmtree(staged_root)

        content_root, pages = _PrepareLocale(
            project_root, build_root, locale, project, registry, report.states,
            locale_data[locale], publication_root, generated_units, generated_translations[locale],
        )
        labels = dict(locale_data[locale]["navigation"])

        for identifier, unit in generated_units.items():
            translation = generated_translations[locale].get(identifier)

            if identifier.startswith("repository:") and translation and translation.state == "approved":
                canonical_title = next((line[2:].strip() for line in unit.body.splitlines()
                                        if line.startswith("# ")), Path(unit.source_path).stem)
                translated_title = next((line[2:].strip() for line in translation.body.splitlines()
                                         if line.startswith("# ")), canonical_title)
                labels[f"{canonical_title} ({unit.source_path})"] = (
                    f"{translated_title} ({unit.source_path})"
                )

        config = LocalizeConfig(canonical_config, locale, content_root, staged_root,
                                labels, publication_root)
        extension, overlay = generated_localization.WriteApiOverlay(
            project_root, build_root, locale, generated_translations[locale], generated_units,
        )
        extension_config = [{str(extension): {"translations_path": str(overlay)}}]
        templates = generated_localization.WriteApiTemplates(project_root, build_root, locale)

        if config.count("  - mkdocstrings:\n") != 1:
            raise ValueError("Locale configuration must contain exactly one mkdocstrings plugin")

        config = config.replace("  - mkdocstrings:\n", "  - mkdocstrings:\n      custom_templates: "
                                + json.dumps(str(templates)) + "\n", 1)

        if config.count("          options:\n") != 1:
            raise ValueError("Locale configuration must contain exactly one Python handler options block")

        config = config.replace("          options:\n", "          options:\n            extensions: "
                                + json.dumps(extension_config) + "\n", 1)
        config = re.sub(r"(?m)^plugins:",
                        f'  - {json.dumps(locale_data[locale]["statusTitle"], ensure_ascii=False)}: '
                        "translation-status/index.md\n\nplugins:", config, count=1)
        locale_config = build_root / f"mkdocs-{locale}.yml"
        locale_config.write_text(config, encoding="utf-8")
        process = subprocess.run(
            [str(environment_python), "-m", "mkdocs", "build", "--strict", "--config-file",
             str(locale_config)], cwd=build_root, env=environment,
            capture_output=True, text=True, check=False,
        )

        if process.returncode:
            raise RuntimeError(f"Strict locale build failed: {locale}\n{process.stdout}{process.stderr}")

        VerifyRenderedLocale(build_root / "rendered-locales", locale, pages)
        generated_localization.VerifyApiProse(build_root / "rendered-locales", locale,
                                              generated_units, generated_translations[locale])

        if site_root.exists():
            shutil.rmtree(site_root)

        shutil.move(str(staged_root), site_root)
        VerifyRenderedLocale(build_root / "site", locale, pages)

        reviewed_records = [record["translations"][locale] for record in registry["units"]
                            if record["translations"][locale].get("path")]
        result[locale] = {
            "strictBuild": "pass", "pages": pages, "renderedApiProse": "pass",
            "generatedTranslationStates": {identifier: locales[locale] for identifier, locales in
                generated_localization.TranslationStates(generated_units, generated_translations).items()},
            "translationReviewComplete": all(entry["state"] == "approved" for entry in pages.values()),
            "authoredTranslationReviewComplete": bool(reviewed_records) and all(
                report.states[record["id"]][locale] == "approved" for record in registry["units"]
                if record["translations"][locale].get("path")
            ),
            "humanReviewComplete": all(entry["state"] == "approved" for entry in pages.values())
            and all(entry.reviewer_type == "human" for entry in generated_translations[locale].values())
            and all(review.get("reviewerType", "human") == "human"
                    for translation in reviewed_records for review in translation.get("reviews", ())),
        }

    return result


def VerifyTrackedTranslations(project_root: Path, registry: Mapping[str, Any]) -> None:
    """Reject draft overlays that exist locally but cannot be reproduced from tracked source."""

    process = subprocess.run(["git", "ls-files", "-z"], cwd=project_root,
                             capture_output=True, text=True, check=True)
    tracked_paths = set(process.stdout.split("\0"))

    for record in registry["units"]:
        for locale, translation in record["translations"].items():
            path = translation.get("path")

            if path and path not in tracked_paths:
                raise ValueError(f"Untracked locale overlay: {record['id']}:{locale}: {path}")


def VerifyRenderedLocale(
    site_root: Path, locale: str, pages: Mapping[str, Mapping[str, str]],
) -> None:
    """Require actual rendered banners and reachability for every locale overlay/fallback."""

    locale_root = (site_root / locale).resolve()
    expected_pages = {}

    for name, entry in pages.items():
        route = _PageRoute(Path(name))
        path = locale_root / route / "index.html"

        if not path.is_file():
            raise ValueError(f"Missing rendered locale page: {locale}/{name}")

        content = path.read_text(encoding="utf-8")

        if (f'data-translation-state="{entry["state"]}"' not in content
                or f'data-documentation-unit="{html.escape(entry["unitId"])}"' not in content):
            raise ValueError(f"Missing actual review-state banner: {locale}/{name}")

        source_hash = entry.get("renderedSourceSha256")

        if source_hash and f'data-rendered-source-sha256="{source_hash}"' not in content:
            raise ValueError(f"Rendered locale source provenance differs: {locale}/{name}")

        expected_pages[path.resolve()] = name

    pending = [locale_root / "index.html"]
    visited: set[Path] = set()

    while pending:
        page_path = pending.pop().resolve()

        if page_path in visited:
            continue

        visited.add(page_path)

        for target in documentation_gates.ParsePage(page_path).targets:
            resolved = documentation_gates.LocalTarget(page_path, target, site_root)

            if (resolved is not None and resolved[0].suffix == ".html"
                    and resolved[0].is_relative_to(locale_root) and resolved[0].is_file()):
                pending.append(resolved[0])

    unreachable = sorted(expected_pages[path] for path in expected_pages if path not in visited)

    if unreachable:
        raise ValueError(f"Unreachable locale pages: {locale}: {', '.join(unreachable)}")
