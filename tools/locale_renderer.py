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

from tools import documentation_coverage as documentationCoverage
from tools import documentation_gates as documentationGates
from tools import generated_localization as generatedLocalization
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
    config: str, locale: str, contentRoot: Path, siteRoot: Path,
    labels: Mapping[str, str], publicationRoot: str,
) -> str:
    """Adapt the verified canonical configuration without loading its environment tags."""

    config = re.sub(r"(?m)^docs_dir:.*$", f"docs_dir: {json.dumps(str(contentRoot))}", config)
    config = re.sub(r"(?m)^site_dir:.*$", f"site_dir: {json.dumps(str(siteRoot))}", config)
    config = re.sub(r"(?m)^site_url:.*$", f"site_url: {publicationRoot}/{locale}/", config)
    config = re.sub(r"(?m)^edit_uri:.*$", f"edit_uri: edit/develop/docs/site/content/{locale}/",
                    config)
    themeLocale = "zh" if locale == "zh-CN" else locale
    config = re.sub(r"(?m)^  language:.*$", f"  language: {themeLocale}", config)
    lines = config.splitlines()
    inNavigation = False

    for index, line in enumerate(lines):
        if line == "nav:":
            inNavigation = True
            continue

        if inNavigation and line and not line.startswith(" "):
            inNavigation = False

        if not inNavigation:
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
    state: str, unitId: str, canonicalUrl: str, notices: Mapping[str, Any],
    renderedSourceHash: str,
) -> str:
    """Expose the actual computed review state and a link to current canonical English."""

    if state == "approved":
        return (
            f'<aside hidden data-translation-state="approved" '
            f'data-documentation-unit="{html.escape(unitId)}" '
            f'data-rendered-source-sha256="{renderedSourceHash}"></aside>\n\n'
        )

    message = notices["states"][state]

    return (
        f'<aside class="fl-translation-notice" data-translation-state="{html.escape(state)}" '
        f'data-documentation-unit="{html.escape(unitId)}" '
        f'data-rendered-source-sha256="{renderedSourceHash}">\n'
        f'<strong>{html.escape(message["title"])}</strong> '
        f'<a href="{html.escape(canonicalUrl)}">{html.escape(notices["canonicalLink"])}</a>'
        f' <details><summary>{html.escape(notices["statusLink"])}</summary>'
        f'<p>{html.escape(message["body"])} '
        f'<a href="{html.escape(notices["statusUrl"])}">'
        f'{html.escape(notices["statusLink"])}</a></p></details>\n</aside>\n\n'
    )


def _PageRoute(relativePath: Path) -> str:
    """Map an authored Markdown path to MkDocs directory URLs."""

    if relativePath.name in {"index.md", "README.md"}:
        return relativePath.parent.as_posix().removeprefix(".").strip("/")

    return relativePath.with_suffix("").as_posix()


def RewriteFallbackLinks(
    body: str, translationPath: Path, canonicalRoot: Path, projectRoot: Path | None = None,
) -> str:
    """Map actual authored and repository source targets onto the current locale's routes."""

    localeRoot = translationPath

    while localeRoot.name not in {"ru", "zh-CN"}:
        localeRoot = localeRoot.parent

        if localeRoot == localeRoot.parent:
            raise ValueError("Translation source must belong to a configured locale")

    sourceParent = translationPath.parent.relative_to(localeRoot).as_posix()

    def Rewrite(match: re.Match[str]) -> str:
        """Preserve labels and fragments while remapping canonical source destinations."""

        target = match.group(1)
        parsed = urlsplit(target)

        if parsed.scheme or parsed.netloc or not parsed.path:
            return match.group(0)

        resolved = (translationPath.parent / unquote(parsed.path)).resolve()

        if resolved.is_relative_to(canonicalRoot.resolve()):
            destination = resolved.relative_to(canonicalRoot).as_posix()

        elif resolved.is_relative_to(localeRoot.resolve()):
            destination = resolved.relative_to(localeRoot).as_posix()

        elif projectRoot and resolved.is_relative_to(projectRoot.resolve()):
            if resolved.is_dir() and (resolved / "README.md").is_file():
                resolved /= "README.md"

            sourcePath = resolved.relative_to(projectRoot).as_posix()
            destination = (documentationCoverage.MarkdownPage(sourcePath)
                           if resolved.suffix == ".md"
                           else documentationCoverage.SOURCE_URL + sourcePath)

        else:
            return match.group(0)

        route = urlsplit(destination)
        localPath = route.path if route.scheme else posixpath.relpath(route.path, sourceParent)
        rewritten = urlunsplit((route.scheme, route.netloc, localPath, parsed.query, parsed.fragment))
        start, end = match.span(1)
        original = match.group(0)

        return original[:start - match.start()] + rewritten + original[end - match.start():]

    return documentationGates.MARKDOWN_LINK.sub(Rewrite, body)


def _PrepareLocale(
    projectRoot: Path, buildRoot: Path, locale: str, project: Mapping[str, Any],
    registry: Mapping[str, Any], states: Mapping[str, Mapping[str, str]],
    notices: dict[str, Any], publicationRoot: str,
    generatedUnits: Mapping[str, Any] | None = None,
    generatedTranslations: Mapping[str, generatedLocalization.ReviewedTranslation] | None = None,
) -> tuple[Path, dict[str, dict[str, str]]]:
    """Overlay tracked translations onto disposable canonical source with visible state."""

    generatedUnits = generatedUnits or {}
    generatedTranslations = generatedTranslations or {}
    canonicalRoot = buildRoot / "content/en"
    contentRoot = buildRoot / "content" / locale

    if contentRoot.is_symlink() or contentRoot.parent.is_symlink():
        raise ValueError(f"Refusing redirected generated locale source: {locale}")

    if contentRoot.exists():
        shutil.rmtree(contentRoot)

    shutil.copytree(canonicalRoot, contentRoot)
    records = {Path(record["sourcePath"]).relative_to(Path(project["contentRoot"]) / "en"): record
               for record in registry["units"] if record["kind"] == "page"}
    evidence: dict[str, dict[str, str]] = {}
    notices["statusUrl"] = f"{publicationRoot}/{locale}/translation-status/"

    for canonicalPath in sorted(canonicalRoot.rglob("*.md")):
        relativePath = canonicalPath.relative_to(canonicalRoot)
        record = records.get(relativePath)
        unitId = record["id"] if record else f"generated:{relativePath.as_posix()}"
        state = states[unitId][locale] if record else "missing"
        route = _PageRoute(relativePath)
        canonicalUrl = f"{publicationRoot}/en/{route + '/' if route else ''}"
        body = canonicalPath.read_text(encoding="utf-8")

        if record and state in {"draft", "review", "approved"}:
            translationPath = projectRoot / record["translations"][locale]["path"]
            body = RewriteFallbackLinks(
                translationPath.read_text(encoding="utf-8"), translationPath,
                projectRoot / project["contentRoot"] / "en", projectRoot,
            )

        elif not record:
            repositoryId = "repository:" + relativePath.as_posix().removeprefix("repository/")

            if relativePath.as_posix().startswith("repository/github/"):
                repositoryId = repositoryId.replace("repository:github/", "repository:.github/", 1)

            if repositoryId in generatedUnits:
                from tools.build_api_reference import RewriteRepositoryLinks

                unitId = repositoryId
                translation = generatedTranslations.get(unitId)
                state = translation.state if translation else "missing"

                if translation and state == "approved":
                    unit = generatedUnits[unitId]
                    body = generatedLocalization.CanonicalHeadingAnchors(unit.body, translation.body)
                    body = RewriteRepositoryLinks(body, projectRoot / unit.sourcePath,
                                                  relativePath.as_posix())

            elif relativePath.as_posix() == "coverage/index.md" and generatedUnits:
                body, state = generatedLocalization.RenderCoverage(projectRoot, generatedTranslations)
                unitId = "generated:coverage/index.md"

            elif relativePath.parts[:2] == ("api", "modules"):
                moduleId = "module:" + relativePath.stem.replace("-", ".")
                module = generatedUnits.get(moduleId)

                if module:
                    unitId = moduleId
                    related = [identifier for identifier, unit in generatedUnits.items()
                               if unit.kind == "symbol" and unit.sourcePath == module.sourcePath]
                    reviewStates = [generatedTranslations[identifier].state
                                     if identifier in generatedTranslations else "missing"
                                     for identifier in related]
                    state = ("approved" if all(value == "approved" for value in reviewStates)
                             else "stale" if "stale" in reviewStates else "missing")
                    body = body.replace("[Module source]", f"[{notices.get('moduleSource', 'Module source')}]")

        renderedSourceHash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        (contentRoot / relativePath).write_text(
            TranslationBanner(state, unitId, canonicalUrl, notices, renderedSourceHash) + body,
            encoding="utf-8",
        )
        evidence[relativePath.as_posix()] = {
            "unitId": unitId, "state": state,
            "renderedContent": "translation" if state in {"draft", "review", "approved"}
            else "english-fallback", "canonicalUrl": canonicalUrl,
            "renderedSourceSha256": renderedSourceHash,
        }

    statusLines = [f'# {notices["statusTitle"]}', "", notices["statusBody"], "",
                    f'| {notices["pageLabel"]} | {notices["stateLabel"]} |', "| --- | --- |"]

    for pageName, entry in evidence.items():
        statusLines.append(
            f'| [{pageName}](../{pageName}) | '
            f'{notices["states"][entry["state"]]["title"]} (`{entry["state"]}`) |'
        )

    statusRoot = contentRoot / "translation-status"
    statusRoot.mkdir()
    (statusRoot / "index.md").write_text(
        AlignMarkdown("\n".join(statusLines) + "\n"), encoding="utf-8",
    )

    return contentRoot, evidence


def RenderLocaleSites(
    projectRoot: Path, buildRoot: Path, configPath: Path, environmentPython: Path,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Build every locale strictly using the canonical guarded installed-wheel environment."""

    expectedRoot = projectRoot / "_build/api-reference"

    if (buildRoot.resolve() != expectedRoot.resolve() or buildRoot.is_symlink()
            or (buildRoot / "site").is_symlink() or not (buildRoot / "site/en/index.html").is_file()):
        raise ValueError("Locale rendering requires the owned verified canonical build root")

    report = ValidateLocales(projectRoot)

    if report.diagnostics:
        raise ValueError("\n".join(report.diagnostics))

    project = tomllib.loads((projectRoot / "docs/i18n/project.toml").read_text(encoding="utf-8"))
    registry = tomllib.loads((projectRoot / project["unitManifest"]).read_text(encoding="utf-8"))
    VerifyTrackedTranslations(projectRoot, registry)
    generatedUnits = generatedLocalization.DiscoverGeneratedUnits(projectRoot)
    generatedTranslations = generatedLocalization.LoadTranslations(projectRoot, generatedUnits)
    localeData = tomllib.loads((projectRoot / "docs/i18n/fallbacks.toml").read_text(encoding="utf-8"))
    canonicalConfig = configPath.read_text(encoding="utf-8")
    publicationRoot = "https://fuzzy-technologies.github.io" + project["publicationPath"]
    result: dict[str, Any] = {}

    for locale in project["locales"][1:]:
        siteRoot = buildRoot / "site" / locale
        stagedRoot = buildRoot / "rendered-locales" / locale

        if siteRoot.is_symlink():
            raise ValueError(f"Refusing redirected generated locale directory: {locale}")

        if stagedRoot.is_symlink() or stagedRoot.parent.is_symlink():
            raise ValueError(f"Refusing redirected locale staging directory: {locale}")

        if stagedRoot.exists():
            shutil.rmtree(stagedRoot)

        contentRoot, pages = _PrepareLocale(
            projectRoot, buildRoot, locale, project, registry, report.states,
            localeData[locale], publicationRoot, generatedUnits, generatedTranslations[locale],
        )
        labels = dict(localeData[locale]["navigation"])

        for identifier, unit in generatedUnits.items():
            translation = generatedTranslations[locale].get(identifier)

            if identifier.startswith("repository:") and translation and translation.state == "approved":
                canonicalTitle = next((line[2:].strip() for line in unit.body.splitlines()
                                        if line.startswith("# ")), Path(unit.sourcePath).stem)
                translatedTitle = next((line[2:].strip() for line in translation.body.splitlines()
                                         if line.startswith("# ")), canonicalTitle)
                labels[f"{canonicalTitle} ({unit.sourcePath})"] = (
                    f"{translatedTitle} ({unit.sourcePath})"
                )

        config = LocalizeConfig(canonicalConfig, locale, contentRoot, stagedRoot,
                                labels, publicationRoot)
        extension, overlay = generatedLocalization.WriteApiOverlay(
            projectRoot, buildRoot, locale, generatedTranslations[locale], generatedUnits,
        )
        extensionConfig = [{str(extension): {"translations_path": str(overlay)}}]
        templates = generatedLocalization.WriteApiTemplates(projectRoot, buildRoot, locale)

        if config.count("  - mkdocstrings:\n") != 1:
            raise ValueError("Locale configuration must contain exactly one mkdocstrings plugin")

        config = config.replace("  - mkdocstrings:\n", "  - mkdocstrings:\n      custom_templates: "
                                + json.dumps(str(templates)) + "\n", 1)

        if config.count("          options:\n") != 1:
            raise ValueError("Locale configuration must contain exactly one Python handler options block")

        config = config.replace("          options:\n", "          options:\n            extensions: "
                                + json.dumps(extensionConfig) + "\n", 1)
        config = re.sub(r"(?m)^plugins:",
                        f'  - {json.dumps(localeData[locale]["statusTitle"], ensure_ascii=False)}: '
                        "translation-status/index.md\n\nplugins:", config, count=1)
        localeConfig = buildRoot / f"mkdocs-{locale}.yml"
        localeConfig.write_text(config, encoding="utf-8")
        process = subprocess.run(
            [str(environmentPython), "-m", "mkdocs", "build", "--strict", "--config-file",
             str(localeConfig)], cwd=buildRoot, env=environment,
            capture_output=True, text=True, check=False,
        )

        if process.returncode:
            raise RuntimeError(f"Strict locale build failed: {locale}\n{process.stdout}{process.stderr}")

        VerifyRenderedLocale(buildRoot / "rendered-locales", locale, pages)
        generatedLocalization.VerifyApiProse(buildRoot / "rendered-locales", locale,
                                              generatedUnits, generatedTranslations[locale])

        if siteRoot.exists():
            shutil.rmtree(siteRoot)

        shutil.move(str(stagedRoot), siteRoot)
        VerifyRenderedLocale(buildRoot / "site", locale, pages)

        reviewedRecords = [record["translations"][locale] for record in registry["units"]
                            if record["translations"][locale].get("path")]
        result[locale] = {
            "strictBuild": "pass", "pages": pages, "renderedApiProse": "pass",
            "generatedTranslationStates": {identifier: locales[locale] for identifier, locales in
                generatedLocalization.TranslationStates(generatedUnits, generatedTranslations).items()},
            "translationReviewComplete": all(entry["state"] == "approved" for entry in pages.values()),
            "authoredTranslationReviewComplete": bool(reviewedRecords) and all(
                report.states[record["id"]][locale] == "approved" for record in registry["units"]
                if record["translations"][locale].get("path")
            ),
            "humanReviewComplete": all(entry["state"] == "approved" for entry in pages.values())
            and all(entry.reviewerType == "human" for entry in generatedTranslations[locale].values())
            and all(review.get("reviewerType", "human") == "human"
                    for translation in reviewedRecords for review in translation.get("reviews", ())),
        }

    return result


def VerifyTrackedTranslations(projectRoot: Path, registry: Mapping[str, Any]) -> None:
    """Reject draft overlays that exist locally but cannot be reproduced from tracked source."""

    process = subprocess.run(["git", "ls-files", "-z"], cwd=projectRoot,
                             capture_output=True, text=True, check=True)
    trackedPaths = set(process.stdout.split("\0"))

    for record in registry["units"]:
        for locale, translation in record["translations"].items():
            path = translation.get("path")

            if path and path not in trackedPaths:
                raise ValueError(f"Untracked locale overlay: {record['id']}:{locale}: {path}")


def VerifyRenderedLocale(
    siteRoot: Path, locale: str, pages: Mapping[str, Mapping[str, str]],
) -> None:
    """Require actual rendered banners and reachability for every locale overlay/fallback."""

    localeRoot = (siteRoot / locale).resolve()
    expectedPages = {}

    for name, entry in pages.items():
        route = _PageRoute(Path(name))
        path = localeRoot / route / "index.html"

        if not path.is_file():
            raise ValueError(f"Missing rendered locale page: {locale}/{name}")

        content = path.read_text(encoding="utf-8")

        if (f'data-translation-state="{entry["state"]}"' not in content
                or f'data-documentation-unit="{html.escape(entry["unitId"])}"' not in content):
            raise ValueError(f"Missing actual review-state banner: {locale}/{name}")

        sourceHash = entry.get("renderedSourceSha256")

        if sourceHash and f'data-rendered-source-sha256="{sourceHash}"' not in content:
            raise ValueError(f"Rendered locale source provenance differs: {locale}/{name}")

        expectedPages[path.resolve()] = name

    pending = [localeRoot / "index.html"]
    visited: set[Path] = set()

    while pending:
        pagePath = pending.pop().resolve()

        if pagePath in visited:
            continue

        visited.add(pagePath)

        for target in documentationGates.ParsePage(pagePath).targets:
            resolved = documentationGates.LocalTarget(pagePath, target, siteRoot)

            if (resolved is not None and resolved[0].suffix == ".html"
                    and resolved[0].is_relative_to(localeRoot) and resolved[0].is_file()):
                pending.append(resolved[0])

    unreachable = sorted(expectedPages[path] for path in expectedPages if path not in visited)

    if unreachable:
        raise ValueError(f"Unreachable locale pages: {locale}: {', '.join(unreachable)}")
