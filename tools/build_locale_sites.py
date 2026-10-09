"""Build installed-wheel documentation and reviewed localized reference routes."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import build_api_reference, documentation_gates, generated_localization  # noqa: E402
from tools.locale_renderer import RenderLocaleSites  # noqa: E402
from tools.release_validation import ReadProjectVersion  # noqa: E402


def Main(arguments: Sequence[str] | None = None) -> int:
    """Render all locale routes and fail on exact links, anchors, or review-state drift."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-python", type=Path)
    parser.add_argument("--require-complete-translations", action="store_true")
    options = parser.parse_args(arguments)
    environment_python, environment, config_path = build_api_reference.BuildReference(
        options.environment_python,
    )
    locale_evidence = RenderLocaleSites(
        build_api_reference.PROJECT_ROOT, build_api_reference.BUILD_ROOT, config_path,
        environment_python, environment,
    )
    diagnostics = documentation_gates.CheckAll(
        build_api_reference.PROJECT_ROOT, build_api_reference.BUILD_ROOT / "site",
    )

    if diagnostics:
        raise ValueError("\n".join(diagnostics))

    evidence_path = build_api_reference.BUILD_ROOT / "build-evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    version, _ = ReadProjectVersion(build_api_reference.PROJECT_ROOT, require_source=True)
    release_major = int(version.split(".")[0])

    if options.require_complete_translations or release_major >= 2:
        states = {page: {locale: data["pages"][page]["state"] for locale, data in locale_evidence.items()}
                  for page in locale_evidence["ru"]["pages"]}
        generated_localization.RequireComplete(states)
        generated_states = {
            identifier: {locale: data["generatedTranslationStates"][identifier]
                         for locale, data in locale_evidence.items()}
            for identifier in locale_evidence["ru"]["generatedTranslationStates"]
        }
        generated_localization.RequireComplete(generated_states)

    evidence["renderedLocales"] = locale_evidence
    evidence["renderedLinksAndAnchors"] = "pass"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Multilingual documentation build: PASS ({build_api_reference.BUILD_ROOT / 'site'})")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
