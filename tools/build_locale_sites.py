"""Build installed-wheel documentation and reviewed localized reference routes."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import build_api_reference as buildApiReference  # noqa: E402
from tools import documentation_gates as documentationGates
from tools import generated_localization as generatedLocalization
from tools.locale_renderer import RenderLocaleSites  # noqa: E402
from tools.release_validation import ReadProjectVersion  # noqa: E402


def Main(arguments: Sequence[str] | None = None) -> int:
    """Render all locale routes and fail on exact links, anchors, or review-state drift."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-python", type=Path, dest='environmentPython')
    parser.add_argument("--require-complete-translations", action="store_true", dest='requireCompleteTranslations')
    options = parser.parse_args(arguments)
    environmentPython, environment, configPath = buildApiReference.BuildReference(
        options.environmentPython,
    )
    localeEvidence = RenderLocaleSites(
        buildApiReference.PROJECT_ROOT, buildApiReference.BUILD_ROOT, configPath,
        environmentPython, environment,
    )
    diagnostics = documentationGates.CheckAll(
        buildApiReference.PROJECT_ROOT, buildApiReference.BUILD_ROOT / "site",
    )

    if diagnostics:
        raise ValueError("\n".join(diagnostics))

    evidencePath = buildApiReference.BUILD_ROOT / "build-evidence.json"
    evidence = json.loads(evidencePath.read_text(encoding="utf-8"))
    version, _ = ReadProjectVersion(buildApiReference.PROJECT_ROOT, requireSource=True)
    releaseMajor = int(version.split(".")[0])

    if options.requireCompleteTranslations or releaseMajor >= 2:
        states = {page: {locale: data["pages"][page]["state"] for locale, data in localeEvidence.items()}
                  for page in localeEvidence["ru"]["pages"]}
        generatedLocalization.RequireComplete(states)
        generatedStates = {
            identifier: {locale: data["generatedTranslationStates"][identifier]
                         for locale, data in localeEvidence.items()}
            for identifier in localeEvidence["ru"]["generatedTranslationStates"]
        }
        generatedLocalization.RequireComplete(generatedStates)

    evidence["renderedLocales"] = localeEvidence
    evidence["renderedLinksAndAnchors"] = "pass"
    evidencePath.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Multilingual documentation build: PASS ({buildApiReference.BUILD_ROOT / 'site'})")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
