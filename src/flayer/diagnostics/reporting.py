"""Stable JSON and concise text representations of sanitized diagnostic reports."""

import json

from .contracts import DiagnosticReport


def RenderJson(report: DiagnosticReport) -> str:
    """Serialize only the versioned public report with deterministic JSON keys."""

    return json.dumps(report.AsDict(), sort_keys=True, allow_nan=False)


def RenderText(report: DiagnosticReport) -> str:
    """Render one safe single-line observation per check without raw details."""

    public = report.AsDict()
    lines = [f"{public['command']}: {public['status']}"]

    for check in report.checks:
        safe = check.AsDict()
        lines.append(f"[{safe['status']}] {safe['name']}: {safe['message']}")

    return "\n".join(" ".join(line.split()) for line in lines)
