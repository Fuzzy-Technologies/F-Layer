"""Provider-independent diagnostic results and output safety contracts."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum

REDACTED = "[redacted]"
SECRET_KEY = re.compile(
    r"password|passwd|secret|token|credential|authorization|cookie|private.?key|api.?key|"
    r"ssh.?key|client.?key|access.?key|refresh.?key",
    re.IGNORECASE,
)
SECRET_VALUE = re.compile(
    r"(?:bearer\s+\S+|-----BEGIN[^\n]*PRIVATE KEY-----[\s\S]*|"
    r"(?:password|passwd|secret|token|api[_-]?key)\s*[=:][^\n]*|"
    r"https?://[^\s]*|(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
SAFE_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


class DiagnosticStatus(str, Enum):
    """Stable outcomes distinguish failure, expired evidence, and missing support."""

    OK = "ok"
    WARNING = "warning"
    FAILED = "failed"
    STALE = "stale"
    UNSUPPORTED = "unsupported"


def Redact(value: object, _depth: int = 0) -> object:
    """Recursively redact credential fields and common sensitive text before output."""

    if _depth >= 16:
        return REDACTED

    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}

        for key, item in value.items():
            sensitive = not isinstance(key, str) or bool(SECRET_KEY.search(key))
            safe_key = key if isinstance(key, str) and SAFE_KEY.fullmatch(key) else REDACTED

            if sensitive:
                safe_key = REDACTED

            candidate = safe_key
            suffix = 2

            while candidate in sanitized:
                candidate = f"{safe_key}:{suffix}"
                suffix += 1

            sanitized[candidate] = REDACTED if sensitive else Redact(item, _depth + 1)

        return sanitized

    if isinstance(value, str):
        return SECRET_VALUE.sub(REDACTED, value)

    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [Redact(item, _depth + 1) for item in value]

    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value

    if isinstance(value, float):
        return value if math.isfinite(value) else None

    return REDACTED


@dataclass(frozen=True)
class CheckResult:
    """One diagnostic observation with details that are sanitized at serialization."""

    name: str
    status: DiagnosticStatus
    message: str
    details: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject malformed adapter results before they can break report rendering."""

        if (
            not isinstance(self.name, str)
            or not self.name
            or not isinstance(self.status, DiagnosticStatus)
            or not isinstance(self.message, str)
            or not isinstance(self.details, Mapping)
        ):
            raise ValueError("Diagnostic check fields do not match the result contract")

    def AsDict(self) -> dict[str, object]:
        """Return stable JSON-compatible fields without arbitrary raw provider output."""

        return {
            "name": Redact(self.name),
            "status": self.status.value,
            "message": Redact(self.message),
            "details": Redact(self.details),
        }


STATUS_PRIORITY = {
    DiagnosticStatus.OK: 0,
    DiagnosticStatus.WARNING: 1,
    DiagnosticStatus.UNSUPPORTED: 2,
    DiagnosticStatus.STALE: 3,
    DiagnosticStatus.FAILED: 4,
}
EXIT_CODES = {
    DiagnosticStatus.OK: 0,
    DiagnosticStatus.WARNING: 1,
    DiagnosticStatus.FAILED: 1,
    DiagnosticStatus.STALE: 3,
    DiagnosticStatus.UNSUPPORTED: 4,
}


@dataclass(frozen=True)
class DiagnosticReport:
    """Versioned report whose aggregate outcome never hides failed checks."""

    command: str
    checks: tuple[CheckResult, ...]

    def __post_init__(self) -> None:
        """Keep report aggregation predictable and reject malformed public inputs."""

        if (
            not isinstance(self.command, str)
            or not self.command
            or not isinstance(self.checks, tuple)
            or not all(isinstance(check, CheckResult) for check in self.checks)
        ):
            raise ValueError("Diagnostic report fields do not match the report contract")

    @property
    def Status(self) -> DiagnosticStatus:
        """Return the most severe result, treating an empty report as unsupported."""

        return max(
            (check.status for check in self.checks),
            key=STATUS_PRIORITY.__getitem__,
            default=DiagnosticStatus.UNSUPPORTED,
        )

    def ExitCode(self) -> int:
        """Return zero only when every requested observation succeeds."""

        return EXIT_CODES[self.Status]

    def AsDict(self) -> dict[str, object]:
        """Expose the report schema and sanitized observations in deterministic order."""

        return {
            "schema_version": 1,
            "command": Redact(self.command),
            "status": self.Status.value,
            "checks": [check.AsDict() for check in self.checks],
        }
