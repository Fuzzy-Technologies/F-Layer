"""Parse explicit GitHub Task-closing references from a pull request body."""

from __future__ import annotations

import os
import re

CLOSING_CLAUSE_PATTERN = re.compile(
    r"\b(?:close(?:s|d)?|fix(?:es|ed)?|resolve(?:s|d)?|implement(?:s|ed)?)\s+"
    r"((?:#\d+)(?:\s*(?:,|and)\s*#\d+)*)",
    re.IGNORECASE,
)
ISSUE_REFERENCE_PATTERN = re.compile(r"#(\d+)")


def ParseLinkedTasks(body: str) -> list[int]:
    """Return unique issue numbers from explicit closing clauses in source order."""

    issueNumbers: list[int] = []
    seenNumbers: set[int] = set()

    for clauseMatch in CLOSING_CLAUSE_PATTERN.finditer(body):
        for issueMatch in ISSUE_REFERENCE_PATTERN.finditer(clauseMatch.group(1)):
            issueNumber = int(issueMatch.group(1))

            if issueNumber in seenNumbers:
                continue

            seenNumbers.add(issueNumber)
            issueNumbers.append(issueNumber)

    return issueNumbers


def Main() -> int:
    """Print linked issue numbers for the GitHub Actions merge workflow."""

    body = os.environ.get("PR_BODY", "")

    for issueNumber in ParseLinkedTasks(body):
        print(issueNumber)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
