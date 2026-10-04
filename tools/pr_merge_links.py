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

    issue_numbers: list[int] = []
    seen_numbers: set[int] = set()

    for clause_match in CLOSING_CLAUSE_PATTERN.finditer(body):
        for issue_match in ISSUE_REFERENCE_PATTERN.finditer(clause_match.group(1)):
            issue_number = int(issue_match.group(1))

            if issue_number in seen_numbers:
                continue

            seen_numbers.add(issue_number)
            issue_numbers.append(issue_number)

    return issue_numbers


def Main() -> int:
    """Print linked issue numbers for the GitHub Actions merge workflow."""

    body = os.environ.get("PR_BODY", "")

    for issue_number in ParseLinkedTasks(body):
        print(issue_number)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
