"""Align authored Markdown tables without changing cells or literal code examples."""

from __future__ import annotations

import argparse
import re
import subprocess
import unicodedata
from collections.abc import Sequence
from pathlib import Path

SEPARATOR_CELL = re.compile(r":?-{3,}:?\Z")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")


def SplitRow(line: str) -> list[str] | None:
    """Split cells at unescaped pipes, including pipes inside inline code."""

    stripped = line.strip()

    if "|" not in stripped:
        return None

    cells: list[str] = []
    start = 1 if stripped.startswith("|") else 0
    index = start

    while index < len(stripped):
        character = stripped[index]

        if character == "\\":
            index += 2
            continue

        if character == "|":
            cells.append(stripped[start:index].strip())
            start = index + 1

        index += 1

    if start < len(stripped):
        cells.append(stripped[start:].strip())

    return cells if cells else None


def _IndentedCode(line: str) -> bool:
    """Recognize a four-column indentation boundary before table detection."""

    prefix = line[:len(line) - len(line.lstrip(" \t"))]

    return len(prefix.expandtabs(4)) >= 4



def DisplayWidth(text: str) -> int:
    """Approximate raw monospace width with wide/fullwidth and combining characters."""

    return sum(0 if unicodedata.combining(character) else
               2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
               for character in text)


def AlignMarkdown(text: str) -> str:
    """Pad valid table columns and separator rules to their complete cell widths."""

    lines = text.splitlines(keepends=True)
    index = 0
    fence: tuple[str, int] | None = None

    while index < len(lines):
        match = FENCE.match(lines[index])

        if match:
            marker = match.group(1)

            if fence is None:
                fence = (marker[0], len(marker))

            elif (
                marker[0] == fence[0] and len(marker) >= fence[1]
                and not lines[index][match.end():].strip()
            ):
                fence = None

            index += 1
            continue

        if fence or index + 1 >= len(lines) or _IndentedCode(lines[index]):
            index += 1
            continue

        if _IndentedCode(lines[index + 1]):
            index += 1
            continue

        header = SplitRow(lines[index])
        separator = SplitRow(lines[index + 1])

        if not header or not separator or len(header) != len(separator) or not all(
            SEPARATOR_CELL.fullmatch(cell) for cell in separator
        ):
            index += 1
            continue

        rows = [header, separator]
        end = index + 2

        while end < len(lines):
            if _IndentedCode(lines[end]):
                break

            row = SplitRow(lines[end])

            if row is None or len(row) != len(header):
                break

            rows.append(row)
            end += 1

        widths = [max(3 + separator[column].count(":"),
                      *(DisplayWidth(row[column]) for offset, row in enumerate(rows) if offset != 1))
                  for column in range(len(header))]

        for offset, row in enumerate(rows):
            rendered = []

            for column, cell in enumerate(row):
                if offset == 1:
                    left = ":" if cell.startswith(":") else ""
                    right = ":" if cell.endswith(":") else ""
                    cell = left + "-" * (widths[column] - len(left) - len(right)) + right

                rendered.append(cell + " " * (widths[column] - DisplayWidth(cell)))

            original = lines[index + offset]
            prefix = original[:len(original) - len(original.lstrip())]
            newline = "\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else ""
            lines[index + offset] = prefix + "| " + " | ".join(rendered) + " |" + newline

        index = end

    return "".join(lines)


def TrackedMarkdown(project_root: Path) -> tuple[Path, ...]:
    """List repository-owned Markdown while excluding disposable generated output."""

    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"], cwd=project_root,
        capture_output=True, text=True, check=True,
    )

    return tuple(project_root / name for name in result.stdout.split("\0") if name)


def CheckMarkdownTables(project_root: Path) -> tuple[str, ...]:
    """Report tracked files whose table columns drift from readable source alignment."""

    diagnostics = []

    for path in TrackedMarkdown(project_root):
        text = path.read_text(encoding="utf-8")

        if AlignMarkdown(text) != text:
            diagnostics.append(f"{path.relative_to(project_root)}: Markdown table columns need alignment")

    return tuple(diagnostics)


def Main(arguments: Sequence[str] | None = None) -> int:
    """Check alignment by default or apply requested table padding and separator rules."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--write", action="store_true")
    options = parser.parse_args(arguments)

    if options.write:
        for path in TrackedMarkdown(options.project_root):
            text = path.read_text(encoding="utf-8")
            aligned = AlignMarkdown(text)

            if aligned != text:
                path.write_text(aligned, encoding="utf-8")
                print(path.relative_to(options.project_root))

    diagnostics = CheckMarkdownTables(options.project_root)

    if diagnostics:
        print("\n".join(diagnostics))

        return 1

    print("Markdown table alignment: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
