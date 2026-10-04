"""Protect table cells and fenced examples during source alignment."""

import subprocess
from pathlib import Path

from tools.markdown_tables import AlignMarkdown, CheckMarkdownTables, SplitRow


def test_TableAlignmentPreservesEscapedAndCodePipes() -> None:
    """Column separators cannot split pipes that belong to a cell's content."""

    text = "| Cell | Note |\n| :--- | ---: |\n| `left|right` | escaped \\| pipe |\n"
    aligned = AlignMarkdown(text)
    original_rows = [SplitRow(line) for line in text.splitlines()]
    aligned_rows = [SplitRow(line) for line in aligned.splitlines()]

    assert original_rows[0] == aligned_rows[0]
    assert original_rows[2] == aligned_rows[2], "Alignment must preserve complete cell values"
    assert aligned_rows[1] is not None
    assert aligned_rows[1][0].startswith(":")
    assert aligned_rows[1][1].endswith(":")
    assert AlignMarkdown(aligned) == aligned, "A second formatting pass must have no changes"


def test_FencedTablesAreNeverRewritten() -> None:
    """Markdown examples inside both supported fence styles remain byte-identical."""

    for marker in ("```", "~~~~"):
        example = (
            f"{marker}markdown\n{marker}not-a-closing-fence\n"
            f"| Short | Very long cell |\n| --- | --- |\n{marker}\n"
        )

        assert AlignMarkdown(example) == example, "Fenced literal content must remain untouched"


def test_OptionalOuterPipesReceiveTheSameAlignment() -> None:
    """Valid tables without outer pipes must not bypass the source-readability gate."""

    text = "Short | Longer heading\n------------------------ | ---\nValue | Result\n"
    aligned = AlignMarkdown(text)

    assert aligned.startswith("| Short | Longer heading |\n")
    assert SplitRow(text.splitlines()[2]) == SplitRow(aligned.splitlines()[2])


def test_IncompleteTableStructureRemainsUntouched() -> None:
    """A pipe expression without a valid separator row is not an authored table."""

    for text in ("| a | b |\n| expression | value |\n", "| a | b |\n| --- |\n"):
        assert AlignMarkdown(text) == text


def test_TrackedTableDriftIsReported(tmp_path: Path) -> None:
    """The gate reports source drift but does not rewrite it or inspect ignored output."""

    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    page = tmp_path / "README.md"
    original = "| Short | Longer heading |\n| --- | --- |\n| Value | Result |\n"
    page.write_text(original, encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=tmp_path, check=True)
    ignored = tmp_path / "_build/preview.md"
    ignored.parent.mkdir()
    ignored.write_text(original, encoding="utf-8")

    assert CheckMarkdownTables(tmp_path) == (
        "README.md: Markdown table columns need alignment",
    )
    assert page.read_text(encoding="utf-8") == original, "Validation must remain read-only"
