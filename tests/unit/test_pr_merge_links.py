"""Tests for explicit pull-request closing-reference parsing."""

from tools.pr_merge_links import ParseLinkedTasks


def test_ParsesSupportedClosingKeywords() -> None:
    """Supported completion keywords produce the referenced issue numbers."""

    body = "Closes #12\nFixes #13\nResolves #14\nImplements #15"

    assert ParseLinkedTasks(body) == [12, 13, 14, 15], (
        "Supported closing keywords were not parsed"
    )


def test_ParsesSeveralReferencesAfterOneKeyword() -> None:
    """One closing clause may reference several Tasks."""

    body = "Closes #12, #13 and #14"

    assert ParseLinkedTasks(body) == [12, 13, 14], (
        "Multi-reference closing clause was parsed incorrectly"
    )


def test_DeduplicatesReferences() -> None:
    """Repeated closing references are returned only once in source order."""

    body = "Closes #12\nFixes #12\nResolves #13"

    assert ParseLinkedTasks(body) == [12, 13], "Duplicate references were not removed"


def test_IgnoresPlainReferences() -> None:
    """Non-closing references must not complete Tasks."""

    body = "Related: #12\nSee #13\nDiscussion in #14"

    assert ParseLinkedTasks(body) == [], (
        "Plain issue references were incorrectly treated as closing references"
    )


def test_IsCaseInsensitive() -> None:
    """Closing keywords are parsed without case sensitivity."""

    assert ParseLinkedTasks("cLoSeS #77") == [77], (
        "Keyword parsing unexpectedly depends on case"
    )
