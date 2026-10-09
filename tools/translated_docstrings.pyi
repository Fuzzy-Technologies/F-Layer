"""Typed boundary for the optional, exactly pinned Griffe documentation extension."""

from typing import Any

class TranslatedDocstrings:
    """Replace documentation prose while preserving statically loaded source."""

    def __init__(self, translations_path: str) -> None:
        """Read the renderer's validated overlay."""

        ...

    def on_instance(self, *, obj: Any, **kwargs: Any) -> None:
        """Honor the external Griffe callback naming contract."""

        ...
