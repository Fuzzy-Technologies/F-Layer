"""Localize static documentation objects without changing installed Python source."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from griffe import Extension, Object


class TranslatedDocstrings(Extension):
    """Replace reviewed API prose while preserving source listings and symbol identities."""

    def __init__(self, translations_path: str) -> None:
        """Read the renderer's already validated exact locale prose overlay."""

        self.translations: dict[str, str] = json.loads(Path(translations_path).read_text(encoding="utf-8"))

    def on_instance(self, *, obj: Object, **kwargs: Any) -> None:
        """Honor Griffe's callback interface without executing the documented module."""

        if obj.docstring is not None and obj.path in self.translations:
            obj.docstring.value = self.translations[obj.path]
