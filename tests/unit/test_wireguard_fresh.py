"""Refuse invalid fresh-generation metadata before any private filesystem or native observation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from flayer.profiles import _wireguard_generation as generations
from flayer.profiles import _wireguard_guest as guest


@pytest.mark.parametrize("fault", ["consent", "pin", "missing", "extra", "bool", "nonce", "callback"])
def test_FreshGenerationMetadataRefusalPrecedesEveryFilesystemOrNativeAction(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A source-pin or consent failure cannot even begin inspecting the supplied paths."""

    pins: Any = dict.fromkeys(("server.conf", "deployment.json", "install.py"), "a" * 64)
    nonce: Any = "b" * 32
    allow = True
    callback = b"approved synthetic callback"
    digest = guest._Digest(callback)

    if fault == "consent":
        allow = False

    elif fault == "pin":
        pins["server.conf"] = "private-invalid-canary"

    elif fault == "missing":
        del pins["server.conf"]

    elif fault == "extra":
        pins["foreign.py"] = "a" * 64

    elif fault == "bool":
        pins["server.conf"] = True

    elif fault == "nonce":
        nonce = False

    else:
        digest = "c" * 64

    monkeypatch.setattr(guest, "_Directory", lambda *args, **kwargs: pytest.fail("Refused metadata must not access the filesystem"))

    with pytest.raises(guest.GuestError):
        generations.PrepareFresh(guest, Path("/source"), Path("/cache"), Path("/candidate"), pins, nonce, callback, digest, allowMutation=allow)
