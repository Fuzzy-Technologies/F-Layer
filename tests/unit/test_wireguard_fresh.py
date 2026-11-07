"""Refuse invalid fresh-generation metadata before any private filesystem or native observation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from test_wireguard_guest import Prepared

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


@pytest.mark.parametrize("field,kind", [("schema_version", "bool"), ("schema_version", "float"), ("port", "float"), ("mtu", "float")])
def test_SharedPrivateBuilderRejectsDescriptorNumericAliasesBeforeBuildingOrPublishing(monkeypatch: pytest.MonkeyPatch, field: str, kind: str) -> None:
    """Use only in-memory source bytes: bool/float aliases cannot impersonate previously validated integer descriptor fields."""

    payload = {item.name: item.content for item in Prepared().serverBundle.files}
    request = guest._Json(payload["deployment.json"])
    alias = True if kind == "bool" else float(request[field])
    assert request[field] == alias and type(request[field]) is not type(alias)
    payload["deployment.json"] = guest._Encode({**request, field: alias})
    reads = []

    def Read(path: Path, **kwargs: Any) -> bytes:
        """Serve the exact three private fixture bodies without any filesystem access."""

        reads.append(path.name)

        return payload[path.name]

    monkeypatch.setattr(guest, "_Read", Read)
    monkeypatch.setattr(guest, "_BuildFacts", lambda: pytest.fail("A descriptor alias must be refused before toolchain observation"))
    monkeypatch.setattr(guest, "_BuildTools", lambda *args: pytest.fail("A descriptor alias must be refused before tool construction"))
    monkeypatch.setattr(guest, "_Run", lambda *args, **kwargs: pytest.fail("A descriptor alias must not run a native command"))

    with pytest.raises(guest.GuestError, match="complete validated request"):
        guest._BuildPayload(Path("/source"), request, Path("/root"), Path("/work"), {})

    assert reads == ["server.conf", "deployment.json", "install.py"]
