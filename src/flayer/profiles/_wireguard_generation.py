"""Prepare an unpublished nonce-bound WG generation from fully pinned cached runtime bytes."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def PrepareCached(
    guest: Any, source: Path, destination: Path, expectedReceipt: str, nonce: str,
    maintenance: bytes, maintenanceSha256: str,
) -> dict[str, Any]:
    """Write a complete private candidate only; this neither grants authority nor publishes or activates managed state."""

    guest._RequireDigest(expectedReceipt)
    guest._RequireDigest(maintenanceSha256)
    guest._Nonce(nonce)
    guest._Directory(source, private=True)
    guest._Directory(destination, private=True)

    if (not source.is_absolute() or not destination.is_absolute() or source == destination
            or source != source.resolve(strict=True) or destination != destination.resolve(strict=True)
            or destination.is_relative_to(guest.BASE.resolve()) or destination.is_relative_to(guest.SYSTEMD.resolve())
            or tuple(destination.iterdir()) or not isinstance(maintenance, bytes) or not 1 <= len(maintenance) <= 1048576
            or guest._Digest(maintenance) != maintenanceSha256):
        raise guest.GuestError("Cached generation requires a new private transient candidate and exact maintenance pin")

    request, _, _ = guest._Request(source)
    owner = request["owner"]
    # Validate cached file ownership without interpreting a separately installed unit as this cache's unit.
    absentUnit = source / ".unpublished-unit"
    previous = guest._Receipt(source, absentUnit, owner, staged=True)

    if (guest._Read(source / "receipt.json") != guest._Encode(previous)
            or guest._Digest(guest._Encode(previous)) != expectedReceipt or previous["nonce"] == nonce):
        raise guest.GuestError("Cached generation receipt or nonce differs from its exact plan")

    guest._KernelMatches(previous)
    preserved = {"server.conf", "deployment.json", "install.py", "wg", "COPYING"}
    payload = {name: guest._Read(source / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                               mode=0o755 if name == "wg" else 0o600) for name in preserved}

    if any(guest._Digest(content) != previous["files"][name] for name, content in payload.items()):
        raise guest.GuestError("Cached generation changed while preparing private bytes")

    payload.update({"lifecycle.py": maintenance, "firewall.nft": guest._Firewall(request, nonce),
                    "service.service": guest._Unit(guest._Paths(owner)[0], owner, nonce=nonce)})

    for name, content in payload.items():
        descriptor = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755 if name == "wg" else 0o600)

        try:
            os.fchmod(descriptor, 0o755 if name == "wg" else 0o600)

            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(descriptor)

        finally:
            os.close(descriptor)

    receipt = {**previous, "schema_version": 2, "nonce": nonce, "status": "staged",
               "files": {name: guest._Digest(content) for name, content in payload.items()},
               "network_sha256": guest._ExpectedNetwork(destination / "firewall.nft", owner, nonce)}
    guest._ReceiptData(receipt, owner, staged=True)

    if guest._Receipt(source, absentUnit, owner, staged=True) != previous:
        raise guest.GuestError("Cached generation changed before candidate completion")

    descriptor = os.open(destination / "receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

    try:
        os.fchmod(descriptor, 0o600)

        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(guest._Encode(receipt))
            stream.flush()
            os.fsync(descriptor)

    finally:
        os.close(descriptor)

    guest._SyncDirectory(destination)
    guest._Receipt(destination, destination / ".unpublished-unit", owner, staged=True)

    return receipt
