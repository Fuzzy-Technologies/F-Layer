"""Prepare an unpublished nonce-bound WG generation from fully pinned cached runtime bytes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any


def _Exclusive(path: Path, content: bytes, mode: int) -> None:
    """Append only a new transient file and synchronize its complete bytes before publishing a receipt."""

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)

    try:
        os.fchmod(descriptor, mode)

        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(descriptor)

    finally:
        os.close(descriptor)


def PrepareFresh(
    guest: Any, source: Path, cached: Path, candidate: Path, sourceFiles: dict[str, str], nonce: str,
    maintenance: bytes, maintenanceSha256: str, *, allowMutation: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run the original vendor/build gate into two unpublished private snapshots, never a legacy install transaction."""

    if allowMutation is not True:
        raise guest.GuestError("Fresh runtime preparation requires explicit mutation consent")

    guest._RequireDigest(maintenanceSha256)
    guest._Nonce(nonce)

    if (type(sourceFiles) is not dict or set(sourceFiles) != {"server.conf", "deployment.json", "install.py"}
            or any(type(digest) is not str or guest._HASH.fullmatch(digest) is None for digest in sourceFiles.values())
            or type(maintenance) is not bytes or not 1 <= len(maintenance) <= 1048576 or guest._Digest(maintenance) != maintenanceSha256):
        raise guest.GuestError("Fresh runtime preparation requires complete source pins and an exact callback program")

    paths = (source, cached, candidate)

    for path in paths:
        guest._Directory(path, private=True)

        if (not path.is_absolute() or path != path.resolve(strict=True)
                or path.is_relative_to(guest.BASE.parent.resolve()) or path.is_relative_to(guest.SYSTEMD.resolve())):
            raise guest.GuestError("Fresh runtime snapshots require canonical transient paths outside managed state")

    if (any(left.is_relative_to(right) for left in paths for right in paths if left != right)
            or len(set(paths)) != 3 or tuple(cached.iterdir()) or tuple(candidate.iterdir())
            or {path.name for path in source.iterdir()} != set(sourceFiles)):
        raise guest.GuestError("Fresh runtime preparation requires separate exact source and empty snapshot directories")

    request, _, _ = guest._Request(source)
    payload = {name: guest._Read(source / name) for name in sourceFiles}

    if ({name: guest._Digest(content) for name, content in payload.items()} != sourceFiles
            or guest._Digest(guest._Read(Path(guest.__file__), limit=1048576)) != maintenanceSha256):
        raise guest.GuestError("Fresh runtime source or callback program differs from its explicit approved pin")

    owner = request["owner"]
    guest._RequireAbsent(owner)
    guest._NamespaceAvailable(owner, request)
    root, _, _ = guest._Paths(owner)
    facts = guest._KernelFacts()
    evidence = guest._VendorEvidence(guest._Fetch(guest.KERNEL_CVE_URL, 1048576), facts["package_version"])

    with tempfile.TemporaryDirectory(prefix=".wg-build-", dir=cached.parent) as temporary:
        work = Path(temporary)
        os.chmod(work, 0o700)
        receipt, built = guest._BuildPayload(source, request, root, work, {**facts, **evidence})

        if receipt["nonce"] == nonce or any(built[name] != content for name, content in payload.items()):
            raise guest.GuestError("Fresh runtime source or generation changed during its private build")

        guest._KernelMatches(receipt)
        guest._RequireAbsent(owner)

        for name, content in built.items():
            _Exclusive(cached / name, content, 0o755 if name == "wg" else 0o600)

        _Exclusive(cached / "receipt.json", guest._Encode(receipt), 0o600)
        guest._SyncDirectory(cached)
        guest._SyncDirectory(cached.parent)

    desired = PrepareCached(guest, cached, candidate, guest._Digest(guest._Encode(receipt)), nonce, maintenance, maintenanceSha256)

    if ({name: guest._Read(source / name) for name in sourceFiles} != payload
            or {path.name for path in source.iterdir()} != set(sourceFiles)):
        raise guest.GuestError("Fresh runtime original source changed before snapshot acknowledgment")

    guest._KernelMatches(receipt)
    guest._RequireAbsent(owner)
    guest._SyncDirectory(candidate.parent)

    return receipt, desired


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
        _Exclusive(destination / name, content, 0o755 if name == "wg" else 0o600)

    receipt = {**previous, "schema_version": 2, "nonce": nonce, "status": "staged",
               "files": {name: guest._Digest(content) for name, content in payload.items()},
               "network_sha256": guest._ExpectedNetwork(destination / "firewall.nft", owner, nonce)}
    guest._ReceiptData(receipt, owner, staged=True)

    if guest._Receipt(source, absentUnit, owner, staged=True) != previous:
        raise guest.GuestError("Cached generation changed before candidate completion")

    _Exclusive(destination / "receipt.json", guest._Encode(receipt), 0o600)

    guest._SyncDirectory(destination)
    guest._Receipt(destination, destination / ".unpublished-unit", owner, staged=True)

    return receipt
