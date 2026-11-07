"""Retain complete private WG snapshots before their receipts can enter a reserved composite plan; grant no runtime authority."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

BASE = Path("/var/lib/flayer/wireguard-preparations")
MAX_PREPARATIONS = 32
MAX_SCRATCH = 8
_SOURCE_FILES = frozenset({"server.conf", "deployment.json", "install.py"})
_EMPTY_PLAN = "0" * 64
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class PreparationError(ValueError):
    """A fixed preparation failure without private source, build output or native diagnostics."""


def _Intent(authority: Any, origin: object) -> dict[str, Any]:
    """Validate an explicitly unreserved origin; this placeholder must never be submitted to reservation or native execution."""

    if type(origin) is not dict or "plan_sha256" in origin:
        raise PreparationError("Preparation origin must omit the unplanned composite digest")

    return cast(dict[str, Any], authority.Intent({**origin, "plan_sha256": _EMPTY_PLAN}))


def Request(guest: Any, authority: Any, completion: Any, value: object) -> dict[str, Any]:
    """Bind full identity, nonauthorizing origin, retained WG source and optional existing runtime before any guest access."""

    fields = {"schema_version", "identity", "origin", "source", "source_files", "cached_receipt", "maintenance_sha256"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or len(guest._Encode(value)) > 32768 or type(value["identity"]) is not dict
            or set(value["identity"]) != {"project", "stack", "provider", "scope_id", "owner_id"}
            or any(type(item) is not str for item in value["identity"].values())
            or any(_NAME.fullmatch(value["identity"][key]) is None for key in ("project", "stack", "provider", "owner_id"))
            or not 1 <= len(value["identity"]["scope_id"]) <= 256 or any(not 33 <= ord(item) <= 126 for item in value["identity"]["scope_id"])
            or not authority._Hash(value["maintenance_sha256"]) or type(value["source_files"]) is not dict
            or set(value["source_files"]) != _SOURCE_FILES or any(not authority._Hash(digest) for digest in value["source_files"].values())):
        raise PreparationError("Preparation requires a closed bounded owned source and approved helper pin")

    intent = _Intent(authority, value["origin"])
    owner = guest._Digest(json.dumps(value["identity"], sort_keys=True, separators=(",", ":")).encode())
    source = completion._Sources(guest, authority, value["identity"], [value["source"]])[0]

    if owner != intent["owner"] or source["pin"]["protocol"] != "wireguard":
        raise PreparationError("Preparation source or origin belongs to another complete owner")

    cached = value["cached_receipt"]

    if cached is not None:
        guest._ReceiptData(cached, owner, staged=True)

        if any(cached["files"][name] != digest for name, digest in value["source_files"].items()):
            raise PreparationError("Preparation must retain all original private source bytes")

    if intent["wireguard_state"] == "active" and (cached is None or cached["status"] != "installed" or guest._Digest(guest._Encode(cached)) != intent["wireguard_receipt_sha256"]):
        raise PreparationError("Disable preparation requires its actual installed original receipt")

    return cast(dict[str, Any], json.loads(guest._Encode(value)))


def _Bundle(guest: Any, request: dict[str, Any], files: object) -> dict[str, bytes]:
    """Retained installer bytes are source data; only the package helper may build or prepare a generation."""

    if (type(files) is not dict or set(files) != _SOURCE_FILES or any(type(data) is not bytes or not 1 <= len(data) <= 1048576 for data in files.values())
            or sum(map(len, files.values())) > 2 * 1024 * 1024 or {name: guest._Digest(data) for name, data in files.items()} != request["source_files"]):
        raise PreparationError("Preparation requires all exact retained private server files")

    digest = guest._Digest(guest._Encode({"identity": request["identity"], "kind": "server", "name": request["identity"]["stack"] + "-wireguard", "files": [
        {"name": name, "size": len(data), "sha256": guest._Digest(data), "sensitive": True} for name, data in sorted(files.items())]}))

    if digest != request["source"]["pin"]["server_digest"]:
        raise PreparationError("Preparation server bytes differ from their complete retained source pin")

    descriptor = None

    try:
        descriptor = json.loads(files["deployment.json"])

    except (ValueError, UnicodeError, RecursionError):
        pass

    if (type(descriptor) is not dict or descriptor.get("owner") != request["origin"]["owner"]
            or descriptor.get("config_sha256") != request["source_files"]["server.conf"]
            or descriptor.get("program_sha256") != request["source_files"]["install.py"]):
        raise PreparationError("Preparation descriptor differs from its complete owner and private source pins")

    return dict(files)


def Result(guest: Any, authority: Any, completion: Any, value: object, generation: object) -> dict[str, Any]:
    """Reconstruct only public receipt metadata; these facts do not attest live input, cloud rules or an activated service."""

    request = Request(guest, authority, completion, value)
    intent = _Intent(authority, request["origin"])
    generation = cast(dict[str, Any], guest._GenerationRecord(generation, intent))

    if generation["schema_version"] != 3:
        raise PreparationError("Preparation requires its sealed native generation contract")
    expected = {"schema_version": 3, "callback_abi": guest.PROTOCOL_RUNTIME_ABI, "change": "disable" if intent["wireguard_state"] == "active" else "enable",
                "source_sha256": guest._Digest(guest._Encode(request["source"])), "source_files": request["source_files"]}

    if (any(generation[key] != item for key, item in expected.items())
            or generation["candidate_receipt"]["files"]["lifecycle.py"] != request["maintenance_sha256"]
            or request["cached_receipt"] is not None and generation["cached_receipt"] != request["cached_receipt"]):
        raise PreparationError("Prepared generation differs from its exact source, original runtime or approved helper")

    manifest = {"schema_version": 1, "request": request, "generation": generation}

    return {"status": "generation-preparation", "request_sha256": guest._Digest(guest._Encode(request)),
            "preparation_sha256": guest._Digest(guest._Encode(manifest)), "generation": generation}


def _Root(guest: Any, request: dict[str, Any], *, create: bool) -> Path:
    """Derive only fixed full-owner and nonce paths, never a path supplied by a controller or retained source."""

    owner = request["origin"]["owner"]

    guest._Directory(BASE.parent.parent)

    for path in (BASE.parent, BASE, BASE / owner):
        guest._Directory(path, create=create, private=True)

    return cast(Path, BASE / owner / request["origin"]["operation_id"])


def _Capacity(guest: Any, root: Path) -> None:
    """Bound sealed snapshots and abandoned transient builds without adopting or deleting either on another operation's behalf."""

    names = []

    with os.scandir(root.parent) as entries:
        for entry in entries:
            names.append(entry.name)

            if len(names) >= MAX_PREPARATIONS + MAX_SCRATCH:
                break

    if len(names) >= MAX_PREPARATIONS + MAX_SCRATCH:
        raise PreparationError("Preparation namespace capacity requires explicit scoped cleanup")

    sealed, scratch = 0, 0

    for name in names:
        guest._Directory(root.parent / name, private=True)

        if re.fullmatch(r"[0-9a-f]{32}", name):
            sealed += 1
        elif re.fullmatch(r"\.prep-[0-9a-f]{32}-[a-z0-9_]{8}", name):
            scratch += 1
        else:
            raise PreparationError("Preparation namespace has an unknown entry")

    if sealed >= MAX_PREPARATIONS or scratch >= MAX_SCRATCH:
        raise PreparationError("Preparation namespace capacity requires explicit scoped cleanup")


def _Guard(guest: Any, peer: Any, authority: Any, request: dict[str, Any]) -> None:
    """Preparation can neither overlap a reservation nor consume peer history, even if a controller copied an old local plan."""

    intent = _Intent(authority, request["origin"])
    pending = authority._Pending(guest, intent)
    _, digest, _, count = authority._Authority(guest, intent, pending)

    if pending is not None or digest != intent["previous_authority_sha256"] or count >= authority.MAX_COMPLETIONS:
        raise PreparationError("Preparation requires its exact unreserved common authority")

    completed = authority._Root(guest) / ("done-" + intent["operation_id"] + ".json")

    if completed.exists() or completed.is_symlink():
        raise PreparationError("A completed operation nonce cannot prepare another generation")

    _, history = authority._Observe(guest, peer, intent)

    if history != intent["wireguard_history_sha256"] or intent["plan_expires_at"] <= int(time.time()):
        raise PreparationError("Preparation origin is stale, expired or has consumed WG history")


def _Read(guest: Any, authority: Any, completion: Any, cache: Any, root: Path, request: dict[str, Any]) -> tuple[dict[str, Any], dict[Path, bytes]]:
    """Read a whole immutable preparation, rejecting every partial manifest, unknown child, source alias or private-file drift."""

    guest._Directory(root, private=True)

    if {path.name for path in root.iterdir()} != {"manifest.json", "source", "cached", "candidate"}:
        raise PreparationError("Preparation snapshot is incomplete or has unknown children")

    manifest = authority._Decode(guest, root / "manifest.json")

    if (set(manifest) != {"schema_version", "request", "generation"} or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or guest._Encode(manifest["request"]) != guest._Encode(request)):
        raise PreparationError("Preparation snapshot belongs to another exact request")

    result = Result(guest, authority, completion, request, manifest["generation"])
    guest._Directory(root / "source", private=True)
    names = set()

    with os.scandir(root / "source") as entries:
        for entry in entries:
            names.add(entry.name)

            if len(names) > len(_SOURCE_FILES):
                break

    if names != _SOURCE_FILES:
        raise PreparationError("Preparation source contains missing or unknown files")

    files = {name: guest._Read(root / "source" / name) for name in sorted(_SOURCE_FILES)}
    _Bundle(guest, request, files)
    descriptor = guest._Request(root / "source")[0]

    if descriptor["owner"] != request["origin"]["owner"]:
        raise PreparationError("Preparation descriptor belongs to another owner")

    payloads = {root / "manifest.json": guest._Encode(manifest), **{root / "source" / name: data for name, data in files.items()}}

    for name in ("cached", "candidate"):
        receipt = result["generation"][name + "_receipt"]
        payload = cache._Source(guest, root / name, receipt, {"port": descriptor["port"]})
        payloads.update({root / name / filename: data for filename, data in payload.items()})

    return result, payloads


@contextmanager
def _Durable(guest: Any, root: Path, payloads: dict[Path, bytes]) -> Iterator[Callable[[Path | None], None]]:
    """Pin exact bytes and inode metadata across every file/ancestor barrier, including same-byte replacement and membership ABA."""

    directories = [BASE.parent.parent, BASE.parent, BASE, root.parent, root, *(root / name for name in ("source", "cached", "candidate"))]
    handles: list[tuple[Path, int, os.stat_result]] = []
    members: dict[Path, set[str]] = {}
    renamed = False

    def Verify(published: Path | None = None) -> None:
        nonlocal renamed

        if published is not None:
            if renamed or published.parent != root.parent or not re.fullmatch(r"[0-9a-f]{32}", published.name):
                raise PreparationError("Preparation acknowledgment has an unexpected publication")

            replacement = []

            for path, descriptor, before in handles:
                mapped = published / path.relative_to(root) if path.is_relative_to(root) else path
                current, linked = os.fstat(descriptor), mapped.lstat()
                stable = (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink)

                if (stable != (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink)
                        or stable != (linked.st_dev, linked.st_ino, linked.st_mode, linked.st_uid, linked.st_nlink)
                        or path == root and (before.st_size, before.st_mtime_ns) != (current.st_size, current.st_mtime_ns)
                        or path not in {root, root.parent} and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)):
                    raise PreparationError("Preparation inode changed across its exact directory publication")

                replacement.append((mapped, descriptor, current))

            expected = {(published / path.relative_to(root) if path.is_relative_to(root) else path):
                        (names - {root.name} | {published.name} if path == root.parent else names) for path, names in members.items()}

            if any(set(os.listdir(path)) != names for path, names in expected.items()):
                raise PreparationError("Preparation membership changed across directory publication")

            handles[:] = replacement
            members.clear()
            members.update(expected)
            renamed = True

        for path, descriptor, before in handles:
            current, linked = os.fstat(descriptor), path.lstat()

            if ((before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (current.st_dev, current.st_ino, current.st_mode, current.st_uid, current.st_nlink, current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                    or (before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)):
                raise PreparationError("Preparation snapshot changed during durable acknowledgment")

        if any(set(os.listdir(path)) != names for path, names in members.items()):
            raise PreparationError("Preparation membership changed during durable acknowledgment")

    try:
        for path in directories:
            guest._Directory(path, private=path != BASE.parent.parent)
            descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            handles.append((path, descriptor, os.fstat(descriptor)))
            info = handles[-1][2]

            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_mode & 0o022
                    or path != BASE.parent.parent and stat.S_IMODE(info.st_mode) != 0o700):
                raise PreparationError("Preparation directory ownership changed before acknowledgment")

            if path == root.parent:
                members[path] = set(os.listdir(descriptor))
            elif path == root:
                members[path] = {"source", "cached", "candidate", "manifest.json"}
            elif path.is_relative_to(root):
                members[path] = {filename.name for filename in payloads if filename.parent == path}

        for path, content in payloads.items():
            mode = 0o755 if path.name == "wg" else 0o600

            if guest._Read(path, limit=8 * 1024 * 1024 if path.name == "wg" else 1048576, mode=mode) != content:
                raise PreparationError("Preparation bytes changed before acknowledgment")

            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            handles.append((path, descriptor, os.fstat(descriptor)))
            info = handles[-1][2]

            if not stat.S_ISREG(info.st_mode) or info.st_uid != guest._ROOT_UID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode:
                raise PreparationError("Preparation file ownership changed before acknowledgment")

            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                if stream.read(len(content) + 1) != content:
                    raise PreparationError("Preparation pinned bytes changed before acknowledgment")

        Verify()

        for _, descriptor, _ in reversed(handles):
            os.fsync(descriptor)

        Verify()
        yield Verify
        Verify()

        for _, descriptor, _ in reversed(handles):
            os.fsync(descriptor)

        Verify()

    finally:
        for _, descriptor, _ in reversed(handles):
            os.close(descriptor)


def Read(guest: Any, authority: Any, completion: Any, cache: Any, value: object, rawIntent: object, generation: object) -> tuple[dict[str, Any], Path, Path]:
    """Select only complete fixed snapshots; caller-held coordination and exposed-reservation admission remain mandatory for cache mutation."""

    request = Request(guest, authority, completion, value)
    intent = authority.Intent(rawIntent)

    if guest._Encode({key: item for key, item in intent.items() if key != "plan_sha256"}) != guest._Encode(request["origin"]):
        raise PreparationError("Preparation selection has a different complete reserved origin")

    expected = Result(guest, authority, completion, request, generation)
    root = _Root(guest, request, create=False)
    result, _ = _Read(guest, authority, completion, cache, root, request)

    if guest._Encode(result) != guest._Encode(expected):
        raise PreparationError("Preparation selection differs from the complete sealed generation")

    return result, root / "cached", root / "candidate"


def _Publish(guest: Any, stage: Path, root: Path, verify: Callable[[Path | None], None]) -> None:
    """Require Linux no-replace directory publication; even an empty foreign target must survive a race unchanged."""

    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)

    if rename is None:
        raise PreparationError("Preparation publication requires Linux no-replace rename support")

    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int

    if rename(-100, os.fsencode(stage), -100, os.fsencode(root), 1) != 0:
        raise PreparationError("Preparation publication refused an existing target or unsupported atomic rename")

    verify(root)
    guest._SyncDirectory(root.parent)
    verify(None)


def Status(guest: Any, peer: Any, authority: Any, completion: Any, cache: Any, value: object) -> dict[str, Any]:
    """Observe one full preparation under shared coordination without creating files, synchronizing or claiming service health."""

    request = Request(guest, authority, completion, value)

    with authority._Locks(guest, readOnly=True):
        root = _Root(guest, request, create=False)

        return _Read(guest, authority, completion, cache, root, request)[0]


@contextmanager
def _Scratch(guest: Any, root: Path) -> Iterator[Path]:
    """Retain every unacknowledged transient tree on refusal or interruption; only explicit future scoped cleanup may remove it."""

    stage = Path(tempfile.mkdtemp(prefix=".prep-" + root.name + "-", dir=root.parent))
    guest._Directory(stage, private=True)

    yield stage


def Prepare(
    guest: Any, peer: Any, authority: Any, completion: Any, tools: Any, cache: Any, value: object, files: object, *, allowMutation: bool = False, scopeConfirm: str = "",
) -> dict[str, Any]:
    """Build/retain snapshots only; never install, activate, fence history, expose ingress or modify an existing source."""

    request = Request(guest, authority, completion, value)
    files = _Bundle(guest, request, files)

    if allowMutation is not True or type(scopeConfirm) is not str or scopeConfirm != request["identity"]["scope_id"]:
        raise PreparationError("Preparation requires explicit mutation consent and exact scope")

    with authority._Locks(guest, readOnly=False):
        known = BASE / request["origin"]["owner"] / request["origin"]["operation_id"]

        if known.exists() or known.is_symlink():
            root = _Root(guest, request, create=False)
            result, payloads = _Read(guest, authority, completion, cache, root, request)

            with _Durable(guest, root, payloads):
                return result

        _Guard(guest, peer, authority, request)
        root = _Root(guest, request, create=True)

        if not root.exists() and not root.is_symlink():
            _Capacity(guest, root)
            maintenance = guest._Read(Path(guest.__file__), limit=1048576)

            if guest._Digest(maintenance) != request["maintenance_sha256"]:
                raise PreparationError("New preparation requires the exact approved package helper")

            with _Scratch(guest, root) as stage:
                for name in ("source", "cached", "candidate"):
                    guest._Directory(stage / name, create=True, private=True)

                for name, content in files.items():
                    tools._Exclusive(stage / "source" / name, content, 0o600)

                descriptor = guest._Request(stage / "source")[0]

                if descriptor["owner"] != request["origin"]["owner"]:
                    raise PreparationError("Preparation descriptor belongs to another owner")

                cached = request["cached_receipt"]
                nonce = request["origin"]["operation_id"]

                if cached is None:
                    cached, desired = tools.PrepareFresh(guest, stage / "source", stage / "cached", stage / "candidate", request["source_files"], nonce,
                                                         maintenance, request["maintenance_sha256"], allowMutation=True)

                else:
                    source = guest._ActivePaths(request["origin"]["owner"])[0] if request["origin"]["wireguard_state"] == "active" else cache._CachePath(guest, cached)
                    payload = cache._Source(guest, source, cached, {"port": descriptor["port"]})

                    for name, content in payload.items():
                        tools._Exclusive(stage / "cached" / name, content, 0o755 if name == "wg" else 0o600)

                    desired = tools.PrepareCached(guest, stage / "cached", stage / "candidate", guest._Digest(guest._Encode(cached)), nonce,
                                                  maintenance, request["maintenance_sha256"])

                generation = {"schema_version": 3, "callback_abi": guest.PROTOCOL_RUNTIME_ABI, "change": "disable" if request["origin"]["wireguard_state"] == "active" else "enable",
                              "source_sha256": guest._Digest(guest._Encode(request["source"])), "source_files": request["source_files"],
                              "cached_receipt": cached, "candidate_receipt": desired}
                Result(guest, authority, completion, request, generation)
                tools._Exclusive(stage / "manifest.json", guest._Encode({"schema_version": 1, "request": request, "generation": generation}), 0o600)
                _, payloads = _Read(guest, authority, completion, cache, stage, request)
                with _Durable(guest, stage, payloads) as verify:
                    _Guard(guest, peer, authority, request)
                    _Publish(guest, stage, root, verify)
                    _Guard(guest, peer, authority, request)

                    return Result(guest, authority, completion, request, generation)

        raise PreparationError("Preparation namespace changed before private construction")
