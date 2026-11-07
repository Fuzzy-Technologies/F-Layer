"""Load only checksum-pinned package protocol helpers on an authenticated root SSH channel; supplied server installers remain data."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import types
from pathlib import Path
from typing import Any, cast

MAX_REQUEST_BYTES = 4 * 1024 * 1024
FROZEN_PINS = "__FLAYER_PROTOCOL_MODULE_PINS__"
PROGRAM_FILES = {
    "guest": "_wireguard_guest.py", "peer": "_wireguard_peer.py", "authority": "_protocol_reservation.py",
    "policy": "_host_input_policy.py", "inputs": "_host_input_guest.py", "cache": "_protocol_generation.py",
    "runtime": "_protocol_runtime.py", "completion": "_protocol_completion.py", "services": "_protocol_services.py",
    "vless": "_vless_guest.py", "rpc": "_protocol_rpc.py",
    "preparation": "_protocol_preparation.py", "tools": "_wireguard_generation.py",
}


def Sources() -> dict[str, bytes]:
    """Read only fixed installed-package resource names; a project cannot supply executable receiver dependencies."""

    from importlib.resources import files

    return {name: files("flayer.profiles").joinpath(filename).read_bytes().replace(b"\r\n", b"\n") for name, filename in PROGRAM_FILES.items()}


def Programs() -> tuple[bytes, dict[str, bytes]]:
    """Freeze complete canonical module hashes into a standalone bootstrap without a self-referential digest."""

    from importlib.resources import files

    programs = Sources()
    pins = {name: hashlib.sha256(content).hexdigest() for name, content in programs.items()}
    source = files("flayer").joinpath("_vpn_protocol_receiver.py").read_bytes().replace(b"\r\n", b"\n")
    marker = FROZEN_PINS.encode("ascii")

    if source.count(marker) != 1:
        raise ValueError("Protocol receiver pin template is ambiguous")

    encoded = json.dumps(json.dumps(pins, sort_keys=True, separators=(",", ":")))[1:-1].encode("ascii")

    return source.replace(marker, encoded), programs


def _Unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse duplicate fields before code/data roles are separated."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate protocol receiver field")

        result[key] = value

    return result


def _Nonfinite(value: str) -> None:
    """Require standard JSON before interpreting any envelope field."""

    raise ValueError("Nonstandard protocol receiver scalar")


def Fingerprint(operation: object, programs: dict[str, bytes]) -> str:
    """Bind the exact requested operation and installed helper set to every successful authenticated response."""

    value = {"operation": operation, "program_pins": {name: hashlib.sha256(source).hexdigest() for name, source in programs.items()}}

    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def _Envelope(content: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Verify every fixed program pin and a closed bounded envelope before creating any guest file or loading request semantics."""

    if type(content) is not bytes or not 1 <= len(content) <= MAX_REQUEST_BYTES:
        raise ValueError("Protocol receiver request exceeds its bound")

    value = json.loads(content, object_pairs_hook=_Unique, parse_constant=_Nonfinite)

    if (type(value) is not dict or set(value) != {"schema_version", "operation", "programs"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1 or type(value["operation"]) is not dict
            or type(value["programs"]) is not dict or set(value["programs"]) != set(PROGRAM_FILES)):
        raise ValueError("Protocol receiver envelope is malformed")

    pins = ({name: hashlib.sha256(source).hexdigest() for name, source in Sources().items()} if __package__ else json.loads(FROZEN_PINS))

    if type(pins) is not dict or set(pins) != set(PROGRAM_FILES):
        raise ValueError("Protocol receiver has no complete immutable program pins")

    programs = {}

    for name in PROGRAM_FILES:
        encoded = value["programs"][name]

        if type(encoded) is not str:
            raise ValueError("Protocol receiver program encoding is malformed")

        source = base64.b64decode(encoded, validate=True)

        if (not 1 <= len(source) <= 1048576 or hashlib.sha256(source).hexdigest() != pins[name]
                or base64.b64encode(source).decode("ascii") != encoded):
            raise ValueError("Protocol receiver program differs from its exact installed-package pin")

        programs[name] = source

    return value["operation"], programs


def Envelope(content: bytes) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Drop parser exception chains before reporting a fixed private-frame diagnostic."""

    result = None

    try:
        result = _Envelope(content)

    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
        pass

    if result is None:
        raise ValueError("Protocol receiver request is invalid or differs from its immutable package pins")

    return result


def Modules(programs: dict[str, bytes]) -> types.SimpleNamespace:
    """Compile only previously verified stdlib-only package modules in memory; entrypoint guards cannot run supplied installers."""

    if set(programs) != set(PROGRAM_FILES):
        raise ValueError("Protocol receiver requires its complete fixed module set")

    modules = {}

    for name, source in programs.items():
        module = types.ModuleType("flayer_protocol_" + name)
        module.__file__ = PROGRAM_FILES[name]
        module.__package__ = ""
        exec(compile(source, PROGRAM_FILES[name], "exec"), module.__dict__)
        modules[name] = module

    return types.SimpleNamespace(**modules)


def Receive(content: bytes) -> bytes:
    """Require root Linux, validate semantics before file staging and expose only the RPC's closed nonsecret result."""

    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("Protocol receiver requires an authenticated privileged Linux guest")

    operation, programs = Envelope(content)
    modules = Modules(programs)
    modules.rpc.Request(modules, operation)

    with tempfile.TemporaryDirectory(prefix="flayer-protocol-", dir="/var/tmp") as directory:
        stage = Path(directory)
        os.chmod(stage, 0o700)

        for name, source in programs.items():
            path = stage / PROGRAM_FILES[name]
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

            with os.fdopen(descriptor, "wb") as stream:
                stream.write(source)

                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode) or os.fstat(stream.fileno()).st_uid != 0:
                    raise ValueError("Protocol receiver program staging has unsafe ownership")

            getattr(modules, name).__file__ = str(path)

        result = modules.rpc.Dispatch(modules, operation)

        return cast(bytes, modules.rpc.Json({"schema_version": 1, "action": operation["action"],
                                             "request_sha256": Fingerprint(operation, programs), "result": result}))


def Main() -> int:
    """Suppress every private parser/native exception and emit only fixed failure or validated public response bytes."""

    try:
        result = Receive(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))

    except Exception:
        sys.stdout.buffer.write(b'{"error":"protocol-operation-failed","schema_version":1}\n')

        return 1

    sys.stdout.buffer.write(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
