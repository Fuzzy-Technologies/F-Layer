"""Receive private VPN installation payloads over an already authenticated root SSH channel."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_REQUEST_BYTES = 4 * 1024 * 1024
_FILENAME = re.compile(r"[a-z][a-z0-9-]{0,62}\.[a-z0-9]{1,12}\Z")


class GuestInstallError(ValueError):
    """Carry only an allowlisted transport and phase, never raw installer diagnostics."""

    def __init__(self, transport: str, phase: str) -> None:
        """Record fixed internal operation labels for a sanitized failure receipt."""

        super().__init__("Guest installation failed")
        self.transport = transport
        self.phase = phase


def DecodeRequest(content: bytes) -> tuple[tuple[str, dict[str, bytes]], ...]:
    """Validate all private data before creating any guest files or running an installer."""

    if not 1 <= len(content) <= MAX_REQUEST_BYTES:
        raise ValueError("Invalid guest request size")

    request = json.loads(content)

    if not isinstance(request, dict) or set(request) != {"bundles"} or not isinstance(request["bundles"], list) or not 1 <= len(request["bundles"]) <= 2:
        raise ValueError("Invalid guest request")

    result: list[tuple[str, dict[str, bytes]]] = []

    for bundle in request["bundles"]:
        if (
            not isinstance(bundle, dict) or set(bundle) != {"transport", "files"}
            or bundle["transport"] not in {"amneziawg", "vless-reality"}
            or not isinstance(bundle["files"], dict) or not 1 <= len(bundle["files"]) <= 8
        ):
            raise ValueError("Invalid transport bundle")

        files = {}

        for name, encoded in bundle["files"].items():
            if not isinstance(name, str) or _FILENAME.fullmatch(name) is None or not isinstance(encoded, str):
                raise ValueError("Invalid transport filename")

            decoded = base64.b64decode(encoded, validate=True)

            if not 1 <= len(decoded) <= 1048576:
                raise ValueError("Invalid transport file size")

            files[name] = decoded

        entrypoint = "install.sh" if bundle["transport"] == "amneziawg" else "install.py"

        if entrypoint not in files or any(transport == bundle["transport"] for transport, _ in result):
            raise ValueError("Invalid installer entrypoint or duplicate transport")

        result.append((bundle["transport"], files))

    return tuple(result)


def Install(bundles: tuple[tuple[str, dict[str, bytes]], ...]) -> None:
    """Use root-owned temporary directories and suppress potentially sensitive installer output."""

    if os.geteuid() != 0:
        raise ValueError("Root privileges are required")

    for transport, files in bundles:
        stage = Path(tempfile.mkdtemp(prefix="flayer-install-", dir="/var/tmp"))

        phase = "stage"

        try:
            os.chmod(stage, 0o700)

            for name, content in files.items():
                descriptor = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)

            command = ["/bin/bash", str(stage / "install.sh")] if transport == "amneziawg" else ["/usr/bin/python3", str(stage / "install.py")]
            phase = "install"
            subprocess.run(command, cwd=stage, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=1800)
            phase = "check"
            subprocess.run(command + ["--check"], cwd=stage, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=60)

        except (OSError, subprocess.SubprocessError):
            raise GuestInstallError(transport, phase) from None

        finally:
            shutil.rmtree(stage)


def Main() -> int:
    """Return only fixed status text, never request data or private installer diagnostics."""

    try:
        bundles = DecodeRequest(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
        Install(bundles)

    except GuestInstallError as error:
        print(f"FLAYER_GUEST_FAILED {error.transport} {error.phase}")

        return 1

    except Exception:
        print("F-Layer guest installation failed", file=sys.stderr)

        return 1

    print("FLAYER_GUEST_INSTALL_OK")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
