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
from collections.abc import Iterator
from contextlib import contextmanager
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

    if not isinstance(request, dict) or set(request) != {"bundles"} or not isinstance(request["bundles"], list) or not 1 <= len(request["bundles"]) <= 3:
        raise ValueError("Invalid guest request")

    result: list[tuple[str, dict[str, bytes]]] = []

    for bundle in request["bundles"]:
        if (
            not isinstance(bundle, dict) or set(bundle) != {"transport", "files"}
            or bundle["transport"] not in {"amneziawg", "vless-reality", "wireguard"}
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


@contextmanager
def _Staged(files: dict[str, bytes]) -> Iterator[Path]:
    """Share private root-owned staging and guaranteed cleanup across installation and maintenance."""

    stage = Path(tempfile.mkdtemp(prefix="flayer-install-", dir="/var/tmp"))

    try:
        os.chmod(stage, 0o700)

        for name, content in files.items():
            descriptor = os.open(stage / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)

        yield stage

    finally:
        shutil.rmtree(stage)


def Install(bundles: tuple[tuple[str, dict[str, bytes]], ...], *, expectedWireGuardHistory: str = "") -> None:
    """Use root-owned temporary directories and suppress potentially sensitive installer output."""

    if os.geteuid() != 0:
        raise ValueError("Root privileges are required")

    wireguard = next((files for transport, files in bundles if transport == "wireguard"), None)

    if (not isinstance(expectedWireGuardHistory, str)
            or (re.fullmatch(r"[0-9a-f]{64}", expectedWireGuardHistory) is None if wireguard is not None else bool(expectedWireGuardHistory))
            or wireguard is not None and set(wireguard) != {"install.py", "maintenance.py", "original.py", "server.conf", "deployment.json"}):
        raise ValueError("WireGuard install requires a complete history-bound original-program envelope")

    for transport, files in sorted(bundles, key=lambda item: item[0] != "wireguard"):
        phase = "stage"

        try:
            with _Staged(files) as stage:
                command = ["/bin/bash", str(stage / "install.sh")] if transport == "amneziawg" else ["/usr/bin/python3", str(stage / "install.py")]
                guard = (["--change", "enroll", "--device-id", "flayer-installation", "--expected-history-sha256", expectedWireGuardHistory]
                         if transport == "wireguard" else [])
                install = command + (["--install", "--allow-mutation", *guard] if guard else [])
                check = command + (["--check-install", *guard] if guard else ["--check"])
                phase = "install"
                subprocess.run(install, cwd=stage, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=1800)
                phase = "check"
                subprocess.run(check, cwd=stage, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=60)

        except (OSError, subprocess.SubprocessError):
            raise GuestInstallError(transport, phase) from None


def WireGuard(content: bytes) -> bytes:
    """Expose one receipt-bound owned operation without forwarding private diagnostics."""

    if os.geteuid() != 0 or not 1 <= len(content) <= MAX_REQUEST_BYTES:
        raise ValueError("WireGuard operation requires a bounded privileged request")

    request = json.loads(content)

    if not isinstance(request, dict) or set(request) != {"bundles", "wireguard"}:
        raise ValueError("Invalid WireGuard operation envelope")

    options = request["wireguard"]

    if (not isinstance(options, dict) or set(options) != {"action", "expected_receipt_sha256", "expected_absence_sha256"}
            or options["action"] not in {"status", "recover", "remove"}
            or any(not isinstance(options[key], str) for key in options)):
        raise ValueError("Invalid WireGuard operation")

    receipt, absence = options["expected_receipt_sha256"], options["expected_absence_sha256"]

    if options["action"] == "status":
        if receipt or absence:
            raise ValueError("Read-only status does not accept mutation preconditions")

    elif (bool(receipt) == bool(absence) or re.fullmatch(r"[0-9a-f]{64}", receipt or absence) is None
          or absence and options["action"] != "recover"):
        raise ValueError("WireGuard mutation requires one exact current receipt or absence proof")

    bundles = DecodeRequest(json.dumps({"bundles": request["bundles"]}).encode())

    if len(bundles) != 1 or bundles[0][0] != "wireguard":
        raise ValueError("WireGuard maintenance accepts only its owned server bundle")

    try:
        with _Staged(bundles[0][1]) as stage:
            command = ["/usr/bin/python3", str(stage / "install.py"), "--" + options["action"]]

            if options["action"] != "status":
                command += ["--allow-mutation", "--expected-receipt-sha256" if receipt else "--expected-absence-sha256", receipt or absence]

            result = subprocess.run(command, cwd=stage, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=False, timeout=300)

            if result.returncode != 0:
                raise ValueError

            if options["action"] != "status":
                return json.dumps({"status": "complete", "action": options["action"]}, sort_keys=True).encode()

            if not 1 <= len(result.stdout) <= 4096:
                raise ValueError

            return result.stdout

    except (OSError, ValueError, subprocess.SubprocessError):
        raise GuestInstallError("wireguard", "maintenance") from None



def _UniquePeerObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject ambiguous repeated fields before privileged peer staging."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate WireGuard peer request field")

        result[key] = value

    return result


def WireGuardPeer(content: bytes) -> bytes:
    """Run one exact peer operation through private staging without forwarding installer diagnostics."""

    if os.geteuid() != 0 or not 1 <= len(content) <= MAX_REQUEST_BYTES:
        raise ValueError("WireGuard peer operation requires a bounded privileged request")

    request = json.loads(content, object_pairs_hook=_UniquePeerObject)

    if not isinstance(request, dict) or set(request) != {"bundles", "wireguard_peer"}:
        raise ValueError("Invalid WireGuard peer envelope")

    options = request["wireguard_peer"]
    fields = {"action", "change", "device_id", "allow_mutation", "expected_receipt_sha256", "expected_previous_receipt_sha256", "expected_history_sha256"}

    if (not isinstance(options, dict) or set(options) != fields or type(options["allow_mutation"]) is not bool
            or any(not isinstance(value, str) for key, value in options.items() if key != "allow_mutation")
            or options["action"] not in {"status", "history-status", "apply", "recover"} or options["change"] not in {"enroll", "revoke"}
            or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", options["device_id"]) is None):
        raise ValueError("Invalid WireGuard peer operation")

    receipt, previous, history = (options[key] for key in ("expected_receipt_sha256", "expected_previous_receipt_sha256", "expected_history_sha256"))

    if options["action"] in {"status", "history-status"}:
        if options["allow_mutation"] or receipt or previous or history:
            raise ValueError("WireGuard peer status accepts no mutation preconditions")

    elif (options["allow_mutation"] is not True or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (receipt, history))
          or (re.fullmatch(r"[0-9a-f]{64}", previous) is None if options["action"] == "recover" else bool(previous))):
        raise ValueError("WireGuard peer mutation requires complete exact preconditions")

    bundles = DecodeRequest(json.dumps({"bundles": request["bundles"]}).encode())

    if (len(bundles) != 1 or bundles[0][0] != "wireguard"
            or set(bundles[0][1]) != {"install.py", "maintenance.py", "server.conf", "deployment.json"}):
        raise ValueError("WireGuard peer maintenance accepts only its exact packed private bundle")

    try:
        with _Staged(bundles[0][1]) as stage:
            command = ["/usr/bin/python3", str(stage / "install.py"), "--" + options["action"], "--change", options["change"], "--device-id", options["device_id"]]

            if options["action"] not in {"status", "history-status"}:
                command += ["--allow-mutation", "--expected-receipt-sha256", receipt, "--expected-history-sha256", history]

                if options["action"] == "recover":
                    command += ["--expected-previous-receipt-sha256", previous]

            result = subprocess.run(command, cwd=stage, stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=300)

            if result.returncode != 0 or not 1 <= len(result.stdout) <= 4096:
                raise ValueError

            return result.stdout

    except (OSError, ValueError, subprocess.SubprocessError):
        raise GuestInstallError("wireguard", "peer") from None


def Runtime(content: bytes) -> bytes:
    """Execute exactly one bounded VLESS maintenance operation without exposing installer errors."""

    if os.geteuid() != 0 or not 1 <= len(content) <= MAX_REQUEST_BYTES:
        raise ValueError("Runtime operation requires a bounded privileged request")

    request = json.loads(content)

    if not isinstance(request, dict) or set(request) != {"bundles", "runtime"}:
        raise ValueError("Invalid runtime envelope")

    options = request["runtime"]

    if (not isinstance(options, dict) or set(options) != {"action", "expected_version", "expected_receipt_sha256"}
            or options["action"] not in {"runtime-status", "upgrade", "rollback-upgrade", "recover-upgrade"}):
        raise ValueError("Invalid runtime action")

    if options["action"] == "runtime-status":
        if options["expected_version"] != "" or options["expected_receipt_sha256"] != "":
            raise ValueError("Read-only runtime status does not accept mutation preconditions")

    elif (options["expected_version"] not in {"26.9.30", "26.10.31"}
          or not isinstance(options["expected_receipt_sha256"], str)
          or re.fullmatch(r"[0-9a-f]{64}", options["expected_receipt_sha256"]) is None):
        raise ValueError("Runtime mutation requires exact previous version and receipt")

    bundles = DecodeRequest(json.dumps({"bundles": request["bundles"]}).encode())

    if len(bundles) != 1 or bundles[0][0] != "vless-reality":
        raise ValueError("Runtime maintenance accepts only the owned VLESS bundle")

    try:
        with _Staged(bundles[0][1]) as stage:
            command = ["/usr/bin/python3", str(stage / "install.py"), "--" + options["action"]]

            if options["action"] != "runtime-status":
                command += ["--allow-mutation", "--expected-version", options["expected_version"],
                            "--expected-receipt-sha256", options["expected_receipt_sha256"]]

            result = subprocess.run(command, cwd=stage, stdin=subprocess.DEVNULL,
                                    capture_output=True, check=False, timeout=300)

            if result.returncode != 0 or not 1 <= len(result.stdout) <= 4096:
                raise ValueError("Runtime operation failed")

            return result.stdout

    except (OSError, ValueError, subprocess.SubprocessError):
        raise GuestInstallError("vless-reality", "runtime") from None


def Main() -> int:
    """Return only fixed status text, never request data or private installer diagnostics."""

    try:
        content = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)

        if 1 <= len(content) <= MAX_REQUEST_BYTES and isinstance(json.loads(content), dict) and "wireguard_peer" in json.loads(content):
            sys.stdout.buffer.write(WireGuardPeer(content))

            return 0

        if 1 <= len(content) <= MAX_REQUEST_BYTES and isinstance(json.loads(content), dict) and "wireguard" in json.loads(content):
            sys.stdout.buffer.write(WireGuard(content))

            return 0

        if 1 <= len(content) <= MAX_REQUEST_BYTES and isinstance(json.loads(content), dict) and "runtime" in json.loads(content):
            sys.stdout.buffer.write(Runtime(content))

            return 0

        request = json.loads(content)

        if isinstance(request, dict) and "wireguard_install" in request:
            request = json.loads(content, object_pairs_hook=_UniquePeerObject)
            options = request["wireguard_install"]

            if (set(request) != {"bundles", "wireguard_install"} or not isinstance(options, dict)
                    or set(options) != {"expected_history_sha256"}):
                raise ValueError("Invalid history-bound WireGuard installation envelope")

            Install(DecodeRequest(json.dumps({"bundles": request["bundles"]}).encode()),
                    expectedWireGuardHistory=options["expected_history_sha256"])

        else:
            Install(DecodeRequest(content))

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
