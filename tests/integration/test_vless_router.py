"""Exercise pinned Xray routing against static DNS and isolated loopback listeners."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles.vless import GenerateVlessMaterial, RenderVlessServer, VlessRealitySettings
from flayer.profiles.vpn import VpnDevice, VpnListener, VpnProfile, VpnRoutes

SETTINGS = VlessRealitySettings("www.example.org", "www.example.org")


def Profile() -> VpnProfile:
    """Define a public fixture without cloud access or external DNS requests."""

    return VpnProfile(
        StackIdentity("example", "vpn", "yandex-cloud", "example-folder", "example-owner"),
        (VpnDevice("phone"),),
        VpnRoutes("full", ("0.0.0.0/0",), ("1.1.1.1",), "disabled"),
        (VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),),
    )


@pytest.mark.parametrize("destination,allowed", [
    ("dual.example.test", True), ("198.51.100.20", True),
    ("private.example.test", False), ("metadata.example.test", False),
    ("2001:db8::20", False), ("10.1.2.3", False),
    ("169.254.169.254", False), ("127.0.0.1", False), ("224.0.0.1", False),
])
def test_RealPinnedXrayRoutesDualStackNamesWithoutAllowingPrivateTargets(
    tmp_path: Path, destination: str, allowed: bool,
    loopback_connection: Callable[[int], socket.socket],
) -> None:
    """Exercise the real router offline; dual-stack DNS must not block public IPv4."""

    binary = os.environ.get("FLAYER_XRAY_BINARY")

    if not binary:
        pytest.skip("Set FLAYER_XRAY_BINARY to the checksum-verified pinned Xray executable")

    config = json.loads(RenderVlessServer(Profile(), SETTINGS, GenerateVlessMaterial(Profile())))
    # Static answers and local sinks exercise routing without external traffic or Reality setup.
    config.setdefault("dns", {}).update({"servers": [], "hosts": {
        "dual.example.test": ["198.51.100.20", "2001:db8::20"],
        "private.example.test": ["127.0.0.1", "2001:db8::20"],
        "metadata.example.test": "169.254.169.254",
    }})

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]

    config["inbounds"] = [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                           "settings": {"auth": "noauth"}}]
    config["outbounds"] = [
        {"tag": "internet", "protocol": "blackhole", "settings": {"response": {"type": "http"}}},
        {"tag": "blocked", "protocol": "blackhole"},
    ]
    path = tmp_path / "router.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    process = subprocess.Popen([binary, "run", "-config", str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        deadline = time.monotonic() + 5

        while True:
            try:
                connection = loopback_connection(port)
                break

            except OSError:
                assert process.poll() is None and time.monotonic() < deadline, "Xray router did not start"
                time.sleep(0.02)

        with connection, connection.makefile("rb") as stream:
            connection.sendall(b"\x05\x01\x00")
            assert stream.read(2) == b"\x05\x00", "SOCKS negotiation failed"

            if ":" in destination:
                address = b"\x04" + socket.inet_pton(socket.AF_INET6, destination)

            elif destination[0].isdigit():
                address = b"\x01" + socket.inet_aton(destination)

            else:
                encoded = destination.encode("ascii")
                address = b"\x03" + bytes([len(encoded)]) + encoded

            connection.sendall(b"\x05\x01\x00" + address + b"\x00\x50")
            response = stream.read(10)
            assert response[:2] == b"\x05\x00", "SOCKS request was rejected before routing"
            connection.sendall(b"GET / HTTP/1.0\r\n\r\n")

            try:
                received = stream.read(5)

            except (ConnectionResetError, TimeoutError):
                received = b""

            assert received.startswith(b"HTTP/") is allowed, "Xray selected the wrong destination policy"

    finally:
        process.terminate()

        try:
            process.wait(timeout=5)

        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
