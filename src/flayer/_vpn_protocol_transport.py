"""Carry fixed protocol RPC operations through the existing host-pinned SSH provisioner without changing its network policy."""

from __future__ import annotations

import base64
import shlex
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from flayer import _vpn_protocol_receiver as receiver
from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_preparation as preparation
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_rpc as rpc
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _protocol_services as services
from flayer.profiles import _wireguard_generation as generationTools
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles.vless import LEGACY_XRAY_VERSION, XRAY_VERSION
from flayer.profiles.vpn import VpnError

if TYPE_CHECKING:
    from flayer.guest import SshGuestProvisioner


def _Codecs() -> SimpleNamespace:
    """Use only pure package-selected validators on the controller, including Windows diagnostics without importing POSIX guest entrypoints."""

    versions = SimpleNamespace(XRAY_VERSION=XRAY_VERSION, LEGACY_VERSION=LEGACY_XRAY_VERSION)

    return SimpleNamespace(guest=guest, authority=authority, policy=policy, inputs=inputs, cache=cache, runtime=runtime,
                           completion=completion, services=services, vless=versions, preparation=preparation, tools=generationTools)


def Encode(operation: object) -> tuple[bytes, bytes]:
    """Validate explicit consent and every closed operation/source model before packing checksum-pinned executable dependencies."""

    result = None

    try:
        rpc.Request(_Codecs(), operation)
        bootstrap, programs = receiver.Programs()
        content = rpc.Json({"schema_version": 1, "operation": operation,
                            "programs": {name: base64.b64encode(source).decode("ascii") for name, source in programs.items()}})

        if len(content) > receiver.MAX_REQUEST_BYTES:
            raise ValueError

        result = bootstrap, content

    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass

    if result is None:
        raise VpnError("Protocol SSH operation requires exact scope, consent, ownership and complete retained evidence")

    return result


def Decode(operation: object, content: bytes, returnCode: int) -> dict[str, Any]:
    """Accept only action-bound closed public facts; suppress every other byte, including raw native or SSH diagnostics."""

    result = None

    try:
        expected = rpc.Request(_Codecs(), operation)

        if type(returnCode) is not int or returnCode != 0:
            raise ValueError

        value = rpc.Decode(content, limit=rpc.MAX_RESULT_BYTES + 256)

        if (set(value) != {"schema_version", "action", "request_sha256", "result"} or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["action"] != expected["action"] or value["request_sha256"] != receiver.Fingerprint(operation, receiver.Sources())):
            raise ValueError

        result = rpc.Result(_Codecs(), expected, value["result"])

    except (ValueError, TypeError, UnicodeError, RecursionError, KeyError):
        pass

    if result is None:
        raise VpnError("Protocol SSH operation failed or returned invalid public facts; retain its exact journal and inspect explicit recovery state; private output was suppressed")

    return result


def Execute(provisioner: SshGuestProvisioner, operation: object) -> dict[str, Any]:
    """Reuse the independently pinned actual IPv4 SSH route; no proxy, adapter, DNS or local VPN setting is changed."""

    bootstrap, content = Encode(operation)
    command = "sudo -n /usr/bin/python3 -c " + shlex.quote(bootstrap.decode("utf-8"))
    result = provisioner.runner.Run((*provisioner.command, command), content, 900)

    return Decode(operation, result.stdout, result.returnCode)
