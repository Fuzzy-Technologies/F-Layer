"""Encode a single owned WireGuard peer operation and validate its nonsecret SSH result."""

from __future__ import annotations

import base64
import hashlib
import json
import re

from flayer.core.contracts import _WireDict
from flayer.profiles.artifacts import ArtifactBundle
from flayer.profiles.vpn import VpnError


def _UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate envelope or descriptor fields instead of choosing an interpretation."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError

        result[key] = value

    return result


def ValidateBundle(bundle: ArtifactBundle) -> dict[str, bytes]:
    """Bind a private server role, owner and descriptor hashes to the exact supplied stack bundle."""

    try:
        if (not isinstance(bundle, ArtifactBundle) or bundle.kind != "server"
                or bundle.name != bundle.identity.stack + "-wireguard"
                or {item.name for item in bundle.files} != {"install.py", "server.conf", "deployment.json"}
                or any(not item.sensitive for item in bundle.files)):
            raise ValueError

        contents = {item.name: item.content for item in bundle.files}
        descriptor = json.loads(contents["deployment.json"], object_pairs_hook=_UniqueObject)
        owner = hashlib.sha256(json.dumps(_WireDict(bundle.identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        if (not isinstance(descriptor, dict) or type(descriptor.get("schema_version")) is not int or descriptor["schema_version"] != 1
                or descriptor.get("owner") != owner
                or descriptor.get("config_sha256") != hashlib.sha256(contents["server.conf"]).hexdigest()
                or descriptor.get("program_sha256") != hashlib.sha256(contents["install.py"]).hexdigest()):
            raise ValueError

        return contents

    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise VpnError("WireGuard maintenance requires an exact private server bundle bound to its stack owner and file hashes") from None


def EncodeRequest(
    bundle: ArtifactBundle, action: str, change: str, deviceId: str, *, allowMutation: bool, scopeConfirm: str,
    expectedReceipt: str, expectedPrevious: str, expectedHistory: str,
) -> bytes:
    """Validate consent and old proofs before packing transient driver/helper bytes around retained server intent."""

    if (not isinstance(action, str) or action not in {"status", "apply", "recover"}
            or not isinstance(change, str) or change not in {"enroll", "revoke"}
            or not isinstance(deviceId, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", deviceId) is None
            or type(allowMutation) is not bool
            or any(not isinstance(value, str) for value in (scopeConfirm, expectedReceipt, expectedPrevious, expectedHistory))):
        raise VpnError("WireGuard peer operation requires a supported action and one exact named device")

    if action == "status":
        if allowMutation or scopeConfirm or expectedReceipt or expectedPrevious or expectedHistory:
            raise VpnError("WireGuard peer status accepts no mutation consent or preconditions")

    elif (not isinstance(bundle, ArtifactBundle) or allowMutation is not True or scopeConfirm != bundle.identity.scopeId
          or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (expectedReceipt, expectedHistory))
          or (re.fullmatch(r"[0-9a-f]{64}", expectedPrevious) is None if action == "recover" else bool(expectedPrevious))):
        raise VpnError("WireGuard peer mutation requires exact scope, consent, current receipt and original history; recovery also requires the original receipt")

    contents = ValidateBundle(bundle)

    from flayer.profiles._wireguard_peer import Programs

    driver, helper = Programs()
    contents.update({"install.py": driver, "maintenance.py": helper})
    payload = json.dumps({"bundles": [{"transport": "wireguard", "files": {
        name: base64.b64encode(content).decode("ascii") for name, content in contents.items()
    }}], "wireguard_peer": {"action": action, "change": change, "device_id": deviceId, "allow_mutation": allowMutation,
                           "expected_receipt_sha256": expectedReceipt, "expected_previous_receipt_sha256": expectedPrevious,
                           "expected_history_sha256": expectedHistory}}, sort_keys=True).encode()

    if len(payload) > 4 * 1024 * 1024:
        raise VpnError("WireGuard peer request exceeds its bounded size")

    return payload


def DecodeResult(
    content: bytes, returnCode: int, bundle: ArtifactBundle, action: str, change: str, deviceId: str,
) -> dict[str, object]:
    """Accept only exact bounded status facts or a fixed mutation outcome, suppressing all other output."""

    try:
        if returnCode != 0 or not 1 <= len(content) <= 4096:
            raise ValueError

        data = json.loads(content, object_pairs_hook=_UniqueObject)

        if not isinstance(data, dict):
            raise ValueError

        if action != "status":
            if (set(data) != {"status", "outcome"} or data["status"] != "complete"
                    or data["outcome"] not in ({"committed"} if action == "apply" else {"committed", "not-applied"})):
                raise ValueError

            return data

        expected = {"status", "receipt_sha256", "previous_receipt_sha256", "deployment_sha256", "history_sha256",
                    "previous_history_sha256", "desired_deployment_sha256", "is_desired", "action", "device_id", "tools_version", "kernel_policy"}

        if (set(data) != expected or any(not isinstance(value, str) for key, value in data.items() if key != "is_desired")
                or type(data["is_desired"]) is not bool or data["status"] not in {"active", "peer-recovery-required"}
                or data["action"] != change or data["device_id"] != deviceId
                or data["tools_version"] != "1.0.20260223" or data["kernel_policy"] != "cached-named-cve-baseline"
                or any(re.fullmatch(r"[0-9a-f]{64}", data[key]) is None
                       for key in ("receipt_sha256", "deployment_sha256", "history_sha256", "desired_deployment_sha256"))
                or any(data[key] != "" and re.fullmatch(r"[0-9a-f]{64}", data[key]) is None
                       for key in ("previous_receipt_sha256", "previous_history_sha256"))
                or bool(data["previous_receipt_sha256"]) != bool(data["previous_history_sha256"])
                or data["status"] == "peer-recovery-required" and not data["previous_receipt_sha256"]
                or data["status"] == "peer-recovery-required" and (
                    data["is_desired"] and data["receipt_sha256"] == data["previous_receipt_sha256"]
                    or not data["is_desired"] and (data["receipt_sha256"] != data["previous_receipt_sha256"]
                                                  or data["history_sha256"] != data["previous_history_sha256"]))
                or data["is_desired"] != (data["deployment_sha256"] == data["desired_deployment_sha256"])
                or data["desired_deployment_sha256"] != hashlib.sha256(
                    next(item.content for item in bundle.files if item.name == "deployment.json")).hexdigest()):
            raise ValueError

        return data

    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise VpnError("WireGuard peer operation failed or returned invalid bounded status; retain the original request and inspect recovery state; private diagnostics were suppressed") from None
