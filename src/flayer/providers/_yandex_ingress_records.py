"""Retain exact bounded ingress plans for recovery without changing their original request fingerprint."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any, cast

from flayer.core.contracts import ParseIdentity, StackIdentity, _WireDict
from flayer.profiles.vpn import VpnError, VpnListener
from flayer.providers._yandex_firewall import SecurityGroupRule, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import _Decode
from flayer.providers.contracts import ProviderResource, ResourceKind, ResourceReference
from flayer.providers.lifecycle import JsonValue, ResourceSpec

MAX_PLAN_BYTES = 1024 * 1024
_MODELS = {IngressDelta, StackIdentity, ResourceSpec, SecurityGroupSnapshot, SecurityGroupRule, ProviderResource, ResourceReference, VpnListener}


def _Closed(value: object, remaining: list[int], depth: int = 0) -> None:
    """Exclude model/scalar extensions and bound recursive serialization before metadata can be published."""

    remaining[0] -= 1

    if depth > 20 or remaining[0] < 0:
        raise VpnError("Ingress plan metadata exceeds its structural bound")

    if type(value) in _MODELS:
        for item in fields(cast(Any, value)):
            _Closed(getattr(value, item.name), remaining, depth + 1)

    elif type(value) is tuple:
        for item in value:
            _Closed(item, remaining, depth + 1)

    elif value is not None and type(value) not in {str, int, bool, ResourceKind}:
        raise VpnError("Ingress plan metadata requires exact nonsecret models and primitive values")


def EncodePlan(plan: IngressDelta) -> bytes:
    """Preserve the complete original rule IDs, creation attribution and nonce; the byte hash equals Fingerprint()."""

    if type(plan) is not IngressDelta:
        raise VpnError("Ingress plan metadata requires an exact supported plan")

    _Closed(plan, [65536])
    content = (json.dumps({"schema_version": 1, "plan": _WireDict(plan)}, sort_keys=True, separators=(",", ":")) + "\n").encode()

    if len(content) > MAX_PLAN_BYTES:
        raise VpnError("Ingress plan metadata exceeds its byte bound")

    return content


def _Object(value: object, expected: set[str]) -> dict[str, Any]:
    """Reject missing and unknown fields instead of silently dropping unsupported recovery metadata."""

    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError

    return value


def _String(value: object) -> str:
    """Do not coerce numbers, booleans or containers into an identifier or policy string."""

    if type(value) is not str:
        raise ValueError

    return value


def _Strings(value: object) -> tuple[str, ...]:
    """Restore a JSON array to the original immutable string collection."""

    if not isinstance(value, list):
        raise ValueError

    return tuple(_String(item) for item in value)


def _Pairs(value: object) -> tuple[tuple[str, str], ...]:
    """Keep complete immutable label entries, leaving duplicate and provider bounds to the validated models."""

    if not isinstance(value, list) or any(not isinstance(pair, list) or len(pair) != 2 for pair in value):
        raise ValueError

    return tuple((_String(pair[0]), _String(pair[1])) for pair in value)


def _Value(value: object, depth: int = 0) -> JsonValue:
    """Restore only bounded immutable resource parameters, excluding floats and arbitrary objects."""

    if depth > 10:
        raise ValueError

    if isinstance(value, list):
        return tuple(_Value(item, depth + 1) for item in value)

    if value is None or type(value) in {str, int, bool}:
        return cast(JsonValue, value)

    raise ValueError


def _Spec(value: object) -> ResourceSpec:
    """Rehydrate the exact frozen creation specification, not a newly compiled listener plan."""

    data = _Object(value, {"logical_id", "kind", "name", "parameters", "dependencies"})
    parameters = data["parameters"]

    if not isinstance(parameters, list) or any(not isinstance(pair, list) or len(pair) != 2 for pair in parameters):
        raise ValueError

    return ResourceSpec(_String(data["logical_id"]), ResourceKind(_String(data["kind"])), _String(data["name"]),
                        tuple((_String(pair[0]), _Value(pair[1])) for pair in parameters), _Strings(data["dependencies"]))


def _Resource(value: object) -> ProviderResource:
    """Restore the complete scoped normalized resource, including every label and address field."""

    data = _Object(value, {"reference", "name", "status", "zone_id", "labels", "public_addresses"})
    reference = _Object(data["reference"], {"provider_id", "scope_id", "kind", "resource_id"})

    return ProviderResource(ResourceReference(_String(reference["provider_id"]), _String(reference["scope_id"]),
                            ResourceKind(_String(reference["kind"])), _String(reference["resource_id"])),
                            _String(data["name"]), _String(data["status"]), None if data["zone_id"] is None else _String(data["zone_id"]),
                            _Pairs(data["labels"]), _Strings(data["public_addresses"]))


def _Snapshot(value: object) -> SecurityGroupSnapshot:
    """Keep original allocated rule IDs, all source allowances, descriptions, labels and network identity."""

    data = _Object(value, {"resource", "network_id", "rules"})

    if not isinstance(data["rules"], list) or len(data["rules"]) > 64:
        raise ValueError

    rules = []

    for raw in data["rules"]:
        rule = _Object(raw, {"rule_id", "direction", "protocol", "from_port", "to_port", "ipv4_cidrs", "description", "labels"})

        if any(item is not None and type(item) is not int for item in (rule["from_port"], rule["to_port"])):
            raise ValueError

        rules.append(SecurityGroupRule(_String(rule["rule_id"]), _String(rule["direction"]), _String(rule["protocol"]),
            rule["from_port"], rule["to_port"], _Strings(rule["ipv4_cidrs"]), _String(rule["description"]), _Pairs(rule["labels"])))

    return SecurityGroupSnapshot(_Resource(data["resource"]), _String(data["network_id"]), tuple(rules))


def _Listener(value: object) -> VpnListener:
    """Retain transport attribution independently from a matching TCP/UDP port number."""

    data = _Object(value, {"transport", "protocol", "port", "source_cidrs"})

    if type(data["port"]) is not int:
        raise ValueError

    return VpnListener(_String(data["transport"]), _String(data["protocol"]), data["port"], _Strings(data["source_cidrs"]))


def DecodePlan(content: bytes) -> IngressDelta:
    """Require complete canonical versioned bytes and rerun every ownership/listener delta invariant without I/O."""

    plan = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= MAX_PLAN_BYTES:
            raise ValueError

        record = _Object(_Decode(content.decode()), {"schema_version", "plan"})

        if type(record["schema_version"]) is not int or record["schema_version"] != 1:
            raise ValueError

        data = _Object(record["plan"], {"identity", "creation_spec", "network_id", "before", "listener", "change", "operation_id",
                                      "deletion_rule_ids", "creation_listener"})
        plan = IngressDelta(ParseIdentity(data["identity"]), _Spec(data["creation_spec"]), _String(data["network_id"]), _Snapshot(data["before"]),
            _Listener(data["listener"]), _String(data["change"]), _String(data["operation_id"]), _Strings(data["deletion_rule_ids"]),
            None if data["creation_listener"] is None else _Listener(data["creation_listener"]))

        if EncodePlan(plan) != content:
            raise ValueError

    except (ValueError, TypeError, RecursionError, UnicodeError):
        plan = None

    if plan is None:
        raise VpnError("Retained ingress plan is invalid, noncanonical or outside its bounded schema")

    return plan
