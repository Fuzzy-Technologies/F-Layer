"""Share closed public input-policy validation and rendering between controller and stdlib-only guest helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")


class PolicyError(ValueError):
    """A fixed public-policy diagnostic without command output or parser state."""


def Json(value: object) -> bytes:
    """Keep persisted public records canonical and compatible with the controller codec."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def Digest(content: bytes) -> str:
    """Bind complete bytes rather than an abbreviated identifier or mutable locator."""

    return hashlib.sha256(content).hexdigest()


def Cidrs(value: object) -> None:
    """Require bounded canonical disjoint IPv4 source declarations before interpolating nft input."""

    if type(value) is not list or not 1 <= len(value) <= 16 or any(type(item) is not str for item in value) or len(set(value)) != len(value):
        raise PolicyError("Host input sources require bounded unique IPv4 networks")

    try:
        networks = tuple(ipaddress.IPv4Network(item, strict=True) for item in value)

        if (any(str(network) != item for network, item in zip(networks, value, strict=True))
                or any(left.overlaps(right) for index, left in enumerate(networks) for right in networks[index + 1:])):
            raise ValueError

    except ValueError:
        raise PolicyError("Host input sources require canonical nonoverlapping IPv4 networks") from None


def Listener(value: object) -> dict[str, Any]:
    """Protect SSH/DHCP and transport attribution before any comparison or rendering."""

    if (type(value) is not dict or set(value) != {"transport", "protocol", "port", "source_cidrs"}
            or any(type(value[key]) is not str for key in ("transport", "protocol"))
            or value["transport"] not in {"amneziawg", "vless-reality", "wireguard", "openvpn"}
            or value["protocol"] not in {"tcp", "udp"} or type(value["port"]) is not int or not 1 <= value["port"] <= 65535
            or value["transport"] in {"amneziawg", "wireguard"} and value["protocol"] != "udp"
            or value["transport"] == "vless-reality" and value["protocol"] != "tcp"
            or (value["protocol"], value["port"]) in {("tcp", 22), ("udp", 68)}):
        raise PolicyError("Host input listener has unsupported, reserved or ambiguous transport semantics")

    Cidrs(value["source_cidrs"])

    return {**value, "source_cidrs": list(value["source_cidrs"])}


def Policy(value: object) -> dict[str, Any]:
    """Decode one closed public owner-bound policy without importing controller packages on the guest."""

    fields = {"schema_version", "identity", "creation_sha256", "original_boot_sha256", "management_cidrs", "listeners", "operation_id"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["identity"]) is not dict or set(value["identity"]) != {"project", "stack", "provider", "scope_id", "owner_id"}
            or any(type(item) is not str for item in value["identity"].values())
            or any(_NAME.fullmatch(value["identity"][key]) is None for key in ("project", "stack", "provider", "owner_id"))
            or not 1 <= len(value["identity"]["scope_id"]) <= 256 or any(not 33 <= ord(item) <= 126 for item in value["identity"]["scope_id"])
            or any(type(value[key]) is not str or _HASH.fullmatch(value[key]) is None for key in ("creation_sha256", "original_boot_sha256"))
            or type(value["operation_id"]) is not str or value["operation_id"] != "" and _NONCE.fullmatch(value["operation_id"]) is None
            or type(value["listeners"]) is not list or len(value["listeners"]) > 4):
        raise PolicyError("Host input policy requires exact bounded owner, creation and operation records")

    Cidrs(value["management_cidrs"])
    listeners = [Listener(item) for item in value["listeners"]]

    if (len({item["transport"] for item in listeners}) != len(listeners)
            or len({(item["protocol"], item["port"]) for item in listeners}) != len(listeners)):
        raise PolicyError("Host input listeners collide or repeat a configured transport")

    result = {**value, "identity": dict(value["identity"]), "management_cidrs": list(value["management_cidrs"]), "listeners": listeners}

    if not result["operation_id"] and Digest(Boot(result)) != result["original_boot_sha256"]:
        raise PolicyError("Initial host input does not match its exact frozen boot program")

    return result


def Owner(value: dict[str, Any]) -> str:
    """Match the permanent full-owner digest used by all guest protocol backends."""

    return Digest(json.dumps(value["identity"], sort_keys=True, separators=(",", ":")).encode())


def Marker(value: dict[str, Any]) -> str:
    """Keep the historical input table untagged and bind overlays to a full owner and operation."""

    return "flayer:input:" + Owner(value) + ":" + value["operation_id"] if value["operation_id"] else ""


def Table(value: dict[str, Any]) -> bytes:
    """Render only the fixed owned table from already validated public policy."""

    lines = ["table inet flayer_bootstrap {"]

    if Marker(value):
        lines.append('  comment "' + Marker(value) + '"')

    lines.extend(["  chain input {", "    type filter hook input priority 0; policy drop;", "    ct state invalid drop",
                  "    ct state established,related accept", '    iifname "lo" accept',
                  "    udp sport 67 udp dport 68 accept", "    ip protocol icmp limit rate 10/second accept"])

    for cidr in value["management_cidrs"]:
        lines.append(f"    ip saddr {cidr} tcp dport 22 accept")

    for listener in value["listeners"]:
        for cidr in listener["source_cidrs"]:
            lines.append(f"    ip saddr {cidr} {listener['protocol']} dport {listener['port']} accept")

    return ("\n".join([*lines, "  }", "}", ""])).encode()


def Boot(value: dict[str, Any]) -> bytes:
    """Render original bytes only for comparison, and overlay bytes with an idempotent owned-table replacement."""

    prefix = b"destroy table inet flayer_bootstrap\n" if value["operation_id"] else b"flush ruleset\n"

    return b"#!/usr/sbin/nft -f\n" + prefix + Table(value)


def Transition(value: object) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Resolve exactly one listener change and a rollback that consumes the same new generation."""

    if (type(value) is not dict or set(value) != {"schema_version", "before", "listener", "change", "operation_id"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["change"]) is not str or value["change"] not in {"enable", "disable"}
            or type(value["operation_id"]) is not str or _NONCE.fullmatch(value["operation_id"]) is None):
        raise PolicyError("Host input transition requires one exact listener change and operation")

    before, listener = Policy(value["before"]), Listener(value["listener"])

    if (value["operation_id"] == before["operation_id"]
            or value["change"] == "enable" and any(item["transport"] == listener["transport"] for item in before["listeners"])
            or value["change"] == "disable" and listener not in before["listeners"]):
        raise PolicyError("Host input transition requires one exact owned listener change and a fresh operation")

    listeners = ([*before["listeners"], listener] if value["change"] == "enable" else [item for item in before["listeners"] if item != listener])
    after = Policy({**before, "operation_id": value["operation_id"], "listeners": listeners})
    restored = Policy({**before, "operation_id": value["operation_id"]})

    return before, after, restored


def Decode(content: bytes) -> dict[str, Any]:
    """Reject duplicate/nonstandard bounded JSON without retaining parser input in exception context."""

    def Unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Require one interpretation of every nested public record."""

        result: dict[str, Any] = {}

        for key, item in pairs:
            if key in result:
                raise ValueError

            result[key] = item

        return result

    def Nonfinite(value: str) -> None:
        """Reject JSON extensions that the verified compiler cannot emit."""

        raise ValueError

    data = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= 1024 * 1024:
            raise ValueError

        parsed = json.loads(content, object_pairs_hook=Unique, parse_constant=Nonfinite)

        if not isinstance(parsed, dict):
            raise ValueError

        data = parsed

    except (ValueError, TypeError, RecursionError, UnicodeError):
        pass

    if data is None:
        raise PolicyError("Host input native JSON is invalid or ambiguous")

    return data


def NativeFingerprint(value: dict[str, Any], content: bytes) -> str:
    """Normalize handles/metainfo only; equality still requires the separately isolated compiled expected table."""

    data = Decode(content)
    table = None
    chain = None
    rules = []
    metadata = 0

    if set(data) != {"nftables"} or not isinstance(data["nftables"], list) or len(data["nftables"]) > 128:
        raise PolicyError("Host input observation has an unsupported bounded schema")

    for entry in data["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise PolicyError("Host input observation is ambiguous")

        if "metainfo" in entry:
            metadata += 1

            if metadata > 1 or not isinstance(entry["metainfo"], dict):
                raise PolicyError("Host input observation has ambiguous kernel metadata")

            continue

        if "add" in entry:
            entry = entry["add"]

        if not isinstance(entry, dict) or len(entry) != 1:
            raise PolicyError("Host input notification is ambiguous")

        kind, raw = next(iter(entry.items()))

        if kind not in {"table", "chain", "rule"} or not isinstance(raw, dict):
            raise PolicyError("Host input table contains unsupported objects")

        item = {key: value for key, value in raw.items() if key != "handle"}

        if item.get("family") != "inet" or item.get("name" if kind == "table" else "table") != "flayer_bootstrap":
            raise PolicyError("Host input observation crosses its exact owned table")

        if kind == "table":
            expected: dict[str, Any] = {"family": "inet", "name": "flayer_bootstrap", **({"comment": Marker(value)} if Marker(value) else {})}

            if table is not None or item != expected:
                raise PolicyError("Host input table ownership or generation marker differs")

            table = item

        elif kind == "chain":
            expected = {"family": "inet", "table": "flayer_bootstrap", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}

            if chain is not None or item != expected or type(item.get("prio")) is not int:
                raise PolicyError("Host input base chain differs from its exact protected hook and policy")

            chain = item

        else:
            if (set(item) != {"family", "table", "chain", "expr"} or item["chain"] != "input"
                    or not isinstance(item["expr"], list) or not 1 <= len(item["expr"]) <= 16):
                raise PolicyError("Host input rule shape or chain is unsupported")

            rules.append(item)

    if table is None or chain is None or not rules:
        raise PolicyError("Host input observation is missing its complete table, chain or rules")

    return Digest(Json({"table": table, "chain": chain, "rules": rules}))
