"""Describe manifest-bound host input policy and one atomic owned-table delta without executing a network command."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, replace
from typing import Any

from flayer._vpn_creation import BundleDigest, CreationBaseline, _Decode, _Json
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles.vpn import VpnError, VpnListener

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_TABLE = "flayer_bootstrap"


def _Digest(content: bytes) -> str:
    """Bind exact public policy bytes without copying their contents into diagnostics."""

    return hashlib.sha256(content).hexdigest()


def _Cidrs(value: tuple[str, ...]) -> None:
    """Keep generated statements within bounded canonical IPv4 source declarations."""

    if type(value) is not tuple or not 1 <= len(value) <= 16 or any(type(item) is not str for item in value) or len(set(value)) != len(value):
        raise VpnError("Host input sources require bounded immutable unique IPv4 networks")

    try:
        networks = tuple(ipaddress.IPv4Network(item, strict=True) for item in value)

        if any(str(network) != item for network, item in zip(networks, value, strict=True)):
            raise ValueError

        if any(left.overlaps(right) for index, left in enumerate(networks) for right in networks[index + 1:]):
            raise ValueError

    except ValueError:
        raise VpnError("Host input sources require canonical nonoverlapping IPv4 networks") from None


def _CheckListener(listener: VpnListener) -> None:
    """Validate closed scalars before comparison; SSH and the unconditional DHCP-client exception are reserved."""

    if (type(listener) is not VpnListener or any(type(value) is not str for value in (listener.transport, listener.protocol))
            or type(listener.port) is not int or listener.transport not in {"amneziawg", "vless-reality", "wireguard", "openvpn"}
            or listener.protocol not in {"tcp", "udp"} or not 1 <= listener.port <= 65535
            or listener.transport in {"amneziawg", "wireguard"} and listener.protocol != "udp"
            or listener.transport == "vless-reality" and listener.protocol != "tcp"
            or (listener.protocol, listener.port) in {("tcp", 22), ("udp", 68)}):
        raise VpnError("Host input listener has unsupported, reserved or ambiguous transport semantics")

    _Cidrs(listener.sourceCidrs)


@dataclass(frozen=True, slots=True)
class InputPolicy:
    """Closed public policy projection, retaining the original creation/boot hashes independently from active listeners."""

    identity: StackIdentity
    creationSha256: str
    originalBootSha256: str
    managementCidrs: tuple[str, ...]
    listeners: tuple[VpnListener, ...]
    operationId: str = ""

    def __post_init__(self) -> None:
        """Protect SSH, transport attribution, source policy and nonsecret serialization before rendering any statement."""

        if (type(self) is not InputPolicy or type(self.identity) is not StackIdentity
                or any(type(value) is not str for value in (self.identity.project, self.identity.stack, self.identity.provider,
                                                          self.identity.scopeId, self.identity.ownerId))
                or any(type(value) is not str or _HASH.fullmatch(value) is None for value in (self.creationSha256, self.originalBootSha256))
                or type(self.operationId) is not str or self.operationId != "" and _NONCE.fullmatch(self.operationId) is None
                or type(self.listeners) is not tuple or len(self.listeners) > 4):
            raise VpnError("Host input policy requires exact public models, owned creation and operation hashes")

        _Cidrs(self.managementCidrs)

        for listener in self.listeners:
            _CheckListener(listener)

        if (len({listener.transport for listener in self.listeners}) != len(self.listeners)
                or len({(listener.protocol, listener.port) for listener in self.listeners}) != len(self.listeners)):
            raise VpnError("Host input listeners collide or repeat a configured transport")

        if not self.operationId and _Digest(self._OriginalFile()) != self.originalBootSha256:
            raise VpnError("Initial host input does not match its exact frozen boot program")

    @property
    def Marker(self) -> str:
        """Bind an overlay to the complete owner and explicit operation, retaining an untagged original table."""

        owner = _Digest(json.dumps(_WireDict(self.identity), sort_keys=True, separators=(",", ":")).encode())

        return "flayer:input:" + owner + ":" + self.operationId if self.operationId else ""

    def Record(self) -> dict[str, object]:
        """Return only closed public source/listener/hash metadata for the future guest receipt and epoch graph."""

        if type(self) is not InputPolicy:
            raise VpnError("Host input metadata cannot serialize an extended model")

        return {"schema_version": 1, **_WireDict(self)}

    def Table(self) -> bytes:
        """Render one exact input table for isolated compilation or an already authorized atomic replacement."""

        lines = ["table inet " + _TABLE + " {"]

        if self.Marker:
            lines.append('  comment "' + self.Marker + '"')

        lines.extend(["  chain input {", "    type filter hook input priority 0; policy drop;", "    ct state invalid drop",
                      "    ct state established,related accept", '    iifname "lo" accept',
                      "    udp sport 67 udp dport 68 accept", "    ip protocol icmp limit rate 10/second accept"])

        for cidr in self.managementCidrs:
            lines.append(f"    ip saddr {cidr} tcp dport 22 accept")

        for listener in self.listeners:
            for cidr in listener.sourceCidrs:
                lines.append(f"    ip saddr {cidr} {listener.protocol} dport {listener.port} accept")

        return ("\n".join([*lines, "  }", "}", ""])).encode()

    def _OriginalFile(self) -> bytes:
        """Reproduce only the historical bootstrap input file for comparison, never a live operation payload."""

        if self.operationId:
            raise VpnError("Only the original policy can describe its historical boot program")

        return b"#!/usr/sbin/nft -f\nflush ruleset\n" + self.Table()

    def BootFile(self) -> bytes:
        """Persist only an explicit overlay; Ubuntu 24.04 destroy is idempotent for this owned table at boot/reload."""

        if not self.operationId:
            raise VpnError("Replacing original boot policy requires an explicit protocol operation")

        return b"#!/usr/sbin/nft -f\ndestroy table inet flayer_bootstrap\n" + self.Table()

    def NativeFingerprint(self, content: bytes) -> str:
        """Normalize kernel handles/metainfo only, retaining all ordered rule expressions for compile/live comparison."""

        data = _DecodeNft(content)
        table = None
        chain = None
        rules = []
        metadata = 0

        if set(data) != {"nftables"} or not isinstance(data["nftables"], list) or len(data["nftables"]) > 128:
            raise VpnError("Host input observation has an unsupported bounded schema")

        for entry in data["nftables"]:
            if not isinstance(entry, dict) or len(entry) != 1:
                raise VpnError("Host input observation is ambiguous")

            if "metainfo" in entry:
                metadata += 1

                if metadata > 1 or not isinstance(entry["metainfo"], dict):
                    raise VpnError("Host input observation has ambiguous kernel metadata")

                continue

            if "add" in entry:
                entry = entry["add"]

            if not isinstance(entry, dict) or len(entry) != 1:
                raise VpnError("Host input notification is ambiguous")

            kind, raw = next(iter(entry.items()))

            if kind not in {"table", "chain", "rule"} or not isinstance(raw, dict):
                raise VpnError("Host input table contains unsupported objects")

            value = {key: item for key, item in raw.items() if key != "handle"}

            if value.get("family") != "inet" or value.get("name" if kind == "table" else "table") != _TABLE:
                raise VpnError("Host input observation crosses its exact owned table")

            if kind == "table":
                tableExpected = {"family": "inet", "name": _TABLE, **({"comment": self.Marker} if self.Marker else {})}

                if table is not None or value != tableExpected:
                    raise VpnError("Host input table ownership or generation marker differs")

                table = value

            elif kind == "chain":
                chainExpected = {"family": "inet", "table": _TABLE, "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}

                if chain is not None or value != chainExpected or type(value.get("prio")) is not int:
                    raise VpnError("Host input base chain differs from its exact protected hook and policy")

                chain = value

            else:
                if (set(value) != {"family", "table", "chain", "expr"} or value["chain"] != "input"
                        or not isinstance(value["expr"], list) or not 1 <= len(value["expr"]) <= 16):
                    raise VpnError("Host input rule shape or chain is unsupported")

                rules.append(value)

        if table is None or chain is None or not rules:
            raise VpnError("Host input observation is missing its complete table, chain or rules")

        return _Digest(_Json({"table": table, "chain": chain, "rules": rules}))


def _DecodeNft(content: bytes) -> dict[str, Any]:
    """Reject duplicate/nonstandard native JSON without retaining parser input in an exception context."""

    def Unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Require one unambiguous interpretation at each depth."""

        result: dict[str, Any] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError

            result[key] = value

        return result

    def Nonfinite(value: str) -> None:
        """Refuse Python JSON extensions that cannot be emitted by the verified compiler."""

        raise ValueError

    data = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= 1024 * 1024:
            raise ValueError

        value = json.loads(content, object_pairs_hook=Unique, parse_constant=Nonfinite)

        if not isinstance(value, dict):
            raise ValueError

        data = value

    except (ValueError, TypeError, RecursionError, UnicodeError):
        pass

    if data is None:
        raise VpnError("Host input native JSON is invalid or ambiguous")

    return data


def BindBootstrap(baseline: CreationBaseline, managementCidrs: tuple[str, ...], listeners: tuple[VpnListener, ...]) -> InputPolicy:
    """Compare against the permanent manifest-bound source, without compiling current desired cloud resources or regenerating bootstrap."""

    if (type(baseline) is not CreationBaseline or type(listeners) is not tuple
            or any(type(listener) is not VpnListener for listener in listeners)
            or tuple(listener.transport for listener in listeners) != tuple(pin.protocol for pin in baseline.protocols)
            or baseline.bundle.identity != baseline.plan.identity or baseline.bundle.kind != "server"
            or baseline.bundle.name != baseline.plan.identity.stack + "-creation"
            or {item.name for item in baseline.bundle.files} != {"creation.json", "cloud-init.json"}
            or any(item.sensitive for item in baseline.bundle.files)):
        raise VpnError("Host input requires its exact frozen creation baseline")

    raw = next(item.content for item in baseline.bundle.files if item.name == "cloud-init.json")

    if not raw.startswith(b"#cloud-config\n"):
        raise VpnError("Frozen bootstrap uses an unsupported source format")

    data = _Decode(raw.removeprefix(b"#cloud-config\n"))
    files = data.get("write_files")

    if not isinstance(files, list):
        raise VpnError("Frozen bootstrap has no verified input file")

    selected = [item for item in files if isinstance(item, dict) and item.get("path") == "/etc/nftables.conf"]

    if (len(selected) != 1 or set(selected[0]) != {"path", "owner", "permissions", "content"}
            or selected[0]["owner"] != "root:root" or selected[0]["permissions"] != "0644" or type(selected[0]["content"]) is not str):
        raise VpnError("Frozen bootstrap input ownership or file declaration is unsupported")

    return InputPolicy(baseline.plan.identity, BundleDigest(baseline.bundle), _Digest(selected[0]["content"].encode()), managementCidrs, listeners)


@dataclass(frozen=True, slots=True)
class InputTransition:
    """One listener delta with scoped live/boot programs and a rollback generation that retains consumed operation authority."""

    before: InputPolicy
    listener: VpnListener
    change: str
    operationId: str

    def __post_init__(self) -> None:
        """Reject collateral listener changes, stale generation reuse or an ambiguous source declaration."""

        if (type(self) is not InputTransition or type(self.before) is not InputPolicy or type(self.listener) is not VpnListener
                or type(self.change) is not str or self.change not in {"enable", "disable"}
                or type(self.operationId) is not str or _NONCE.fullmatch(self.operationId) is None or self.operationId == self.before.operationId):
            raise VpnError("Host input transition requires one exact owned listener change and a new operation")

        _CheckListener(self.listener)

        if (self.change == "enable" and any(item.transport == self.listener.transport for item in self.before.listeners)
                or self.change == "disable" and self.listener not in self.before.listeners):
            raise VpnError("Host input transition requires one exact owned listener change")

        self.After()

    def After(self) -> InputPolicy:
        """Preserve all unrelated listeners, source policies, SSH and frozen creation identity in their original order."""

        listeners = ((*self.before.listeners, self.listener) if self.change == "enable"
                     else tuple(item for item in self.before.listeners if item != self.listener))

        return replace(self.before, listeners=listeners, operationId=self.operationId)

    def Restored(self) -> InputPolicy:
        """Restore old access semantics while retaining the operation's new marker; never reinstate the previous generation token."""

        return replace(self.before, operationId=self.operationId)

    def LiveScript(self, *, rollback: bool = False) -> bytes:
        """Replace only the proved existing input table in one nft batch; admission and locking belong to the guest coordinator."""

        if type(rollback) is not bool:
            raise VpnError("Host input rollback selection must be explicit")

        policy = self.Restored() if rollback else self.After()

        return b"delete table inet flayer_bootstrap\n" + policy.Table()
