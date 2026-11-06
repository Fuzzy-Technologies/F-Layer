"""Plan exact owned listener deltas without dispatching a cloud command or inferring API atomicity."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass

from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles.vpn import VpnListener
from flayer.providers._yandex_firewall import (
    ExpectedRules,
    SecurityGroupRule,
    SecurityGroupSnapshot,
)
from flayer.providers.contracts import ResourceKind
from flayer.providers.lifecycle import ResourceSpec


def _Digest(value: object) -> str:
    """Bind complete normalized nonsecret metadata, including provider IDs and rule labels."""

    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def _RuleBody(rule: SecurityGroupRule) -> dict[str, object]:
    """Compare all rule metadata while allowing only a newly allocated provider identifier to differ."""

    return {key: value for key, value in _WireDict(rule).items() if key != "rule_id"}


def _Covers(rule: SecurityGroupRule, listener: VpnListener) -> bool:
    """Detect any existing ingress allowance on the target port, including broader protocols or ranges."""

    return (rule.direction == "ingress" and rule.protocol in {"any", listener.protocol}
            and (rule.fromPort is None or rule.toPort is not None and rule.fromPort <= listener.port <= rule.toPort))


@dataclass(frozen=True, slots=True)
class IngressDelta:
    """One validated listener addition/removal against a complete frozen owned security-group observation."""

    identity: StackIdentity
    creationSpec: ResourceSpec
    networkId: str
    before: SecurityGroupSnapshot
    listener: VpnListener
    change: str
    operationId: str
    deletionRuleIds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Refuse unknown ownership, collateral rules, open target ports and incomplete listener removals."""

        if (not isinstance(self.identity, StackIdentity) or self.identity.provider != "yandex-cloud"
                or not isinstance(self.creationSpec, ResourceSpec) or self.creationSpec.kind != ResourceKind.SECURITY_GROUP
                or self.creationSpec.logicalId != "firewall" or self.creationSpec.name != self.identity.stack + "-firewall"
                or not isinstance(self.before, SecurityGroupSnapshot) or not isinstance(self.listener, VpnListener)
                or not isinstance(self.change, str) or self.change not in {"enable", "disable"}
                or not isinstance(self.operationId, str) or re.fullmatch(r"[0-9a-f]{32}", self.operationId) is None
                or self.listener.transport not in {"amneziawg", "vless-reality", "wireguard", "openvpn"}
                or self.listener.transport in {"amneziawg", "wireguard"} and self.listener.protocol != "udp"
                or self.listener.transport == "vless-reality" and self.listener.protocol != "tcp"
                or self.listener.protocol == "tcp" and self.listener.port == 22
                or not isinstance(self.deletionRuleIds, tuple) or len(self.deletionRuleIds) > 32
                or any(not isinstance(value, str) for value in self.deletionRuleIds)
                or len(set(self.deletionRuleIds)) != len(self.deletionRuleIds)):
            raise ValueError("Ingress delta requires one supported listener, exact operation and frozen creation identity")

        self._Owner(self.before)
        covering = tuple(rule for rule in self.before.rules if _Covers(rule, self.listener))

        if self.change == "enable":
            if self.deletionRuleIds or covering or len(self.before.rules) >= 64:
                raise ValueError("Protocol enable requires a closed target port, capacity and no rule deletions")

        else:
            if not self.deletionRuleIds or {rule.ruleId for rule in covering} != set(self.deletionRuleIds):
                raise ValueError("Protocol disable must remove exactly all owned allowances for its target port")

            original = {_Digest(_RuleBody(rule)) for rule in ExpectedRules(self.creationSpec)}
            prefix = "flayer:" + self.Owner + ":" + self.listener.transport + ":"

            for rule in covering:
                if (rule.protocol != self.listener.protocol or rule.fromPort != self.listener.port or rule.toPort != self.listener.port
                        or rule.labels or (_Digest(_RuleBody(rule)) not in original
                                          and re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}", rule.description) is None)):
                    raise ValueError("Protocol disable cannot remove a broad, annotated or unproved listener rule")

            if Counter(cidr for rule in covering for cidr in rule.ipv4Cidrs) != Counter(self.listener.sourceCidrs):
                raise ValueError("Protocol disable requires its complete exact source policy without duplicate allowances")

        object.__setattr__(self, "deletionRuleIds", tuple(sorted(self.deletionRuleIds)))

    def _Owner(self, snapshot: SecurityGroupSnapshot) -> None:
        """Bind active policy to the original resource, folder, network and complete creation labels."""

        resource = snapshot.resource

        if (resource.reference.providerId != self.identity.provider or resource.reference.scopeId != self.identity.scopeId
                or resource.name != self.creationSpec.name or resource.status != "ACTIVE"
                or not resource.HasLabels(self.creationSpec.OwnershipLabels(self.identity)) or snapshot.networkId != self.networkId):
            raise ValueError("Ingress policy is inactive or outside its exact frozen ownership and network")

    @property
    def Owner(self) -> str:
        """Derive a bounded full-identity tag without relying on a local project name alone."""

        return hashlib.sha256(json.dumps(_WireDict(self.identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    @property
    def BeforeSha256(self) -> str:
        """Identify every original rule and resource field, preserving IDs, descriptions and labels."""

        return _Digest(_WireDict(self.before))

    @property
    def Addition(self) -> SecurityGroupRule | None:
        """Describe the sole addition with an explicitly provisional identifier, never an observed provider ID."""

        if self.change != "enable":
            return None

        return SecurityGroupRule("planned-" + self.operationId, "ingress", self.listener.protocol, self.listener.port, self.listener.port,
                                 self.listener.sourceCidrs, "flayer:" + self.Owner + ":" + self.listener.transport + ":" + self.operationId)

    def CheckBefore(self, snapshot: SecurityGroupSnapshot) -> None:
        """Require a fresh complete expected-old observation immediately before a separately authorized writer."""

        if not isinstance(snapshot, SecurityGroupSnapshot):
            raise ValueError("Ingress preflight requires a complete supported snapshot")

        self._Owner(snapshot)

        if snapshot != self.before:
            raise ValueError("Ingress changed after planning; no mutation may be submitted")

    def ValidateResult(self, snapshot: SecurityGroupSnapshot) -> tuple[str, ...]:
        """Prove complete readback and return newly allocated IDs without accepting unrelated collateral changes."""

        if not isinstance(snapshot, SecurityGroupSnapshot):
            raise ValueError("Ingress result requires a complete supported snapshot")

        self._Owner(snapshot)

        if snapshot.resource != self.before.resource:
            raise ValueError("Ingress result changed original resource metadata")

        old = {rule.ruleId: rule for rule in self.before.rules}
        retained = {key: rule for key, rule in old.items() if key not in self.deletionRuleIds}
        actual = {rule.ruleId: rule for rule in snapshot.rules}
        added = tuple(sorted(set(actual) - set(old)))

        if any(actual.get(key) != rule for key, rule in retained.items()) or any(key in actual for key in self.deletionRuleIds):
            raise ValueError("Ingress result changed an unrelated rule or retained a removed allowance")

        addition = self.Addition

        if (set(actual) != set(retained) | set(added) or len(added) != (1 if addition is not None else 0)
                or addition is not None and (added[0] == addition.ruleId or _RuleBody(actual[added[0]]) != _RuleBody(addition))):
            raise ValueError("Ingress result differs from its sole exact planned listener delta")

        return added
