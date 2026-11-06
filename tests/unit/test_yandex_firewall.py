"""Exercise complete effective policy parsing with synthetic public cloud observations."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import (
    ParseSecurityGroup,
    RuleSemantics,
    SecurityGroupRule,
    SecurityGroupSnapshot,
)
from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import ResourceSpec
from flayer.providers.yandex import YandexCloudSettings
from flayer.vpn_project import VpnYandexProvider


def Resource() -> ProviderResource:
    """Use documentation-only scope and resource IDs without calling a provider."""

    return ProviderResource(ResourceReference("yandex-cloud", "example-folder", ResourceKind.SECURITY_GROUP, "example-group"),
                            "gateway-firewall", "UNKNOWN")


def Payload() -> dict[str, Any]:
    """Mirror the documented CLI snake_case response, including int64 JSON string ports."""

    return {"id": "example-group", "folder_id": "example-folder", "network_id": "example-network", "rules": [
        {"id": "rule-admin", "direction": "INGRESS", "protocol_name": "TCP", "protocol_number": "6",
         "ports": {"from_port": "22", "to_port": "22"}, "cidr_blocks": {"v4_cidr_blocks": ["198.51.100.42/32"]}},
        {"id": "rule-egress", "direction": "EGRESS", "protocol_name": "ANY", "protocol_number": "-1",
         "cidr_blocks": {"v4_cidr_blocks": ["0.0.0.0/0"], "v6_cidr_blocks": []}},
    ]}


def test_DocumentedPolicyRetainsRuleIdentityAndCompleteNetworkBinding() -> None:
    """Equivalent field encodings preserve policy without discarding IDs needed for later bounded mutations."""

    original = Payload()
    snapshot = ParseSecurityGroup(original, Resource())
    changed = copy.deepcopy(original)
    changed["rules"].reverse()
    changed["rules"][0]["ports"] = {"from_port": "0", "to_port": "65535"}
    changed["rules"][1]["ports"] = {"from_port": 22, "to_port": 22}
    changed["rules"][1]["protocol_name"] = None

    assert ParseSecurityGroup(changed, Resource()) == snapshot
    assert snapshot.networkId == "example-network" and snapshot.rules[0].ruleId == "rule-admin"
    assert snapshot.rules[0].fromPort == snapshot.rules[0].toPort == 22


@pytest.mark.parametrize("fault", ["scope", "id", "network", "rules", "duplicate", "direction", "protocol", "number",
                                  "ipv6", "group-target", "predefined", "unknown", "ports", "boolean", "leading-zero", "reversed", "cidr", "description"])
def test_UnsupportedOrAmbiguousEffectivePolicyCannotBeAdopted(fault: str) -> None:
    """Reject hidden targets, unknown fields and alternate numerical syntax before comparison or deletion."""

    data = Payload()
    rule = data["rules"][0]

    if fault in {"scope", "id", "network", "rules"}:
        key, value = {"scope": ("folder_id", "other-folder"), "id": ("id", "other-group"),
                      "network": ("network_id", None), "rules": ("rules", {})}[fault]
        data[key] = value

    elif fault == "duplicate":
        data["rules"].append(copy.deepcopy(rule))

    elif fault == "ipv6":
        rule["cidr_blocks"]["v6_cidr_blocks"] = ["::/0"]

    elif fault == "cidr":
        rule["cidr_blocks"]["v4_cidr_blocks"] = ["198.51.100.42/24"]

    elif fault in {"direction", "protocol", "number", "group-target", "predefined", "unknown", "description"}:
        key, value = {"direction": ("direction", "FORWARD"), "protocol": ("protocol_name", "ICMP"),
                      "number": ("protocol_number", "17"), "group-target": ("security_group_id", "other-group"),
                      "predefined": ("predefined_target", "self_security_group"), "unknown": ("action", "allow"),
                      "description": ("description", "bad\nvalue")}[fault]
        rule[key] = value

    else:
        rule["ports"] = {"ports": [], "boolean": {"from_port": True, "to_port": "22"},
                         "leading-zero": {"from_port": "022", "to_port": "22"},
                         "reversed": {"from_port": "23", "to_port": "22"}}[fault]

    with pytest.raises(ValueError):
        ParseSecurityGroup(data, Resource())


def test_ComparisonPreservesMultiplicityDescriptionAndPolicyDespiteDifferentProviderIds() -> None:
    """A duplicate or annotated rule cannot disappear through set-based comparison."""

    rules = ParseSecurityGroup(Payload(), Resource()).rules

    assert RuleSemantics(rules) == RuleSemantics(tuple(replace(rule, ruleId="new-" + rule.ruleId) for rule in rules))
    assert RuleSemantics(rules) != RuleSemantics((*rules, replace(rules[0], ruleId="duplicate")))
    assert RuleSemantics(rules) != RuleSemantics((replace(rules[0], description="external"), *rules[1:]))
    assert RuleSemantics(rules) != RuleSemantics((replace(rules[0], labels=(("purpose", "external"),)), *rules[1:]))

    with pytest.raises(ValueError):
        SecurityGroupSnapshot(Resource(), "example-network", (rules[0], rules[0]))

    with pytest.raises(ValueError):
        SecurityGroupRule("rule", "ingress", "udp", 100, None, ("0.0.0.0/0",))


def test_DocumentedOptionalRuleLabelsRemainCompleteAndDeterministic() -> None:
    """Observe exact bounded label metadata without dropping it from ownership snapshots or policy comparisons."""

    payload = Payload()
    payload["rules"][0]["labels"] = {"z-purpose": "admin", "a.path/@": ""}
    snapshot = ParseSecurityGroup(payload, Resource())

    assert snapshot.rules[0].labels == (("a.path/@", ""), ("z-purpose", "admin"))
    assert ParseSecurityGroup(Payload(), Resource()).rules[0].labels == ()
    payload["rules"][0]["labels"] = {"a.path/@": "", "z-purpose": "admin"}
    assert ParseSecurityGroup(payload, Resource()) == snapshot


@pytest.mark.parametrize("labels", [None, [], "invalid", {"UPPER": "value"}, {"a": "UPPER"}, {"a": 1}, {1: "value"},
                                   {"a" * 64: "value"}, {"a": "v" * 64}, {"a": "line\nbreak"},
                                   {"key" + str(index): "value" for index in range(65)}])
def test_InvalidOrUnboundedRuleLabelsFailClosed(labels: Any) -> None:
    """Provider metadata must not bypass its documented structural, count, name or length bounds."""

    payload = Payload()
    payload["rules"][0]["labels"] = labels

    with pytest.raises(ValueError):
        ParseSecurityGroup(payload, Resource())


@pytest.mark.parametrize("labels", [{"purpose": "admin"}, (("purpose", "admin"), ("purpose", "other")), (("purpose",),), (("purpose", []),)])
def test_DirectRuleConstructionRequiresImmutableUniqueLabels(labels: Any) -> None:
    """Direct dataclass callers cannot evade the same validated immutable metadata contract."""

    with pytest.raises(ValueError):
        SecurityGroupRule("rule", "ingress", "udp", 100, 100, ("0.0.0.0/0",), labels=labels)


def test_AdapterReadsPolicyFromTheSameScopedIdAndRefusesChangedOwnership(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the actual normalization path with a fully isolated JSON command boundary."""

    provider = VpnYandexProvider(YandexCloudSettings("example-folder", "fixture-profile"))
    calls = []
    resource = replace(Resource(), labels=(("flayer-spec", "a" * 63),))
    payload = {**Payload(), "name": resource.name, "labels": dict(resource.labels)}

    def Read(command: tuple[str, ...], operation: str) -> dict[str, Any]:
        """Return synthetic public metadata, never invoke the CLI or cloud."""

        calls.append(command)

        return payload

    monkeypatch.setattr(provider, "_ReadJson", Read)

    assert provider.ReadSecurityGroupRules(resource).networkId == "example-network"
    assert calls == [("vpc", "security-group", "get", "--id", "example-group")]
    payload["labels"] = {"flayer-spec": "b" * 63}

    with pytest.raises(VpnError, match="ownership changed"):
        provider.ReadSecurityGroupRules(resource)


@pytest.mark.parametrize("fault", ["none", "labels", "name", "operation"])
def test_CreationDeletionRechecksExactSpecAndOperationBeforeIdBoundDispatch(
    monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """Exercise the real deletion guard with an exact in-memory resource and command recorder."""

    identity = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
    spec = ResourceSpec("network", ResourceKind.NETWORK, "gateway-network")
    resource = ProviderResource(ResourceReference("yandex-cloud", "example-folder", ResourceKind.NETWORK, "example-network"),
                                spec.name, labels=(*spec.OwnershipLabels(identity), ("flayer-operation", "a" * 32)))
    current = resource

    if fault == "labels":
        current = replace(resource, labels=tuple((key, "b" * 63 if key == "flayer-spec" else value) for key, value in resource.labels))

    elif fault == "name":
        current = replace(resource, name="other-network")

    elif fault == "operation":
        current = replace(resource, labels=tuple((key, "b" * 32 if key == "flayer-operation" else value) for key, value in resource.labels))

    provider = VpnYandexProvider(YandexCloudSettings("example-folder", "fixture-profile"))
    calls = []

    def Get(reference: ResourceReference) -> ProviderResource:
        """Confirm absence only after the recorded fake deletion dispatch."""

        assert reference == resource.reference

        if calls:
            raise ProviderError(ProviderErrorCode.NOT_FOUND, "fixture-get")

        return current

    monkeypatch.setattr(provider, "GetResource", Get)
    monkeypatch.setattr(provider, "_MutationRun", lambda command, operation: calls.append(command))

    if fault != "none":
        with pytest.raises(ProviderError):
            provider.DeleteCreationResource(resource, spec, identity, operationId="a" * 32)

        assert not calls

    else:
        provider.DeleteCreationResource(resource, spec, identity, operationId="a" * 32)

        assert calls == [("vpc", "network", "delete", "--id", "example-network")]
