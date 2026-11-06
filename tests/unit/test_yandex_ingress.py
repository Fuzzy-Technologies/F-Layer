"""Prove exact listener deltas with synthetic immutable cloud policy and no provider or network calls."""

from __future__ import annotations

from dataclasses import replace

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnListener
from flayer.providers._yandex_firewall import SecurityGroupRule, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers.contracts import ProviderResource, ResourceKind, ResourceReference
from flayer.providers.lifecycle import ResourceSpec


def Policy() -> tuple[StackIdentity, ResourceSpec, SecurityGroupSnapshot]:
    """Represent one frozen original group with administration, two live transports and egress."""

    identity = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
    fields = (("direction", "ingress"), ("protocol", "udp"), ("from_port", 51820), ("to_port", 51820), ("cidr", "0.0.0.0/0"))
    spec = ResourceSpec("firewall", ResourceKind.SECURITY_GROUP, "gateway-firewall", (("rules", (fields,)),), ("network",))
    resource = ProviderResource(ResourceReference("yandex-cloud", "example-folder", ResourceKind.SECURITY_GROUP, "example-group"),
                                spec.name, "ACTIVE", labels=spec.OwnershipLabels(identity))
    rules = (SecurityGroupRule("admin", "ingress", "tcp", 22, 22, ("198.51.100.42/32",)),
             SecurityGroupRule("awg", "ingress", "udp", 51820, 51820, ("0.0.0.0/0",)),
             SecurityGroupRule("vless", "ingress", "tcp", 443, 443, ("0.0.0.0/0",)),
             SecurityGroupRule("egress", "egress", "any", None, None, ("0.0.0.0/0",), labels=(("purpose", "egress"),)))

    return identity, spec, SecurityGroupSnapshot(resource, "example-network", rules)


def Plan() -> IngressDelta:
    """Plan the new independent WireGuard UDP listener without touching AWG or VLESS."""

    identity, spec, before = Policy()

    return IngressDelta(identity, spec, "example-network", before,
                        VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)), "enable", "a" * 32)


def Result(plan: IngressDelta) -> SecurityGroupSnapshot:
    """Independently model a provider allocating an actual rule ID for the one requested addition."""

    addition = plan.Addition
    assert addition is not None

    return replace(plan.before, rules=(*plan.before.rules, replace(addition, ruleId="provider-new-rule")))


def test_EnableHasOneOwnedAdditionAndPreservesTheCompleteOriginalGraphAndOtherRules() -> None:
    """The proof includes metadata and IDs; no cloud writer, bootstrap or key generation is invoked."""

    plan = Plan()
    before = plan.before
    creation = plan.creationSpec
    plan.CheckBefore(before)
    addition = plan.Addition

    assert addition is not None and addition.protocol == "udp" and addition.fromPort == addition.toPort == 51821
    assert addition.ipv4Cidrs == ("0.0.0.0/0",) and not plan.deletionRuleIds
    assert addition.description == "flayer:" + plan.Owner + ":wireguard:" + "a" * 32
    assert plan.ValidateResult(Result(plan)) == ("provider-new-rule",)
    assert plan.before == before and plan.creationSpec == creation and len(plan.BeforeSha256) == 64
    assert Plan().BeforeSha256 == plan.BeforeSha256 and plan.Addition == addition


@pytest.mark.parametrize("fault", ["resource-id", "folder", "provider", "name", "labels", "status", "network",
                                  "rule-id", "source", "description", "rule-label", "extra-rule"])
def test_EveryExpectedOldFieldIsRecheckedBeforeAWriterCouldSubmit(fault: str) -> None:
    """Equivalent-looking permissions cannot hide changed scope, labels, descriptions, IDs or extra policy."""

    plan = Plan()
    snapshot = plan.before
    resource = snapshot.resource

    if fault in {"resource-id", "folder", "provider"}:
        reference = replace(resource.reference, **{"resourceId": "other-group"} if fault == "resource-id" else
                            {"scopeId": "other-folder"} if fault == "folder" else {"providerId": "other-provider"})
        snapshot = replace(snapshot, resource=replace(resource, reference=reference))

    elif fault in {"name", "labels", "status"}:
        snapshot = replace(snapshot, resource=replace(resource, **{"name": "other-firewall"} if fault == "name" else
                           {"labels": ()} if fault == "labels" else {"status": "UPDATING"}))

    elif fault == "network":
        snapshot = replace(snapshot, networkId="other-network")

    elif fault == "extra-rule":
        snapshot = replace(snapshot, rules=(*snapshot.rules, SecurityGroupRule("extra", "ingress", "udp", 9000, 9000, ("0.0.0.0/0",))))

    else:
        original = snapshot.rules[0]
        options = {"rule-id": {"ruleId": "new-admin"}, "source": {"ipv4Cidrs": ("0.0.0.0/0",)},
                   "description": {"description": "changed"}, "rule-label": {"labels": (("purpose", "changed"),)}}[fault]
        snapshot = replace(snapshot, rules=(replace(original, **options), *snapshot.rules[1:]))

    with pytest.raises(ValueError):
        plan.CheckBefore(snapshot)

    if fault in {"resource-id", "rule-id", "source", "description", "rule-label", "extra-rule"}:
        assert replace(plan, before=snapshot).BeforeSha256 != plan.BeforeSha256


@pytest.mark.parametrize("fault", ["missing-addition", "extra-addition", "changed-admin", "renamed-admin", "lost-egress-label",
                                  "wrong-tag", "extra-new-label", "wrong-source", "wrong-port", "wrong-protocol", "provisional-id"])
def test_ResultRequiresTheSoleCompleteDeltaAndEveryUnrelatedRuleUnchanged(fault: str) -> None:
    """A superficially successful API response is not proof that its entire resulting policy is the planned one."""

    plan = Plan()
    result = Result(plan)
    rules = list(result.rules)
    index = next(index for index, rule in enumerate(rules) if rule.ruleId == "provider-new-rule")

    if fault == "missing-addition":
        rules.pop(index)

    elif fault == "extra-addition":
        rules.append(SecurityGroupRule("foreign-new", "ingress", "tcp", 9000, 9000, ("0.0.0.0/0",)))

    elif fault in {"changed-admin", "renamed-admin", "lost-egress-label"}:
        index = next(index for index, rule in enumerate(rules) if rule.ruleId == ("egress" if fault == "lost-egress-label" else "admin"))
        rules[index] = replace(rules[index], **{"labels": ()} if fault == "lost-egress-label" else
                               {"ruleId": "admin-renamed"} if fault == "renamed-admin" else {"ipv4Cidrs": ("0.0.0.0/0",)})

    else:
        addition = plan.Addition
        assert addition is not None
        options = {"wrong-tag": {"description": "foreign"}, "extra-new-label": {"labels": (("purpose", "unexpected"),)},
                   "wrong-source": {"ipv4Cidrs": ("198.51.100.0/24",)}, "wrong-port": {"fromPort": 51822, "toPort": 51822},
                   "wrong-protocol": {"protocol": "tcp"}, "provisional-id": {"ruleId": addition.ruleId}}[fault]
        rules[index] = replace(rules[index], **options)

    with pytest.raises(ValueError):
        plan.ValidateResult(replace(result, rules=tuple(rules)))


@pytest.mark.parametrize("fault", ["resource-id", "additional-label", "network", "updating"])
def test_ReadbackRejectsConcurrentResourceDriftAndUnfinishedProviderPolicy(fault: str) -> None:
    """An exact-looking new rule cannot prove completion while the group or its original metadata is different."""

    plan = Plan()
    result = Result(plan)
    resource = result.resource

    if fault == "network":
        result = replace(result, networkId="other-network")

    else:
        resource = (replace(resource, reference=replace(resource.reference, resourceId="other-group")) if fault == "resource-id" else
                    replace(resource, labels=(*resource.labels, ("external", "new"))) if fault == "additional-label" else
                    replace(resource, status="UPDATING"))
        result = replace(result, resource=resource)

    with pytest.raises(ValueError):
        plan.ValidateResult(result)


def test_EnableRequiresProviderRuleCapacity() -> None:
    """Reject an addition that would exceed the bounded complete provider policy contract."""

    plan = Plan()
    extra = tuple(SecurityGroupRule("extra-" + str(index), "egress", "tcp", index + 1000, index + 1000, ("0.0.0.0/0",)) for index in range(60))

    with pytest.raises(ValueError, match="capacity"):
        replace(plan, before=replace(plan.before, rules=(*plan.before.rules, *extra)))


def test_DisableOriginalCreationRuleRetainsSshOtherTransportAndAnnotatedEgress() -> None:
    """The first removal can use a proved original creation allowance whose description is empty."""

    identity, spec, before = Policy()
    listener = VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))
    plan = IngressDelta(identity, spec, before.networkId, before,
                        listener, "disable", "b" * 32, ("awg",), creationListener=listener)
    result = replace(before, rules=tuple(rule for rule in before.rules if rule.ruleId != "awg"))

    assert plan.Addition is None and plan.ValidateResult(result) == ()
    assert {rule.ruleId for rule in result.rules} == {"admin", "vless", "egress"}
    assert plan.before == before and before.resource.labels == spec.OwnershipLabels(identity)

    with pytest.raises(ValueError):
        plan.ValidateResult(before)


@pytest.mark.parametrize("transport", ["wireguard", "openvpn", "amneziawg"])
@pytest.mark.parametrize("binding", ["missing", "original-awg"])
def test_OriginalRuleCannotBeAttributedToAProtocolFromPortSemanticsAlone(transport: str, binding: str) -> None:
    """The frozen generic cloud spec has no transport names; require an independently attested original protocol role."""

    identity, spec, before = Policy()
    original = VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))
    target = replace(original, transport=transport)
    supplied = original if binding == "original-awg" else None

    if transport == "amneziawg" and supplied is not None:
        assert IngressDelta(identity, spec, before.networkId, before, target, "disable", "b" * 32,
                            ("awg",), creationListener=supplied).deletionRuleIds == ("awg",)

    else:
        with pytest.raises(ValueError):
            IngressDelta(identity, spec, before.networkId, before, target, "disable", "b" * 32, ("awg",), creationListener=supplied)


def test_AddedTaggedRuleCanLaterBeRemovedWithAllSourcesAndItsActualProviderId() -> None:
    """New listener ownership includes the full stack hash and original operation tag, not only a protocol name."""

    enable = replace(Plan(), listener=VpnListener("wireguard", "udp", 51821, ("203.0.113.0/24", "198.51.100.0/24")))
    active = Result(enable)
    added = enable.ValidateResult(active)
    disable = IngressDelta(enable.identity, enable.creationSpec, active.networkId, active, enable.listener, "disable", "c" * 32, added)

    assert disable.ValidateResult(enable.before) == () and disable.deletionRuleIds == added
    assert disable.before != enable.before and disable.BeforeSha256 != enable.BeforeSha256
    foreign = replace(active, rules=tuple(replace(rule, description=rule.description.replace(enable.Owner, "f" * 64))
                                         if rule.ruleId in added else rule for rule in active.rules))

    with pytest.raises(ValueError, match="unproved"):
        replace(disable, before=foreign)


@pytest.mark.parametrize("fault", ["missing-id", "extra-id", "duplicate-id", "broad", "any-protocol", "wrong-source", "duplicate-source", "annotated-target"])
def test_DisableCannotDeleteCollateralOrLeaveHiddenTargetAllowances(fault: str) -> None:
    """Only the complete exact selected listener may be deleted; broader rules and unhandled metadata stop planning."""

    enable = Plan()
    active = Result(enable)
    target = next(rule for rule in active.rules if rule.ruleId == "provider-new-rule")
    deletion = (target.ruleId,)

    if fault in {"missing-id", "extra-id", "duplicate-id"}:
        deletion = () if fault == "missing-id" else (target.ruleId, "admin" if fault == "extra-id" else target.ruleId)

    else:
        if fault == "duplicate-source":
            active = replace(active, rules=(*active.rules, replace(target, ruleId="duplicate")))
            deletion = (target.ruleId, "duplicate")

        else:
            options = {"broad": {"fromPort": 1, "toPort": 65535}, "any-protocol": {"protocol": "any"},
                       "wrong-source": {"ipv4Cidrs": ("198.51.100.0/24",)}, "annotated-target": {"labels": (("purpose", "changed"),)}}[fault]
            active = replace(active, rules=tuple(replace(rule, **options) if rule.ruleId == target.ruleId else rule for rule in active.rules))

    with pytest.raises(ValueError):
        IngressDelta(enable.identity, enable.creationSpec, active.networkId, active, enable.listener, "disable", "b" * 32, deletion)


@pytest.mark.parametrize("rule", [SecurityGroupRule("existing", "ingress", "udp", 51821, 51821, ("198.51.100.0/24",)),
                                  SecurityGroupRule("existing", "ingress", "udp", 1, 65535, ("0.0.0.0/0",)),
                                  SecurityGroupRule("existing", "ingress", "any", None, None, ("0.0.0.0/0",))])
def test_EnableRefusesAnyExistingAllowanceOnTheTargetPort(rule: SecurityGroupRule) -> None:
    """A broad rule cannot be ignored because it uses another CIDR or protocol encoding."""

    plan = Plan()

    with pytest.raises(ValueError, match="closed target"):
        replace(plan, before=replace(plan.before, rules=(*plan.before.rules, rule)))


@pytest.mark.parametrize("listener", [VpnListener("wireguard", "tcp", 51821, ("0.0.0.0/0",)),
                                     VpnListener("amneziawg", "tcp", 51821, ("0.0.0.0/0",)),
                                     VpnListener("vless-reality", "udp", 443, ("0.0.0.0/0",)),
                                     VpnListener("openvpn", "tcp", 22, ("0.0.0.0/0",)),
                                     VpnListener("unknown", "udp", 9000, ("0.0.0.0/0",))])
def test_OnlySupportedProtocolCombinationsCanProduceAnIngressPlan(listener: VpnListener) -> None:
    """An explicit protocol operation can never become SSH management or an arbitrary listener capability."""

    with pytest.raises(ValueError):
        replace(Plan(), listener=listener)


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_OpenVpnSelectsOneExplicitListenerWithoutChangingTheOtherPortProtocol(protocol: str) -> None:
    """TCP and UDP are independent listener namespaces; OpenVPN does not implicitly open both."""

    plan = replace(Plan(), listener=VpnListener("openvpn", protocol, 1194, ("0.0.0.0/0",)))

    assert plan.Addition is not None and plan.Addition.protocol == protocol
    assert plan.ValidateResult(Result(plan)) == ("provider-new-rule",)
