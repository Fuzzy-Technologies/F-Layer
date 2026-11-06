"""Retain original ingress plans across process boundaries without adopting new policy or accepting hidden model fields."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any

import pytest
from test_yandex_ingress import Plan, Policy, Result

from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnError, VpnListener
from flayer.providers._yandex_firewall import SecurityGroupRule
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_records import MAX_PLAN_BYTES, DecodePlan, EncodePlan


def Bytes(value: object) -> bytes:
    """Encode malformed synthetic fixtures using the same canonical spelling as the persisted wire envelope."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


@pytest.mark.parametrize("change", ["enable", "disable-original", "disable-tagged"])
def test_PlanRoundTripRetainsItsExactOriginalFingerprintAndAllPolicyMetadata(change: str) -> None:
    """Allocated IDs, frozen specs, unrelated labels and original protocol attestation survive recovery unchanged."""

    plan = Plan()

    if change == "disable-original":
        identity, spec, before = Policy()
        listener = VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))
        plan = IngressDelta(identity, spec, before.networkId, before, listener, "disable", "b" * 32, ("awg",), listener)

    elif change == "disable-tagged":
        plan = replace(plan, before=Result(plan), change="disable", operationId="b" * 32, deletionRuleIds=("provider-new-rule",))

    content = EncodePlan(plan)
    restored = DecodePlan(content)

    assert restored == plan and EncodePlan(restored) == content
    assert hashlib.sha256(content).hexdigest() == plan.Fingerprint() == restored.Fingerprint()
    assert restored.BeforeSha256 == plan.BeforeSha256 and restored.creationSpec == plan.creationSpec
    assert restored.deletionRuleIds == plan.deletionRuleIds and restored.creationListener == plan.creationListener
    assert restored.before.rules == plan.before.rules


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("schema_version",), 2),
    (("plan", "unknown"), "suppressed-fixture"), (("plan", "operation_id"), "../foreign"),
    (("plan", "identity", "owner_id"), "different-owner"),
    (("plan", "before", "unknown"), "suppressed-fixture"),
    (("plan", "before", "network_id"), ["example-network"]),
    (("plan", "before", "resource", "reference", "scope_id"), "different-folder"),
    (("plan", "before", "resource", "reference", "kind"), "instance"),
    (("plan", "before", "resource", "status"), "UPDATING"),
    (("plan", "before", "resource", "labels"), []),
    (("plan", "before", "rules", 0, "unknown"), "suppressed-fixture"),
    (("plan", "before", "rules", 0, "from_port"), True),
    (("plan", "before", "rules", 0, "labels"), [["duplicate", "a"], ["duplicate", "b"]]),
    (("plan", "before", "rules", 0, "ipv4_cidrs"), ["0.0.0.1/0"]),
    (("plan", "listener", "port"), True), (("plan", "listener", "unknown"), "suppressed-fixture"),
    (("plan", "listener", "source_cidrs"), "0.0.0.0/0"),
    (("plan", "creation_spec", "parameters"), [["rules", 1.5]]),
    (("plan", "creation_spec", "parameters"), [["rules"]]),
    (("plan", "creation_spec", "dependencies"), [False]),
    (("plan", "deletion_rule_ids"), ["admin"]),
    (("plan", "creation_listener"), {}),
])
def test_PlanDecoderRejectsMalformedOrContradictoryRetainedData(path: tuple[str | int, ...], value: object) -> None:
    """Full delta validation runs again after parsing, before a stored plan can reach an SDK writer or reader."""

    data = json.loads(EncodePlan(Plan()))
    target: Any = data

    for item in path[:-1]:
        target = target[item]

    target[path[-1]] = value

    with pytest.raises(VpnError) as caught:
        DecodePlan(Bytes(data))

    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert "suppressed-fixture" not in str(caught.value)


@pytest.mark.parametrize("content", [b"", b"[]", b"{", b"\xff", b'{"schema_version":1,"schema_version":1,"plan":{}}',
                                     b'{"schema_version":1,"plan":{"number":NaN}}', b"[" * 1500 + b"]" * 1500])
def test_ParserRejectsDuplicateNonstandardOrUnboundedStructuresWithoutRawExceptionContext(content: bytes) -> None:
    """A sanitized error must not retain JSONDecodeError.doc or a nested raw parser cause."""

    with pytest.raises(VpnError) as caught:
        DecodePlan(content)

    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_DecoderRequiresCanonicalNormalizedPolicyInsteadOfAcceptingEquivalentReorderedBytes() -> None:
    """Recovery is bound to exact published bytes, including rule ordering and all original IDs."""

    original = EncodePlan(Plan())
    data = json.loads(original)
    data["plan"]["before"]["rules"].reverse()

    for content in (original + b"\n", json.dumps(json.loads(original), indent=2).encode(), Bytes(data)):
        with pytest.raises(VpnError):
            DecodePlan(content)


def LargePlan() -> IngressDelta:
    """Retain a supported snapshot with one free rule slot, exceeding the original 64 KiB peer metadata boundary."""

    plan = Plan()
    labels = tuple((f"key-{index:02d}", "x" * 60) for index in range(64))
    extra = tuple(SecurityGroupRule(f"extra-{index:02d}", "egress", "any", None, None, ("0.0.0.0/0",), labels=labels) for index in range(59))

    return replace(plan, before=replace(plan.before, rules=(*plan.before.rules, *extra)))


def test_CompleteLargePolicyRetainsItsLabelsAndUsesTheExplicitPlanByteBound() -> None:
    """Valid snapshots are not silently truncated to fit a smaller legacy journal, and oversized metadata never publishes."""

    plan = LargePlan()
    content = EncodePlan(plan)

    assert 65536 < len(content) < MAX_PLAN_BYTES and DecodePlan(content) == plan
    oversized = replace(Plan().before.resource, labels=(*Plan().before.resource.labels, ("extra", "x" * MAX_PLAN_BYTES)))

    with pytest.raises(VpnError, match="byte bound"):
        EncodePlan(replace(Plan(), before=replace(Plan().before, resource=oversized)))

    with pytest.raises(VpnError):
        DecodePlan(b" " * (MAX_PLAN_BYTES + 1))


def test_EncodingRejectsCredentialBearingModelAndScalarExtensionsBeforeSerialization() -> None:
    """Generic wire serialization must never discover synthetic credential fields on an otherwise valid inherited model."""

    @dataclass(frozen=True, slots=True)
    class ExtendedIdentity(StackIdentity):
        """Represent an unsafe model supplied at a public metadata boundary."""

        privateKey: str = "suppressed-fixture"

    @dataclass(frozen=True, eq=False)
    class ExtendedString(str):
        """Represent a credential-bearing dataclass that also satisfies ordinary string validators."""

        privateKey: str = "suppressed-fixture"

    plan = Plan()
    identity = plan.identity
    extended = ExtendedIdentity(identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId)

    for unsafe in (replace(plan, identity=extended), replace(plan, operationId=ExtendedString("a" * 32))):
        with pytest.raises(VpnError, match="exact nonsecret"):
            EncodePlan(unsafe)
