"""Bind protocol epoch evidence to known complete cloud deltas without any provider or guest operation."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, replace
from typing import Any

import pytest
from test_yandex_ingress import Plan, Policy, Result

from flayer import _vpn_protocol_epochs as epochs
from flayer._vpn_creation import ProtocolPin, _Json
from flayer._vpn_host_input import InputPolicy, InputTransition
from flayer._vpn_ingress_journal import IngressJournal
from flayer._vpn_protocol_sources import ProtocolSource
from flayer.core.contracts import _WireDict
from flayer.profiles import _host_input_policy as inputCodec
from flayer.profiles.vpn import VpnError, VpnListener
from flayer.providers._yandex_firewall import SecurityGroupRule, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import IngressOperation, IngressOperationReference


def Operation(plan: IngressDelta, result: SecurityGroupSnapshot, identifier: str = "example-operation") -> IngressOperation:
    """Model a separately verified complete adapter reply rather than inferring success from a current policy."""

    reference = IngressOperationReference(identifier, plan.before.resource.reference.resourceId, plan.Fingerprint())

    return IngressOperation(reference, "complete", plan.ValidateResult(result), policy=result)


def Evidence(kind: str) -> epochs.CloudEvidence:
    """Retain synthetic enable/disable, undispatched cancellation and explicitly completed inverse-operation facts."""

    plan = Plan()

    if kind in {"disable", "restore-disabled"}:
        identity, spec, before = Policy()
        listener = VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))
        plan = IngressDelta(identity, spec, before.networkId, before, listener, "disable", "a" * 32, ("awg",), listener)
        applied = replace(before, rules=tuple(rule for rule in before.rules if rule.ruleId != "awg"))

    else:
        applied = Result(plan)

    if kind == "undispatched":
        return epochs.CloudEvidence(plan, plan.before, "not-applied")

    operation = Operation(plan, applied)

    if kind in {"enable", "disable"}:
        return epochs.CloudEvidence(plan, applied, "committed", operation)

    change = "disable" if plan.change == "enable" else "enable"
    inverse = IngressDelta(plan.identity, plan.creationSpec, plan.networkId, applied, plan.listener, change,
                           epochs.RestorationNonce(plan.operationId), operation.addedRuleIds if change == "disable" else ())
    result = (replace(applied, rules=tuple(rule for rule in applied.rules if rule.ruleId not in inverse.deletionRuleIds))
              if change == "disable" else Result(inverse))

    return epochs.CloudEvidence(plan, result, "not-applied", operation, applied, inverse, Operation(inverse, result, "example-restoration"))


@pytest.mark.parametrize("kind", ["enable", "disable", "undispatched", "restore-enabled", "restore-disabled"])
def test_CompleteCloudEvidenceRoundTripsExactRulesAndKnownOperationReferences(kind: str) -> None:
    """Metadata is self-contained and bounded, while restored provider IDs/descriptions remain actual readback values."""

    value = Evidence(kind)
    encoded = _Json(value.Record())
    assert epochs.DecodeCloudEvidence(encoded) == value
    assert epochs.DecodeCloudEvidence(encoded).Record() == value.Record()
    assert len(encoded) <= 1048576

    if kind == "restore-disabled":
        assert value.result != value.plan.before
        restored = next(rule for rule in value.result.rules if rule.ruleId == "provider-new-rule")
        assert restored.description.endswith(epochs.RestorationNonce(value.plan.operationId))
        assert restored.ipv4Cidrs == value.plan.listener.sourceCidrs
        assert all(rule in value.result.rules for rule in value.plan.before.rules if rule.ruleId != "awg")


@pytest.mark.parametrize("fault", ["unknown-outcome", "missing-operation", "pending", "failed", "wrong-resource", "wrong-plan", "wrong-policy", "wrong-added-ids", "collateral", "hidden-compensation"])
def test_CommittedEpochCannotAdoptAnUnknownOperationOrAnOldLookingCloudResult(fault: str) -> None:
    """A self-supplied snapshot never substitutes for the exact known terminal operation and full verified readback."""

    value = Evidence("enable")
    operation = value.operation
    assert operation is not None

    with pytest.raises(ValueError):
        if fault == "unknown-outcome":
            replace(value, outcome="probably-applied")

        elif fault == "missing-operation":
            replace(value, operation=None)

        elif fault == "pending":
            replace(value, operation=IngressOperation(operation.reference, "pending"))

        elif fault == "failed":
            replace(value, operation=IngressOperation(operation.reference, "failed", errorCode=7))

        elif fault == "wrong-resource":
            replace(value, operation=replace(operation, reference=replace(operation.reference, resourceId="foreign-group")))

        elif fault == "wrong-plan":
            replace(value, operation=replace(operation, reference=replace(operation.reference, planSha256="f" * 64)))

        elif fault == "wrong-policy":
            replace(value, operation=replace(operation, policy=value.plan.before))

        elif fault == "wrong-added-ids":
            replace(value, operation=replace(operation, addedRuleIds=("unrelated-rule",)))

        elif fault == "collateral":
            replace(value, result=replace(value.result, rules=tuple(rule for rule in value.result.rules if rule.ruleId != "admin")))

        else:
            replace(value, applied=value.result)


@pytest.mark.parametrize("fault", ["missing-known-main", "missing-inverse", "missing-known-inverse", "same-provider-operation", "wrong-nonce", "changed-listener", "changed-before", "changed-final", "old-ids", "unknown-undispatched"])
def test_NoOpEpochRetainsOnlyCompleteExactCompensationAndActualRestoredPolicy(fault: str) -> None:
    """Partial, queued or collateral inverse operations cannot be represented as a successful protocol rollback."""

    value = Evidence("restore-disabled")
    inverse = value.restoration
    originalOperation, inverseOperation = value.operation, value.restorationOperation
    assert inverse is not None and originalOperation is not None and inverseOperation is not None

    with pytest.raises(ValueError):
        if fault == "missing-known-main":
            replace(value, operation=None)

        elif fault == "missing-inverse":
            replace(value, restoration=None)

        elif fault == "missing-known-inverse":
            replace(value, restorationOperation=None)

        elif fault == "same-provider-operation":
            reference = replace(inverseOperation.reference, operationId=originalOperation.reference.operationId)
            replace(value, restorationOperation=replace(inverseOperation, reference=reference))

        elif fault == "wrong-nonce":
            replace(value, restoration=replace(inverse, operationId="f" * 32))

        elif fault == "changed-listener":
            replace(value, restoration=replace(inverse, listener=replace(inverse.listener, port=51822)))

        elif fault == "changed-before":
            before = replace(inverse.before, rules=tuple(rule for rule in inverse.before.rules if rule.ruleId != "admin"))
            replace(value, restoration=replace(inverse, before=before))

        elif fault == "changed-final":
            replace(value, result=replace(value.result, rules=tuple(rule for rule in value.result.rules if rule.ruleId != "vless")))

        elif fault == "old-ids":
            replace(value, result=value.plan.before)

        else:
            epochs.CloudEvidence(value.plan, value.plan.before, "not-applied", originalOperation)


@pytest.mark.parametrize("path,value", [
    (("schema_version",), True), (("private_key",), "suppressed-fixture"), (("outcome",), "unknown"),
    (("operation", "status"), "pending"), (("operation", "reference", "plan_sha256"), "f" * 64),
    (("operation", "added_rule_ids"), []), (("result", "rules", 0, "from_port"), 22.0),
])
def test_StoredCloudEvidenceRejectsMalformedOrNonexactCanonicalRecords(path: tuple[str | int, ...], value: object) -> None:
    """Closed decoding reruns complete outcome checks and rejects Python scalar aliases without parser context."""

    raw = copy.deepcopy(Evidence("enable").Record())
    target: Any = raw

    for key in path[:-1]:
        target = target[key]

    target[path[-1]] = value

    with pytest.raises(VpnError) as caught:
        epochs.DecodeCloudEvidence(_Json(raw))

    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert "suppressed-fixture" not in str(caught.value)


def test_HiddenModelFieldsAreRejectedBeforeRecursiveCloudSerialization() -> None:
    """A subclass with private fields cannot turn a public receipt serializer into a credential disclosure path."""

    @dataclass(frozen=True, slots=True)
    class ExtendedSnapshot(SecurityGroupSnapshot):
        """Model an unapproved credential-bearing cloud reply extension."""

        privateKey: str = "suppressed-fixture"

    value = Evidence("enable")
    extended = ExtendedSnapshot(value.result.resource, value.result.networkId, value.result.rules)

    with pytest.raises(VpnError):
        replace(value, result=extended)


def test_CompleteCloudRollbackCapacityIsReservedBeforeAnyDispatch() -> None:
    """Large individually valid rule metadata must fail before mutation rather than make a later epoch unreadable."""

    plan = Plan()
    labels = tuple(("note-" + str(index), "x" * 63) for index in range(64))
    extra = tuple(SecurityGroupRule("fixture-rule-" + str(index), "egress", "any", None, None, ("0.0.0.0/0",), labels=labels)
                  for index in range(59))
    large = replace(plan, before=replace(plan.before, rules=(*plan.before.rules, *extra)))

    with pytest.raises(VpnError, match="space"):
        epochs.RequireCloudEvidenceCapacity(large)


@pytest.mark.parametrize("kind", ["no-effect", "applied-failure", "restoration-failure"])
def test_KnownTerminalFailureRetainsItsCodeAndSeparatelyVerifiedCompletePolicy(kind: str) -> None:
    """A done/error operation is distinct from unknown submission, and its exact effect still needs complete readback."""

    value = Evidence("restore-enabled")
    operation = value.operation
    assert operation is not None
    failed = IngressOperation(operation.reference, "failed", errorCode=7)

    if kind == "no-effect":
        value = epochs.CloudEvidence(value.plan, value.plan.before, "not-applied", failed)

    elif kind == "applied-failure":
        value = replace(value, operation=failed)

    else:
        assert value.restorationOperation is not None
        value = replace(value, restorationOperation=IngressOperation(value.restorationOperation.reference, "failed", errorCode=7))

    assert epochs.DecodeCloudEvidence(_Json(value.Record())) == value
    record = value.Record()["restoration_operation" if kind == "restoration-failure" else "operation"]
    assert record["status"] == "failed" and record["error_code"] == 7


def Commit(kind: str = "committed") -> epochs.EpochCommit:
    """Build only public synthetic commit bytes; actual segment/source traversal is a separate POSIX graph test."""

    cloud = Evidence("enable" if kind == "committed" else "undispatched")
    plan, identity = cloud.plan, cloud.plan.identity
    listeners = (VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",)), VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)))
    public = {"identity": _WireDict(identity), "listeners": [_WireDict(item) for item in listeners],
              "management_cidrs": ["198.51.100.42/32"], "operation_id": ""}
    before = InputPolicy(identity, "b" * 64, inputCodec.Digest(inputCodec.Boot(public)), ("198.51.100.42/32",), listeners)
    transition = InputTransition(before, plan.listener, plan.change, plan.operationId)
    outcome = "applied" if kind == "committed" else "unchanged" if kind == "cancelled" else "rolled-back"
    inputProof = epochs.InputEvidence(transition, outcome, "c" * 64, "d" * 64 if outcome != "unchanged" else "")
    names = ("amneziawg", "vless-reality", "wireguard")
    sources = tuple(ProtocolSource(identity, ProtocolPin(name, "1" * 64, "2" * 64, "3" * 64)) for name in names)
    active = names if kind == "committed" else names[:2]
    owner = inputCodec.Owner(inputCodec.Policy(transition.Record()["before"]))
    absence = hashlib.sha256(_Json({"domain": "f-layer/wireguard/absent/v1", "owner": owner})).hexdigest()
    services = tuple(epochs.ServiceProof(name, "3" * 64, "active" if name in active else "absent",
                                       "4" * 64 if name in active else "", "" if name in active else absence) for name in names)
    history = "6" * 64
    reservation = {"schema_version": 1, "owner": owner, "creation_sha256": "b" * 64, "previous_authority_sha256": "7" * 64,
                   "previous_state_sha256": "8" * 64, "operation_id": plan.operationId, "plan_expires_at": 1,
                   "plan_sha256": hashlib.sha256(_Json({"schema_version": 1, "cloud_plan_sha256": plan.Fingerprint(), "input": transition.Record()})).hexdigest(),
                   "wireguard_state": "absent", "wireguard_receipt_sha256": "", "wireguard_absence_sha256": absence,
                   "wireguard_history_sha256": history}
    serviceBytes = _Json({"schema_version": 1, "services": [proof.Record() for proof in services]})
    intent = IngressJournal(plan, "b" * 64, "8" * 64, 1).Bundle()
    metadata = {"schema_version": 1, "identity": _WireDict(identity), "creation_sha256": "b" * 64, "parent": None,
                "closed_peer_head": None, "closed_peer_head_sha256": "b" * 64, "closed_peer_count": 0, "previous_state_sha256": "8" * 64,
                "sources": [source.Record() for source in sources], "configured_listeners": [_WireDict(item) for item in (*listeners, plan.listener)],
                "active_protocols": active, "static_fingerprint": "a" * 64, "wireguard_receipt_sha256": "4" * 64 if kind == "committed" else "",
                "wireguard_history_sha256": "e" * 64 if kind == "committed" else history,
                "generation_receipt_sha256": "4" * 64 if kind == "committed" else "", "reservation": reservation, "authority_parent": None,
                "ingress_intents": [{"role": "change", "name": intent.name, "sha256": epochs.BundleDigest(intent)}],
                "cloud_sha256": hashlib.sha256(_Json(cloud.Record())).hexdigest(), "input_sha256": hashlib.sha256(_Json(inputProof.Record())).hexdigest(),
                "services_sha256": hashlib.sha256(serviceBytes).hexdigest()}
    encoded = _Json(metadata)
    completion = {"schema_version": 1 if kind == "cancelled" else 2, "owner": owner, "creation_sha256": "b" * 64,
                  "operation_id": plan.operationId, "intent_sha256": hashlib.sha256(_Json(reservation) if kind == "cancelled" else encoded).hexdigest(),
                  "parent": None, "previous_authority_sha256": "7" * 64, "history_sha256": metadata["wireguard_history_sha256"],
                  "outcome": "cancelled" if kind == "cancelled" else cloud.outcome}

    return epochs.EpochCommit(identity, encoded, cloud, inputProof, services, _Json(completion))


@pytest.mark.parametrize("kind", ["committed", "cancelled", "rolled-back"])
def test_IntentBindsCompleteProofsBeforeGuestCompletionAndFinalPeerGenesis(kind: str) -> None:
    """The guest binds intent SHA, then its completion enters the final bundle digest without a circular hash reference."""

    commit = Commit(kind)
    bundle = commit.Bundle()
    files = {item.name: item for item in bundle.files}
    assert set(files) == {"epoch.json", "cloud.json", "input.json", "services.json"}
    assert all(not item.sensitive for item in bundle.files) and commit.Digest() != hashlib.sha256(commit.metadata).hexdigest()
    assert epochs.DecodeEpochBundle(bundle) == commit
    assert epochs.DecodeCloudEvidence(files["cloud.json"].content) == commit.cloud
    assert epochs.DecodeInputEvidence(files["input.json"].content) == commit.input
    assert epochs._Services(files["services.json"].content) == commit.services


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("private_key", "suppressed-fixture"), ("closed_peer_count", True), ("closed_peer_count", 1),
    ("closed_peer_head_sha256", "f" * 64), ("cloud_sha256", "f" * 64), ("input_sha256", "f" * 64),
    ("services_sha256", "f" * 64), ("active_protocols", ["wireguard"]), ("wireguard_receipt_sha256", ""),
])
def test_EpochCommitRejectsContradictoryIntentBeforeItCanPrepareAnArtifact(field: str, value: object) -> None:
    """Canonical independent proof hashes, configured/active projections and segment closure must agree exactly."""

    commit = Commit()
    metadata = epochs._Decode(commit.metadata)
    metadata[field] = value

    with pytest.raises(ValueError):
        replace(commit, metadata=_Json(metadata))


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("owner", "a" * 64), ("intent_sha256", "a" * 64), ("history_sha256", "a" * 64),
    ("previous_authority_sha256", "a" * 64), ("operation_id", "f" * 32), ("outcome", "not-applied"),
])
def test_GuestCompletionCannotSubstituteAnotherIntentOwnerHistoryOrOutcome(field: str, value: object) -> None:
    """The final epoch cannot manufacture a successful guest authority consumption from an unrelated receipt."""

    commit = Commit()
    completion = epochs._Decode(commit.completion)
    completion[field] = value

    with pytest.raises(ValueError):
        replace(commit, completion=_Json(completion))
