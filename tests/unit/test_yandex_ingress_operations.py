"""Exercise the real scoped CLI adapter with an in-memory operation service and no executable or network."""

from __future__ import annotations

import copy
import json
import subprocess
from dataclasses import replace
from typing import Any

import pytest
from test_yandex_ingress import Plan, Policy, Result

from flayer.profiles.vpn import VpnError, VpnListener
from flayer.providers._yandex_firewall import SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import IngressOperationReference
from flayer.providers.contracts import ProviderError
from flayer.providers.lifecycle import MutationError
from flayer.providers.yandex import CommandResult, YandexCloudSettings
from flayer.vpn_project import VpnYandexProvider

METADATA = "type.googleapis.com/yandex.cloud.vpc.v1.UpdateSecurityGroupMetadata"
RESPONSE = "type.googleapis.com/yandex.cloud.vpc.v1.SecurityGroup"


def Payload(snapshot: SecurityGroupSnapshot) -> dict[str, Any]:
    """Encode documented CLI fields independently of the production parser and JSON proof helper."""

    rules = []

    for rule in snapshot.rules:
        item: dict[str, Any] = {"id": rule.ruleId, "direction": rule.direction.upper(), "protocol_name": rule.protocol.upper(),
                               "description": rule.description, "labels": dict(rule.labels),
                               "cidr_blocks": {"v4_cidr_blocks": list(rule.ipv4Cidrs)}}

        if rule.fromPort is not None:
            item["ports"] = {"from_port": str(rule.fromPort), "to_port": str(rule.toPort)}

        rules.append(item)

    resource = snapshot.resource

    return {"id": resource.reference.resourceId, "folder_id": resource.reference.scopeId, "name": resource.name,
            "status": resource.status, "labels": dict(resource.labels), "network_id": snapshot.networkId, "rules": rules}


class OperationRunner:
    """Model an async request whose old-looking policy can remain unchanged until the retained operation finishes."""

    def __init__(self, plan: IngressDelta) -> None:
        """Keep all cloud data synthetic and never provide a fallback to a real runner."""

        self.calls: list[tuple[str, ...]] = []
        self.current = Payload(plan.before)
        self.desired = Payload(Result(plan) if plan.Addition is not None else replace(plan.before, rules=tuple(
            rule for rule in plan.before.rules if rule.ruleId not in plan.deletionRuleIds)))
        self.added = ["provider-new-rule"] if plan.Addition is not None else []
        self.operation: dict[str, Any] = {"id": "operation-example", "done": False,
            "metadata": {"@type": METADATA, "security_group_id": plan.before.resource.reference.resourceId}}
        self.submitResult: CommandResult | Exception | None = None
        self.readContent: str | None = None
        self.policyContent: str | None = None

    def Finish(self, *, error: bool = False) -> None:
        """Complete only the model operation; until this call old policy does not prove a canceled mutation."""

        self.operation["done"] = True
        self.operation["metadata"]["added_rule_ids"] = list(self.added)

        if error:
            self.operation["error"] = {"code": 7, "message": "suppressed-private-fixture", "details": []}

        else:
            self.operation["response"] = {"@type": RESPONSE, **copy.deepcopy(self.desired)}
            self.current = copy.deepcopy(self.desired)

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Accept only exact read/update/get vectors and supply JSON without invoking any shell or socket."""

        self.calls.append(command)
        assert command[0] == "yc" and timeout == 45.0
        flags = ("--profile", "fixture-profile", "--folder-id", "example-folder", "--format", "json", "--no-browser", "--retry", "0")
        assert command[-len(flags):] == flags

        if command[1:4] == ("vpc", "security-group", "get"):
            assert command[command.index("--id") + 1] == "example-group"

            return CommandResult(0, self.policyContent if self.policyContent is not None else json.dumps(self.current))

        if command[1:4] == ("vpc", "security-group", "update-rules"):
            if isinstance(self.submitResult, Exception):
                raise self.submitResult

            if self.operation.get("done") and "response" in self.operation:
                self.current = copy.deepcopy(self.desired)

            return self.submitResult or CommandResult(0, json.dumps(self.operation))

        assert command[1:3] == ("operation", "get") and command[3] == "operation-example"

        return CommandResult(0, self.readContent if self.readContent is not None else json.dumps(self.operation))


def Provider(plan: IngressDelta) -> tuple[VpnYandexProvider, OperationRunner]:
    """Inject the sole execution boundary before constructing the public concrete adapter."""

    runner = OperationRunner(plan)

    return VpnYandexProvider(YandexCloudSettings("example-folder", "fixture-profile"), runner), runner


def Options(plan: IngressDelta) -> dict[str, Any]:
    """Carry the exact explicit consent boundary instead of weakening it for test fixtures."""

    return {"allowMutation": True, "scopeConfirm": "example-folder", "expectedBefore": plan.BeforeSha256}


def test_SubmitReturnsOnlyTheReferenceAndPendingReadNeverRepeatsTheMutation() -> None:
    """Persistable submission evidence cannot be mistaken for a healthy listener or used as a retry loop."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))

    assert reference == IngressOperationReference("operation-example", "example-group", plan.Fingerprint())
    assert len(runner.calls) == 2
    update = runner.calls[-1]
    addition = plan.Addition
    assert addition is not None
    assert update[1:8] == ("vpc", "security-group", "update-rules", "--id", "example-group", "--async", "--print-metadata")
    assert update[8:10] == ("--add-rule", "description=" + addition.description + ",direction=ingress,protocol=udp,port=51821,v4-cidrs=[0.0.0.0/0]")

    for _ in range(2):
        pending = provider.ReadIngressChange(plan, reference)
        assert pending.status == "pending" and pending.policy is None and not pending.addedRuleIds

    assert [command[3] for command in runner.calls if command[1] == "vpc"] == ["get", "update-rules"]
    runner.Finish()
    completed = provider.ReadIngressChange(plan, reference)

    assert completed.status == "complete" and completed.addedRuleIds == ("provider-new-rule",)
    assert completed.policy == Result(plan) and completed.errorCode is None
    assert sum(command[1:4] == ("vpc", "security-group", "update-rules") for command in runner.calls) == 1


def test_OriginalListenerDeletionUsesOnlyItsProvedIdsAndVerifiesTheUnrelatedPolicy() -> None:
    """Removal never emits whole-group update, a resource delete, or a listener addition."""

    identity, spec, before = Policy()
    listener = VpnListener("amneziawg", "udp", 51820, ("0.0.0.0/0",))
    plan = IngressDelta(identity, spec, before.networkId, before, listener, "disable", "b" * 32, ("awg",), creationListener=listener)
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))
    update = runner.calls[-1]

    assert update[8:10] == ("--delete-rule-id", "awg") and "--add-rule" not in update
    runner.Finish()
    completed = provider.ReadIngressChange(plan, reference)

    assert completed.status == "complete" and completed.policy is not None and not completed.addedRuleIds
    assert {rule.ruleId for rule in completed.policy.rules} == {"admin", "vless", "egress"}


@pytest.mark.parametrize("key,value", [("allowMutation", False), ("allowMutation", 1), ("scopeConfirm", "other-folder"),
                                     ("expectedBefore", "f" * 64), ("expectedBefore", ""), ("expectedBefore", None)])
def test_InvalidConsentOrOldProofFailsBeforeAnyCloudRead(key: str, value: Any) -> None:
    """Invalid mutation inputs cannot even trigger authentication or an ownership observation."""

    plan = Plan()
    provider, runner = Provider(plan)
    options = Options(plan)
    options[key] = value

    with pytest.raises(MutationError) as error:
        provider.BeginIngressChange(plan, **options)

    assert error.value.outcomeUnknown is False and not runner.calls


def test_FreshCompletePolicyDriftRejectsSubmissionBeforeAnyMutation() -> None:
    """A plan's old policy is re-observed immediately before dispatch, including harmless-looking rule metadata."""

    plan = Plan()
    provider, runner = Provider(plan)
    runner.current["rules"][0]["description"] = "changed"

    with pytest.raises(MutationError) as error:
        provider.BeginIngressChange(plan, **Options(plan))

    assert error.value.outcomeUnknown is False and len(runner.calls) == 1


@pytest.mark.parametrize("identifier", ["target,admin", "--target", "r" * 129])
def test_UnsafeDeletionIdentifiersCannotExpandAProvedRuleSetOrReachTheCli(identifier: str) -> None:
    """The generic opaque-ID contract cannot be interpolated directly into a CLI string-slice argument."""

    original = Plan()
    active = Result(original)
    active = replace(active, rules=tuple(replace(rule, ruleId=identifier) if rule.ruleId == "provider-new-rule" else rule for rule in active.rules))
    plan = IngressDelta(original.identity, original.creationSpec, active.networkId, active, original.listener, "disable", "b" * 32, (identifier,))
    provider, runner = Provider(plan)

    with pytest.raises(MutationError) as error:
        provider.BeginIngressChange(plan, **Options(plan))

    assert not runner.calls and error.value.outcomeUnknown is False


@pytest.mark.parametrize("phase", ["preflight", "readback"])
@pytest.mark.parametrize("case", ["duplicate-rules", "duplicate-rule-field", "duplicate-labels", "oversized", "nonfinite"])
def test_DirectPolicyReadsUseTheSameStrictBoundedJsonProofBeforeDispatchAndAfterSuccess(phase: str, case: str) -> None:
    """An ambiguous direct SG response cannot be hidden behind a separately valid operation envelope."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = None

    if phase == "readback":
        reference = provider.BeginIngressChange(plan, **Options(plan))
        runner.Finish()

    content = json.dumps(runner.current)

    if case == "duplicate-rules":
        content = content.replace('"rules": [', '"rules": [], "rules": [', 1)

    elif case == "duplicate-rule-field":
        content = content.replace('"direction": "INGRESS"', '"direction": "EGRESS", "direction": "INGRESS"', 1)

    elif case == "duplicate-labels":
        content = content.replace('"labels": {', '"labels": {}, "labels": {', 1)

    else:
        content = json.dumps({**runner.current, "unrelated_annotation": "x" * (1024 * 1024) if case == "oversized" else float("nan")})

    runner.policyContent = content

    with pytest.raises(MutationError) as error:
        if reference is None:
            provider.BeginIngressChange(plan, **Options(plan))

        else:
            provider.ReadIngressChange(plan, reference)

    assert error.value.outcomeUnknown is (phase == "readback")
    assert sum(command[1:4] == ("vpc", "security-group", "update-rules") for command in runner.calls) == int(phase == "readback")


def test_PublicPolicyReaderDiscardsTheRawDecoderExceptionAndResponseBeforeRaising() -> None:
    """Suppressing traceback display alone must not retain JSONDecodeError.doc through implicit exception context."""

    plan = Plan()
    provider, runner = Provider(plan)
    runner.policyContent = '{"suppressed-private-fixture":'

    with pytest.raises(VpnError) as error:
        provider.ReadSecurityGroupRules(plan.before.resource)

    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "suppressed-private-fixture" not in str(error.value) and len(runner.calls) == 1


def test_ImmediateProviderSuccessStillReturnsAReferenceBeforeAnyPostSubmissionRead() -> None:
    """Even a fast operation must allow durable reference publication before later verification calls."""

    plan = Plan()
    provider, runner = Provider(plan)
    runner.Finish()
    runner.current = Payload(plan.before)
    reference = provider.BeginIngressChange(plan, **Options(plan))

    assert len(runner.calls) == 2 and isinstance(reference, IngressOperationReference)
    assert provider.ReadIngressChange(plan, reference).status == "complete"


@pytest.mark.parametrize("earlyError", [True, False])
def test_ProtobufDefaultPendingAndEarlyErrorAreNotTerminalFailureOrHealthyPolicy(earlyError: bool) -> None:
    """The documented absent false field and nonterminal error observation cannot retire an unresolved operation."""

    plan = Plan()
    provider, runner = Provider(plan)
    del runner.operation["done"]
    reference = provider.BeginIngressChange(plan, **Options(plan))

    if earlyError:
        runner.operation["error"] = {"code": 7, "message": "suppressed-private-fixture"}

    result = provider.ReadIngressChange(plan, reference)

    assert result.status == "pending" and result.policy is None
    assert result.errorCode == (7 if earlyError else None)
    assert len(runner.calls) == 3 and "suppressed-private-fixture" not in repr(result)


@pytest.mark.parametrize("response", [subprocess.TimeoutExpired("suppressed-private-fixture", 45),
                                      CommandResult(1, stderr="permission_denied suppressed-private-fixture"),
                                      CommandResult(0, "suppressed-private-fixture"), CommandResult(0, "[]"),
                                      CommandResult(0, "x" * (1024 * 1024 + 1))])
def test_SubmissionFailureOrMalformedResponseNeverRetriesOrClaimsNotApplied(response: CommandResult | Exception) -> None:
    """Once dispatch happened, even an old-looking model policy cannot prove a delayed operation was canceled."""

    plan = Plan()
    provider, runner = Provider(plan)
    runner.submitResult = response

    with pytest.raises(MutationError) as error:
        provider.BeginIngressChange(plan, **Options(plan))

    assert error.value.outcomeUnknown is True and "suppressed-private-fixture" not in str(error.value)
    assert len(runner.calls) == 2 and runner.current == Payload(plan.before)


@pytest.mark.parametrize("case", ["plan", "resource", "operation-response"])
def test_OperationReferenceCannotBeReboundToAnotherPlanOrResource(case: str) -> None:
    """The retained provider ID is not a free selector for accepting a different transition."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))
    calls = len(runner.calls)

    if case == "plan":
        plan = replace(plan, operationId="b" * 32)

    elif case == "resource":
        reference = replace(reference, resourceId="other-group")

    else:
        runner.operation["id"] = "different-operation"

    with pytest.raises(MutationError):
        provider.ReadIngressChange(plan, reference)

    assert len(runner.calls) == calls + int(case == "operation-response")


@pytest.mark.parametrize("case", ["wrong-group", "metadata-type", "extra-metadata", "boolean-done", "unknown-field", "duplicate",
                                  "pending-response", "missing-terminal-result", "two-terminal-results", "wrong-response-type", "added-ids",
                                  "error-code", "nonfinite", "nonobject", "secret-error-extra"])
def test_InvalidOrUnrelatedOperationCannotBecomeVerifiedSuccess(case: str) -> None:
    """Reject malformed or ambiguous facts without leaking provider error bodies or metadata."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))
    runner.Finish()
    operation = runner.operation

    if case in {"wrong-group", "metadata-type", "extra-metadata", "added-ids"}:
        key, value = {"wrong-group": ("security_group_id", "other-group"), "metadata-type": ("@type", "unrelated.Type"),
                      "extra-metadata": ("private_extra", "suppressed-private-fixture"), "added-ids": ("added_rule_ids", ["a", "b"])}[case]
        operation["metadata"][key] = value

    elif case == "boolean-done":
        operation["done"] = 1

    elif case == "unknown-field":
        operation["private_extra"] = "suppressed-private-fixture"

    elif case == "pending-response":
        operation["done"] = False

    elif case == "missing-terminal-result":
        del operation["response"]

    elif case in {"two-terminal-results", "error-code", "nonfinite", "secret-error-extra"}:
        operation["error"] = {"code": 7, "message": "suppressed-private-fixture"}

        if case != "two-terminal-results":
            del operation["response"]

        if case == "error-code":
            operation["error"]["code"] = True

        elif case == "nonfinite":
            operation["error"]["details"] = [{"value": float("nan")}]

        elif case == "secret-error-extra":
            operation["error"]["private_extra"] = "suppressed-private-fixture"

    elif case == "wrong-response-type":
        operation["response"]["@type"] = "unrelated.Type"

    if case == "duplicate":
        runner.readContent = json.dumps(operation).replace('"done": true', '"done": false, "done": true')

    elif case == "nonobject":
        runner.readContent = "[]"

    with pytest.raises(MutationError) as error:
        provider.ReadIngressChange(plan, reference)

    assert "suppressed-private-fixture" not in str(error.value) and error.value.outcomeUnknown is True
    assert len(runner.calls) == 3, "Invalid operation facts must stop before current-policy readback"


def test_TerminalFailureIsBoundedAndCannotClaimOldPolicyOrHealthyCompletion() -> None:
    """A failed provider operation can still require scoped reconciliation; its private message is discarded."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))
    runner.Finish(error=True)
    result = provider.ReadIngressChange(plan, reference)

    assert result.status == "failed" and result.errorCode == 7 and result.policy is None
    assert "suppressed-private-fixture" not in repr(result) and len(runner.calls) == 3


@pytest.mark.parametrize("case", ["current-rule", "current-id", "current-network", "current-updating", "operation-response", "allocated-id"])
def test_CompletedOperationStillRequiresExactResponseAndFreshWholePolicy(case: str) -> None:
    """Current collateral drift or inconsistent allocated-rule evidence cannot be hidden by API success."""

    plan = Plan()
    provider, runner = Provider(plan)
    reference = provider.BeginIngressChange(plan, **Options(plan))
    runner.Finish()

    if case == "current-rule":
        runner.current["rules"][0]["description"] = "changed"

    elif case == "current-id":
        runner.current["id"] = "other-group"

    elif case == "current-network":
        runner.current["network_id"] = "other-network"

    elif case == "current-updating":
        runner.current["status"] = "UPDATING"

    elif case == "operation-response":
        runner.operation["response"]["rules"][0]["description"] = "changed"

    else:
        runner.operation["metadata"]["added_rule_ids"] = ["wrong-allocated-id"]

    with pytest.raises((MutationError, ProviderError)):
        provider.ReadIngressChange(plan, reference)

    assert sum(command[1:4] == ("vpc", "security-group", "update-rules") for command in runner.calls) == 1
