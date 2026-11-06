"""Submit one scoped asynchronous ingress mutation and verify only its retained operation and complete policy."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import ParseSecurityGroup, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
)
from flayer.providers.lifecycle import MutationError

if TYPE_CHECKING:
    from flayer.vpn_project import VpnYandexProvider

_METADATA_TYPE = "type.googleapis.com/yandex.cloud.vpc.v1.UpdateSecurityGroupMetadata"
_RESPONSE_TYPE = "type.googleapis.com/yandex.cloud.vpc.v1.SecurityGroup"
_MAX_RESPONSE_BYTES = 1024 * 1024


def _Identifier(value: object) -> bool:
    """Reject command-option syntax as well as unbounded or unsupported operation identifiers."""

    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None


@dataclass(frozen=True, slots=True)
class IngressOperationReference:
    """Minimal nonsecret evidence to persist before reading or polling a submitted cloud operation."""

    operationId: str
    resourceId: str
    planSha256: str

    def __post_init__(self) -> None:
        """Bind a safe explicit provider operation to one resource and the complete immutable local request."""

        if (not _Identifier(self.operationId) or not _Identifier(self.resourceId)
                or not isinstance(self.planSha256, str) or re.fullmatch(r"[0-9a-f]{64}", self.planSha256) is None):
            raise ValueError("Ingress operation reference requires exact bounded identifiers and request proof")


@dataclass(frozen=True, slots=True)
class IngressOperation:
    """A bounded pending/failure result or a complete verified operation plus current effective policy."""

    reference: IngressOperationReference
    status: str
    addedRuleIds: tuple[str, ...] = ()
    errorCode: int | None = None
    policy: SecurityGroupSnapshot | None = None

    def __post_init__(self) -> None:
        """Keep a provider acknowledgment distinct from a healthy verified current rule set."""

        if (not isinstance(self.reference, IngressOperationReference) or not isinstance(self.status, str)
                or self.status not in {"pending", "failed", "complete"}
                or not isinstance(self.addedRuleIds, tuple) or len(self.addedRuleIds) > 1
                or any(not _Identifier(value) for value in self.addedRuleIds)
                or self.errorCode is not None and (type(self.errorCode) is not int or not 1 <= self.errorCode <= 16)
                or self.status == "complete" and (self.errorCode is not None or not isinstance(self.policy, SecurityGroupSnapshot))
                or self.status != "complete" and self.policy is not None
                or self.status == "failed" and self.errorCode is None):
            raise ValueError("Ingress operation facts are inconsistent or outside their bounded contract")


def _Unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse duplicate keys at every depth before interpreting a cloud operation."""

    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError

        result[key] = value

    return result


def _Nonfinite(value: str) -> None:
    """Require standard JSON instead of accepting Python's NaN or Infinity extension."""

    raise ValueError


def _Decode(content: str) -> dict[str, Any]:
    """Apply the same byte bound and unambiguous JSON contract to operations and direct policy observations."""

    if not isinstance(content, str) or not 1 <= len(content) <= _MAX_RESPONSE_BYTES or len(content.encode()) > _MAX_RESPONSE_BYTES:
        raise ValueError

    value = json.loads(content, object_pairs_hook=_Unique, parse_constant=_Nonfinite)

    if not isinstance(value, dict):
        raise ValueError

    return value


def ReadPolicy(provider: VpnYandexProvider, resource: ProviderResource) -> SecurityGroupSnapshot:
    """Read complete scoped policy through a bounded duplicate-rejecting boundary before trusting any rule or ownership field."""

    reference = resource.reference

    if (reference.kind != ResourceKind.SECURITY_GROUP or reference.providerId != provider.Identity.providerId
            or reference.scopeId != provider.Identity.scopeId or not _Identifier(reference.resourceId)):
        raise VpnError("Security-group policy requires an exact resource in the configured scope")

    result = provider._Run(("vpc", "security-group", "get", "--id", reference.resourceId), "vpn-firewall-policy")

    try:
        payload = _Decode(result.stdout)

    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise VpnError("Security-group policy JSON is unavailable, ambiguous or exceeds its bound") from None

    observed = provider._ValidateObservation(provider._NormalizeResource(payload, ResourceKind.SECURITY_GROUP, "vpn-firewall-policy"))

    if observed.reference != reference or observed.name != resource.name or not observed.HasLabels(resource.labels):
        raise VpnError("Security-group ownership changed before policy observation")

    try:
        return ParseSecurityGroup(payload, observed)

    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise VpnError("Security-group effective policy is unavailable or unsupported; no rules were changed") from None


def _Operation(content: str, plan: IngressDelta, expected: str = "") -> dict[str, Any]:
    """Discard all raw provider diagnostics and require exact typed target metadata before retaining an ID."""

    try:
        value = _Decode(content)

        if (not isinstance(value, dict) or set(value) - {"id", "description", "created_at", "created_by", "modified_at", "done", "metadata", "error", "response"}
                or not _Identifier(value.get("id")) or expected and value["id"] != expected
                or type(value.get("done", False)) is not bool
                or any(not isinstance(value[key], str) or len(value[key]) > 256 for key in ("description", "created_at", "created_by", "modified_at") if key in value)):
            raise ValueError

        metadata = value.get("metadata")

        if (not isinstance(metadata, dict) or set(metadata) - {"@type", "security_group_id", "added_rule_ids"}
                or metadata.get("@type") != _METADATA_TYPE or metadata.get("security_group_id") != plan.before.resource.reference.resourceId
                or not isinstance(metadata.get("added_rule_ids", []), list)
                or len(metadata.get("added_rule_ids", [])) > (1 if plan.Addition is not None else 0)
                or any(not _Identifier(item) for item in metadata.get("added_rule_ids", []))):
            raise ValueError

        error, response = value.get("error"), value.get("response")

        if (value.get("done", False) and (error is None) == (response is None)
                or not value.get("done", False) and response is not None
                or response is not None and (not isinstance(response, dict) or response.get("@type") != _RESPONSE_TYPE)):
            raise ValueError

        if error is not None and (not isinstance(error, dict) or set(error) - {"code", "message", "details"}
                                  or type(error.get("code")) is not int or not 1 <= error["code"] <= 16
                                  or not isinstance(error.get("message", ""), str) or len(error.get("message", "")) > 4096
                                  or not isinstance(error.get("details", []), list) or len(error.get("details", [])) > 32):
            raise ValueError

    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass

    else:
        return value

    raise MutationError(ProviderErrorCode.INVALID_RESPONSE, "vpn-ingress-operation", True)


def _Scope(provider: VpnYandexProvider, plan: IngressDelta) -> None:
    """Reject a different configured cloud scope before any observation or mutation."""

    if (not isinstance(plan, IngressDelta) or not _Identifier(plan.before.resource.reference.resourceId)
            or any(not _Identifier(value) for value in plan.deletionRuleIds)
            or provider.Identity.providerId != plan.identity.provider
            or provider.Identity.scopeId != plan.identity.scopeId):
        raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "vpn-ingress-scope", False)


def Begin(
    provider: VpnYandexProvider, plan: IngressDelta, *, allowMutation: bool, scopeConfirm: str, expectedBefore: str,
) -> IngressOperationReference:
    """Submit once after consent and exact fresh policy proof; the caller must journal intent before dispatch and this ID before polling."""

    if (not isinstance(plan, IngressDelta) or allowMutation is not True or scopeConfirm != plan.identity.scopeId
            or not isinstance(expectedBefore, str) or expectedBefore != plan.BeforeSha256):
        raise MutationError(ProviderErrorCode.UNSUPPORTED, "vpn-ingress-consent", False)

    _Scope(provider, plan)

    failureCode = None

    try:
        plan.CheckBefore(provider.ReadSecurityGroupRules(plan.before.resource))

    except ValueError:
        failureCode = ProviderErrorCode.CONFLICT

    except ProviderError as error:
        failureCode = error.code

    if failureCode is not None:
        raise MutationError(failureCode, "vpn-ingress-preflight", False)

    arguments = ["vpc", "security-group", "update-rules", "--id", plan.before.resource.reference.resourceId, "--async", "--print-metadata"]

    if plan.deletionRuleIds:
        arguments.extend(("--delete-rule-id", ",".join(plan.deletionRuleIds)))

    addition = plan.Addition

    if addition is not None:
        arguments.extend(("--add-rule", "description=" + addition.description + ",direction=ingress,protocol=" + addition.protocol
                          + ",port=" + str(addition.fromPort) + ",v4-cidrs=[" + ",".join(addition.ipv4Cidrs) + "]"))

    result = provider._MutationRun(tuple(arguments), "vpn-ingress-update")
    operation = _Operation(result.stdout, plan)

    return IngressOperationReference(operation["id"], plan.before.resource.reference.resourceId, plan.Fingerprint())


def Inspect(provider: VpnYandexProvider, plan: IngressDelta, reference: IngressOperationReference) -> IngressOperation:
    """Observe the retained operation once, then require its exact success response and fresh full-policy readback."""

    _Scope(provider, plan)

    if (not isinstance(reference, IngressOperationReference) or reference.resourceId != plan.before.resource.reference.resourceId
            or reference.planSha256 != plan.Fingerprint()):
        raise MutationError(ProviderErrorCode.CONFLICT, "vpn-ingress-reference", False)

    result = provider._Run(("operation", "get", reference.operationId, "--print-metadata"), "vpn-ingress-operation")
    operation = _Operation(result.stdout, plan, reference.operationId)
    added = tuple(sorted(operation["metadata"].get("added_rule_ids", [])))
    code = operation["error"]["code"] if operation.get("error") is not None else None

    if not operation.get("done", False):
        return IngressOperation(reference, "pending", added, code)

    if code is not None:
        return IngressOperation(reference, "failed", added, code)

    try:
        response = operation["response"]
        resource = provider._ValidateObservation(provider._NormalizeResource(response, ResourceKind.SECURITY_GROUP, "vpn-ingress-result"))
        snapshot = ParseSecurityGroup(response, resource)

        if plan.ValidateResult(snapshot) != added:
            raise ValueError

        current = provider.ReadSecurityGroupRules(plan.before.resource)

        if plan.ValidateResult(current) != added or current != snapshot:
            raise ValueError

    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, ProviderError):
        pass

    else:
        return IngressOperation(reference, "complete", added, policy=current)

    raise MutationError(ProviderErrorCode.CONFLICT, "vpn-ingress-readback", True)
