"""Bind immutable protocol epochs to closed peer segments and complete nonsecret transition evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, cast

from flayer import _vpn_revisions as revisions
from flayer._vpn_artifact_metadata import BundleSummary, ReadSummary
from flayer._vpn_creation import (
    _SERVER_FILES,
    BundleDigest,
    CreationBaseline,
    LoadCreationBaseline,
    _Decode,
    _Json,
)
from flayer._vpn_host_input import InputPolicy, InputTransition
from flayer._vpn_ingress_journal import IngressJournal
from flayer._vpn_protocol_sources import DecodeSource, ProtocolSource, ReadSourceMetadata
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.guest import PrivatePath, ReadPrivate
from flayer.profiles import _host_input_policy as inputCodec
from flayer.profiles import _protocol_reservation as reservations
from flayer.profiles.artifacts import (
    MAX_ARTIFACT_BYTES,
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
)
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import ExpectedRules, RuleSemantics, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import IngressOperation, IngressOperationReference
from flayer.providers._yandex_ingress_records import (
    DecodePlan,
    EncodePlan,
    _Closed,
    _Listener,
    _Snapshot,
)
from flayer.vpn_project import SelectedVpnProject

_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_PROTOCOL_EPOCHS = 4096
MAX_GRAPH_BYTES = 16 * 1024 * 1024


def _SnapshotRecord(snapshot: SecurityGroupSnapshot) -> dict[str, Any]:
    """Exclude hidden model/scalar fields before copying complete public cloud policy into an epoch."""

    if type(snapshot) is not SecurityGroupSnapshot:
        raise VpnError("Protocol epoch requires an exact complete cloud policy snapshot")

    _Closed(snapshot, [65536])

    return cast(dict[str, Any], json.loads(_Json(_WireDict(snapshot))))


def _Reference(plan: IngressDelta, operation: IngressOperation | None, snapshot: SecurityGroupSnapshot, *, allowFailure: bool = False, unchanged: bool = False) -> dict[str, Any]:
    """Accept a known terminal operation with exact scope, complete policy and actual allocated-rule evidence."""

    if (type(operation) is not IngressOperation or type(operation.reference) is not IngressOperationReference
            or any(type(value) is not str for value in (operation.reference.operationId, operation.reference.resourceId,
                                                       operation.reference.planSha256, operation.status))
            or operation.status not in {"complete", "failed"} or type(operation.addedRuleIds) is not tuple
            or any(type(value) is not str for value in operation.addedRuleIds)
            or operation.reference.resourceId != plan.before.resource.reference.resourceId or operation.reference.planSha256 != plan.Fingerprint()):
        raise VpnError("Protocol epoch requires a known terminal cloud operation bound to its exact plan")

    IngressOperationReference.__post_init__(operation.reference)
    _SnapshotRecord(snapshot)

    if unchanged:
        plan.CheckBefore(snapshot)

    else:
        plan.ValidateResult(snapshot)

    if operation.status == "failed":
        if (not allowFailure or type(operation.errorCode) is not int or not 1 <= operation.errorCode <= 16
                or operation.policy is not None or operation.addedRuleIds):
            raise VpnError("Protocol epoch requires a known terminal failure and separately verified complete policy")

    elif (unchanged or operation.errorCode is not None or operation.policy is None
          or _Json(_SnapshotRecord(operation.policy)) != _Json(_SnapshotRecord(snapshot))
          or operation.addedRuleIds != plan.ValidateResult(snapshot)):
        raise VpnError("Protocol epoch cloud operation differs from its exact complete readback")

    return {"reference": _WireDict(operation.reference), "status": operation.status,
            "added_rule_ids": operation.addedRuleIds, "error_code": operation.errorCode}


def RestorationNonce(operationId: str) -> str:
    """Separate the explicitly planned compensation from a retried original cloud dispatch."""

    if type(operationId) is not str or _NONCE.fullmatch(operationId) is None:
        raise VpnError("Protocol restoration requires the full original operation nonce")

    return hashlib.sha256(("f-layer/protocol/restore/v1:" + operationId).encode()).hexdigest()[:32]


def RequireCloudEvidenceCapacity(plan: IngressDelta) -> None:
    """Reserve conservative complete rollback/readback space before a coordinator may expose any cloud write."""

    # Two full plans, their snapshots and bounded fresh rule/operation IDs fit within this conservative envelope.
    if 6 * len(EncodePlan(plan)) + 32768 > MAX_ARTIFACT_BYTES:
        raise VpnError("Protocol plan leaves insufficient bounded space for complete cloud recovery evidence")


@dataclass(frozen=True, slots=True)
class CloudEvidence:
    """A committed delta or a known no-op, retaining actual restored provider IDs instead of guessing old rules."""

    plan: IngressDelta
    result: SecurityGroupSnapshot
    outcome: str
    operation: IngressOperation | None = None
    applied: SecurityGroupSnapshot | None = None
    restoration: IngressDelta | None = None
    restorationOperation: IngressOperation | None = None

    def __post_init__(self) -> None:
        """Reject pending/unknown outcomes and collateral rollback before immutable epoch preparation."""

        if type(self) is not CloudEvidence or type(self.outcome) is not str or self.outcome not in {"committed", "not-applied"}:
            raise VpnError("Protocol cloud evidence requires one exact supported outcome")

        RequireCloudEvidenceCapacity(self.plan)
        _SnapshotRecord(self.result)

        if self.outcome == "committed":
            if self.applied is not None or self.restoration is not None or self.restorationOperation is not None:
                raise VpnError("Committed protocol cloud evidence cannot contain compensation")

            _Reference(self.plan, self.operation, self.result)

        elif self.applied is None:
            if (self.restoration is not None or self.restorationOperation is not None
                    or _Json(_SnapshotRecord(self.result)) != _Json(_SnapshotRecord(self.plan.before))):
                raise VpnError("Unchanged protocol outcome requires exact old cloud policy and no compensation")

            if self.operation is not None:
                _Reference(self.plan, self.operation, self.result, allowFailure=True, unchanged=True)

        else:
            _Reference(self.plan, self.operation, self.applied, allowFailure=True)

            if type(self.restoration) is not IngressDelta:
                raise VpnError("Applied protocol rollback requires its exact separately planned inverse operation")

            EncodePlan(self.restoration)
            expected = "disable" if self.plan.change == "enable" else "enable"

            if (self.restoration.change != expected or self.restoration.identity != self.plan.identity
                    or self.restoration.creationSpec != self.plan.creationSpec or self.restoration.networkId != self.plan.networkId
                    or self.restoration.listener != self.plan.listener
                    or self.restoration.operationId != RestorationNonce(self.plan.operationId)
                    or _Json(_SnapshotRecord(self.restoration.before)) != _Json(_SnapshotRecord(self.applied))):
                raise VpnError("Protocol restoration changes more than the exact inverse owned listener delta")

            restored = _Reference(self.restoration, self.restorationOperation, self.result, allowFailure=True)

            if self.operation is not None and restored["reference"]["operation_id"] == self.operation.reference.operationId:
                raise VpnError("Protocol restoration cannot reuse the original provider operation")

    def Record(self) -> dict[str, Any]:
        """Retain only closed full public plans/readbacks and verified terminal operation references."""

        CloudEvidence.__post_init__(self)

        return {"schema_version": 1, "plan": json.loads(EncodePlan(self.plan)), "result": _SnapshotRecord(self.result), "outcome": self.outcome,
                "operation": _Reference(self.plan, self.operation, self.applied if self.applied is not None else self.result,
                    allowFailure=self.outcome == "not-applied", unchanged=self.outcome == "not-applied" and self.applied is None) if self.operation is not None else None,
                "applied": _SnapshotRecord(self.applied) if self.applied is not None else None,
                "restoration": json.loads(EncodePlan(self.restoration)) if self.restoration is not None else None,
                "restoration_operation": _Reference(self.restoration, self.restorationOperation, self.result, allowFailure=True) if self.restoration is not None else None}


def _Operation(value: object, snapshot: SecurityGroupSnapshot) -> IngressOperation | None:
    """Reconstruct only a complete bounded acknowledgement; unknown or pending data is not epoch evidence."""

    if value is None:
        return None

    if (type(value) is not dict or set(value) != {"reference", "status", "added_rule_ids", "error_code"}
            or type(value["reference"]) is not dict or set(value["reference"]) != {"operation_id", "resource_id", "plan_sha256"}
            or any(type(item) is not str for item in value["reference"].values())
            or type(value["status"]) is not str or value["status"] not in {"complete", "failed"}
            or type(value["added_rule_ids"]) is not list or any(type(item) is not str for item in value["added_rule_ids"])):
        raise VpnError("Retained protocol cloud operation has an unsupported public schema")

    reference = value["reference"]

    return IngressOperation(IngressOperationReference(reference["operation_id"], reference["resource_id"], reference["plan_sha256"]),
                            value["status"], tuple(value["added_rule_ids"]), value["error_code"], snapshot if value["status"] == "complete" else None)


def DecodeCloudEvidence(content: bytes) -> CloudEvidence:
    """Verify exact canonical complete cloud evidence without retaining raw parser context in diagnostics."""

    result = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= MAX_ARTIFACT_BYTES:
            raise ValueError

        value = _Decode(content)

        if (set(value) != {"schema_version", "plan", "result", "outcome", "operation", "applied", "restoration", "restoration_operation"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1):
            raise ValueError

        applied = _Snapshot(value["applied"]) if value["applied"] is not None else None
        final = _Snapshot(value["result"])
        candidate = CloudEvidence(DecodePlan(_Json(value["plan"])), final, value["outcome"], _Operation(value["operation"], applied or final),
                                 applied, DecodePlan(_Json(value["restoration"])) if value["restoration"] is not None else None,
                                 _Operation(value["restoration_operation"], final))

        if _Json(candidate.Record()) != content:
            raise ValueError

        result = candidate

    except (ValueError, TypeError, RecursionError):
        pass

    if result is None:
        raise VpnError("Retained protocol cloud evidence is invalid, unknown or noncanonical")

    return result


def _Hash(value: object, *, empty: bool = False) -> bool:
    """Keep every public authority scalar plain and either a complete digest or an explicitly allowed absence."""

    return type(value) is str and (empty and value == "" or _HASH.fullmatch(value) is not None)


def _Pointer(value: object, pattern: str) -> dict[str, str] | None:
    """Confine immutable parent references to their full owner namespace and complete digest."""

    if value is None:
        return None

    if (type(value) is not dict or set(value) != {"name", "sha256"} or type(value["name"]) is not str
            or re.fullmatch(pattern, value["name"]) is None or not _Hash(value["sha256"])):
        raise VpnError("Protocol epoch parent reference is invalid or outside its owned namespace")

    return dict(value)


@dataclass(frozen=True, slots=True)
class ServiceProof:
    """Public source-bound receipt/absence reference; live verification remains the authenticated guest boundary's responsibility."""

    protocol: str
    sourceSha256: str
    state: str
    receiptSha256: str = ""
    absenceSha256: str = ""

    def __post_init__(self) -> None:
        """Reject incomplete or contradictory active/absent facts before epoch serialization."""

        if (type(self) is not ServiceProof or type(self.protocol) is not str or self.protocol not in _SERVER_FILES
                or type(self.state) is not str or self.state not in {"active", "absent"} or not _Hash(self.sourceSha256)
                or not _Hash(self.receiptSha256, empty=True) or not _Hash(self.absenceSha256, empty=True)
                or self.state == "active" and (not self.receiptSha256 or self.absenceSha256 != "")
                or self.state == "absent" and (self.receiptSha256 != "" or not self.absenceSha256)):
            raise VpnError("Protocol service proof requires exact source and active receipt or complete absence")

    def Record(self) -> dict[str, Any]:
        """Serialize no command output, native configuration or private credential body."""

        ServiceProof.__post_init__(self)

        return _WireDict(self)


@dataclass(frozen=True, slots=True)
class InputEvidence:
    """One complete public input delta and a verified terminal receipt or explicitly unchanged policy."""

    transition: InputTransition
    outcome: str
    nativeSha256: str
    journalSha256: str = ""

    def __post_init__(self) -> None:
        """Bind terminal policy bytes to their exact generation without treating a native hash alone as live attestation."""

        if (type(self) is not InputEvidence or type(self.transition) is not InputTransition
                or type(self.outcome) is not str or self.outcome not in {"applied", "unchanged", "rolled-back"}
                or not _Hash(self.nativeSha256) or not _Hash(self.journalSha256, empty=True)
                or bool(self.journalSha256) != (self.outcome != "unchanged")):
            raise VpnError("Protocol input evidence requires a complete supported terminal result")

        InputTransition.__post_init__(self.transition)
        self.transition.Record()

    def Policy(self) -> InputPolicy:
        """Retain the new marker on rollback and the original marker only for a never-mutated input policy."""

        InputEvidence.__post_init__(self)

        return (self.transition.After() if self.outcome == "applied" else self.transition.Restored()
                if self.outcome == "rolled-back" else self.transition.before)

    def Record(self) -> dict[str, Any]:
        """Preserve the complete public delta and final boot/native receipt references."""

        policy = self.Policy()
        boot = policy.BootFile() if policy.operationId else policy._OriginalFile()

        return {"schema_version": 1, "transition": self.transition.Record(), "outcome": self.outcome,
                "native_sha256": self.nativeSha256, "journal_sha256": self.journalSha256, "boot_sha256": hashlib.sha256(boot).hexdigest()}


def _InputPolicy(value: object) -> InputPolicy:
    """Reconstruct the typed facade only after the shared stdlib record passes complete validation."""

    data = inputCodec.Policy(value)
    identity = data["identity"]

    return InputPolicy(StackIdentity(identity["project"], identity["stack"], identity["provider"], identity["scope_id"], identity["owner_id"]),
                       data["creation_sha256"], data["original_boot_sha256"], tuple(data["management_cidrs"]),
                       tuple(_Listener(item) for item in data["listeners"]), data["operation_id"])


def DecodeInputEvidence(content: bytes) -> InputEvidence:
    """Reject incomplete terminal input metadata, aliases and raw parser state before graph traversal."""

    result = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= 32768:
            raise ValueError

        value = _Decode(content)

        if (set(value) != {"schema_version", "transition", "outcome", "native_sha256", "journal_sha256", "boot_sha256"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1):
            raise ValueError

        before, _, _ = inputCodec.Transition(value["transition"])
        transition = value["transition"]
        candidate = InputEvidence(InputTransition(_InputPolicy(before), _Listener(transition["listener"]), transition["change"], transition["operation_id"]),
                                  value["outcome"], value["native_sha256"], value["journal_sha256"])

        if _Json(candidate.Record()) != content:
            raise ValueError

        result = candidate

    except (ValueError, TypeError, RecursionError):
        pass

    if result is None:
        raise VpnError("Retained protocol input evidence is invalid or noncanonical")

    return result


def _Services(content: bytes) -> tuple[ServiceProof, ...]:
    """Decode a bounded canonical closed public proof list with no arbitrary native reply fields."""

    value = _Decode(content)

    if (set(value) != {"schema_version", "services"} or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["services"]) is not list or not 1 <= len(value["services"]) <= 3):
        raise VpnError("Protocol service evidence has an unsupported bounded schema")

    result = []

    for raw in value["services"]:
        if type(raw) is not dict or set(raw) != {"protocol", "source_sha256", "state", "receipt_sha256", "absence_sha256"}:
            raise VpnError("Protocol service evidence has unknown or missing public fields")

        result.append(ServiceProof(raw["protocol"], raw["source_sha256"], raw["state"], raw["receipt_sha256"], raw["absence_sha256"]))

    return tuple(result)


def _Metadata(content: bytes, identity: StackIdentity) -> dict[str, Any]:
    """Validate closed authorizing intent before any graph lookup or recursive serialization."""

    if (type(identity) is not StackIdentity or any(type(item) is not str for item in (identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId))
            or type(content) is not bytes or not 1 <= len(content) <= 32768):
        raise VpnError("Protocol epoch intent requires bounded bytes and an exact complete owner")

    value = _Decode(content)
    fields = {"schema_version", "identity", "creation_sha256", "parent", "closed_peer_head", "closed_peer_head_sha256", "closed_peer_count",
              "previous_state_sha256", "sources", "configured_listeners", "active_protocols", "static_fingerprint", "wireguard_receipt_sha256",
              "wireguard_history_sha256", "generation_receipt_sha256", "reservation", "authority_parent", "ingress_intents", "cloud_sha256", "input_sha256", "services_sha256"}

    if (type(identity) is not StackIdentity or any(type(item) is not str for item in (identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId))
            or type(content) is not bytes or not 1 <= len(content) <= 32768 or set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["identity"] != _WireDict(identity)
            or any(not _Hash(value[key]) for key in ("creation_sha256", "closed_peer_head_sha256", "previous_state_sha256", "static_fingerprint",
                                                   "wireguard_history_sha256", "cloud_sha256", "input_sha256", "services_sha256"))
            or any(not _Hash(value[key], empty=True) for key in ("wireguard_receipt_sha256", "generation_receipt_sha256"))
            or type(value["closed_peer_count"]) is not int or not 0 <= value["closed_peer_count"] <= 4096
            or type(value["sources"]) is not list or not 1 <= len(value["sources"]) <= 3
            or type(value["configured_listeners"]) is not list or type(value["active_protocols"]) is not list
            or type(value["ingress_intents"]) is not list or len(value["ingress_intents"]) > 2):
        raise VpnError("Protocol epoch intent has invalid closed authority fields")

    parent = _Pointer(value["parent"], re.escape(identity.stack) + r"-ep-[0-9a-f]{16}")
    peer = _Pointer(value["closed_peer_head"], re.escape(identity.stack) + r"-wc-[0-9a-f]{16}")
    _Pointer(value["authority_parent"], r"done-[0-9a-f]{32}\.json")
    reservation = reservations.Intent(value["reservation"])
    sources = tuple(DecodeSource(item, identity) for item in value["sources"])
    protocols = tuple(source.pin.protocol for source in sources)
    active = value["active_protocols"]

    for reference in value["ingress_intents"]:
        if (type(reference) is not dict or set(reference) != {"role", "name", "sha256"}
                or type(reference["role"]) is not str or reference["role"] not in {"change", "restoration"}):
            raise VpnError("Protocol epoch ingress reference has unknown or missing fields")

        _Pointer({key: reference[key] for key in ("name", "sha256")}, re.escape(identity.stack) + r"-ip-[0-9a-f]{16}")

    if len({item["role"] for item in value["ingress_intents"]}) != len(value["ingress_intents"]):
        raise VpnError("Protocol epoch has duplicate ingress intent roles")

    if (protocols != tuple(protocol for protocol in _SERVER_FILES if protocol in protocols)
            or len(set(protocols)) != len(protocols) or any(type(item) is not str for item in active)
            or active != [protocol for protocol in protocols if protocol in active] or len(set(active)) != len(active)
            or len(value["configured_listeners"]) != len(protocols)
            or tuple(inputCodec.Listener(item)["transport"] for item in value["configured_listeners"]) != protocols
            or bool(value["wireguard_receipt_sha256"]) != ("wireguard" in active)
            or bool(peer) != bool(value["closed_peer_count"])
            or value["closed_peer_head_sha256"] != (hashlib.sha256(_Json(peer)).hexdigest() if peer is not None
                                                    else parent["sha256"] if parent is not None else value["creation_sha256"])
            or reservation["creation_sha256"] != value["creation_sha256"] or reservation["previous_state_sha256"] != value["previous_state_sha256"]
            or content != _Json(value)):
        raise VpnError("Protocol epoch intent has inconsistent selection, segment closure or reservation")

    return value


@dataclass(frozen=True, slots=True)
class EpochCommit:
    """Immutable authorizing intent and verified guest completion, with no cyclic dependence on its final bundle digest."""

    identity: StackIdentity
    metadata: bytes = field(repr=False)
    cloud: CloudEvidence
    input: InputEvidence
    services: tuple[ServiceProof, ...]
    completion: bytes = field(repr=False)

    def __post_init__(self) -> None:
        """Cross-bind all complete public proof bytes and consumed guest authority before preparing a graph record."""

        if (type(self) is not EpochCommit or type(self.cloud) is not CloudEvidence or type(self.input) is not InputEvidence
                or type(self.services) is not tuple or any(type(item) is not ServiceProof for item in self.services)
                or type(self.completion) is not bytes or not 1 <= len(self.completion) <= 8192):
            raise VpnError("Protocol epoch commit requires exact complete public models and guest completion")

        CloudEvidence.__post_init__(self.cloud)
        InputEvidence.__post_init__(self.input)
        metadata = _Metadata(self.metadata, self.identity)
        reservation = reservations.Intent(metadata["reservation"])
        plan = self.cloud.plan
        transition = self.input.transition
        services = {proof.protocol: proof for proof in self.services}
        policy = self.input.Policy()
        expected = {source["pin"]["protocol"]: source["pin"]["server_digest"] for source in metadata["sources"]}
        configured = {_Listener(item).transport: _Listener(item) for item in metadata["configured_listeners"]}
        ingressRoles = {item["role"] for item in metadata["ingress_intents"]}

        if (self.cloud.outcome == "committed" and self.input.outcome != "applied"
                or self.cloud.outcome == "not-applied" and self.input.outcome == "applied"
                or self.cloud.outcome == "not-applied" and plan.change == "enable" and self.cloud.operation is not None and self.input.outcome != "rolled-back"
                or plan.identity != self.identity or policy.identity != self.identity or policy.creationSha256 != metadata["creation_sha256"]
                or plan.operationId != reservation["operation_id"] or transition.operationId != plan.operationId
                or transition.listener != plan.listener or transition.change != plan.change
                or self.cloud.operation is not None and "change" not in ingressRoles
                or self.cloud.restoration is not None and "restoration" not in ingressRoles
                or self.cloud.restoration is None and "restoration" in ingressRoles
                or reservation["plan_sha256"] != hashlib.sha256(_Json({"schema_version": 1, "cloud_plan_sha256": plan.Fingerprint(),
                                                                       "input": transition.Record()})).hexdigest()
                or tuple(proof.protocol for proof in self.services) != tuple(expected) or set(services) != set(expected)
                or {listener.transport: listener for listener in policy.listeners} != {protocol: configured[protocol] for protocol in metadata["active_protocols"]}
                or any(proof.sourceSha256 != expected[proof.protocol] or (proof.state == "active") != (proof.protocol in metadata["active_protocols"])
                       for proof in self.services)
                or "wireguard" in services and services["wireguard"].receiptSha256 != metadata["wireguard_receipt_sha256"]
                or metadata["cloud_sha256"] != hashlib.sha256(_Json(self.cloud.Record())).hexdigest()
                or metadata["input_sha256"] != hashlib.sha256(_Json(self.input.Record())).hexdigest()
                or metadata["services_sha256"] != hashlib.sha256(self.ServiceBytes()).hexdigest()):
            raise VpnError("Protocol epoch evidence differs from its exact intent, sources, listener delta or active receipts")

        owner = hashlib.sha256(json.dumps(_WireDict(self.identity), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        if reservation["owner"] != owner:
            raise VpnError("Protocol epoch reservation belongs to another complete owner")

        absence = hashlib.sha256(_Json({"domain": "f-layer/wireguard/absent/v1", "owner": owner})).hexdigest()

        if (reservation["wireguard_state"] == "absent" and reservation["wireguard_absence_sha256"] != absence
                or "wireguard" in services and services["wireguard"].state == "absent" and services["wireguard"].absenceSha256 != absence):
            raise VpnError("Protocol epoch absence proof belongs to another WG namespace")

        previousActive = any(listener.transport == "wireguard" for listener in transition.before.listeners)
        generation = metadata["generation_receipt_sha256"]

        if (previousActive != (reservation["wireguard_state"] == "active")
                or previousActive and metadata["wireguard_history_sha256"] == reservation["wireguard_history_sha256"]
                or plan.listener.transport != "wireguard" and generation
                or plan.listener.transport == "wireguard" and plan.change == "disable" and generation
                or plan.listener.transport == "wireguard" and plan.change == "enable" and self.cloud.outcome == "committed"
                and (not generation or generation != metadata["wireguard_receipt_sha256"])
                or generation and metadata["wireguard_history_sha256"] == reservation["wireguard_history_sha256"]
                or not previousActive and not generation and metadata["wireguard_history_sha256"] != reservation["wireguard_history_sha256"]
                or previousActive and plan.listener.transport != "wireguard" and metadata["wireguard_receipt_sha256"] != reservation["wireguard_receipt_sha256"]):
            raise VpnError("Protocol epoch loses its actual preceding WG state, consumed fence or new installation generation")

        completion = _Decode(self.completion)
        fields = {"schema_version", "owner", "creation_sha256", "operation_id", "intent_sha256", "parent", "previous_authority_sha256", "history_sha256", "outcome"}

        if (set(completion) != fields or type(completion["schema_version"]) is not int or completion["schema_version"] not in {1, 2}
                or completion["owner"] != owner or completion["creation_sha256"] != metadata["creation_sha256"]
                or completion["operation_id"] != reservation["operation_id"] or completion["parent"] != metadata["authority_parent"]
                or completion["previous_authority_sha256"] != reservation["previous_authority_sha256"]
                or completion["history_sha256"] != metadata["wireguard_history_sha256"] or self.completion != _Json(completion)):
            raise VpnError("Protocol epoch guest completion does not consume its exact preceding authority")

        if completion["schema_version"] == 1:
            if (completion["outcome"] != "cancelled" or self.cloud.outcome != "not-applied" or self.cloud.operation is not None
                    or self.input.outcome != "unchanged" or completion["intent_sha256"] != hashlib.sha256(_Json(reservation)).hexdigest()):
                raise VpnError("Legacy unexposed cancellation cannot claim an exposed protocol transition")

        elif completion["outcome"] != self.cloud.outcome or completion["intent_sha256"] != hashlib.sha256(self.metadata).hexdigest():
            raise VpnError("Protocol completion does not bind the complete canonical epoch intent")

    def ServiceBytes(self) -> bytes:
        """Bind the ordered complete public service-proof list independently of the final epoch record."""

        if type(self.services) is not tuple or any(type(proof) is not ServiceProof for proof in self.services):
            raise VpnError("Protocol service evidence requires closed immutable proof models")

        return _Json({"schema_version": 1, "services": [proof.Record() for proof in self.services]})

    def Bundle(self) -> ArtifactBundle:
        """Include completion after intent binding, then use the resulting full bundle digest as the next peer genesis."""

        EpochCommit.__post_init__(self)
        metadata = _Metadata(self.metadata, self.identity)
        name = self.identity.stack + "-ep-" + hashlib.sha256(metadata["reservation"]["operation_id"].encode()).hexdigest()[:16]

        return ArtifactBundle(self.identity, "server", name, (
            Artifact("epoch.json", _Json({"schema_version": 1, "intent": _Decode(self.metadata), "completion": _Decode(self.completion)}), False),
            Artifact("cloud.json", _Json(self.cloud.Record()), False), Artifact("input.json", _Json(self.input.Record()), False),
            Artifact("services.json", self.ServiceBytes(), False)))

    def Digest(self) -> str:
        """Retain exact complete file/owner identity for immutable graph pointers and the next peer segment."""

        return BundleDigest(self.Bundle())


def DecodeEpochBundle(bundle: ArtifactBundle) -> EpochCommit:
    """Require exact complete public epoch files and rerun all intent/completion cross-bindings."""

    result = None

    try:
        if (type(bundle) is not ArtifactBundle or type(bundle.identity) is not StackIdentity
                or type(bundle.kind) is not str or bundle.kind != "server" or type(bundle.files) is not tuple
                or any(type(item) is not Artifact or type(item.content) is not bytes or item.sensitive is not False for item in bundle.files)
                or {item.name for item in bundle.files} != {"epoch.json", "cloud.json", "input.json", "services.json"}):
            raise ValueError

        files = {item.name: item.content for item in bundle.files}
        value = _Decode(files["epoch.json"])

        if set(value) != {"schema_version", "intent", "completion"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError

        candidate = EpochCommit(bundle.identity, _Json(value["intent"]), DecodeCloudEvidence(files["cloud.json"]),
                                DecodeInputEvidence(files["input.json"]), _Services(files["services.json"]), _Json(value["completion"]))

        if candidate.Bundle() != bundle:
            raise ValueError

        result = candidate

    except (ValueError, TypeError, RecursionError, KeyError):
        pass

    if result is None:
        raise VpnError("Protocol epoch bundle is incomplete, foreign or noncanonical")

    return result


def _ReadEpoch(project: SelectedVpnProject, pointer: dict[str, str]) -> EpochCommit:
    """Verify public roles before opening content; graph traversal never opens a private payload through an epoch alias."""

    name = pointer["name"]
    directory = project.Artifacts / ("server-" + name)
    summary, _ = ReadSummary(directory, project.vpn.identity, name, pointer["sha256"])
    names = ("epoch.json", "cloud.json", "input.json", "services.json")

    if {item.name for item in summary.files} != set(names) or any(item.sensitive for item in summary.files):
        raise VpnError("Protocol epoch cannot redirect traversal into private or unknown artifact roles")

    bundle = ArtifactBundle(project.vpn.identity, "server", name, tuple(Artifact(filename,
        ReadOwnedArtifactFile(directory / filename, project.vpn.identity, kind="server", name=name), False) for filename in names))

    if BundleDigest(bundle) != pointer["sha256"]:
        raise VpnError("Protocol epoch differs from its complete externally pinned public bundle")

    return DecodeEpochBundle(bundle)


def _Sources(project: SelectedVpnProject, state: revisions.RevisionState) -> tuple[ProtocolSource, ...]:
    """Resolve only the effective source in one verified segment, preserving all unrelated retained protocol roles."""

    original = state.segment.sources if state.segment is not None else tuple(ProtocolSource(project.vpn.identity, pin) for pin in state.baseline.protocols)

    return tuple(ProtocolSource(project.vpn.identity, pin, "peer", state.activeRecord["request_name"], state.activeRecord["request_sha256"])
                 if pin.protocol == "wireguard" and state.activeRecord is not None else next(source for source in original if source.pin.protocol == pin.protocol)
                 for pin in state.pins)


@dataclass(frozen=True, slots=True)
class ProtocolGraph:
    """A verified local committed graph; this alone is not cloud/guest health or permission to mutate."""

    baseline: CreationBaseline
    epochs: tuple[EpochCommit, ...]
    revision: revisions.RevisionState
    head: dict[str, str] | None
    sources: tuple[ProtocolSource, ...]
    activeProtocols: tuple[str, ...]
    artifactNames: frozenset[str]

    def Fingerprint(self) -> str:
        """Close current peer and epoch authority without depending on edited desired settings or private-key availability."""

        return hashlib.sha256(_Json({"creation_sha256": BundleDigest(self.baseline.bundle), "epoch": self.head,
            "peer_head_sha256": self.revision.headDigest, "sources": [source.Record() for source in self.sources],
            "active_protocols": self.activeProtocols, "receipt_sha256": self.revision.receipt, "history_sha256": self.revision.history})).hexdigest()


def RequireGraphCapacity(graph: ProtocolGraph, plan: IngressDelta) -> None:
    """Reserve one complete worst-case epoch before a coordinator may consume guest or cloud authority."""

    if type(graph) is not ProtocolGraph:
        raise VpnError("Protocol capacity requires an exact verified committed graph")

    RequireCloudEvidenceCapacity(plan)
    records = graph.revision.recordCount + sum(_Metadata(epoch.metadata, epoch.identity)["closed_peer_count"] + 1 for epoch in graph.epochs)
    size = sum(sum(len(item.content) for item in epoch.Bundle().files) for epoch in graph.epochs)

    if records >= MAX_PROTOCOL_EPOCHS or size + MAX_ARTIFACT_BYTES + 65536 > MAX_GRAPH_BYTES:
        raise VpnError("Protocol graph lacks complete bounded operation or recovery-evidence capacity")


def _MetadataSources(project: SelectedVpnProject, sources: tuple[ProtocolSource, ...]) -> dict[str, tuple[BundleSummary, BundleSummary, dict[str, Any] | None]]:
    """Validate the complete nonsecret source-role pins, including inactive retained material, without opening private bodies."""

    return {source.pin.protocol: ReadSourceMetadata(project, source) for source in sources}


def _ClosedPeers(project: SelectedVpnProject, state: revisions.RevisionState) -> set[str]:
    """Verify retained peer-request metadata for every completed record, including superseded and cancelled candidates."""

    if revisions.Pending(project, segment=state.segment) is not None:
        raise VpnError("A protocol epoch cannot close a segment with an unresolved peer transaction")

    current = state.head
    count = 0
    names: set[str] = set()
    genesis = state.segment.genesis if state.segment is not None else BundleDigest(state.baseline.bundle)

    while current is not None:
        count += 1

        if count > state.recordCount or current["name"] in names:
            raise VpnError("Closed peer segment changed or became cyclic during epoch traversal")

        names.add(current["name"])
        bundle = revisions._ReadBundle(project, current["name"], current["sha256"], ("record.json",))
        record = revisions._CompletionRecord(project, bundle.files[0].content, BundleDigest(state.baseline.bundle), genesis=genesis)

        if record["request_sha256"]:
            pin = revisions._Pin(record["desired_pin"])
            source = ProtocolSource(project.vpn.identity, pin, "peer", record["request_name"], record["request_sha256"])
            _, _, metadata = ReadSourceMetadata(project, source)

            if metadata is None or _Json(metadata) != _Json({key: (1 if key == "schema_version" else "" if key == "request_sha256" else record[key]) for key in metadata}):
                raise VpnError("Closed peer request does not match its exact completion metadata")

            names.add(source.requestName)

        current = revisions._Pointer(record["parent"], project)

    if count != state.recordCount:
        raise VpnError("Closed peer segment lost a previously verified completion")

    return names


def _Segment(epoch: EpochCommit) -> revisions.PeerSegment:
    """Use the complete final epoch bundle as the next independent mutable peer namespace genesis."""

    value = _Metadata(epoch.metadata, epoch.identity)

    return revisions.PeerSegment(epoch.Digest(), tuple(DecodeSource(item, epoch.identity) for item in value["sources"]),
                                 tuple(value["active_protocols"]), value["static_fingerprint"], value["wireguard_receipt_sha256"], value["wireguard_history_sha256"])


def _History(project: SelectedVpnProject, epoch: EpochCommit, before: ProtocolGraph, summaries: dict[str, tuple[BundleSummary, BundleSummary, dict[str, Any] | None]]) -> None:
    """Prove the same v1 fence understood by queued old drivers without reading private deployment/configuration bodies."""

    value = _Metadata(epoch.metadata, project.vpn.identity)
    reservation = value["reservation"]
    oldActive = "wireguard" in before.activeProtocols

    if (reservation["wireguard_history_sha256"] != before.revision.history
            or oldActive != (reservation["wireguard_state"] == "active")
            or oldActive and before.revision.receipt and reservation["wireguard_receipt_sha256"] != before.revision.receipt):
        raise VpnError("Protocol epoch does not continue its exact preceding WG receipt/history")

    receipt = value["generation_receipt_sha256"] if value["generation_receipt_sha256"] else reservation["wireguard_receipt_sha256"]
    expected = before.revision.history

    if receipt:
        source = summaries["wireguard"][1]
        deployment = next(item.sha256 for item in source.files if item.name == "deployment.json")
        expected = revisions.CommittedHistory(project, "revoke", "protocol-" + reservation["operation_id"], receipt, receipt, deployment, before.revision.history)

    if value["wireguard_history_sha256"] != expected:
        raise VpnError("Protocol epoch does not retain its exact consumed old-driver-compatible WG history")


def _Continue(project: SelectedVpnProject, before: ProtocolGraph, epoch: EpochCommit) -> None:
    """Prove closure and one explicit configured/active transition before admitting another peer segment."""

    value = _Metadata(epoch.metadata, project.vpn.identity)
    plan, reservation = epoch.cloud.plan, value["reservation"]
    currentSources = _Sources(project, before.revision)
    desired = tuple(DecodeSource(item, project.vpn.identity) for item in value["sources"])
    old = {source.pin.protocol: source for source in currentSources}
    new = {source.pin.protocol: source for source in desired}
    target = plan.listener.transport
    active = set(before.activeProtocols)
    firewall = next(spec for spec in before.baseline.plan.resources if spec.logicalId == "firewall")

    if (value["creation_sha256"] != BundleDigest(before.baseline.bundle) or value["parent"] != before.head
            or value["closed_peer_head"] != before.revision.head or value["closed_peer_head_sha256"] != before.revision.headDigest
            or value["closed_peer_count"] != before.revision.recordCount or value["previous_state_sha256"] != before.Fingerprint()
            or plan.creationSpec != firewall or set(old) - set(new) or set(new) - set(old) - {target}
            or any(new[name] != source for name, source in old.items() if name != target)
            or plan.change == "disable" and (target not in active or desired != currentSources)
            or plan.change == "enable" and target in active):
        raise VpnError("Protocol epoch changes its immutable creation, closed peer segment or unrelated configured sources")

    initial = epoch.input.transition.before if not before.epochs else before.epochs[-1].input.Policy()

    if not before.epochs:
        from flayer._vpn_host_input import BindBootstrap

        BindBootstrap(before.baseline, initial.managementCidrs, initial.listeners)

        if RuleSemantics(plan.before.rules) != RuleSemantics(ExpectedRules(firewall)):
            raise VpnError("Initial epoch cloud policy differs from its complete frozen creation rules")

    elif plan.before != before.epochs[-1].cloud.result:
        raise VpnError("Protocol epoch does not start from the exact preceding complete cloud receipt")

    if _Json(epoch.input.transition.before.Record()) != _Json(initial.Record()):
        raise VpnError("Protocol epoch input policy does not continue its exact preceding owned generation")

    original = before.epochs[0].input.transition.before if before.epochs else initial
    originalRole = next((listener for listener in original.listeners if listener.transport == target), None)

    if plan.creationListener is not None and plan.creationListener != originalRole:
        raise VpnError("Original cloud allowance is not attested by its immutable creation protocol role")

    if epoch.cloud.outcome == "committed":
        active = active | {target} if plan.change == "enable" else active - {target}

    if tuple(value["active_protocols"]) != tuple(source.pin.protocol for source in desired if source.pin.protocol in active):
        raise VpnError("Protocol epoch active selection differs from its sole known transition outcome")

    summaries = _MetadataSources(project, desired)

    if plan.change == "enable" and (target not in old or new[target] != old[target]):
        metadata = summaries[target][2]

        if (new[target].kind != "protocol" or metadata is None or metadata["operation_id"] != plan.operationId
                or metadata["previous_state_sha256"] != before.Fingerprint()):
            raise VpnError("Protocol enable requires its new exact request and preceding graph authority")

    if before.epochs:
        previous = _Decode(before.epochs[-1].completion)
        authority = {"name": "done-" + previous["operation_id"] + ".json", "sha256": hashlib.sha256(before.epochs[-1].completion).hexdigest()}

    else:
        authority = None

    expectedAuthority = (authority["sha256"] if authority is not None else hashlib.sha256(_Json({"domain": "f-layer/ingress/authority/v1",
        "owner": reservation["owner"], "creation_sha256": value["creation_sha256"]})).hexdigest())

    if value["authority_parent"] != authority or reservation["previous_authority_sha256"] != expectedAuthority:
        raise VpnError("Protocol epoch does not continue the exact preceding common guest authority")

    _History(project, epoch, before, summaries)


def _IngressIntents(project: SelectedVpnProject, epoch: EpochCommit) -> set[str]:
    """Retain complete immutable dispatch intent references, including compensation's independent validity window."""

    metadata = _Metadata(epoch.metadata, project.vpn.identity)
    names = set()

    for reference in metadata["ingress_intents"]:
        name = reference["name"]
        directory = project.Artifacts / ("server-" + name)
        summary, content = ReadSummary(directory, project.vpn.identity, name, reference["sha256"], publicFile="intent.json")

        if len(summary.files) != 1 or summary.files[0].sensitive or content is None:
            raise VpnError("Protocol ingress intent cannot redirect traversal to an unsupported artifact role")

        value = _Decode(content)
        fields = {"schema_version", "identity", "creation_sha256", "previous_state_sha256", "plan_expires_at", "plan_sha256", "plan_record"}

        if set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise VpnError("Retained protocol ingress intent has an unsupported closed schema")

        journal = IngressJournal(DecodePlan(_Json(value["plan_record"])), value["creation_sha256"], value["previous_state_sha256"], value["plan_expires_at"])
        expected = epoch.cloud.plan if reference["role"] == "change" else epoch.cloud.restoration

        if (expected is None or EncodePlan(journal.plan) != EncodePlan(expected) or _Json(journal.Intent()) != content
                or journal.creationSha256 != metadata["creation_sha256"] or journal.previousStateSha256 != metadata["previous_state_sha256"]
                or reference["role"] == "change" and journal.planExpiresAt != metadata["reservation"]["plan_expires_at"]
                or journal.Bundle().name != name or BundleDigest(journal.Bundle()) != reference["sha256"]):
            raise VpnError("Retained ingress intent differs from its exact epoch plan, creation or preceding state")

        names.add(name)

    return names


def LoadCommittedGraph(project: SelectedVpnProject) -> ProtocolGraph:
    """Verify the complete committed local graph; public lifecycle admission remains blocked until coordinator integration."""

    for filename in ("protocol-pending.json", ".protocol-pending.json.new", ".protocol-head.json.new", "protocol-ingress-pending.json", ".protocol-ingress-pending.json.new"):
        path = project.root / filename

        if path.exists() or path.is_symlink():
            raise VpnError("Pending protocol metadata requires exact coordinator recovery before committed graph traversal")

    baseline = LoadCreationBaseline(project)
    path = project.root / "protocol-head.json"
    raw = ReadPrivate(path, limit=65536) if path.exists() or path.is_symlink() else None
    head = _Pointer(_Decode(raw), re.escape(project.vpn.identity.stack) + r"-ep-[0-9a-f]{16}") if raw is not None else None

    if raw is not None and (head is None or raw != _Json(head)):
        raise VpnError("Protocol epoch head must be its exact canonical nonempty pointer")

    current = head
    epochs = []
    visited: set[str] = set()
    total = 0

    while current is not None:
        if current["name"] in visited or len(visited) >= MAX_PROTOCOL_EPOCHS:
            raise VpnError("Protocol epoch history is cyclic or exceeds its bound")

        visited.add(current["name"])
        epoch = _ReadEpoch(project, current)
        total += sum(len(item.content) for item in epoch.Bundle().files)

        if total > MAX_GRAPH_BYTES:
            raise VpnError("Protocol epoch graph exceeds its complete metadata byte bound")

        epochs.append(epoch)
        current = _Pointer(_Metadata(epoch.metadata, project.vpn.identity)["parent"], re.escape(project.vpn.identity.stack) + r"-ep-[0-9a-f]{16}")

    revision = revisions.LoadPeerSegment(project, baseline)
    graph = ProtocolGraph(baseline, (), revision, None, _Sources(project, revision), tuple(pin.protocol for pin in baseline.protocols), frozenset())
    expected: set[str] = set()
    segments: set[str] = set()
    records = 0

    for epoch in reversed(epochs):
        expected.update(_ClosedPeers(project, graph.revision))
        records += graph.revision.recordCount + 1

        if records > MAX_PROTOCOL_EPOCHS:
            raise VpnError("Combined protocol/peer history exceeds its complete operation bound")

        _Continue(project, graph, epoch)
        expected.update(_IngressIntents(project, epoch))
        segment = _Segment(epoch)
        segments.add(segment.genesis)
        expected.add(epoch.Bundle().name)
        expected.update(source.requestName for source in segment.sources if source.requestName)
        revision = revisions.LoadPeerSegment(project, baseline, segment)
        graph = ProtocolGraph(baseline, (*graph.epochs, epoch), revision, {"name": epoch.Bundle().name, "sha256": epoch.Digest()},
                              _Sources(project, revision), segment.activeProtocols, frozenset(expected))

    records += graph.revision.recordCount
    expected.update(_ClosedPeers(project, graph.revision))
    expected.update(source.requestName for source in graph.sources if source.requestName)

    if records > MAX_PROTOCOL_EPOCHS:
        raise VpnError("Combined protocol/peer history exceeds its complete operation bound")

    _MetadataSources(project, graph.sources)
    parent = project.root / "protocol-epochs"

    if parent.exists() or parent.is_symlink():
        PrivatePath(parent, directory=True)

        if not segments or {item.name for item in parent.iterdir()} != segments:
            raise VpnError("Protocol graph has unknown or missing peer segment directories")

    elif segments:
        raise VpnError("Protocol graph lost its retained peer segment namespace")

    prefixes = tuple("server-" + project.vpn.identity.stack + "-" + role + "-" for role in ("wp", "wc", "tp", "ip", "ep"))
    actual = {item.name.removeprefix("server-") for item in project.Artifacts.iterdir() if item.name.startswith(prefixes)}

    if actual - expected:
        raise VpnError("Unrecorded protocol/peer/ingress artifacts require recovery; no missing head was adopted")

    return ProtocolGraph(baseline, graph.epochs, graph.revision, head, graph.sources, graph.activeProtocols, frozenset(expected))
