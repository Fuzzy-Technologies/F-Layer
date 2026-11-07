"""Bind native-generation epoch metadata without guest, provider, filesystem or private payload access."""

from __future__ import annotations

import copy
import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from test_vpn_protocol_epochs import Commit, Operation
from test_wireguard_generations import Receipt

from flayer import _vpn_protocol_epochs as epochs
from flayer._vpn_creation import _Json
from flayer._vpn_host_input import InputTransition
from flayer._vpn_ingress_journal import IngressJournal
from flayer.profiles import _wireguard_guest as guest
from flayer.providers._yandex_ingress import IngressDelta


def Generation(metadata: dict[str, Any], change: str, nonce: str, *, cached: dict[str, Any] | None = None) -> dict[str, Any]:
    """Construct only public receipt pins, preserving credentials/runtime/kernel while changing the unit/network generation."""

    owner = metadata["reservation"]["owner"]
    original = {**Receipt(1), "owner": owner} if cached is None else copy.deepcopy(cached)
    desired = {**copy.deepcopy(original), "schema_version": 2, "nonce": nonce, "status": "staged",
               "network_sha256": hashlib.sha256(("native-policy:" + nonce).encode()).hexdigest()}
    desired["files"]["lifecycle.py"] = "f" * 64
    desired["files"]["firewall.nft"] = hashlib.sha256(("native-firewall:" + nonce).encode()).hexdigest()
    desired["files"]["service.service"] = guest._Digest(guest._Unit(guest._Paths(owner)[0], owner, nonce=nonce))
    source = next(value for value in metadata["sources"] if value["pin"]["protocol"] == "wireguard")

    return {"schema_version": 3, "change": change, "callback_abi": guest.PROTOCOL_RUNTIME_ABI,
            "source_sha256": hashlib.sha256(_Json(source)).hexdigest(),
            "source_files": {name: original["files"][name] for name in ("server.conf", "deployment.json", "install.py")},
            "cached_receipt": original, "candidate_receipt": desired}


def Native(base: Any, generation: dict[str, Any], *, phase: str) -> epochs.EpochCommit:
    """Seal complete typed evidence beside exact generation metadata and an independently encoded guest completion."""

    metadata = epochs._Decode(base.metadata)
    metadata.update(schema_version=2, generation=generation)
    reservation = metadata["reservation"]
    original = generation["cached_receipt"]
    reservation["wireguard_state"] = "active" if generation["change"] == "disable" else "absent"
    reservation["wireguard_receipt_sha256"] = guest._Digest(_Json(original)) if generation["change"] == "disable" else ""
    reservation["wireguard_absence_sha256"] = "" if generation["change"] == "disable" else guest._AbsenceDigest(reservation["owner"])
    request = {"schema_version": 2, "cloud_plan_sha256": base.cloud.plan.Fingerprint(), "input": base.input.transition.Record(), "generation": generation}
    reservation["plan_sha256"] = hashlib.sha256(_Json(request)).hexdigest()
    fresh = {**generation["candidate_receipt"], "status": "installed"}
    generated = phase in {"active", "restored", "rolled-back"}
    active = phase in {"active", "restored", "unchanged"} or phase == "unstarted" and generation["change"] == "disable"
    metadata["generation_receipt_sha256"] = hashlib.sha256(_Json(fresh)).hexdigest() if generated else ""
    metadata["wireguard_receipt_sha256"] = hashlib.sha256(_Json(fresh if generated else original)).hexdigest() if active else ""
    originalHistory = guest._ProtocolHistory(reservation, request)
    metadata["wireguard_history_sha256"] = hashlib.sha256(_Json(guest._GenerationAudit(reservation, request))).hexdigest() if generated else originalHistory
    native = {"schema_version": 1, "intent": reservation, "request": request, "history_sha256": originalHistory,
              "admitted_program_sha256": generation["candidate_receipt"]["files"]["lifecycle.py"], "phase": phase, "rollback": base.cloud.outcome != "committed"}
    metadata["native_sha256"] = "" if phase == "unstarted" else hashlib.sha256(_Json(native)).hexdigest()
    metadata["active_protocols"] = [value["pin"]["protocol"] for value in metadata["sources"] if value["pin"]["protocol"] != "wireguard" or active]
    services = tuple(replace(proof, state="active" if active else "absent", receiptSha256=metadata["wireguard_receipt_sha256"],
                             absenceSha256="" if active else guest._AbsenceDigest(reservation["owner"])) if proof.protocol == "wireguard" else proof
                     for proof in base.services)
    metadata["services_sha256"] = hashlib.sha256(_Json({"schema_version": 1, "services": [value.Record() for value in services]})).hexdigest()
    metadata["cloud_sha256"] = hashlib.sha256(_Json(base.cloud.Record())).hexdigest()
    metadata["input_sha256"] = hashlib.sha256(_Json(base.input.Record())).hexdigest()
    plans = [("change", base.cloud.plan), *([("restoration", base.cloud.restoration)] if base.cloud.restoration is not None else [])]
    metadata["ingress_intents"] = []

    for role, plan in plans:
        bundle = IngressJournal(plan, metadata["creation_sha256"], metadata["previous_state_sha256"], 1).Bundle()
        metadata["ingress_intents"].append({"role": role, "name": bundle.name, "sha256": epochs.BundleDigest(bundle)})

    encoded = _Json(metadata)
    completion = {**epochs._Decode(base.completion), "schema_version": 2, "operation_id": reservation["operation_id"],
                  "intent_sha256": hashlib.sha256(encoded).hexdigest(), "history_sha256": metadata["wireguard_history_sha256"], "outcome": base.cloud.outcome}

    return epochs.EpochCommit(base.identity, encoded, base.cloud, base.input, services, _Json(completion))


def Enabled(*, phase: str = "active") -> epochs.EpochCommit:
    """Use synthetic public metadata only; no helper or key body is opened."""

    base = Commit("committed" if phase == "active" else "rolled-back")
    generation = Generation(epochs._Decode(base.metadata), "enable", base.cloud.plan.operationId)

    return Native(base, generation, phase=phase)


def Disabled(*, phase: str = "inactive") -> epochs.EpochCommit:
    """Continue the same synthetic credential generation, with known original and compensation cloud operations."""

    previous = Enabled()
    metadata = epochs._Decode(previous.metadata)
    old = {**metadata["generation"]["candidate_receipt"], "status": "installed"}
    plan = previous.cloud.plan
    before = previous.cloud.result
    listener = plan.listener
    ids = tuple(rule.ruleId for rule in before.rules if rule.direction == "ingress" and rule.protocol == listener.protocol
                and rule.fromPort == listener.port and rule.toPort == listener.port)
    delta = IngressDelta(plan.identity, plan.creationSpec, plan.networkId, before, listener, "disable", "d" * 32, ids)
    applied = replace(before, rules=tuple(rule for rule in before.rules if rule.ruleId not in ids))
    operation = Operation(delta, applied, "example-disable")
    cloud = epochs.CloudEvidence(delta, applied, "committed", operation)
    transition = InputTransition(previous.input.Policy(), listener, "disable", delta.operationId)
    inputProof = epochs.InputEvidence(transition, "applied", "a" * 64, "b" * 64)

    if phase != "inactive":
        inverse = IngressDelta(plan.identity, plan.creationSpec, plan.networkId, applied, listener, "enable", epochs.RestorationNonce(delta.operationId))
        assert inverse.Addition is not None
        restored = replace(applied, rules=(*applied.rules, replace(inverse.Addition, ruleId="restored-wg-rule")))
        cloud = epochs.CloudEvidence(delta, restored, "not-applied", operation, applied, inverse, Operation(inverse, restored, "example-restore"))
        inputProof = epochs.InputEvidence(transition, "rolled-back", "a" * 64, "b" * 64)

    metadata["reservation"]["operation_id"] = delta.operationId
    metadata["reservation"]["wireguard_history_sha256"] = metadata["wireguard_history_sha256"]
    base = SimpleNamespace(identity=previous.identity, metadata=_Json(metadata), cloud=cloud, input=inputProof,
                           services=previous.services, completion=previous.completion)

    generation = Generation(metadata, "disable", delta.operationId, cached=old)

    return Native(base, generation, phase=phase)


@pytest.mark.parametrize("phase", ["active", "rolled-back", "unstarted"])
def test_EnabledNativeEvidenceRoundTripsItsExactGenerationAndTerminalProof(phase: str) -> None:
    """A fresh fence remains recorded even if an attempted activation rolls back to complete absence."""

    value = Enabled(phase=phase)
    assert epochs.DecodeEpochBundle(value.Bundle()) == value


@pytest.mark.parametrize("phase", ["inactive", "restored", "unchanged", "unstarted"])
def test_DisabledNativeEvidenceRetainsBothHistoryLinksAndTheExactRestoredIdentity(phase: str) -> None:
    """Rollback after old-unit retirement uses the fresh root, while an unstarted/unchanged operation retains the original root."""

    value = Disabled(phase=phase)
    metadata = epochs._Decode(value.metadata)
    assert epochs.DecodeEpochBundle(value.Bundle()) == value

    if phase == "restored":
        assert metadata["generation_receipt_sha256"] == metadata["wireguard_receipt_sha256"]
        assert metadata["wireguard_receipt_sha256"] != metadata["reservation"]["wireguard_receipt_sha256"]


@pytest.mark.parametrize("fault", ["source", "native", "old-contract", "candidate", "old-history", "one-fence", "original-receipt"])
def test_NativeEpochRefusesReboundSourcesMissingProofsOrAReplayedOriginalGeneration(fault: str) -> None:
    """Rehash the outer completion too: semantic bindings must survive a copied or self-supplied proof envelope."""

    value = Disabled(phase="restored")
    metadata = epochs._Decode(value.metadata)

    if fault == "source":
        metadata["generation"]["source_sha256"] = "1" * 64

    elif fault == "native":
        metadata["native_sha256"] = ""

    elif fault == "old-contract":
        metadata["generation"]["schema_version"] = 2
        del metadata["generation"]["callback_abi"]

    elif fault == "candidate":
        metadata["generation"]["candidate_receipt"]["files"]["server.conf"] = "1" * 64

    elif fault == "old-history":
        metadata["wireguard_history_sha256"] = metadata["reservation"]["wireguard_history_sha256"]

    elif fault == "one-fence":
        generation = metadata["generation"]
        record = {"schema_version": 1, "owner": metadata["reservation"]["owner"], "action": "revoke",
                  "device_id": "protocol-" + metadata["reservation"]["operation_id"], "previous_receipt_sha256": metadata["generation_receipt_sha256"],
                  "receipt_sha256": metadata["generation_receipt_sha256"], "deployment_sha256": generation["cached_receipt"]["deployment_sha256"],
                  "previous_history_sha256": metadata["reservation"]["wireguard_history_sha256"]}
        metadata["wireguard_history_sha256"] = hashlib.sha256(_Json(record)).hexdigest()

    else:
        metadata["wireguard_receipt_sha256"] = metadata["reservation"]["wireguard_receipt_sha256"]

    encoded = _Json(metadata)
    completion = {**epochs._Decode(value.completion), "intent_sha256": hashlib.sha256(encoded).hexdigest(), "history_sha256": metadata["wireguard_history_sha256"]}

    with pytest.raises(ValueError):
        replace(value, metadata=encoded, completion=_Json(completion))


@pytest.mark.parametrize("fault", ["source", "candidate"])
def test_RehashedCompositeAndNativeProofCannotAuthorizeAnotherSourceOrCredentialPin(fault: str) -> None:
    """Recompute the entire reserved plan, native record and completion rather than failing only on a stale outer hash."""

    value = Disabled(phase="restored")
    generation = copy.deepcopy(epochs._Decode(value.metadata)["generation"])

    if fault == "source":
        generation["source_sha256"] = "1" * 64

    else:
        generation["candidate_receipt"]["files"]["server.conf"] = "1" * 64

    with pytest.raises(ValueError):
        Native(value, generation, phase="restored")


def test_NativeRollbackCannotUseUnchangedInputEvenWithARehashedCompleteComposite() -> None:
    """A native terminal rollback must retain the exact restored marker, including when no cloud operation was submitted."""

    value = Enabled(phase="rolled-back")
    carrier = SimpleNamespace(identity=value.identity, metadata=value.metadata, cloud=value.cloud,
                              input=replace(value.input, outcome="unchanged", journalSha256=""),
                              services=value.services, completion=value.completion)

    with pytest.raises(ValueError, match="restored host-input"):
        Native(carrier, epochs._Decode(value.metadata)["generation"], phase="rolled-back")
