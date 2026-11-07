"""Cross-bind only public terminal completion data without touching guest files, native commands or cloud APIs."""

from __future__ import annotations

import copy
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
import test_vpn_native_epochs as fixtures

from flayer import _vpn_protocol_epochs as epochs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _wireguard_guest as guest


def Envelope(phase: str = "active") -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Give the pure epoch fixture a real initial authority digest, retaining its exact native/composite/input/service bindings."""

    epoch = fixtures.Enabled(phase=phase) if phase in {"active", "rolled-back"} else fixtures.Disabled(phase=phase)
    metadata = epochs._Decode(epoch.metadata)
    intent = metadata["reservation"]
    intent["previous_authority_sha256"] = authority._Initial(guest, intent)
    request = {"schema_version": 2, "cloud_plan_sha256": epoch.cloud.plan.Fingerprint(), "input": epoch.input.transition.Record(), "generation": metadata["generation"]}
    native = {"schema_version": 1, "intent": intent, "request": request, "history_sha256": guest._ProtocolHistory(intent, request),
              "admitted_program_sha256": request["generation"]["candidate_receipt"]["files"]["lifecycle.py"],
              "phase": phase, "rollback": epoch.cloud.outcome == "not-applied"}
    metadata["native_sha256"] = guest._Digest(guest._Encode(native))
    record = {**epochs._Decode(epoch.completion), "previous_authority_sha256": intent["previous_authority_sha256"],
              "intent_sha256": guest._Digest(guest._Encode(metadata))}
    epoch = replace(epoch, metadata=guest._Encode(metadata), completion=guest._Encode(record))
    value = {"schema_version": 1, "metadata": metadata, "request": request, "input": epoch.input.Record(),
             "services": {"schema_version": 1, "services": [proof.Record() for proof in epoch.services]}, "outcome": epoch.cloud.outcome}

    return value, intent, record


@pytest.mark.parametrize("phase", ["active", "inactive", "restored", "unchanged", "rolled-back"])
def test_NativeCompletionReconstructsTheExactRecordAcceptedByTheImmutableEpochReader(phase: str) -> None:
    """The guest record has no circular bundle digest and claims only the terminal witnesses selected by its reserved plan."""

    value, intent, expected = Envelope(phase)
    result = completion.Candidate(guest, authority, policy, cache, value, intent)
    assert result["record"] == expected and authority.Completion(expected, intent) == expected


@pytest.mark.parametrize("fault", ["extra", "alias", "old-generation", "source", "input", "services", "native", "history", "receipt", "parent", "peer", "selection", "cloud", "input-type"])
def test_CompletionRefusesReboundOrIncompleteWitnessesBeforeAnyGuestAccess(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Rehash modified witness envelopes too; no outer hash can authorize another source, plan, phase or receipt."""

    value, intent, _ = Envelope("restored")
    value = copy.deepcopy(value)
    metadata = value["metadata"]

    if fault == "extra":
        value["private_key"] = "suppressed-canary"

    elif fault == "alias":
        metadata["schema_version"] = True

    elif fault == "old-generation":
        value["request"]["generation"]["schema_version"] = 2
        del value["request"]["generation"]["callback_abi"]
        intent["plan_sha256"] = guest._Digest(guest._Encode(value["request"]))

    elif fault == "source":
        metadata["sources"][-1]["pin"]["server_digest"] = "0" * 64

    elif fault == "input":
        value["input"]["boot_sha256"] = "0" * 64

    elif fault == "input-type":
        value["input"]["schema_version"] = True

    elif fault == "services":
        value["services"]["services"][-1]["source_sha256"] = "0" * 64

    elif fault == "native":
        metadata["native_sha256"] = "0" * 64

    elif fault == "history":
        metadata["wireguard_history_sha256"] = intent["wireguard_history_sha256"]

    elif fault == "receipt":
        metadata["wireguard_receipt_sha256"] = intent["wireguard_receipt_sha256"]

    elif fault == "parent":
        metadata["authority_parent"] = {"name": "done-" + "a" * 32 + ".json", "sha256": "0" * 64}

    elif fault == "peer":
        metadata["closed_peer_count"] = True

    elif fault == "selection":
        metadata["active_protocols"] = ["wireguard"]

    else:
        metadata["cloud_sha256"] = []

    metadata["input_sha256"] = guest._Digest(guest._Encode(value["input"]))
    metadata["services_sha256"] = guest._Digest(guest._Encode(value["services"]))
    monkeypatch.setattr(authority, "_Root", lambda *args: pytest.fail("Refused completion data must not inspect guest files"))
    monkeypatch.setattr(guest, "_Run", lambda *args, **kwargs: pytest.fail("Refused completion data must not execute a native command"))

    with pytest.raises(completion.CompletionError):
        completion.Complete(guest, SimpleNamespace(), authority, policy, SimpleNamespace(), cache, SimpleNamespace(), value, intent, allowMutation=True)


def test_WellFormedCompletionStillRequiresExplicitMutationConsentBeforeAnyGuestAccess(monkeypatch: pytest.MonkeyPatch) -> None:
    """A complete data-only candidate does not itself authorize publishing common authority."""

    value, intent, _ = Envelope()
    monkeypatch.setattr(authority, "_Root", lambda *args: pytest.fail("Missing consent must not inspect guest files"))

    with pytest.raises(completion.CompletionError, match="consent"):
        completion.Complete(guest, SimpleNamespace(), authority, policy, SimpleNamespace(), cache, SimpleNamespace(), value, intent)


@pytest.mark.parametrize("fault", ["schema", "outcome", "owner", "creation", "operation", "parent", "previous", "history", "extra"])
def test_CommonCompletionCodecKeepsHistoricalAndNativeOutcomesClosed(fault: str) -> None:
    """Existing cancellations remain schema 1; committed/not-applied native records use an explicit different schema."""

    _, intent, record = Envelope()

    if fault == "schema":
        record["schema_version"] = True

    elif fault == "outcome":
        record["outcome"] = "cancelled"

    elif fault == "owner":
        record["owner"] = "0" * 64

    elif fault == "creation":
        record["creation_sha256"] = "0" * 64

    elif fault == "operation":
        record["operation_id"] = "../elsewhere"

    elif fault == "parent":
        record["parent"] = {"name": "../foreign", "sha256": "0" * 64}

    elif fault == "previous":
        record["previous_authority_sha256"] = "0" * 64

    elif fault == "history":
        record["history_sha256"] = False

    else:
        record["unknown"] = "suppressed-canary"

    with pytest.raises(ValueError):
        authority.Completion(record, intent)
