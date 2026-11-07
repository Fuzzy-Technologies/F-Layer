"""Verify sealed generation requests without guest access or private runtime payloads."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from test_host_input_transaction import Delta
from test_wireguard_generations import Receipt

from flayer import _vpn_host_input as host
from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as generations
from flayer.profiles import _wireguard_guest as guest


def Composite(change: str = "disable") -> tuple[dict[str, Any], dict[str, Any]]:
    """Construct only synthetic public hash metadata; no declared receipt attests a running server."""

    transition = Delta()

    if change == "enable":
        before = host.InputPolicy(transition.before.identity, transition.before.creationSha256, transition.before.originalBootSha256,
                                  transition.before.managementCidrs, transition.before.listeners[:-1], "d" * 32)
        transition = host.InputTransition(before, transition.listener, "enable", transition.operationId)

    owner = policy.Owner(transition.before.Record())
    cached = {**Receipt(1), "owner": owner}
    candidate = None

    if change == "enable":
        candidate = {**copy.deepcopy(cached), "schema_version": 2, "nonce": transition.operationId, "status": "staged", "network_sha256": "e" * 64}
        candidate["files"]["lifecycle.py"] = "f" * 64
        candidate["files"]["firewall.nft"] = "e" * 64
        candidate["files"]["service.service"] = guest._Digest(guest._Unit(guest._Paths(owner)[0], owner, nonce=transition.operationId))

    value = {"schema_version": 2, "cloud_plan_sha256": "a" * 64, "input": transition.Record(),
             "generation": {"schema_version": 1, "change": change, "source_sha256": "f" * 64,
                            "source_files": {name: cached["files"][name] for name in generations._SOURCE_FILES},
                            "cached_receipt": cached, "candidate_receipt": candidate}}
    intent = {"owner": owner, "creation_sha256": transition.before.creationSha256, "operation_id": transition.operationId,
              "plan_sha256": policy.Digest(policy.Json(value)), "wireguard_state": "active" if change == "disable" else "absent",
              "wireguard_receipt_sha256": guest._Digest(guest._Encode(cached)) if change == "disable" else ""}

    return value, intent


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_GenerationRequestBindsExactSourceCloudInputAndReceiptMetadata(change: str) -> None:
    """Accept only the closed composite; older input-only requests cannot accidentally authorize generation input."""

    value, intent = Composite(change)
    assert generations.Request(guest, policy, value, intent) == value

    with pytest.raises(inputs.InputError):
        inputs.Request(policy, value, intent)


@pytest.mark.parametrize("fault", ["extra", "version", "cloud", "owner", "creation", "operation", "plan", "source", "source-files", "cache", "target", "candidate"])
@pytest.mark.parametrize("change", ["enable", "disable"])
def test_GenerationRequestRefusesCopiedOrUnboundMetadata(change: str, fault: str) -> None:
    """Every fixture is metadata-only; rejection must precede any filesystem, service or provider call."""

    value, intent = Composite(change)

    if fault == "extra":
        value["private_key"] = "suppressed-canary"

    elif fault == "version":
        value["schema_version"] = True

    elif fault == "cloud":
        value["cloud_plan_sha256"] = "invalid"

    elif fault in {"owner", "creation", "operation", "plan"}:
        intent[{"owner": "owner", "creation": "creation_sha256", "operation": "operation_id", "plan": "plan_sha256"}[fault]] = "9" * (32 if fault == "operation" else 64)

    elif fault == "source":
        value["generation"]["source_sha256"] = "invalid"

    elif fault == "source-files":
        value["generation"]["source_files"]["install.py"] = "1" * 64

    elif fault == "cache":
        value["generation"]["cached_receipt"]["owner"] = "9" * 64

    elif fault == "target":
        value["generation"]["change"] = "enable" if change == "disable" else "disable"

    else:
        value["generation"]["candidate_receipt"] = None if change == "enable" else value["generation"]["cached_receipt"]

    with pytest.raises(ValueError):
        generations.Request(guest, policy, value, intent)


@pytest.mark.parametrize("fault", ["nonce", "runtime", "credentials", "kernel", "unit", "generation-version", "firewall", "network"])
def test_RehashedCompositeCannotAuthorizeAChangedRuntimeOrCredential(fault: str) -> None:
    """Structural generation invariants survive recomputing the outer plan hash."""

    value, intent = Composite("enable")
    candidate = value["generation"]["candidate_receipt"]

    if fault == "nonce":
        candidate["nonce"] = "1" * 32

    elif fault in {"runtime", "credentials", "unit"}:
        candidate["files"][{"runtime": "wg", "credentials": "server.conf", "unit": "service.service"}[fault]] = "1" * 64

    elif fault == "kernel":
        candidate["kernel"]["checked_at"] += 1

    elif fault == "firewall":
        candidate["files"]["firewall.nft"] = value["generation"]["cached_receipt"]["files"]["firewall.nft"]

    elif fault == "network":
        candidate["network_sha256"] = value["generation"]["cached_receipt"]["network_sha256"]

    else:
        candidate["schema_version"] = 1

    intent["plan_sha256"] = policy.Digest(policy.Json(value))

    with pytest.raises(ValueError):
        generations.Request(guest, policy, value, intent)


def test_CompositeCapacityIsCheckedBeforeAnyGuestAccess(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reserve journal capacity before a complete future request could consume dispatch authority."""

    value, intent = Composite()
    monkeypatch.setattr(generations, "MAX_REQUEST_BYTES", len(policy.Json(value)) - 1)

    with pytest.raises(generations.GenerationError):
        generations.Request(guest, policy, value, intent)
