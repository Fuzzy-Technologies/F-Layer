"""Immutable lifecycle contract and ownership-digest boundary regression tests."""

from __future__ import annotations

import dataclasses

import pytest

from flayer.core.contracts import StackIdentity
from flayer.providers.contracts import ProviderErrorCode, ResourceKind
from flayer.providers.lifecycle import MAX_PARAMETER_VALUES, MutationError, ResourceSpec


@pytest.mark.parametrize(
    "changes",
    [
        {"logical_id": "Invalid"}, {"name": "invalid name"}, {"kind": "network"},
        {"parameters": []}, {"parameters": (("value", []),)},
        {"parameters": (("value", 1.5),)}, {"parameters": (("value", "\x00"),)},
        {"parameters": (("value", "x" * 16385),)}, {"parameters": (("value", 2 ** 64),)},
        {"parameters": (("value", 1), ("value", 2))},
        {"parameters": (("invalid key", 1),)}, {"parameters": ((1, 2),)},
        {"parameters": (("value",),)},
        {"dependencies": []}, {"dependencies": ("network",)},
        {"dependencies": ("other", "other")}, {"dependencies": ([],)},
        {"dependencies": ("Invalid",)},
    ],
)
def test_ResourceSpecRejectsMutableOrInvalidFields(changes: dict[str, object]) -> None:
    """Malformed direct constructions cannot bypass the immutable request contract."""

    values: dict[str, object] = {
        "logical_id": "network", "name": "example-network", "kind": ResourceKind.NETWORK,
    }
    values.update(changes)

    with pytest.raises(ValueError):
        ResourceSpec(**values)  # type: ignore[arg-type]


def test_ResourceSpecBoundsDepthAndNodeCount() -> None:
    """Recursive inputs are bounded before fingerprint serialization or provider translation."""

    value: object = "example"

    for _ in range(12):
        value = (value,)

    with pytest.raises(ValueError):
        ResourceSpec("network", ResourceKind.NETWORK, "network", (("deep", value),))  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        ResourceSpec("network", ResourceKind.NETWORK, "network", (("many", (0,) * (MAX_PARAMETER_VALUES + 1)),))


def test_OwnershipIncludesStableBoundedSpecDigest() -> None:
    """Logical ownership and desired content are distinguishable without exposing parameters."""

    identity = StackIdentity("project", "stack", "yandex-cloud", "test-folder", "owner")
    spec = ResourceSpec("network", ResourceKind.NETWORK, "network")
    labels = dict(spec.OwnershipLabels(identity))

    assert labels["managed-by"] == "f-layer", "Manager ownership label was lost"
    assert labels["flayer-resource"] == "network", "Logical recovery label was lost"
    assert len(labels["flayer-spec"]) == 40, "Digest exceeds the provider label size contract"
    assert labels == dict(spec.OwnershipLabels(identity)), "Ownership digest is unstable"
    assert labels["flayer-spec"] != dict(dataclasses.replace(
        spec, name="changed-network"
    ).OwnershipLabels(identity))["flayer-spec"], "Desired-name drift was invisible"


def test_ResourceSpecRepresentationOmitsOpaqueParameters() -> None:
    """Request representations cannot accidentally print public metadata or local input paths."""

    spec = ResourceSpec("network", ResourceKind.NETWORK, "network", (("value", "opaque-value"),))

    assert "opaque-value" not in repr(spec), "Opaque request parameters leaked through repr"

    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.name = "changed"  # type: ignore[misc]


def test_MutationFailureHasOnlySanitizedStableFields() -> None:
    """A recoverable outcome is explicit rather than inferred from vendor error text."""

    error = MutationError(ProviderErrorCode.TIMEOUT, "create", True)

    assert error.outcome_unknown is True, "Uncertain submission was represented as safe absence"
    assert error.retryable is False, "Uncertain mutation advertised a blind retry recommendation"
    assert MutationError(ProviderErrorCode.TIMEOUT, "create", False).retryable is True, "Safe preflight retry classification changed"

    with pytest.raises(ValueError):
        MutationError(ProviderErrorCode.TIMEOUT, "create", 1)  # type: ignore[arg-type]
