"""Tests for provider identity, immutability and ownership invariants."""

from dataclasses import FrozenInstanceError

import pytest

from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderIdentity,
    ProviderResource,
    ResourceKind,
    ResourceReference,
    ValidateIdentifier,
)


@pytest.mark.parametrize(
    "value", ["", "--folder", "folder with spaces", "a\n", "\u00e9", "a" * 129]
)
def test_IdentifiersRejectUnsafeValues(value: str) -> None:
    """Identifiers cannot introduce flags, control characters or unbounded values."""

    with pytest.raises(ValueError, match="Provider identifiers") as error:
        ValidateIdentifier(value)

    assert value not in str(error.value) or not value, "Rejected identifiers leaked into errors"


def test_IdentityAndReferencesAreImmutable() -> None:
    """Validated references are stable keys bound to a provider and a scope."""

    identity = ProviderIdentity("example-cloud", "test-folder", "external")
    reference = ResourceReference("example-cloud", "test-folder", ResourceKind.INSTANCE, "vm-1")

    with pytest.raises(FrozenInstanceError):
        identity.scope_id = "another-folder"  # type: ignore[misc]

    with pytest.raises(FrozenInstanceError):
        reference.resource_id = "vm-2"  # type: ignore[misc]

    assert hash(reference) == hash(reference), "Resource reference changed its identity"


def test_ReferencesRejectArbitraryKinds() -> None:
    """String compatibility cannot bypass the resource-kind enum contract."""

    with pytest.raises(ValueError, match="Resource kind"):
        ResourceReference("example", "folder", "instance", "vm")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "values",
    [
        {"reference": None},
        {"name": None},
        {"status": None},
        {"zone_id": "--zone"},
        {"labels": [("project", "test")]},
        {"labels": (("project", "test"), ("project", "another"))},
        {"labels": (("project", 1),)},
        {"public_addresses": ["203.0.113.10"]},
        {"public_addresses": (None,)},
    ],
)
def test_ResourcesRejectInvalidFields(values: dict[str, object]) -> None:
    """Resource objects cannot contain mutable or malformed normalized fields."""

    arguments: dict[str, object] = {
        "reference": ResourceReference("example", "folder", ResourceKind.INSTANCE, "vm"),
        "name": "example-vm",
    }
    arguments.update(values)

    with pytest.raises(ValueError):
        ProviderResource(**arguments)  # type: ignore[arg-type]


def test_LabelChecksRequireExplicitNonEmptyOwnership() -> None:
    """Names and an empty ownership policy never authorize resource adoption."""

    reference = ResourceReference("example", "folder", ResourceKind.NETWORK, "network")
    resource = ProviderResource(reference, "same-name", labels=(("project", "example"),))

    assert resource.HasLabels((("project", "example"),)), "Matching ownership labels were rejected"
    assert not resource.HasLabels(()), "Empty labels accidentally claimed resource ownership"
    assert not resource.HasLabels((("project", "different"),)), "Foreign ownership was accepted"
    assert not resource.HasLabels((("missing", "value"),)), "Missing ownership label was accepted"


@pytest.mark.parametrize("code", list(ProviderErrorCode))
def test_ErrorCategoriesHaveBoundedRetryRecommendations(code: ProviderErrorCode) -> None:
    """Only transient timeouts and throttling recommend retrying a read operation."""

    error = ProviderError(code, "list")

    assert error.code == code, "Provider failure lost its normalized category"
    assert error.retryable == (code in {ProviderErrorCode.TIMEOUT, ProviderErrorCode.THROTTLED}), (
        "Provider failure recommended unsafe retries"
    )
    assert str(error) == f"Provider operation list failed: {code.value}", (
        "Provider failure contains unexpected external details"
    )
