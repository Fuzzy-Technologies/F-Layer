"""Reject hidden VM ingress and collateral storage deletion using synthetic provider metadata."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import Any

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import InstanceAttachments, ParseInstanceAttachments
from flayer.providers.contracts import (
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.lifecycle import ResourceSpec
from flayer.providers.yandex import YandexCloudSettings
from flayer.vpn_project import VpnYandexProvider


def Resource() -> ProviderResource:
    """Represent an explicitly scoped original instance with a documentation-only public address."""

    return ProviderResource(ResourceReference("yandex-cloud", "example-folder", ResourceKind.INSTANCE, "example-instance"),
                            "gateway-instance", "RUNNING", "ru-central1-a", (("flayer-spec", "a" * 63),), ("203.0.113.20",))


def Payload() -> dict[str, Any]:
    """Match documented CLI instance attachments, keeping metadata and all secrets absent."""

    return {"id": "example-instance", "folder_id": "example-folder", "name": "gateway-instance", "zone_id": "ru-central1-a",
            "status": "RUNNING", "labels": {"flayer-spec": "a" * 63}, "boot_disk": {"disk_id": "example-disk", "mode": "READ_WRITE", "auto_delete": False},
            "network_interfaces": [{"index": "0", "subnet_id": "example-subnet", "security_group_ids": ["example-firewall"],
                                    "primary_v4_address": {"address": "10.42.0.2", "one_to_one_nat": {"address": "203.0.113.20", "ip_version": "IPV4"}}}]}


def test_DocumentedAttachmentSnapshotPreservesAllPolicyAndStorageIdentities() -> None:
    """Index and protobuf default encodings cannot hide a second interface or an auto-deleting disk."""

    data = Payload()
    snapshot = ParseInstanceAttachments(data, Resource())
    changed = copy.deepcopy(data)
    changed["network_interfaces"][0]["index"] = 0
    changed["boot_disk"].pop("auto_delete")

    assert ParseInstanceAttachments(changed, Resource()) == snapshot
    assert snapshot.subnetId == "example-subnet" and snapshot.bootDiskId == "example-disk"
    assert snapshot.securityGroupIds == ("example-firewall",) and snapshot.publicAddress == "203.0.113.20"


@pytest.mark.parametrize("fault", ["scope", "id", "no-nic", "extra-nic", "index", "index-bool", "ipv6", "unknown-nic",
                                  "no-groups", "duplicate-group", "bad-private", "bad-public", "no-nat", "ipv6-nat",
                                  "unknown-nat", "unknown-address", "auto-delete", "missing-boot", "read-only-boot",
                                  "secondary", "filesystems", "local-disks"])
def test_AmbiguousNetworkOrCollateralDeletionAttachmentFailsClosed(fault: str) -> None:
    """Only the bounded original single-NIC and independent boot-disk model can be accepted."""

    data = Payload()
    nic = data["network_interfaces"][0]
    primary = nic["primary_v4_address"]

    if fault in {"scope", "id", "missing-boot"}:
        key, value = {"scope": ("folder_id", "foreign"), "id": ("id", "foreign"), "missing-boot": ("boot_disk", None)}[fault]
        data[key] = value

    elif fault in {"secondary", "filesystems", "local-disks"}:
        data[{"secondary": "secondary_disks", "filesystems": "filesystems", "local-disks": "local_disks"}[fault]] = [{"disk_id": "foreign", "auto_delete": True}]

    elif fault == "no-nic":
        data["network_interfaces"] = []

    elif fault == "extra-nic":
        data["network_interfaces"].append(copy.deepcopy(nic))

    elif fault in {"index", "index-bool", "ipv6", "unknown-nic", "no-groups", "duplicate-group"}:
        key, value = {"index": ("index", "1"), "index-bool": ("index", False), "ipv6": ("primary_v6_address", {"address": "2001:db8::1"}),
                      "unknown-nic": ("secondary_v4_addresses", []), "no-groups": ("security_group_ids", []),
                      "duplicate-group": ("security_group_ids", ["example-firewall", "example-firewall"])}[fault]
        nic[key] = value

    elif fault in {"auto-delete", "read-only-boot"}:
        data["boot_disk"]["auto_delete" if fault == "auto-delete" else "mode"] = True if fault == "auto-delete" else "READ_ONLY"

    elif fault in {"bad-private", "unknown-address", "no-nat"}:
        key, value = {"bad-private": ("address", "010.42.0.2"), "unknown-address": ("secondary_address", "10.42.0.3"), "no-nat": ("one_to_one_nat", None)}[fault]
        primary[key] = value

    else:
        key, value = {"bad-public": ("address", "example.org"), "ipv6-nat": ("ip_version", "IPV6"), "unknown-nat": ("extra_target", "foreign")}[fault]
        primary["one_to_one_nat"][key] = value

    with pytest.raises(ValueError):
        ParseInstanceAttachments(data, Resource())


def test_AdapterRechecksTheExactSameInstanceObservationAndSuppressesUnsupportedPayload(monkeypatch: pytest.MonkeyPatch) -> None:
    """The adapter itself performs the fixed ID read and does not trust labels from a previous response."""

    provider = VpnYandexProvider(YandexCloudSettings("example-folder", "fixture-profile"))
    data = Payload()
    calls = []

    def Read(command: tuple[str, ...], operation: str) -> dict[str, Any]:
        """Return only synthetic metadata; no CLI is invoked."""

        calls.append(command)

        return data

    monkeypatch.setattr(provider, "_ReadJson", Read)

    assert provider.ReadInstanceAttachments(Resource()) == ParseInstanceAttachments(data, Resource())
    assert calls == [("compute", "instance", "get", "--id", "example-instance")]
    data["boot_disk"]["auto_delete"] = True

    with pytest.raises(VpnError, match="attachment policy"):
        provider.ReadInstanceAttachments(Resource())


@pytest.mark.parametrize("fault", ["none", "missing-proof", "group", "disk"])
def test_FinalInstanceDeletionRequiresAndRechecksItsExactAttachmentSnapshot(
    monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """A change after initial policy preflight must stop before the actual deletion dispatch."""

    identity = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
    spec = ResourceSpec("instance", ResourceKind.INSTANCE, "gateway-instance", (("zone_id", "ru-central1-a"),))
    resource = replace(Resource(), labels=spec.OwnershipLabels(identity))
    proof = ParseInstanceAttachments(Payload(), resource)
    observed: InstanceAttachments = proof

    if fault == "group":
        observed = replace(proof, securityGroupIds=("foreign-group",))

    elif fault == "disk":
        observed = replace(proof, bootDiskId="foreign-disk")

    provider = VpnYandexProvider(YandexCloudSettings("example-folder", "fixture-profile"))
    calls = []

    def Get(reference: ResourceReference) -> ProviderResource:
        """Return confirmed absence only after a recorded fake deletion dispatch."""

        if calls:
            raise ProviderError(ProviderErrorCode.NOT_FOUND, "fixture-get")

        return resource

    monkeypatch.setattr(provider, "ValidateSpec", lambda spec: None)
    monkeypatch.setattr(provider, "GetResource", Get)
    monkeypatch.setattr(provider, "ReadInstanceAttachments", lambda resource: observed)
    monkeypatch.setattr(provider, "_MutationRun", lambda command, operation: calls.append(command))

    if fault != "none":
        with pytest.raises((VpnError, ProviderError)):
            provider.DeleteCreationResource(resource, spec, identity, attachments=None if fault == "missing-proof" else proof)

        assert not calls

    else:
        provider.DeleteCreationResource(resource, spec, identity, attachments=proof)

        assert calls == [("compute", "instance", "delete", "--id", "example-instance")]
