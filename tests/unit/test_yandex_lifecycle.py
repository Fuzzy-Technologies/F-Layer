"""Deterministic Yandex lifecycle command, ownership, recovery and artifact tests."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import subprocess
import traceback
from pathlib import Path
from unittest.mock import Mock

import pytest

from flayer.core.contracts import StackIdentity
from flayer.providers.contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ResourceKind,
)
from flayer.providers.lifecycle import LifecycleProvider, MutationError, ResourceSpec
from flayer.providers.yandex import CommandResult, YandexCloudSettings
from flayer.providers.yandex_lifecycle import MAX_USER_DATA_BYTES, YandexLifecycleProvider

IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "test-folder", "owner")
ZONE = "example-zone"
OPERATION_ID = "a" * 32
KEY_BYTES = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"x" * 32
PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(KEY_BYTES).decode("ascii")


class RecordingRunner:
    """Emulate CLI resources entirely in memory and retain deterministic command evidence."""

    def __init__(self) -> None:
        """Initialize fake observations without credentials or a real executable."""

        self.calls: list[tuple[str, ...]] = []
        self.resources: dict[str, dict[str, object]] = {}
        self.overrides: dict[str, CommandResult | Exception] = {}
        self.last_user_data: bytes | None = None
        self.last_temporary_path: str | None = None
        self.last_temporary_mode: int | None = None

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Supply fake read/create/delete responses; never invoke a shell, socket or CLI."""

        assert timeout == 45.0, "Configured command deadline was lost"

        self.calls.append(command)
        operation = command[3]

        if operation in self.overrides:
            response = self.overrides[operation]

            if isinstance(response, Exception):
                raise response

            return response

        if operation == "list":
            if int(command[command.index("--limit") + 1]) > 1000:
                return CommandResult(1, stderr=(
                    "InvalidArgument: page_size: Value must be less than or equal to 1000"
                ))

            values = [row for row in self.resources.values() if row["test_kind"] == command[2]]

            return CommandResult(0, json.dumps(values))

        if operation == "get":
            resource_id = command[command.index("--id") + 1]

            if resource_id not in self.resources:
                return CommandResult(1, stderr="NOT_FOUND synthetic resource")

            return CommandResult(0, json.dumps(self.resources[resource_id]))

        if operation == "delete":
            resource_id = command[command.index("--id") + 1]
            self.resources.pop(resource_id, None)

            return CommandResult(0)

        assert operation == "create", "Fake runner received an unsupported operation"

        labels = command[command.index("--labels") + 1]
        name = command[command.index("--name") + 1]
        resource_id = f"resource-{len(self.resources) + 1}"
        row: dict[str, object] = {
            "id": resource_id, "name": name, "folder_id": "test-folder",
            "labels": dict(item.split("=", 1) for item in labels.split(",")),
            "test_kind": command[2],
        }

        if "--zone" in command:
            row["zone_id"] = command[command.index("--zone") + 1]

        if command[2] == "address":
            row["external_ipv4_address"] = {"address": "192.0.2.10", "zone_id": ZONE}

        if command[2] == "instance":
            row["status"] = "RUNNING"
            row["network_interfaces"] = [{
                "primary_v4_address": {"one_to_one_nat": {"address": "192.0.2.10"}}
            }]

        elif command[2] == "disk":
            row["status"] = "READY"

        if "--metadata-from-file" in command:
            argument = command[command.index("--metadata-from-file") + 1]
            path = Path(argument.removeprefix("user-data="))
            self.last_user_data = path.read_bytes()
            self.last_temporary_path = str(path)
            self.last_temporary_mode = path.stat().st_mode & 0o777

        self.resources[resource_id] = row

        return CommandResult(0, json.dumps(row))


def Specs() -> tuple[ResourceSpec, ...]:
    """Build the explicit six-resource gateway subset with no hidden boot disk creation."""

    network = ResourceSpec("network", ResourceKind.NETWORK, "gateway-network")
    subnet = ResourceSpec("subnet", ResourceKind.SUBNET, "gateway-subnet", (
        ("zone_id", ZONE), ("ipv4_cidr", "10.42.0.0/24"), ("network_dependency", "network"),
    ), ("network",))
    group = ResourceSpec("security-group", ResourceKind.SECURITY_GROUP, "gateway-sg", (
        ("network_dependency", "network"), ("rules", (
            (("direction", "ingress"), ("protocol", "tcp"), ("cidr", "192.0.2.0/24"),
             ("from_port", 22), ("to_port", 22)),
            (("direction", "egress"), ("protocol", "any"), ("cidr", "0.0.0.0/0")),
        )),
    ), ("network",))
    address = ResourceSpec("address", ResourceKind.ADDRESS, "gateway-address", (("zone_id", ZONE),))
    disk = ResourceSpec("boot-disk", ResourceKind.DISK, "gateway-disk", (
        ("zone_id", ZONE), ("image_id", "example-image"), ("size_gib", 20),
    ))
    instance = ResourceSpec("instance", ResourceKind.INSTANCE, "gateway-instance", (
        ("zone_id", ZONE), ("cores", 2), ("memory_gib", 2), ("boot_disk_dependency", "boot-disk"),
        ("subnet_dependency", "subnet"), ("security_group_dependency", "security-group"),
        ("address_dependency", "address"), ("ssh_public_key", PUBLIC_KEY),
        ("ssh_username", "gateway-admin"),
    ), ("boot-disk", "subnet", "security-group", "address"))

    return network, subnet, group, address, disk, instance


def Provider() -> tuple[YandexLifecycleProvider, RecordingRunner]:
    """Construct a lifecycle adapter backed exclusively by the in-memory fake CLI."""

    runner = RecordingRunner()
    provider = YandexLifecycleProvider(YandexCloudSettings("test-folder"), runner)

    return provider, runner


def ReplaceOption(spec: ResourceSpec, key: str, value: object) -> ResourceSpec:
    """Create malformed option requests without modifying shared fixture data."""

    options = dict(spec.parameters)
    options[key] = value  # type: ignore[assignment]

    return dataclasses.replace(spec, parameters=tuple(options.items()))


def CreateDependencies(provider: YandexLifecycleProvider) -> dict[str, object]:
    """Create fake graph dependencies with current normalized ownership observations."""

    resources: dict[str, object] = {}

    for spec in Specs()[:-1]:
        mapping = {key: resources[key] for key in spec.dependencies}
        resources[spec.logical_id] = provider.CreateResource(spec, IDENTITY, mapping, OPERATION_ID)  # type: ignore[arg-type]

    return resources


def test_ConstructionAndSpecValidationRemainOffline() -> None:
    """Lifecycle capability cannot execute a command merely through construction or validation."""

    provider, runner = Provider()

    for spec in Specs():
        provider.ValidateSpec(spec)

    assert isinstance(provider, LifecycleProvider), "Adapter violates lifecycle protocol"
    assert ProviderCapability.CREATE_RESOURCE in provider.Capabilities, "Create capability is invisible"
    assert ProviderCapability.DELETE_RESOURCE in provider.Capabilities, "Delete capability is invisible"
    assert runner.calls == [], "Offline validation accessed infrastructure"


def test_CreateAndDeleteSixKindsUseExactOwnedDependencies() -> None:
    """Every mutatable graph resource has an explicit labeled creation and reverse deletion."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    spec = Specs()[-1]
    instance = provider.CreateResource(spec, IDENTITY, {
        key: resources[key] for key in spec.dependencies
    }, OPERATION_ID)  # type: ignore[arg-type]
    resources[spec.logical_id] = instance
    creates = [command for command in runner.calls if command[3] == "create"]
    command = creates[-1]

    assert len(creates) == 6, "A managed resource was hidden inside another CLI mutation"
    assert "--source-image-id" in creates[-2], "Disk create uses an undocumented image option"
    assert "--create-boot-disk" not in command, "Compound disk creation can orphan an unowned disk"
    assert command[command.index("--use-boot-disk") + 1].endswith(
        ",auto-delete=false"
    ), "Disk lifecycle escaped explicit orchestration"
    assert "ssh-keys=gateway-admin:" in command[command.index("--metadata") + 1], "SSH user was lost"
    assert instance.public_addresses == ("192.0.2.10",), "Public address observation was lost"

    for command in creates:
        assert command[command.index("--folder-id") + 1] == "test-folder", "Mutation lost scope"
        assert command[command.index("--retry") + 1] == "0", "Mutation retries can duplicate resources"
        assert "--no-browser" in command and "--async" not in command, "Mutation became interactive"
        assert "managed-by=f-layer" in command[command.index("--labels") + 1], "Ownership was omitted"

    for item in reversed(Specs()):
        resource = resources[item.logical_id]
        provider.DeleteResource(resource.reference, IDENTITY, item.logical_id)  # type: ignore[attr-defined]

    deletes = [command for command in runner.calls if command[3] == "delete"]

    assert len(deletes) == 6 and not runner.resources, "Explicit cleanup left fake resources"
    assert all("--id" in item and "--name" not in item for item in deletes), "Deletion used names"


def test_IdempotentOwnedDiscoveryPreventsSecondCreate() -> None:
    """Stable exact ownership discovery returns the existing resource without recreating it."""

    provider, runner = Provider()
    spec = Specs()[0]
    first = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    second = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    assert first == second, "Idempotent creation changed a stable resource reference"
    assert sum(command[3] == "create" for command in runner.calls) == 1, "Resource was duplicated"


@pytest.mark.parametrize("variation", ["duplicate", "digest", "name", "status", "zone"])
def test_FindRejectsAmbiguousDriftedOrMalformedOwnership(variation: str) -> None:
    """Reconciliation fails closed on duplicate logical ownership and stale desired content."""

    provider, runner = Provider()
    spec = Specs()[3] if variation == "zone" else Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    row = runner.resources[resource.reference.resource_id]

    if variation == "duplicate":
        runner.resources["duplicate"] = {**row, "id": "duplicate"}

    elif variation == "digest":
        row["labels"] = {**dict(row["labels"]), "flayer-spec": "different"}  # type: ignore[arg-type]

    elif variation == "name":
        row["name"] = "other-name"

    elif variation == "status":
        row["status"] = "opaque-secret-status"

    else:
        row["external_ipv4_address"] = {"address": "192.0.2.10", "zone_id": "other-zone"}

    with pytest.raises(ProviderError):
        provider.FindResource(spec, IDENTITY)


@pytest.mark.parametrize("field", ["managed-by", "flayer-owner", "flayer-stack", "flayer-project", "flayer-resource"])
def test_DeleteVerifiesEveryOwnershipLabel(field: str) -> None:
    """A matching name or partial ownership cannot authorize exact-ID destruction."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    row = runner.resources[resource.reference.resource_id]
    row["labels"] = {**dict(row["labels"]), field: "foreign"}  # type: ignore[arg-type]

    with pytest.raises(MutationError) as caught:
        provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id)

    assert caught.value.outcome_unknown is False, "Ownership refusal was classified as dispatched"
    assert caught.value.code == ProviderErrorCode.SCOPE_MISMATCH, "Ownership failure lost its category"
    assert not any(command[3] == "delete" for command in runner.calls), "Foreign resource was deleted"


def test_DeleteMissingResourceIsSafeAndRepeated() -> None:
    """Missing exact references are an already-completed delete without a new mutation."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    runner.resources.clear()
    provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id)

    assert not any(command[3] == "delete" for command in runner.calls), "Missing resource was mutated"


@pytest.mark.parametrize("variation", ["provider", "folder", "response-folder"])
def test_ExactScopeMismatchPreventsMutation(variation: str) -> None:
    """Both request scope and fresh vendor scope must agree before destruction."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    identity = IDENTITY

    if variation == "provider":
        identity = dataclasses.replace(identity, provider="other-provider")

    elif variation == "folder":
        identity = dataclasses.replace(identity, scope_id="other-folder")

    else:
        runner.resources[resource.reference.resource_id]["folder_id"] = "other-folder"

    with pytest.raises(ProviderError):
        provider.DeleteResource(resource.reference, identity, spec.logical_id)

    assert not any(command[3] == "delete" for command in runner.calls), "Cross-scope deletion occurred"


@pytest.mark.parametrize(
    "response",
    [
        CommandResult(1, stderr="synthetic-secret-in-vendor-message"),
        CommandResult(0, "synthetic-secret-not-json"),
        subprocess.TimeoutExpired(("synthetic-secret-command",), 45),
        OSError("synthetic-secret-executable"),
        RuntimeError("synthetic-secret-unexpected-runner"),
    ],
)
def test_DispatchedCreateFailureIsUncertainSanitizedAndNeverRetried(
    response: CommandResult | Exception,
) -> None:
    """No dispatched failure can be mistaken for a safe instruction to recreate an orphan."""

    provider, runner = Provider()
    runner.overrides["create"] = response

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(Specs()[0], IDENTITY, {}, OPERATION_ID)

    evidence = "".join(traceback.format_exception(caught.value))

    assert caught.value.outcome_unknown is True, "Dispatched create was classified definitely absent"
    assert "synthetic-secret" not in evidence, "Vendor output or runner exception leaked"
    assert sum(command[3] == "create" for command in runner.calls) == 1, "Uncertain create was retried"


@pytest.mark.parametrize("field,value", [
    ("folder_id", "other-folder"), ("labels", {}), ("name", "other-name"),
    ("status", "UNKNOWN-SECRET"), ("id", "invalid id"),
])
def test_SuccessfulCreatePayloadMustMatchExactScopeAndOwnership(field: str, value: object) -> None:
    """Exit zero does not prove a resource belongs to the requested stack."""

    provider, runner = Provider()
    row: dict[str, object] = {
        "id": "fake-resource", "folder_id": "test-folder", "name": Specs()[0].name,
        "labels": {**dict(Specs()[0].OwnershipLabels(IDENTITY)), "flayer-operation": OPERATION_ID},
    }
    row[field] = value
    runner.overrides["create"] = CommandResult(0, json.dumps(row))

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(Specs()[0], IDENTITY, {}, OPERATION_ID)

    assert caught.value.outcome_unknown is True, "Bad create response discarded an orphan possibility"


@pytest.mark.parametrize("failure", ["still-present", "read-denied", "timeout"])
def test_DeleteRequiresConfirmedAbsenceAndPreservesUncertainty(failure: str) -> None:
    """A successful CLI exit or timeout cannot clear deletion evidence while the resource may exist."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    if failure == "timeout":
        runner.overrides["delete"] = subprocess.TimeoutExpired(("yc",), 45)

    else:
        original_run = runner.Run

        def Run(command: tuple[str, ...], timeout: float) -> CommandResult:
            """Inject post-delete observations without affecting the ownership preflight."""

            if command[3] == "delete":
                runner.calls.append(command)

                if failure == "read-denied":
                    runner.overrides["get"] = CommandResult(1, stderr="forbidden synthetic-secret")

                return CommandResult(0)

            return original_run(command, timeout)

        runner.Run = Run  # type: ignore[method-assign]

    with pytest.raises(MutationError) as caught:
        provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id)

    assert caught.value.outcome_unknown is True, "Unconfirmed deletion was classified complete"
    assert sum(command[3] == "delete" for command in runner.calls) == 1, "Deletion was blindly retried"


@pytest.mark.parametrize("index,key,value", [
    (0, "arbitrary_metadata", "unsupported"), (1, "ipv4_cidr", "10.42.0.1/24"),
    (1, "zone_id", "bad zone"), (1, "network_dependency", "missing"),
    (2, "rules", ()), (2, "rules", ((("direction", "ingress"),),)),
    (2, "rules", ((("direction", "ingress"), ("protocol", "icmp"), ("cidr", "0.0.0.0/0")),)),
    (4, "size_gib", True), (4, "size_gib", 1025), (4, "type", "arbitrary-type"),
    (5, "ssh_public_key", "PRIVATE KEY synthetic-secret"), (5, "ssh_public_key", "ssh-ed25519 AAAA"),
    (5, "ssh_public_key", PUBLIC_KEY + "\n"), (5, "ssh_username", "root;echo-secret"),
    (5, "cores", 0), (5, "memory_gib", True), (5, "user_data_file", "unsafe/../file"),
    (5, "user_data_sha256", "bad-digest"),
])
def test_UnsupportedOptionsFailBeforeAnyInfrastructureAccess(index: int, key: str, value: object) -> None:
    """Unsafe options are classified as definitely not submitted before read or mutation."""

    provider, runner = Provider()
    spec = ReplaceOption(Specs()[index], key, value)

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    assert caught.value.outcome_unknown is False, "Pure request rejection was classified as dispatched"
    assert runner.calls == [], "Invalid request accessed infrastructure"


def test_UnownedOrWrongZoneDependenciesCannotAuthorizeCreate() -> None:
    """Dependency observations are refreshed rather than trusting a caller-supplied object."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    spec = Specs()[-1]
    address = resources["address"]
    runner.resources[address.reference.resource_id]["labels"] = {}  # type: ignore[attr-defined]

    with pytest.raises(MutationError):
        provider.CreateResource(spec, IDENTITY, {
            key: resources[key] for key in spec.dependencies
        }, OPERATION_ID)  # type: ignore[arg-type]

    assert not any(command[2:4] == ("instance", "create") for command in runner.calls), "Unowned dependency was used"


def ArtifactSpec(tmp_path: Path, content: bytes) -> ResourceSpec:
    """Write a synthetic private nonsecret cloud-init artifact and bind its exact digest."""

    path = tmp_path / "server-cloud-init.json"
    path.write_bytes(content)
    path.chmod(0o600)
    spec = ReplaceOption(Specs()[-1], "user_data_file", str(path))

    return ReplaceOption(spec, "user_data_sha256", hashlib.sha256(content).hexdigest())


def test_InitializationUsesPrivateCopiedBoundedVerifiedArtifact(tmp_path: Path) -> None:
    """A verified immutable input snapshot reaches CLI metadata and its temporary copy is removed."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    content = b'#cloud-config\n{"ssh_pwauth":false,"disable_root":true}\n'
    spec = ArtifactSpec(tmp_path, content)
    provider.CreateResource(spec, IDENTITY, {
        key: resources[key] for key in spec.dependencies
    }, OPERATION_ID)  # type: ignore[arg-type]

    assert runner.last_user_data == content, "Initialization bytes changed between validation and CLI"
    assert runner.last_temporary_path is not None and not Path(
        runner.last_temporary_path
    ).exists(), "Private temporary initialization artifact was retained"

    if os.name == "posix":
        assert runner.last_temporary_mode == 0o600, "CLI input snapshot was world readable"


@pytest.mark.parametrize("variation", [
    "missing", "symlink", "parent-symlink", "directory", "permissions", "oversized", "digest",
    "invalid-json", "unsupported-json", "invalid-utf8", "truncated-integer", "fifo",
])
def test_UnsafeInitializationNeverAccessesCloud(tmp_path: Path, variation: str) -> None:
    """Untrusted local file boundaries fail before discovery, mutation or secret-bearing errors."""

    provider, runner = Provider()
    spec = ArtifactSpec(tmp_path, b'{"ssh_pwauth":false}\n')
    path = Path(str(dict(spec.parameters)["user_data_file"]))

    if variation == "missing":
        path.unlink()

    elif variation == "symlink":
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)

    elif variation == "parent-symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        spec = ReplaceOption(spec, "user_data_file", str(alias / path.name))

    elif variation == "directory":
        path.unlink()
        path.mkdir()

    elif variation == "permissions":
        if os.name != "posix":
            pytest.skip("POSIX permission check is platform-specific")

        path.chmod(0o644)

    elif variation == "oversized":
        path.write_bytes(b"x" * (MAX_USER_DATA_BYTES + 1))

    elif variation == "digest":
        path.write_bytes(b'{"ssh_pwauth":true}\n')

    elif variation == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO regression requires a POSIX host")

        path.unlink()
        os.mkfifo(path, 0o600)

    else:
        content = {
            "invalid-json": b"synthetic-secret-invalid-json",
            "unsupported-json": b'{"password":"synthetic-secret"}',
            "invalid-utf8": b"\xff",
            "truncated-integer": b'{"ssh_pwauth":' + b"1" * 5000 + b"}",
        }[variation]
        spec = ArtifactSpec(tmp_path, content)

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    assert caught.value.outcome_unknown is False, "Invalid local artifact was classified as dispatched"
    assert runner.calls == [], "Invalid local initialization accessed cloud infrastructure"
    assert "synthetic-secret" not in "".join(traceback.format_exception(caught.value)), "Artifact contents leaked"


def test_InitializationTemporaryFileFailureRemainsSafe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Failure to prepare private CLI input happens before mutation and exposes no local path."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    spec = ArtifactSpec(tmp_path, b'{"ssh_pwauth":false}\n')
    monkeypatch.setattr("flayer.providers.yandex_lifecycle.tempfile.NamedTemporaryFile", Mock(
        side_effect=OSError("synthetic-secret-local-path")
    ))

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, {
            key: resources[key] for key in spec.dependencies
        }, OPERATION_ID)  # type: ignore[arg-type]

    assert caught.value.outcome_unknown is False, "Temporary file failure was classified as dispatched"
    assert not any(command[2:4] == ("instance", "create") for command in runner.calls), "Failed file preparation dispatched"
    assert "synthetic-secret" not in "".join(traceback.format_exception(caught.value)), "Local input path leaked"


def test_TimeoutAfterAcceptedCreateRetainsDiscoverableOperationNonce() -> None:
    """An accepted mutation remains uniquely attributable after its response is lost."""

    provider, runner = Provider()
    original_run = runner.Run

    def Run(command: tuple[str, ...], timeout: float) -> CommandResult:
        """Lose only the create response after preserving the fake remote resource."""

        response = original_run(command, timeout)

        if command[3] == "create":
            raise subprocess.TimeoutExpired(("synthetic-secret-command",), timeout)

        return response

    runner.Run = Run  # type: ignore[method-assign]
    spec = Specs()[0]

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    recovered = provider.FindResource(spec, IDENTITY)

    assert caught.value.outcome_unknown is True, "Accepted mutation was classified absent"
    assert recovered is not None, "Stable logical labels cannot reconcile an interrupted create"
    assert dict(recovered.labels)["flayer-operation"] == OPERATION_ID, "Operation attribution was lost"
    assert sum(command[3] == "create" for command in runner.calls) == 1, "Recovery recreated an orphan"


@pytest.mark.parametrize("operation_id", ["", "b" * 31, "b" * 33, "z" * 32, True])
def test_InvalidOperationNonceCannotAccessCloud(operation_id: object) -> None:
    """Every mutation requires an explicit bounded journal operation identity."""

    provider, runner = Provider()

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(Specs()[0], IDENTITY, {}, operation_id)  # type: ignore[arg-type]

    assert caught.value.outcome_unknown is False, "Invalid operation was classified submitted"
    assert runner.calls == [], "Invalid operation nonce accessed infrastructure"


def test_PreexistingResourceKeepsItsOriginalOperationNonce() -> None:
    """An idempotent adoption cannot claim another operation's resource as newly created."""

    provider, runner = Provider()
    spec = Specs()[0]
    first = provider.CreateResource(spec, IDENTITY, {}, "b" * 32)
    second = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)

    assert first.reference == second.reference, "Existing ownership was duplicated"
    assert dict(second.labels)["flayer-operation"] == "b" * 32, "Adoption overwrote operation attribution"
    assert sum(command[3] == "create" for command in runner.calls) == 1, "Adoption mutated an existing resource"


@pytest.mark.parametrize("variation", ["missing-map", "wrong-kind", "wrong-zone", "inactive", "no-address"])
def test_DependencyStructureFreshZoneAndStatusAreRequired(variation: str) -> None:
    """The caller cannot substitute arbitrary references or stale observations for graph bindings."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    spec = Specs()[-1]
    mapping = {key: resources[key] for key in spec.dependencies}
    address = resources["address"]

    if variation == "missing-map":
        mapping.pop("address")

    elif variation == "wrong-kind":
        mapping["address"] = resources["boot-disk"]

    elif variation == "wrong-zone":
        runner.resources[address.reference.resource_id]["external_ipv4_address"] = {  # type: ignore[attr-defined]
            "address": "192.0.2.10", "zone_id": "other-zone",
        }

    elif variation == "inactive":
        runner.resources[address.reference.resource_id]["status"] = "DELETING"  # type: ignore[attr-defined]

    else:
        runner.resources[address.reference.resource_id]["external_ipv4_address"] = {  # type: ignore[attr-defined]
            "zone_id": ZONE,
        }

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, mapping, OPERATION_ID)  # type: ignore[arg-type]

    assert caught.value.outcome_unknown is False, "Dependency preflight was classified submitted"
    assert not any(command[2:4] == ("instance", "create") for command in runner.calls), "Invalid dependency was used"


@pytest.mark.parametrize("rules", [
    ("invalid-shape",),
    ((("direction", "ingress"), ("direction", "egress"), ("protocol", "any"), ("cidr", "0.0.0.0/0")),),
    ((("direction", "unknown"), ("protocol", "any"), ("cidr", "0.0.0.0/0")),),
    ((("direction", "egress"), ("protocol", "any"), ("cidr", "0.0.0.0/0"), ("from_port", 1)),),
    ((("direction", "ingress"), ("protocol", "tcp"), ("cidr", "192.0.2.0/24")),),
    ((("direction", "ingress"), ("protocol", "tcp"), ("cidr", "192.0.2.0/24"), ("from_port", 100), ("to_port", 99)),),
    ((("direction", "egress"), ("protocol", "any"), ("cidr", "0.0.0.0/0")),) * 2,
])
def test_MalformedSecurityRulesNeverReachVendor(rules: object) -> None:
    """Security rules cannot insert unsupported options, duplicate fields or inverted ranges."""

    provider, runner = Provider()
    spec = ReplaceOption(Specs()[2], "rules", rules)

    with pytest.raises(MutationError):
        provider.ValidateSpec(spec)

    assert runner.calls == [], "Malformed security rule reached the provider transport"


def test_SSHKeyStructuralBoundsAndCommentRemoval() -> None:
    """RSA public keys must meet a minimum bit count and comments never enter CLI metadata."""

    provider, _ = Provider()

    def EncodeField(value: bytes) -> bytes:
        """Encode one OpenSSH binary public key field for deterministic synthetic test keys."""

        return len(value).to_bytes(4, "big") + value

    rsa = b"".join(EncodeField(field) for field in (
        b"ssh-rsa", b"\x01\x00\x01", b"\x00\x80" + b"\x00" * 255,
    ))
    provider.ValidateSpec(ReplaceOption(Specs()[-1], "ssh_public_key", "ssh-rsa " + base64.b64encode(
        rsa
    ).decode("ascii")))

    for data in (b"\x00", KEY_BYTES[:-1], KEY_BYTES[:4] + b"other-algo" + KEY_BYTES[15:]):
        with pytest.raises(MutationError):
            provider.ValidateSpec(ReplaceOption(Specs()[-1], "ssh_public_key", "ssh-ed25519 " + base64.b64encode(
                data
            ).decode("ascii")))

    resources = CreateDependencies(provider)
    spec = ReplaceOption(Specs()[-1], "ssh_public_key", PUBLIC_KEY + " untrusted-comment,$(echo)")
    provider.CreateResource(spec, IDENTITY, {
        key: resources[key] for key in spec.dependencies
    }, OPERATION_ID)  # type: ignore[arg-type]

    runner = provider._runner
    metadata = runner.calls[-1][runner.calls[-1].index("--metadata") + 1]  # type: ignore[attr-defined]

    assert "untrusted-comment" not in metadata, "Public-key comment entered a CLI property value"


def test_UnknownObservedNameAndGetFailuresRemainSanitized() -> None:
    """Observed malformed fields and pre-delete access failures cannot bypass provider validation."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    runner.resources[resource.reference.resource_id]["name"] = "invalid secret name"

    with pytest.raises(ProviderError):
        provider.GetResource(resource.reference)

    runner.overrides["get"] = CommandResult(1, stderr="forbidden synthetic-secret")

    with pytest.raises(ProviderError) as caught:
        provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id)

    assert "synthetic-secret" not in str(caught.value), "Pre-delete vendor error escaped sanitization"
    assert not any(command[3] == "delete" for command in runner.calls), "Failed ownership observation mutated cloud"


def test_PrivateTemporaryCleanupFailurePreservesRemoteUncertainty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cleanup failure cannot discard evidence that cloud mutation may have completed."""

    provider, runner = Provider()
    resources = CreateDependencies(provider)
    spec = ArtifactSpec(tmp_path, b'{"ssh_pwauth":false}\n')
    original_unlink = os.unlink

    with monkeypatch.context() as context:
        context.setattr("flayer.providers.yandex_lifecycle.os.unlink", Mock(
            side_effect=OSError("synthetic-secret-input-path")
        ))

        with pytest.raises(MutationError) as caught:
            provider.CreateResource(spec, IDENTITY, {
                key: resources[key] for key in spec.dependencies
            }, OPERATION_ID)  # type: ignore[arg-type]

    assert caught.value.outcome_unknown is True, "Post-mutation cleanup failure lost remote uncertainty"
    assert "synthetic-secret" not in "".join(traceback.format_exception(caught.value)), "Cleanup path leaked"
    assert runner.last_temporary_path is not None, "Fake CLI never received a temporary input"

    original_unlink(runner.last_temporary_path)


def test_RollbackDeletionRechecksItsExactOperationNonce() -> None:
    """Fresh provider ownership cannot authorize rollback of another operation's creation."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, "b" * 32)

    with pytest.raises(MutationError) as caught:
        provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id, OPERATION_ID)

    assert caught.value.outcome_unknown is False, "Nonce mismatch was classified dispatched"
    assert not any(command[3] == "delete" for command in runner.calls), "Cross-operation rollback deleted a resource"

    provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id, "b" * 32)

    assert not runner.resources, "Correctly attributed rollback could not remove its resource"


@pytest.mark.parametrize("operation_id", ["invalid", "b" * 31, True])
def test_InvalidRollbackNonceRejectsBeforeLookup(operation_id: object) -> None:
    """An invalid rollback operation identifier cannot trigger even an exact-ID observation."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    previous_count = len(runner.calls)

    with pytest.raises(MutationError):
        provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id, operation_id)  # type: ignore[arg-type]

    assert len(runner.calls) == previous_count, "Malformed rollback nonce accessed infrastructure"


def test_AllSixtyFourExplicitTCPRulesFitTheImmutableBudget() -> None:
    """The documented maximum rule count is representable without exceeding generic node bounds."""

    provider, runner = Provider()
    rules = tuple(
        (("direction", "ingress"), ("protocol", "tcp"), ("cidr", "192.0.2.0/24"),
         ("from_port", port), ("to_port", port))
        for port in range(1, 65)
    )
    provider.ValidateSpec(ReplaceOption(Specs()[2], "rules", rules))

    with pytest.raises(MutationError):
        provider.ValidateSpec(dataclasses.replace(Specs()[0], name="invalid-"))

    assert runner.calls == [], "Boundary validation accessed infrastructure"


@pytest.mark.parametrize("phase,failure", [
    ("list", CommandResult(1, stderr="forbidden synthetic-secret")),
    ("list", subprocess.TimeoutExpired(("synthetic-secret",), 45)),
    ("list", RuntimeError("synthetic-secret-transport")),
    ("get", CommandResult(1, stderr="forbidden synthetic-secret")),
    ("get", subprocess.TimeoutExpired(("synthetic-secret",), 45)),
])
def test_PredispatchReadFailureIsDefinitelyNotSubmitted(
    phase: str, failure: CommandResult | Exception,
) -> None:
    """Read-only preflight failure permits safe rollback instead of an unrecoverable absent-create journal."""

    provider, runner = Provider()
    resources = CreateDependencies(provider) if phase == "get" else {}
    spec = Specs()[-1] if phase == "get" else Specs()[0]
    previous_creates = sum(command[3] == "create" for command in runner.calls)
    runner.overrides[phase] = failure

    with pytest.raises(MutationError) as caught:
        provider.CreateResource(spec, IDENTITY, {
            key: resources[key] for key in spec.dependencies
        }, OPERATION_ID)  # type: ignore[arg-type]

    assert caught.value.outcome_unknown is False, "Read-only preflight failure was classified submitted"
    assert sum(command[3] == "create" for command in runner.calls) == previous_creates, "Read failure still dispatched mutation"
    assert "synthetic-secret" not in "".join(traceback.format_exception(caught.value)), "Preflight runner details leaked"


@pytest.mark.parametrize("phase", ["find", "get", "delete-before", "delete-after"])
def test_UnexpectedReadTransportErrorsAreAlwaysSanitized(phase: str) -> None:
    """An injected transport implementation cannot leak raw exceptions through lifecycle reads."""

    provider, runner = Provider()
    spec = Specs()[0]
    resource = provider.CreateResource(spec, IDENTITY, {}, OPERATION_ID)
    error = RuntimeError("synthetic-private-transport-error")

    if phase == "find":
        runner.overrides["list"] = error

    elif phase == "delete-after":
        original_run = runner.Run

        def Run(command: tuple[str, ...], timeout: float) -> CommandResult:
            """Inject a transport exception only after the fake delete was dispatched."""

            response = original_run(command, timeout)

            if command[3] == "delete":
                runner.overrides["get"] = error

            return response

        runner.Run = Run  # type: ignore[method-assign]

    else:
        runner.overrides["get"] = error

    with pytest.raises(ProviderError) as caught:
        if phase == "find":
            provider.FindResource(spec, IDENTITY)

        elif phase == "get":
            provider.GetResource(resource.reference)

        else:
            provider.DeleteResource(resource.reference, IDENTITY, spec.logical_id)

    assert "synthetic-private" not in "".join(traceback.format_exception(caught.value)), "Read transport exception leaked"
    assert sum(command[3] == "delete" for command in runner.calls) == (phase == "delete-after"), "Read failure caused unexpected delete dispatch"

    if phase == "delete-after":
        assert isinstance(caught.value, MutationError) and caught.value.outcome_unknown is True, "Post-delete transport failure lost uncertainty"
