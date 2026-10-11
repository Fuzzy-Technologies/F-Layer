"""Deterministic tests for bounded, scoped and sanitized Yandex CLI discovery."""

from __future__ import annotations

import json
import subprocess
import traceback
from unittest.mock import Mock

import pytest

from flayer.providers.contracts import (
    CloudProvider,
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ResourceKind,
    ResourceReference,
)
from flayer.providers.yandex import (
    CommandResult,
    SubprocessCommandRunner,
    YandexCloudProvider,
    YandexCloudSettings,
)


class FakeCommandRunner:
    """Record commands and supply fake outputs without executing a CLI or cloud call."""

    def __init__(self, results: list[CommandResult | Exception]) -> None:
        """Store the ordered responses and independently recorded invocation evidence."""

        self.results = list(results)
        self.calls: list[tuple[tuple[str, ...], float]] = []

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Supply the next deterministic result or explicitly injected execution failure."""

        self.calls.append((command, timeout))
        result = self.results.pop(0)

        if isinstance(result, Exception):
            raise result

        return result


def ResourcePayload(resource_id: str = "resource-1", **values: object) -> dict[str, object]:
    """Build public synthetic provider observations, never private infrastructure data."""

    payload: dict[str, object] = {
        "id": resource_id,
        "folder_id": "test-folder",
        "name": "example-resource",
        "labels": {"project": "example"},
    }
    payload.update(values)

    return payload


def ProviderWithPayload(payload: object) -> tuple[YandexCloudProvider, FakeCommandRunner]:
    """Build an isolated provider with one JSON response for a read operation."""

    runner = FakeCommandRunner([CommandResult(0, json.dumps(payload))])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    return provider, runner


@pytest.mark.parametrize(
    "values",
    [
        {"folder_id": "--other-folder"},
        {"profile": "profile with spaces"},
        {"executable": ""},
        {"executable": "yc\x00"},
        {"command_timeout": 0},
        {"command_timeout": 301},
        {"command_timeout": float("nan")},
        {"command_timeout": True},
        {"command_timeout": "45"},
        {"inventory_limit": 0},
        {"inventory_limit": 100001},
        {"inventory_limit": True},
        {"inventory_limit": 1.5},
    ],
)
def test_SettingsRejectUnboundedOrUnsafeValues(values: dict[str, object]) -> None:
    """Settings require safe selectors, finite timeouts and a bounded integer limit."""

    arguments: dict[str, object] = {"folder_id": "test-folder"}
    arguments.update(values)

    with pytest.raises(ValueError):
        YandexCloudSettings(**arguments)  # type: ignore[arg-type]


def test_ConstructingProviderHasNoImplicitInfrastructureAccess() -> None:
    """Construction and capability inspection cannot execute commands or read credentials."""

    runner = FakeCommandRunner([])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    assert isinstance(provider, CloudProvider), "Yandex adapter violates the provider protocol"
    assert provider.Identity.provider_id == "yandex-cloud", "Unexpected provider identity"
    assert provider.Identity.scope_id == "test-folder", "Explicit provider scope was lost"
    assert provider.Identity.authentication_source == "cli-profile", "Unexpected credential source"
    assert provider.Capabilities == {
        ProviderCapability.INVENTORY, ProviderCapability.RESOURCE_LOOKUP
    }, "Provider advertised unimplemented mutation capabilities"
    assert runner.calls == [], "Provider construction accessed external infrastructure"


def test_DefaultRunnerCanBeConstructedWithoutExecutingIt() -> None:
    """Production defaults create an adapter without discovering or invoking local tools."""

    provider = YandexCloudProvider(YandexCloudSettings("test-folder"))

    assert provider.Identity.scope_id == "test-folder", "Production provider lost its folder scope"


def test_SubprocessRunnerUsesNoShellAndBoundsExecution(monkeypatch: pytest.MonkeyPatch) -> None:
    """The production runner uses a direct vector, closed stdin and an explicit timeout."""

    process = subprocess.CompletedProcess(("yc", "--version"), 0, "example-version", "")
    run = Mock(return_value=process)
    monkeypatch.setattr(subprocess, "run", run)
    result = SubprocessCommandRunner().Run(("yc", "--version"), 7.5)

    assert result.stdout == "example-version", "Runner lost successful command output"
    assert run.call_args.args == (("yc", "--version"),), "Runner changed the command vector"
    assert run.call_args.kwargs["shell"] is False, "Runner enabled shell interpretation"
    assert run.call_args.kwargs["stdin"] == subprocess.DEVNULL, "Runner can prompt interactively"
    assert run.call_args.kwargs["timeout"] == 7.5, "Runner lost its bounded timeout"
    assert run.call_args.kwargs["capture_output"] is True, "Runner exposed external output"


def test_CommandResultRepresentationOmitsCapturedSecrets() -> None:
    """Transient raw output cannot leak through accidental dataclass repr logging."""

    result = CommandResult(1, "synthetic-secret-stdout", "synthetic-secret-stderr")

    assert "secret" not in repr(result), "CommandResult representation exposed command output"


def test_AvailabilityChecksOnlyCliVersion() -> None:
    """CLI availability distinguishes a local executable from authenticated cloud access."""

    runner = FakeCommandRunner([CommandResult(0, "Yandex Cloud CLI example-version")])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder", command_timeout=9), runner)
    status = provider.CheckAvailability()

    assert status.available and status.authenticated is None, "Availability implied authentication"
    assert runner.calls == [(("yc", "--version"), 9)], "Availability probe accessed infrastructure"


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (FileNotFoundError("synthetic-secret"), ProviderErrorCode.UNAVAILABLE),
        (PermissionError("synthetic-secret"), ProviderErrorCode.UNAVAILABLE),
        (subprocess.TimeoutExpired("synthetic-secret", 4), ProviderErrorCode.TIMEOUT),
        (CommandResult(1, "synthetic-secret", ""), ProviderErrorCode.COMMAND_FAILED),
    ],
)
def test_AvailabilityFailuresAreSanitized(
    failure: CommandResult | Exception, code: ProviderErrorCode
) -> None:
    """Failures become typed status without exposing paths, process output or secrets."""

    runner = FakeCommandRunner([failure])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)
    status = provider.CheckAvailability()

    assert not status.available and status.error_code == code, "Incorrect availability failure"
    assert status.authenticated is None, "Failed local check guessed credential validity"
    assert "synthetic-secret" not in repr(status), "Availability status leaked external details"


def test_AuthenticationProbesExplicitFolderWithoutTokenExport() -> None:
    """Authentication verifies folder access without creating or capturing IAM tokens."""

    provider, runner = ProviderWithPayload({"id": "test-folder", "name": "example-folder"})
    status = provider.CheckAuthentication()
    command, timeout = runner.calls[0]

    assert status.available and status.authenticated, "Folder access probe did not succeed"
    assert command[:6] == (
        "yc", "resource-manager", "folder", "get", "--id", "test-folder"
    ), "Authentication probe changed its bounded folder target"
    assert "create-token" not in command and "--token" not in command, "Provider exported tokens"
    assert "--no-browser" in command and timeout == 45, "Authentication can hang interactively"


@pytest.mark.parametrize("payload", [{"id": "foreign-folder"}, [], None])
def test_AuthenticationRejectsUnverifiedScope(payload: object) -> None:
    """A successful command cannot authenticate an unverified or foreign folder."""

    provider, _ = ProviderWithPayload(payload)
    status = provider.CheckAuthentication()

    assert status.authenticated is False, "Authentication accepted an unverified folder"
    assert status.error_code == ProviderErrorCode.SCOPE_MISMATCH, (
        "Folder mismatch lost its category"
    )


def test_AuthenticationReportsMissingLocalAdapter() -> None:
    """Authentication preserves a missing CLI as unavailable without cloud assumptions."""

    runner = FakeCommandRunner([FileNotFoundError("synthetic-secret")])
    status = YandexCloudProvider(YandexCloudSettings("test-folder"), runner).CheckAuthentication()

    assert not status.available and status.authenticated is False, (
        "Missing CLI was treated as ready"
    )
    assert status.error_code == ProviderErrorCode.UNAVAILABLE, "Missing CLI lost its failure code"


@pytest.mark.parametrize(
    ("details", "code"),
    [
        ("rpc error: code = Unauthenticated", ProviderErrorCode.AUTHENTICATION),
        ("token expired", ProviderErrorCode.AUTHENTICATION),
        ("rpc error: code = PermissionDenied", ProviderErrorCode.PERMISSION_DENIED),
        ("FORBIDDEN", ProviderErrorCode.PERMISSION_DENIED),
        ("rpc error: code = NotFound", ProviderErrorCode.NOT_FOUND),
        ("rpc error: code = DeadlineExceeded", ProviderErrorCode.TIMEOUT),
        ("rpc error: code = ResourceExhausted", ProviderErrorCode.THROTTLED),
        ("rpc error: code = AlreadyExists", ProviderErrorCode.CONFLICT),
        ("arbitrary failure", ProviderErrorCode.COMMAND_FAILED),
    ],
)
def test_ProviderErrorsNormalizeWithoutExternalText(details: str, code: ProviderErrorCode) -> None:
    """Error categories retain useful diagnostics while raw vendor details never propagate."""

    runner = FakeCommandRunner([CommandResult(1, "", f"{details}; synthetic-secret")])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.INSTANCE)

    assert error.value.code == code, "Vendor failure was assigned an incorrect category"
    assert "synthetic-secret" not in str(error.value), "Provider error leaked command output"
    assert "synthetic-secret" not in repr(error.value), "Provider error repr leaked command output"


@pytest.mark.parametrize(
    "failure",
    [
        subprocess.TimeoutExpired("yc", 45, output="synthetic-secret"),
        OSError("synthetic-secret"),
    ],
)
def test_ExecutionExceptionsSuppressSecretTracebacks(failure: Exception) -> None:
    """Exception chains cannot expose captured process output or local path details."""

    runner = FakeCommandRunner([failure])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.NETWORK)

    assert error.value.__context__ is None, "Sanitized error retained the original exception"

    rendered = "".join(traceback.format_exception(error.value))

    assert "synthetic-secret" not in rendered, "Sanitized error retained a secret exception chain"


def test_ListResourcesNormalizesAndSortsOnlyPublicContractFields() -> None:
    """Inventory keeps ownership labels and IPs while dropping instance user data and metadata."""

    payload = [
        ResourcePayload("vm-2", metadata={"user-data": "synthetic-secret"}),
        ResourcePayload(
            "vm-1",
            status="RUNNING",
            zone_id="example-zone-a",
            labels={"project": "example", "managed-by": "f-layer"},
            network_interfaces=[{
                "primary_v4_address": {"one_to_one_nat": {"address": "203.0.113.10"}}
            }],
        ),
    ]
    provider, runner = ProviderWithPayload(payload)
    resources = provider.ListResources(ResourceKind.INSTANCE)
    command, _ = runner.calls[0]

    assert [resource.reference.resource_id for resource in resources] == ["vm-1", "vm-2"], (
        "Inventory ordering depends on vendor response order"
    )
    assert resources[0].status == "RUNNING", "VM state was lost during normalization"
    assert resources[0].zone_id == "example-zone-a", "VM zone was lost during normalization"
    assert resources[0].labels == (("managed-by", "f-layer"), ("project", "example")), (
        "Ownership labels were not normalized deterministically"
    )
    assert resources[0].public_addresses == ("203.0.113.10",), "External address was lost"
    assert resources[1].status == "UNKNOWN", "Missing vendor state was guessed"
    assert "synthetic-secret" not in repr(resources), "Raw instance metadata leaked into resources"
    assert command == (
        "yc", "compute", "instance", "list", "--limit", "1000",
        "--profile", "default", "--folder-id", "test-folder", "--format", "json",
        "--no-browser", "--retry", "0",
    ), "Inventory command lost explicit scope, format or retry bounds"


def test_ReservedAddressUsesExternalIpv4Field() -> None:
    """Address resources translate the provider's external address field into generic endpoints."""

    provider, _ = ProviderWithPayload([
        ResourcePayload(external_ipv4_address={"address": "203.0.113.20"})
    ])
    resources = provider.ListResources(ResourceKind.ADDRESS)

    assert resources[0].public_addresses == ("203.0.113.20",), "Reserved address was not translated"


def test_InstanceWithoutNatHasNoPublicEndpoint() -> None:
    """Private-only interfaces never synthesize external addresses from internal fields."""

    provider, _ = ProviderWithPayload([ResourcePayload(
        network_interfaces=[{"primary_v4_address": {"address": "192.0.2.10"}}]
    )])
    resources = provider.ListResources(ResourceKind.INSTANCE)

    assert resources[0].public_addresses == (), "Private address was exposed as a public endpoint"


def test_EmptyInventoryIsSuccessful() -> None:
    """An empty folder is an observable empty inventory rather than an unavailable provider."""

    provider, _ = ProviderWithPayload([])

    assert provider.ListResources(ResourceKind.NETWORK) == (), "Empty resource list was rejected"


@pytest.mark.parametrize("kind", list(ResourceKind))
@pytest.mark.parametrize("configured_limit", [7, 1000, 10000, 100000])
def test_ListRespectsCloudPageMaximum(kind: ResourceKind, configured_limit: int) -> None:
    """Configured inventory ceilings cannot exceed the API request page-size bound."""

    runner = FakeCommandRunner([CommandResult(0, "[]")])
    provider = YandexCloudProvider(
        YandexCloudSettings("test-folder", inventory_limit=configured_limit), runner
    )

    assert provider.ListResources(kind) == (), "Empty inventory must remain discoverable"

    command, _ = runner.calls[0]
    limit = int(command[command.index("--limit") + 1])

    assert 1 <= limit <= 1000, "CLI limit violates the cloud page_size maximum"
    assert limit <= configured_limit, "CLI request exceeded the caller's smaller ceiling"


@pytest.mark.parametrize("configured_limit", [1000, 10000, 100000])
@pytest.mark.parametrize("row_count", [999, 1000, 1001])
def test_CloudPageSaturationRemainsIncomplete(configured_limit: int, row_count: int) -> None:
    """A full cloud-sized page must not silently hide resources from ownership discovery."""

    payload = [ResourcePayload(f"resource-{index}") for index in range(row_count)]
    runner = FakeCommandRunner([CommandResult(0, json.dumps(payload))])
    provider = YandexCloudProvider(
        YandexCloudSettings("test-folder", inventory_limit=configured_limit), runner
    )

    if row_count < 1000:
        assert len(provider.ListResources(ResourceKind.NETWORK)) == row_count, (
            "A non-saturated valid response was rejected"
        )

    else:
        with pytest.raises(ProviderError) as error:
            provider.ListResources(ResourceKind.NETWORK)

        assert error.value.code == ProviderErrorCode.INCOMPLETE_INVENTORY, (
            "Cloud-page saturation was mistaken for complete ownership inventory"
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        None,
        [None],
        [ResourcePayload(id=None)],
        [ResourcePayload(id="--malformed")],
        [ResourcePayload(name=None)],
        [ResourcePayload(status=1)],
        [ResourcePayload(zone_id="--malformed")],
        [ResourcePayload(labels=[])],
        [ResourcePayload(labels={"project": 1})],
        [ResourcePayload(network_interfaces={})],
        [ResourcePayload(network_interfaces=[None])],
        [ResourcePayload(network_interfaces=[{"primary_v4_address": None}])],
        [ResourcePayload(network_interfaces=[{
            "primary_v4_address": {"one_to_one_nat": {"address": False}}
        }])],
        [ResourcePayload(network_interfaces=[{
            "primary_v4_address": {"one_to_one_nat": {"address": "invalid-address"}}
        }])],
        [ResourcePayload("duplicate"), ResourcePayload("duplicate")],
    ],
)
def test_MalformedResourceInventoryFailsClosed(payload: object) -> None:
    """Unexpected response shape or identity cannot produce a seemingly valid inventory."""

    provider, _ = ProviderWithPayload(payload)

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.INSTANCE)

    assert error.value.code == ProviderErrorCode.INVALID_RESPONSE, "Malformed resource was accepted"
    assert error.value.__context__ is None, "Malformed resource retained a vendor parsing exception"


@pytest.mark.parametrize(
    "external", [None, [], {"address": "invalid-address"}, {"address": True}, {"address": ""}]
)
def test_AddressResourcesRejectMalformedEndpoints(external: object) -> None:
    """Malformed reserved addresses cannot enter the normalized inventory."""

    provider, _ = ProviderWithPayload([ResourcePayload(external_ipv4_address=external)])

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.ADDRESS)

    assert error.value.code == ProviderErrorCode.INVALID_RESPONSE, "Malformed endpoint was accepted"


@pytest.mark.parametrize(
    "output",
    [
        "",
        "synthetic-secret: not-json",
        "{" + '"a": [' * 1100,
        "[" + "7" * 5000 + "]",
        '["synthetic-secret",' + "7" * 5000 + "]",
    ],
)
def test_JsonErrorsCannotExposeResponseText(output: str) -> None:
    """Invalid or excessively nested JSON produces only a stable sanitized error."""

    runner = FakeCommandRunner([CommandResult(0, output)])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.INSTANCE)

    assert error.value.code == ProviderErrorCode.INVALID_RESPONSE, "Invalid JSON was accepted"
    assert error.value.__context__ is None, "Sanitized JSON error retained the original exception"
    assert "synthetic-secret" not in "".join(traceback.format_exception(error.value)), (
        "JSON decode traceback leaked the captured response"
    )


def test_ListRejectsForeignFolderResponse() -> None:
    """Explicit command scope must also match every returned resource's observed folder."""

    provider, _ = ProviderWithPayload([ResourcePayload(folder_id="foreign-folder")])

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.NETWORK)

    assert error.value.code == ProviderErrorCode.SCOPE_MISMATCH, "Foreign folder resources escaped"


def test_InventoryLimitSaturationFailsInsteadOfReturningPartialState() -> None:
    """A response at the vendor limit is potentially truncated and cannot claim completeness."""

    runner = FakeCommandRunner([CommandResult(0, json.dumps([ResourcePayload()]))])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder", inventory_limit=1), runner)

    with pytest.raises(ProviderError) as error:
        provider.ListResources(ResourceKind.NETWORK)

    assert error.value.code == ProviderErrorCode.INCOMPLETE_INVENTORY, "Truncated inventory escaped"


def test_UnsupportedKindCannotInjectCommands() -> None:
    """Arbitrary strings cannot select CLI subcommands even when they resemble enum values."""

    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), FakeCommandRunner([]))

    with pytest.raises(ProviderError) as error:
        provider.ListResources("instance")  # type: ignore[arg-type]

    assert error.value.code == ProviderErrorCode.UNSUPPORTED, "Arbitrary kind entered CLI execution"


@pytest.mark.parametrize(
    ("provider_id", "scope_id"), [("foreign-cloud", "test-folder"), ("yandex-cloud", "foreign")]
)
def test_GetRejectsForeignReferencesBeforeExecution(provider_id: str, scope_id: str) -> None:
    """A reference from another provider or folder cannot trigger even a read operation."""

    runner = FakeCommandRunner([])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)
    reference = ResourceReference(provider_id, scope_id, ResourceKind.INSTANCE, "vm-1")

    with pytest.raises(ProviderError) as error:
        provider.GetResource(reference)

    assert error.value.code == ProviderErrorCode.SCOPE_MISMATCH, "Foreign reference was accepted"
    assert runner.calls == [], "Foreign reference accessed external infrastructure"


def test_GetResourceReturnsNormalizedMatchingIdentity() -> None:
    """Lookup reads the exact validated ID and requires an identical normalized reference."""

    provider, runner = ProviderWithPayload(ResourcePayload("vm-1"))
    reference = ResourceReference("yandex-cloud", "test-folder", ResourceKind.INSTANCE, "vm-1")
    resource = provider.GetResource(reference)

    assert resource.reference == reference, "Lookup returned another resource identity"
    assert runner.calls[0][0][:6] == (
        "yc", "compute", "instance", "get", "--id", "vm-1"
    ), "Lookup changed the requested resource ID"


@pytest.mark.parametrize(
    "payload", [ResourcePayload("other-vm"), ResourcePayload("vm-1", folder_id="foreign")]
)
def test_GetRechecksObservedScopeAndIdentity(payload: object) -> None:
    """Vendor global ID lookup cannot return a resource outside the reference scope."""

    provider, _ = ProviderWithPayload(payload)
    reference = ResourceReference("yandex-cloud", "test-folder", ResourceKind.INSTANCE, "vm-1")

    with pytest.raises(ProviderError) as error:
        provider.GetResource(reference)

    assert error.value.code == ProviderErrorCode.SCOPE_MISMATCH, (
        "Global ID lookup escaped its scope"
    )


def test_CompleteInventoryQueriesEverySupportedKind() -> None:
    """Discovery composes all six supported resource kinds inside the same explicit folder."""

    runner = FakeCommandRunner([
        CommandResult(0, json.dumps([ResourcePayload(f"resource-{index}")]))
        for index, _ in enumerate(ResourceKind)
    ])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder", profile="example"), runner)
    resources = provider.DiscoverInventory()

    assert tuple(resource.reference.kind for resource in resources) == tuple(ResourceKind), (
        "Complete inventory omitted a supported resource kind"
    )
    assert [command[1:3] for command, _ in runner.calls] == [
        ("compute", "instance"), ("compute", "disk"), ("vpc", "network"),
        ("vpc", "subnet"), ("vpc", "address"), ("vpc", "security-group"),
    ], "Inventory used an unsupported provider command"
    assert all(
        command[command.index("--folder-id") + 1] == "test-folder" for command, _ in runner.calls
    ), (
        "Complete inventory crossed folder boundaries"
    )


def test_DiscoveryDoesNotReturnPartialSuccess() -> None:
    """A later resource-kind failure aborts discovery instead of producing a partial snapshot."""

    runner = FakeCommandRunner([
        CommandResult(0, json.dumps([ResourcePayload()])),
        CommandResult(1, "", "rpc error: code = PermissionDenied; synthetic-secret"),
    ])
    provider = YandexCloudProvider(YandexCloudSettings("test-folder"), runner)

    with pytest.raises(ProviderError) as error:
        provider.DiscoverInventory()

    assert error.value.code == ProviderErrorCode.PERMISSION_DENIED, "Partial inventory was returned"
    assert len(runner.calls) == 2, "Failed discovery continued unnecessary external calls"
