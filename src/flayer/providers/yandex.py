"""Read-only Yandex Cloud CLI adapter with bounded commands and sanitized failures."""

from __future__ import annotations

import ipaddress
import json
import math
import subprocess
from dataclasses import dataclass, field
from typing import Protocol

from .contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ProviderIdentity,
    ProviderResource,
    ProviderStatus,
    ResourceKind,
    ResourceReference,
    ValidateIdentifier,
)

PROVIDER_ID = "yandex-cloud"
MAX_CLI_LIST_LIMIT = 1000
RESOURCE_COMMANDS: dict[ResourceKind, tuple[str, str]] = {
    ResourceKind.INSTANCE: ("compute", "instance"),
    ResourceKind.DISK: ("compute", "disk"),
    ResourceKind.NETWORK: ("vpc", "network"),
    ResourceKind.SUBNET: ("vpc", "subnet"),
    ResourceKind.ADDRESS: ("vpc", "address"),
    ResourceKind.SECURITY_GROUP: ("vpc", "security-group"),
}
ERROR_MARKERS: tuple[tuple[ProviderErrorCode, tuple[str, ...]], ...] = (
    (ProviderErrorCode.AUTHENTICATION, ("unauthenticated", "invalid token", "token expired")),
    (ProviderErrorCode.PERMISSION_DENIED, ("permissiondenied", "permission_denied", "forbidden")),
    (ProviderErrorCode.NOT_FOUND, ("notfound", "not_found", "not found")),
    (ProviderErrorCode.TIMEOUT, ("deadlineexceeded", "deadline_exceeded", "timed out")),
    (ProviderErrorCode.THROTTLED, ("resourceexhausted", "resource_exhausted", "too many requests")),
    (ProviderErrorCode.CONFLICT, ("alreadyexists", "already_exists", "conflict")),
)


@dataclass(frozen=True, slots=True)
class YandexCloudSettings:
    """Explicit folder/profile configuration with no stored tokens or secret keys."""

    folderId: str
    profile: str = "default"
    executable: str = "yc"
    commandTimeout: float = 45.0
    inventoryLimit: int = 10000

    def __post_init__(self) -> None:
        """Reject unsafe scope selectors and unbounded subprocess parameters."""

        ValidateIdentifier(self.folderId)
        ValidateIdentifier(self.profile)

        if (
            not isinstance(self.executable, str)
            or not self.executable.strip()
            or "\x00" in self.executable
        ):
            raise ValueError("Yandex CLI executable must be a non-empty executable path or name")

        if (
            isinstance(self.commandTimeout, bool)
            or not isinstance(self.commandTimeout, (int, float))
            or not math.isfinite(self.commandTimeout)
            or not 0 < self.commandTimeout <= 300
        ):
            raise ValueError(
                "Provider command timeout must be finite and between 0 and 300 seconds"
            )

        if (
            isinstance(self.inventoryLimit, bool)
            or not isinstance(self.inventoryLimit, int)
            or not 1 <= self.inventoryLimit <= 100000
        ):
            raise ValueError("Provider inventory limit must be an integer between 1 and 100000")


@dataclass(frozen=True, slots=True)
class CommandResult:
    """An ephemeral command result whose representation omits potentially secret output."""

    returnCode: int
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)


class CommandRunner(Protocol):
    """Injectable execution boundary for deterministic tests and alternative transports."""

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Execute one argument vector without modifying its order or scope."""

        ...


class SubprocessCommandRunner:
    """Execute the configured CLI directly without a shell or interactive standard input."""

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Capture output transiently while enforcing a per-command timeout."""

        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=timeout,
        )

        return CommandResult(result.returncode, result.stdout, result.stderr)


class YandexCloudProvider:
    """Normalize CLI inventory inside one folder; expose no cloud mutation methods."""

    def __init__(
        self, settings: YandexCloudSettings, runner: CommandRunner | None = None
    ) -> None:
        """Construct a provider without executing commands or reading credential files."""

        self._settings = settings
        self._runner = runner if runner is not None else SubprocessCommandRunner()
        self._identity = ProviderIdentity(PROVIDER_ID, settings.folderId, "cli-profile")

    @property
    def Identity(self) -> ProviderIdentity:
        """Return the non-secret identity used to validate all resources and references."""

        return self._identity

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Declare implemented read operations without inferring lifecycle capability."""

        return frozenset({ProviderCapability.INVENTORY, ProviderCapability.RESOURCE_LOOKUP})

    def CheckAvailability(self) -> ProviderStatus:
        """Check CLI execution locally; no token, profile or infrastructure read occurs."""

        try:
            self._Run(("--version",), "availability", scoped=False)

        except ProviderError as error:
            return ProviderStatus(self.Identity, False, errorCode=error.code)

        return ProviderStatus(self.Identity, True)

    def CheckAuthentication(self) -> ProviderStatus:
        """Verify access to the selected folder through the CLI's existing credentials."""

        try:
            payload = self._ReadJson(
                ("resource-manager", "folder", "get", "--id", self._settings.folderId),
                "authentication",
            )

            if not isinstance(payload, dict) or payload.get("id") != self._settings.folderId:
                raise ProviderError(ProviderErrorCode.SCOPE_MISMATCH, "authentication")

        except ProviderError as error:
            available = error.code != ProviderErrorCode.UNAVAILABLE

            return ProviderStatus(self.Identity, available, False, error.code)

        return ProviderStatus(self.Identity, True, True)

    def ListResources(self, kind: ResourceKind) -> tuple[ProviderResource, ...]:
        """Read one resource kind, rejecting malformed or possibly truncated inventory."""

        command = self._CommandForKind(kind)
        limit = min(self._settings.inventoryLimit, MAX_CLI_LIST_LIMIT)
        payload = self._ReadJson(
            (*command, "list", "--limit", str(limit)), "list"
        )

        if not isinstance(payload, list):
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, "list")

        if len(payload) >= limit:
            raise ProviderError(ProviderErrorCode.INCOMPLETE_INVENTORY, "list")

        resources = tuple(self._NormalizeResource(item, kind, "list") for item in payload)

        if len({resource.reference.resourceId for resource in resources}) != len(resources):
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, "list")

        return tuple(sorted(resources, key=lambda item: item.reference.resourceId))

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Read by ID and revalidate returned scope because vendor ID lookup is global."""

        if (
            reference.providerId != self.Identity.providerId
            or reference.scopeId != self.Identity.scopeId
        ):
            raise ProviderError(ProviderErrorCode.SCOPE_MISMATCH, "get")

        command = self._CommandForKind(reference.kind)
        payload = self._ReadJson((*command, "get", "--id", reference.resourceId), "get")
        resource = self._NormalizeResource(payload, reference.kind, "get")

        if resource.reference != reference:
            raise ProviderError(ProviderErrorCode.SCOPE_MISMATCH, "get")

        return resource

    def DiscoverInventory(self) -> tuple[ProviderResource, ...]:
        """Return a deterministic complete inventory, never a partial success snapshot."""

        resources: list[ProviderResource] = []

        for kind in ResourceKind:
            resources.extend(self.ListResources(kind))

        return tuple(resources)

    @staticmethod
    def _CommandForKind(kind: ResourceKind) -> tuple[str, str]:
        """Require an explicit supported enum rather than arbitrary CLI arguments."""

        if not isinstance(kind, ResourceKind) or kind not in RESOURCE_COMMANDS:
            raise ProviderError(ProviderErrorCode.UNSUPPORTED, "resource-kind")

        return RESOURCE_COMMANDS[kind]

    def _Run(
        self, arguments: tuple[str, ...], operation: str, scoped: bool = True
    ) -> CommandResult:
        """Run one bounded command and discard vendor error details before propagating."""

        flags = (
            "--profile", self._settings.profile,
            "--folder-id", self._settings.folderId,
            "--format", "json",
            "--no-browser",
            "--retry", "0",
        ) if scoped else ()
        command = (self._settings.executable, *arguments, *flags)

        failureCode: ProviderErrorCode | None = None

        try:
            result = self._runner.Run(command, self._settings.commandTimeout)

        except subprocess.TimeoutExpired:
            failureCode = ProviderErrorCode.TIMEOUT

        except OSError:
            failureCode = ProviderErrorCode.UNAVAILABLE

        if failureCode is not None:
            raise ProviderError(failureCode, operation)

        if result.returnCode != 0:
            error = self._CommandFailure(arguments, result, operation)
            del result

            raise error

        return result

    def _CommandFailure(
        self, arguments: tuple[str, ...], result: CommandResult, operation: str,
    ) -> ProviderError:
        """Classify transient command output without retaining raw vendor diagnostics."""

        details = (result.stderr or result.stdout).casefold()
        code = ProviderErrorCode.COMMAND_FAILED

        for candidate, markers in ERROR_MARKERS:
            if any(marker in details for marker in markers):
                code = candidate
                break

        return ProviderError(code, operation)

    def _ReadJson(self, arguments: tuple[str, ...], operation: str) -> object:
        """Parse JSON without retaining its text in propagated decode exceptions."""

        result = self._Run(arguments, operation)

        try:
            payload: object = json.loads(result.stdout)

        except (ValueError, RecursionError):
            pass

        else:
            return payload

        del result

        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, operation)

    def _NormalizeResource(
        self, payload: object, kind: ResourceKind, operation: str
    ) -> ProviderResource:
        """Keep only contract fields and fail closed on malformed identity or endpoints."""

        if not isinstance(payload, dict):
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, operation)

        if payload.get("folder_id") != self.Identity.scopeId:
            raise ProviderError(ProviderErrorCode.SCOPE_MISMATCH, operation)

        resourceId = payload.get("id")
        name = payload.get("name", "")
        status = payload.get("status", "UNKNOWN")
        zoneId = payload.get("zone_id")
        labels = payload.get("labels", {})

        if (
            not isinstance(resourceId, str)
            or not isinstance(name, str)
            or not isinstance(status, str)
            or (zoneId is not None and not isinstance(zoneId, str))
            or not isinstance(labels, dict)
            or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in labels.items()
            )
        ):
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, operation)

        try:
            reference = ResourceReference(PROVIDER_ID, self.Identity.scopeId, kind, resourceId)
            publicAddresses = self._PublicAddresses(payload, kind)
            resource = ProviderResource(
                reference, name, status, zoneId, tuple(sorted(labels.items())), publicAddresses
            )

        except (ValueError, TypeError, AttributeError):
            pass

        else:
            return resource

        raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, operation)

    @staticmethod
    def _PublicAddresses(payload: dict[str, object], kind: ResourceKind) -> tuple[str, ...]:
        """Extract documented external IPv4 fields without retaining arbitrary metadata."""

        addresses: list[str] = []

        if kind == ResourceKind.ADDRESS:
            external = payload.get("external_ipv4_address", {})

            if not isinstance(external, dict):
                raise ValueError("External address must be an object")

            address = external.get("address")

            if address is not None:
                if not isinstance(address, str) or not address:
                    raise ValueError("External IPv4 address must be a non-empty string")

                addresses.append(str(ipaddress.IPv4Address(address)))

        elif kind == ResourceKind.INSTANCE:
            interfaces = payload.get("network_interfaces", [])

            if not isinstance(interfaces, list):
                raise ValueError("Instance interfaces must be a list")

            for interface in interfaces:
                address = interface.get("primary_v4_address", {}).get("one_to_one_nat", {}).get(
                    "address"
                )

                if address is not None:
                    if not isinstance(address, str) or not address:
                        raise ValueError("External IPv4 address must be a non-empty string")

                    addresses.append(str(ipaddress.IPv4Address(address)))

        return tuple(sorted(set(addresses)))
