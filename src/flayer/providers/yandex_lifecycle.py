"""Bounded Yandex mutations with explicit ownership and recoverable uncertain outcomes."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from flayer.core.contracts import StackIdentity, ValidateName

from .contracts import (
    ProviderCapability,
    ProviderError,
    ProviderErrorCode,
    ProviderResource,
    ResourceKind,
    ResourceReference,
    ValidateIdentifier,
)
from .lifecycle import LOGICAL_ID_LABEL, OPERATION_ID_LABEL, JsonValue, MutationError, ResourceSpec
from .yandex import CommandResult, YandexCloudProvider

MAX_USER_DATA_BYTES = 262144
USERNAME_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
OPERATION_ID_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
RESOURCE_NAME_PATTERN = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
REQUIRED_PARAMETERS: dict[ResourceKind, frozenset[str]] = {
    ResourceKind.NETWORK: frozenset(),
    ResourceKind.SUBNET: frozenset({"zone_id", "ipv4_cidr", "network_dependency"}),
    ResourceKind.SECURITY_GROUP: frozenset({"network_dependency", "rules"}),
    ResourceKind.ADDRESS: frozenset({"zone_id"}),
    ResourceKind.DISK: frozenset({"zone_id", "image_id", "size_gib"}),
    ResourceKind.INSTANCE: frozenset({
        "zone_id", "cores", "memory_gib", "boot_disk_dependency", "subnet_dependency",
        "security_group_dependency", "address_dependency", "ssh_public_key",
    }),
}
OPTIONAL_PARAMETERS: dict[ResourceKind, frozenset[str]] = {
    ResourceKind.NETWORK: frozenset(),
    ResourceKind.SUBNET: frozenset(),
    ResourceKind.SECURITY_GROUP: frozenset(),
    ResourceKind.ADDRESS: frozenset(),
    ResourceKind.DISK: frozenset({"type"}),
    ResourceKind.INSTANCE: frozenset({
        "ssh_username", "user_data_file", "user_data_sha256", "platform_id", "core_fraction",
    }),
}
DEPENDENCY_KINDS = {
    "network_dependency": ResourceKind.NETWORK,
    "boot_disk_dependency": ResourceKind.DISK,
    "subnet_dependency": ResourceKind.SUBNET,
    "security_group_dependency": ResourceKind.SECURITY_GROUP,
    "address_dependency": ResourceKind.ADDRESS,
}
KNOWN_STATUSES = frozenset({
    "UNKNOWN", "ACTIVE", "CREATING", "PROVISIONING", "READY", "RUNNING", "STARTING",
    "STOPPING", "STOPPED", "RESTARTING", "UPDATING", "DELETING", "ERROR", "FAILED",
})
USER_DATA_FIELDS = frozenset({
    "ssh_pwauth", "disable_root", "users", "package_update", "package_upgrade", "packages",
    "write_files", "runcmd",
})


def _String(value: JsonValue) -> str:
    """Require a string without coercion or echoing external input."""

    if not isinstance(value, str):
        raise ValueError("Lifecycle option requires a string")

    return value


def _Integer(value: JsonValue, minimum: int, maximum: int) -> int:
    """Bound numeric resource requests while rejecting booleans and floats."""

    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Lifecycle numeric option exceeds its bounds")

    return value


def ValidateComputeShape(options: Mapping[str, JsonValue]) -> None:
    """Validate the supported Intel shapes without consulting a cloud account."""

    cores = _Integer(options["cores"], 2, 32)
    memory = _Integer(options["memory_gib"], 1, 128)

    if "platform_id" not in options and "core_fraction" not in options:
        return

    if "platform_id" not in options or "core_fraction" not in options:
        raise ValueError("Specify platform_id and core_fraction together")

    platform = _String(options["platform_id"])
    fractions = {"standard-v1": (5, 20, 100), "standard-v2": (5, 20, 50, 100),
                 "standard-v3": (20, 50, 100)}
    fraction = _Integer(options["core_fraction"], 1, 100)

    if platform not in fractions or fraction not in fractions[platform]:
        raise ValueError("Unsupported platform_id/core_fraction combination")

    if _String(options.get("zone_id", "")).startswith("kz1-") and platform != "standard-v3":
        raise ValueError("Kazakhstan deployments require platform_id standard-v3")

    if fraction == 100:
        valid_cores = (*range(2, 17, 2), 20, 24, 28, 32)
        ratios = tuple(float(value) for value in range(1, 9 if platform == "standard-v1" else 17))

    else:
        valid_cores = (2, 4)
        ratios = tuple(value / 2 for value in range(1, 5 if fraction == 5 else 9))

        if platform == "standard-v2" and fraction == 5:
            ratios = (0.25, *ratios)

    if cores not in valid_cores or memory / cores not in ratios:
        raise ValueError("Unsupported vCPU/RAM combination for the selected platform and core_fraction")


def _PublicKey(value: JsonValue) -> str:
    """Accept a structurally valid public SSH key and discard optional comments."""

    text = _String(value)

    if len(text) > 8192 or "\n" in text or "\r" in text:
        raise ValueError("SSH public key must be one bounded OpenSSH line")

    parts = text.split()

    if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ssh-rsa"}:
        raise ValueError("SSH key must use a supported public key algorithm")

    try:
        content = base64.b64decode(parts[1], validate=True)
        offset = 0
        fields: list[bytes] = []

        while offset < len(content):
            if len(content) - offset < 4:
                raise ValueError("SSH public key field is truncated")

            length = int.from_bytes(content[offset:offset + 4], "big")
            offset += 4

            if length < 1 or offset + length > len(content):
                raise ValueError("SSH public key field is malformed")

            fields.append(content[offset:offset + length])
            offset += length

        valid = bool(fields) and fields[0] == parts[0].encode("ascii")

        if parts[0] == "ssh-ed25519":
            valid = valid and len(fields) == 2 and len(fields[1]) == 32

        else:
            valid = valid and len(fields) == 3 and 2048 <= int.from_bytes(
                fields[2], "big"
            ).bit_length() <= 16384 and int.from_bytes(fields[1], "big") >= 3

        if not valid:
            raise ValueError("SSH public key structure is unsupported")

    except (ValueError, IndexError):
        pass

    else:
        return " ".join(parts[:2])

    raise ValueError("SSH public key structure is unsupported")


def _Rules(value: JsonValue) -> tuple[str, ...]:
    """Translate a strict bounded IPv4 rule subset without arbitrary CLI properties."""

    if not isinstance(value, tuple) or not 1 <= len(value) <= 64:
        raise ValueError("Security rules require 1..64 immutable rules")

    results: list[str] = []

    for row in value:
        if not isinstance(row, tuple) or any(
            not isinstance(pair, tuple) or len(pair) != 2 or not isinstance(pair[0], str)
            for pair in row
        ):
            raise ValueError("Security rule requires immutable named pairs")

        rule = dict(cast(tuple[tuple[str, JsonValue], ...], row))

        if len(rule) != len(row) or set(rule) - {
            "direction", "protocol", "cidr", "from_port", "to_port"
        } or not {"direction", "protocol", "cidr"} <= set(rule):
            raise ValueError("Security rule contains missing or unsupported options")

        direction = _String(rule["direction"])
        protocol = _String(rule["protocol"])

        if direction not in {"ingress", "egress"} or protocol not in {"tcp", "udp", "any"}:
            raise ValueError("Security rule direction or protocol is unsupported")

        cidr = str(ipaddress.IPv4Network(_String(rule["cidr"]), strict=True))
        result = f"direction={direction},protocol={protocol},v4-cidrs={cidr}"

        if protocol == "any":
            if "from_port" in rule or "to_port" in rule:
                raise ValueError("Any-protocol rules cannot specify ports")

        else:
            if not {"from_port", "to_port"} <= set(rule):
                raise ValueError("TCP and UDP rules require an explicit port range")

            lower = _Integer(rule["from_port"], 1, 65535)
            upper = _Integer(rule["to_port"], lower, 65535)
            result += f",from-port={lower},to-port={upper}"

        results.append(result)

    if len(set(results)) != len(results):
        raise ValueError("Security rules must be unique")

    return tuple(results)


class YandexLifecycleProvider(YandexCloudProvider):
    """Create and delete an explicit six-kind subset using existing read-only observation."""

    @property
    def Capabilities(self) -> frozenset[ProviderCapability]:
        """Advertise implemented mutations without promising credentials or account permission."""

        return super().Capabilities | frozenset({
            ProviderCapability.CREATE_RESOURCE, ProviderCapability.DELETE_RESOURCE,
        })

    def _Run(
        self, arguments: tuple[str, ...], operation: str, scoped: bool = True
    ) -> CommandResult:
        """Sanitize unexpected custom transport failures for reads and mutations alike."""

        failed = False

        try:
            result = super()._Run(arguments, operation, scoped)

        except ProviderError:
            raise

        except Exception:
            failed = True

        if failed:
            raise ProviderError(ProviderErrorCode.COMMAND_FAILED, operation)

        return result

    def ValidateSpec(self, spec: ResourceSpec) -> None:
        """Validate the complete supported option/dependency subset without cloud access."""

        failure = False

        try:
            if not isinstance(spec, ResourceSpec):
                raise ValueError("Lifecycle requests require ResourceSpec")

            if RESOURCE_NAME_PATTERN.fullmatch(spec.name) is None:
                raise ValueError("Resource name violates provider naming requirements")

            options = dict(spec.parameters)
            required = REQUIRED_PARAMETERS[spec.kind]

            if not required <= options.keys() or options.keys() - required - OPTIONAL_PARAMETERS[
                spec.kind
            ]:
                raise ValueError("Unsupported lifecycle options")

            expected: set[str] = set()

            for key in options:
                if key in DEPENDENCY_KINDS:
                    dependency = _String(options[key])
                    ValidateName(dependency, "dependency")
                    expected.add(dependency)

            dependency_options = sum(key in DEPENDENCY_KINDS for key in options)

            if expected != set(spec.dependencies) or len(expected) != dependency_options:
                raise ValueError("Dependencies must match explicit typed dependency options")

            if "zone_id" in options:
                ValidateIdentifier(_String(options["zone_id"]))

            if spec.kind == ResourceKind.SUBNET:
                ipaddress.IPv4Network(_String(options["ipv4_cidr"]), strict=True)

            elif spec.kind == ResourceKind.SECURITY_GROUP:
                _Rules(options["rules"])

            elif spec.kind == ResourceKind.DISK:
                ValidateIdentifier(_String(options["image_id"]))
                _Integer(options["size_gib"], 10, 1024)

                if options.get("type", "network-ssd") not in {"network-ssd", "network-hdd"}:
                    raise ValueError("Unsupported boot disk type")

            elif spec.kind == ResourceKind.INSTANCE:
                ValidateComputeShape(options)
                _PublicKey(options["ssh_public_key"])

                if USERNAME_PATTERN.fullmatch(_String(options.get("ssh_username", "yc-user"))) is None:
                    raise ValueError("Unsupported SSH username")

                if ("user_data_file" in options) != ("user_data_sha256" in options):
                    raise ValueError("Initialization file requires its immutable content digest")

                if "user_data_file" in options:
                    path = Path(_String(options["user_data_file"]))

                    if not str(path) or ".." in path.parts or "\x00" in str(path):
                        raise ValueError("Initialization file path is unsafe")

                    if SHA256_PATTERN.fullmatch(_String(options["user_data_sha256"])) is None:
                        raise ValueError("Initialization digest must be SHA256")

        except (ValueError, TypeError, KeyError):
            failure = True

        if failure:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "validate-spec", False)

    def _ValidateIdentity(self, identity: StackIdentity) -> None:
        """Require the selected provider and folder to match the complete stack boundary."""

        if not isinstance(identity, StackIdentity) or (
            identity.provider != self.Identity.provider_id
            or identity.scope_id != self.Identity.scope_id
        ):
            raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "identity", False)

    @staticmethod
    def _ValidateObservation(resource: ProviderResource) -> ProviderResource:
        """Reject opaque vendor status/name text before it reaches orchestration or reports."""

        failed = resource.status not in KNOWN_STATUSES

        try:
            ValidateName(resource.name, "observed.name")

        except ValueError:
            failed = True

        if failed:
            raise ProviderError(ProviderErrorCode.INVALID_RESPONSE, "observe")

        return resource

    def GetResource(self, reference: ResourceReference) -> ProviderResource:
        """Use the scoped base adapter while restricting observed lifecycle fields."""

        return self._ValidateObservation(super().GetResource(reference))

    def FindResource(
        self, spec: ResourceSpec, identity: StackIdentity
    ) -> ProviderResource | None:
        """Reconcile exact logical ownership; duplicates and changed desired content conflict."""

        self.ValidateSpec(spec)
        self._ValidateIdentity(identity)
        labels = identity.OwnershipLabels()
        labels[LOGICAL_ID_LABEL] = spec.logical_id
        ownership = tuple(sorted(labels.items()))
        matches = tuple(
            resource for resource in self.ListResources(spec.kind) if resource.HasLabels(ownership)
        )

        if len(matches) > 1:
            raise ProviderError(ProviderErrorCode.CONFLICT, "find")

        if not matches:
            return None

        resource = self._ValidateObservation(matches[0])

        if not resource.HasLabels(spec.OwnershipLabels(identity)) or resource.name != spec.name:
            raise ProviderError(ProviderErrorCode.CONFLICT, "find")

        options = dict(spec.parameters)

        if "zone_id" in options and self._ResourceZone(resource) != options["zone_id"]:
            raise ProviderError(ProviderErrorCode.SCOPE_MISMATCH, "find")

        return resource

    @staticmethod
    def _ResourceZone(resource: ProviderResource) -> str | None:
        """Return the normalized zone; address adapters populate the nested IPv4 zone."""

        return resource.zone_id

    def _NormalizeResource(
        self, payload: object, kind: ResourceKind, operation: str
    ) -> ProviderResource:
        """Preserve the documented address allocation zone without storing vendor metadata."""

        if kind == ResourceKind.ADDRESS and isinstance(payload, dict):
            external = payload.get("external_ipv4_address")

            if isinstance(external, dict) and "zone_id" in external:
                payload = {**payload, "zone_id": external["zone_id"]}

        return super()._NormalizeResource(payload, kind, operation)

    def _Dependencies(
        self, spec: ResourceSpec, identity: StackIdentity,
        dependencies: Mapping[str, ProviderResource],
    ) -> dict[str, ProviderResource]:
        """Refresh every dependency by ID and verify type, scope, complete ownership and zone."""

        if not isinstance(dependencies, Mapping) or set(dependencies) != set(spec.dependencies):
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "dependencies", False)

        options = dict(spec.parameters)
        refreshed: dict[str, ProviderResource] = {}

        for key, kind in DEPENDENCY_KINDS.items():
            if key not in options:
                continue

            logical_id = _String(options[key])
            resource = dependencies[logical_id]

            if not isinstance(resource, ProviderResource) or resource.reference.kind != kind:
                raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "dependencies", False)

            observed = self.GetResource(resource.reference)
            labels = identity.OwnershipLabels()
            labels[LOGICAL_ID_LABEL] = logical_id

            if not observed.HasLabels(tuple(sorted(labels.items()))):
                raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "dependencies", False)

            if kind in {ResourceKind.SUBNET, ResourceKind.DISK, ResourceKind.ADDRESS} and (
                observed.zone_id != options.get("zone_id")
            ):
                raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "dependencies", False)

            if observed.status not in {"UNKNOWN", "ACTIVE", "READY", "RUNNING"}:
                raise MutationError(ProviderErrorCode.CONFLICT, "dependencies", False)

            refreshed[logical_id] = observed

        return refreshed

    @staticmethod
    def _ReadUserData(path: Path, expected_digest: str) -> bytes:
        """Read one owned, private, bounded nonsecret cloud-init JSON artifact without symlinks."""

        descriptor: int | None = None
        content: bytes | None = None

        try:
            absolute = path.absolute()

            for component in (absolute, *absolute.parents):
                if component.is_symlink():
                    raise ValueError("Initialization paths cannot contain symbolic links")

            before = absolute.lstat()

            if not stat.S_ISREG(before.st_mode):
                raise ValueError("Initialization artifact must be a regular file")

            descriptor = os.open(
                absolute, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            )
            actual = os.fstat(descriptor)

            if not stat.S_ISREG(actual.st_mode) or (actual.st_dev, actual.st_ino) != (
                before.st_dev, before.st_ino
            ) or not 0 < actual.st_size <= MAX_USER_DATA_BYTES:
                raise ValueError("Initialization artifact is unsafe")

            if os.name == "posix" and (
                actual.st_uid != os.getuid() or stat.S_IMODE(actual.st_mode) & 0o077
            ):
                raise ValueError("Initialization artifact must be private and owned")

            with os.fdopen(descriptor, "rb") as source:
                descriptor = None
                data = source.read(MAX_USER_DATA_BYTES + 1)

            if len(data) > MAX_USER_DATA_BYTES or hashlib.sha256(data).hexdigest() != expected_digest:
                raise ValueError("Initialization artifact content differs from the plan")

            text = data.decode("utf-8")

            if text.startswith("#cloud-config\n"):
                text = text[len("#cloud-config\n"):]

            body = json.loads(text)

            if not isinstance(body, dict) or set(body) - USER_DATA_FIELDS:
                raise ValueError("Initialization artifact contains unsupported fields")

            content = data

        except (OSError, ValueError, RecursionError):
            pass

        finally:
            if descriptor is not None:
                os.close(descriptor)

        if content is None:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "initialization", False)

        return content

    def _Arguments(
        self, spec: ResourceSpec, dependencies: Mapping[str, ProviderResource]
    ) -> tuple[str, ...]:
        """Translate only the verified six-kind subset to documented direct CLI arguments."""

        options = dict(spec.parameters)
        arguments: list[str] = []

        if spec.kind == ResourceKind.SUBNET:
            network = dependencies[_String(options["network_dependency"])]
            arguments.extend((
                "--network-id", network.reference.resource_id, "--zone", _String(options["zone_id"]),
                "--range", _String(options["ipv4_cidr"]),
            ))

        elif spec.kind == ResourceKind.SECURITY_GROUP:
            network = dependencies[_String(options["network_dependency"])]
            arguments.extend(("--network-id", network.reference.resource_id))

            for rule in _Rules(options["rules"]):
                arguments.extend(("--rule", rule))

        elif spec.kind == ResourceKind.ADDRESS:
            arguments.extend(("--external-ipv4", f"zone={options['zone_id']}"))

        elif spec.kind == ResourceKind.DISK:
            arguments.extend((
                "--zone", _String(options["zone_id"]), "--source-image-id", _String(options["image_id"]),
                "--size", str(options["size_gib"]), "--type", _String(options.get("type", "network-ssd")),
            ))

        elif spec.kind == ResourceKind.INSTANCE:
            disk = dependencies[_String(options["boot_disk_dependency"])]
            subnet = dependencies[_String(options["subnet_dependency"])]
            group = dependencies[_String(options["security_group_dependency"])]
            address = dependencies[_String(options["address_dependency"])]

            if len(address.public_addresses) != 1:
                raise MutationError(ProviderErrorCode.INVALID_RESPONSE, "address", False)

            interface = (
                f"subnet-id={subnet.reference.resource_id},nat-ip-version=ipv4,"
                f"nat-address={address.public_addresses[0]},"
                f"security-group-ids={group.reference.resource_id}"
            )
            username = _String(options.get("ssh_username", "yc-user"))
            public_key = _PublicKey(options["ssh_public_key"])
            arguments.extend((
                "--zone", _String(options["zone_id"]), "--cores", str(options["cores"]),
                "--memory", str(options["memory_gib"]),
                "--use-boot-disk", f"disk-id={disk.reference.resource_id},auto-delete=false",
                "--network-interface", interface, "--metadata", f"ssh-keys={username}:{public_key}",
            ))

            if "platform_id" in options:
                arguments.extend(("--platform", _String(options["platform_id"]),
                                  "--core-fraction", str(options["core_fraction"])))

        return tuple(arguments)

    def _MutationRun(self, arguments: tuple[str, ...], operation: str) -> CommandResult:
        """Never retry a dispatched mutation or retain raw runner exceptions in the error."""

        code: ProviderErrorCode | None = None
        outcome_unknown = True

        try:
            result = self._Run(arguments, operation)

        except ProviderError as error:
            code = error.code

        except Exception:
            code = ProviderErrorCode.COMMAND_FAILED

        else:
            return result

        raise MutationError(code or ProviderErrorCode.COMMAND_FAILED, operation, outcome_unknown)

    def CreateResource(
        self, spec: ResourceSpec, identity: StackIdentity,
        dependencies: Mapping[str, ProviderResource], operation_id: str,
    ) -> ProviderResource:
        """Create once with stable ownership labels and an explicit, separately owned boot disk."""

        self.ValidateSpec(spec)
        self._ValidateIdentity(identity)

        if not isinstance(operation_id, str) or OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
            raise MutationError(ProviderErrorCode.UNSUPPORTED, "operation-id", False)

        options = dict(spec.parameters)
        content: bytes | None = None
        existing: ProviderResource | None = None
        arguments: tuple[str, ...] = ()
        preflight_failure: ProviderErrorCode | None = None

        try:
            content = self._ReadUserData(
                Path(_String(options["user_data_file"])), _String(options["user_data_sha256"])
            ) if "user_data_file" in options else None
            existing = self.FindResource(spec, identity)

            if existing is None:
                refreshed = self._Dependencies(spec, identity, dependencies)
                arguments = self._Arguments(spec, refreshed)

        except MutationError:
            raise

        except ProviderError as error:
            preflight_failure = error.code

        except Exception:
            preflight_failure = ProviderErrorCode.COMMAND_FAILED

        if preflight_failure is not None:
            raise MutationError(preflight_failure, "create", False)

        if existing is not None:
            return existing

        creation_labels = (*spec.OwnershipLabels(identity), (OPERATION_ID_LABEL, operation_id))
        labels = ",".join(f"{key}={value}" for key, value in creation_labels)
        command = (*self._CommandForKind(spec.kind), "create", "--name", spec.name, "--labels", labels)
        temporary_path: str | None = None
        mutation_started = False
        failure: ProviderErrorCode | None = None
        created: ProviderResource | None = None

        try:
            if content is not None:
                with tempfile.NamedTemporaryFile(mode="wb", delete=False) as destination:
                    temporary_path = destination.name
                    destination.write(content)
                    destination.flush()
                    os.fsync(destination.fileno())

                arguments = (*arguments, "--metadata-from-file", f"user-data={temporary_path}")

            mutation_started = True
            result = self._MutationRun((*command, *arguments), "create")

            try:
                payload: object = json.loads(result.stdout)

            except (ValueError, RecursionError):
                failure = ProviderErrorCode.INVALID_RESPONSE

            else:
                resource = self._ValidateObservation(self._NormalizeResource(payload, spec.kind, "create"))

                if not resource.HasLabels(creation_labels) or resource.name != spec.name:
                    failure = ProviderErrorCode.SCOPE_MISMATCH

                elif "zone_id" in options and resource.zone_id != options["zone_id"]:
                    failure = ProviderErrorCode.SCOPE_MISMATCH

                else:
                    created = resource

        except MutationError:
            raise

        except ProviderError as error:
            failure = error.code

        except (OSError, ValueError):
            failure = ProviderErrorCode.COMMAND_FAILED

        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)

                except FileNotFoundError:
                    pass

                except OSError:
                    failure = ProviderErrorCode.COMMAND_FAILED

        if failure is None and created is not None:
            return created

        raise MutationError(failure or ProviderErrorCode.INVALID_RESPONSE, "create", mutation_started)

    def DeleteResource(
        self, reference: ResourceReference, identity: StackIdentity, logical_id: str,
        operation_id: str | None = None,
    ) -> None:
        """Observe and verify ownership before exact-ID deletion, then confirm absence once."""

        self._ValidateIdentity(identity)
        ValidateName(logical_id, "delete.logical_id")
        labels = identity.OwnershipLabels()
        labels[LOGICAL_ID_LABEL] = logical_id

        if operation_id is not None:
            if not isinstance(operation_id, str) or OPERATION_ID_PATTERN.fullmatch(operation_id) is None:
                raise MutationError(ProviderErrorCode.UNSUPPORTED, "operation-id", False)

            labels[OPERATION_ID_LABEL] = operation_id

        try:
            resource = self.GetResource(reference)

        except ProviderError as error:
            if error.code == ProviderErrorCode.NOT_FOUND:
                return

            raise

        if not resource.HasLabels(tuple(sorted(labels.items()))):
            raise MutationError(ProviderErrorCode.SCOPE_MISMATCH, "delete", False)

        command = self._CommandForKind(reference.kind)
        self._MutationRun((*command, "delete", "--id", reference.resource_id), "delete")
        failure = ProviderErrorCode.CONFLICT

        try:
            self.GetResource(reference)

        except ProviderError as error:
            if error.code == ProviderErrorCode.NOT_FOUND:
                return

            failure = error.code

        raise MutationError(failure, "delete", True)
