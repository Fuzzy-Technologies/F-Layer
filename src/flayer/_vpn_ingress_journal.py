"""Retain exact ingress intent and dispatch uncertainty before a separately authorized protocol cloud write."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, replace
from typing import Any

from flayer._vpn_creation import BundleDigest, LoadCreationBaseline, _Json
from flayer._vpn_revisions import AtomicRecord, Digest
from flayer.core.contracts import _WireDict
from flayer.guest import PrivatePath, ReadPrivate
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import IngressOperationReference, _Decode
from flayer.providers._yandex_ingress_records import MAX_PLAN_BYTES, DecodePlan, EncodePlan
from flayer.vpn_project import SelectedVpnProject

_FILENAME = "protocol-ingress-pending.json"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
PLAN_SECONDS = 600


@dataclass(frozen=True, slots=True)
class IngressJournal:
    """One nonsecret immutable plan plus a monotonic local cloud-dispatch state; this is not a guest reservation."""

    plan: IngressDelta
    creationSha256: str
    previousStateSha256: str
    planExpiresAt: int
    phase: str = "prepared"
    operation: IngressOperationReference | None = None

    def __post_init__(self) -> None:
        """Keep source models closed and prevent unknown dispatch from being represented as undispatched intent."""

        if (type(self) is not IngressJournal
                or any(type(value) is not str or _HASH.fullmatch(value) is None for value in (self.creationSha256, self.previousStateSha256))
                or type(self.planExpiresAt) is not int or self.planExpiresAt <= 0
                or type(self.phase) is not str or self.phase not in {"prepared", "dispatching", "recorded"}
                or (self.operation is not None) != (self.phase == "recorded")):
            raise VpnError("Ingress journal requires exact intent, authority hashes and a consistent dispatch phase")

        EncodePlan(self.plan)

        if self.operation is not None and (
            type(self.operation) is not IngressOperationReference
            or any(type(value) is not str for value in (self.operation.operationId, self.operation.resourceId, self.operation.planSha256))
            or self.operation.resourceId != self.plan.before.resource.reference.resourceId or self.operation.planSha256 != self.plan.Fingerprint()
        ):
            raise VpnError("Ingress journal operation differs from its exact owned plan and resource")

    def Intent(self) -> dict[str, Any]:
        """Preserve complete recovery intent independently from the mutable dispatch acknowledgment."""

        if type(self) is not IngressJournal:
            raise VpnError("Ingress journal metadata does not accept model extensions")

        return {"schema_version": 1, "identity": _WireDict(self.plan.identity), "creation_sha256": self.creationSha256,
                "previous_state_sha256": self.previousStateSha256, "plan_expires_at": self.planExpiresAt,
                "plan_sha256": self.plan.Fingerprint(), "plan_record": json.loads(EncodePlan(self.plan))}

    def Record(self) -> dict[str, Any]:
        """Serialize only validated fixed fields, retaining no arbitrary provider response or private material."""

        return {**self.Intent(), "phase": self.phase, "operation": None if self.operation is None else _WireDict(self.operation)}

    def Bundle(self) -> ArtifactBundle:
        """Name the immutable complete original intent by its own bytes, separately from server credentials."""

        content = _Json(self.Intent())
        reserved = {**self.Intent(), "phase": "recorded", "operation": {"operation_id": "x" * 128,
                    "resource_id": self.plan.before.resource.reference.resourceId, "plan_sha256": self.plan.Fingerprint()}}

        if max(len(_Json(self.Record())), len(_Json(reserved))) > MAX_PLAN_BYTES:
            raise VpnError("Ingress journal exceeds its bounded publication size")

        name = self.plan.identity.stack + "-ip-" + Digest(content)[:16]

        return ArtifactBundle(self.plan.identity, "server", name, (Artifact("intent.json", content, False),))


def _CheckProject(project: SelectedVpnProject, journal: IngressJournal) -> None:
    """Bind local intent to the permanent actual creation specification; fresh cloud/guest attestation belongs to the coordinator."""

    baseline = LoadCreationBaseline(project)
    spec = next(item for item in baseline.plan.resources if item.logicalId == "firewall")

    if (journal.plan.identity != project.vpn.identity or journal.creationSha256 != BundleDigest(baseline.bundle)
            or journal.plan.creationSpec != spec):
        raise VpnError("Ingress journal does not belong to this exact original project creation")


def _ReadIntent(project: SelectedVpnProject, journal: IngressJournal) -> None:
    """Require complete immutable intent before dispatch or acknowledgment; never reconstruct it from a fresh plan."""

    bundle = journal.Bundle()
    directory = project.Artifacts / ("server-" + bundle.name)
    PrivatePath(directory, directory=True)

    if {path.name for path in directory.iterdir()} != {"manifest.json", "intent.json"}:
        raise VpnError("Ingress intent has incomplete or unknown immutable files; retain recovery state")

    if ReadOwnedArtifactFile(directory / "intent.json", project.vpn.identity, kind="server", name=bundle.name) != bundle.files[0].content:
        raise VpnError("Immutable ingress intent differs from its original journal")


def DecodeJournal(content: bytes) -> IngressJournal:
    """Reject ambiguous, noncanonical and contradictory metadata without retaining parser exceptions or raw diagnostics."""

    journal = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= MAX_PLAN_BYTES:
            raise ValueError

        data = _Decode(content.decode())
        expected = {"schema_version", "identity", "creation_sha256", "previous_state_sha256", "plan_expires_at", "plan_sha256",
                    "plan_record", "phase", "operation"}

        if (set(data) != expected or type(data["schema_version"]) is not int or data["schema_version"] != 1):
            raise ValueError

        plan = DecodePlan(_Json(data["plan_record"]))
        operation = data["operation"]

        if operation is not None:
            if not isinstance(operation, dict) or set(operation) != {"operation_id", "resource_id", "plan_sha256"}:
                raise ValueError

            operation = IngressOperationReference(operation["operation_id"], operation["resource_id"], operation["plan_sha256"])

        journal = IngressJournal(plan, data["creation_sha256"], data["previous_state_sha256"], data["plan_expires_at"], data["phase"], operation)

        if data != journal.Record() or content != _Json(journal.Record()):
            raise ValueError

        journal.Bundle()

    except (ValueError, TypeError, RecursionError, UnicodeError):
        journal = None

    if journal is None:
        raise VpnError("Ingress recovery journal is invalid, noncanonical or outside its bounded schema")

    return journal


def LoadJournal(project: SelectedVpnProject) -> IngressJournal | None:
    """Recognize a complete interrupted forward publication conservatively, retaining uncertain cloud authority."""

    values = []

    for filename in (_FILENAME, "." + _FILENAME + ".new"):
        path = project.root / filename

        if path.exists() or path.is_symlink():
            values.append(DecodeJournal(ReadPrivate(path, limit=MAX_PLAN_BYTES)))

    if not values:
        return None

    if len(values) == 2 and values[0] != values[1] and (
        values[0].Intent() != values[1].Intent() or (values[0].phase, values[1].phase) not in {("prepared", "dispatching"), ("dispatching", "recorded")}
    ):
        raise VpnError("Interrupted ingress journal is not the exact next publication; retain both files")

    journal = values[-1]
    _CheckProject(project, journal)

    if journal.phase != "prepared":
        _ReadIntent(project, journal)

    return journal


def PublishIntent(project: SelectedVpnProject, journal: IngressJournal) -> None:
    """Under ProjectLock, write pending intent before its immutable bundle; no provider/guest operation is performed."""

    if type(journal) is not IngressJournal or journal.phase != "prepared":
        raise VpnError("New ingress intent must be an undispatched exact journal")

    _CheckProject(project, journal)
    bundle = journal.Bundle()
    current = LoadJournal(project)

    if current is not None and current != journal:
        raise VpnError("Another ingress operation is pending; no intent was overwritten")

    AtomicRecord(project, _FILENAME, journal.Record())
    directory = project.Artifacts / ("server-" + bundle.name)

    if directory.exists() or directory.is_symlink():
        _ReadIntent(project, journal)

    else:
        WriteArtifactBundle(project.Artifacts, bundle)


def BeginDispatch(project: SelectedVpnProject, expected: IngressJournal) -> IngressJournal:
    """Persist uncertain dispatch before the one separately consented cloud write; a repeated call cannot authorize another write."""

    if type(expected) is not IngressJournal or expected.phase != "prepared" or LoadJournal(project) != expected:
        raise VpnError("Ingress dispatch requires its exact undispatched journal; pending or unknown submission cannot be repeated")

    now = int(time.time())

    if not now < expected.planExpiresAt <= now + PLAN_SECONDS:
        raise VpnError("Ingress plan expired or has an invalid expiry; no dispatch was authorized")

    _ReadIntent(project, expected)
    temporary = project.root / ("." + _FILENAME + ".new")

    if temporary.exists() or temporary.is_symlink():
        ReconcileJournal(project, expected)

    dispatched = replace(expected, phase="dispatching")
    AtomicRecord(project, _FILENAME, dispatched.Record())

    return dispatched


def RecordOperation(project: SelectedVpnProject, expected: IngressJournal, operation: IngressOperationReference) -> IngressJournal:
    """Durably bind the returned operation before polling, including after expiry or an interrupted acknowledgment publication."""

    if type(expected) is not IngressJournal or expected.phase != "dispatching":
        raise VpnError("An ingress acknowledgment requires its original dispatching journal")

    recorded = replace(expected, phase="recorded", operation=operation)
    current = LoadJournal(project)

    if current not in (expected, recorded):
        raise VpnError("Ingress acknowledgment differs from the exact pending operation")

    _ReadIntent(project, expected)
    assert current is not None
    temporary = project.root / ("." + _FILENAME + ".new")

    if temporary.exists() or temporary.is_symlink():
        ReconcileJournal(project, current)

    AtomicRecord(project, _FILENAME, recorded.Record())

    return recorded


def ReconcileJournal(project: SelectedVpnProject, expected: IngressJournal) -> None:
    """Under ProjectLock, durably finish only the recognized current publication; never reset or advance dispatch authority."""

    if type(expected) is not IngressJournal or LoadJournal(project) != expected:
        raise VpnError("Ingress reconciliation requires the exact current journal")

    AtomicRecord(project, _FILENAME, expected.Record())
