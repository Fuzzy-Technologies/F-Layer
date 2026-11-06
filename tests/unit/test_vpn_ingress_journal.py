"""Preserve one cloud-dispatch authority and its exact recovery plan across durable publication interruptions."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project_v2 import Project, Snapshot
from test_yandex_ingress import Plan
from test_yandex_ingress_records import LargePlan

from flayer import _vpn_ingress_journal as journal
from flayer import _vpn_revisions as revisions
from flayer._vpn_creation import BundleDigest, LoadCreationBaseline, _Json
from flayer.guest import ReadPrivate, WritePrivate
from flayer.profiles.artifacts import ArtifactError, WriteArtifactBundle
from flayer.profiles.vpn import VpnError
from flayer.providers._yandex_firewall import ExpectedRules, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers._yandex_ingress_operations import IngressOperationReference
from flayer.providers._yandex_ingress_records import MAX_PLAN_BYTES
from flayer.vpn_project import SelectedVpnProject
from flayer.vpn_project_v2 import PrepareSelectedProject

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private journals require POSIX; no WSL or desktop network is started")


def Intent() -> journal.IngressJournal:
    """Build only synthetic nonsecret intent; the pure codec never reads a private project or provider."""

    return journal.IngressJournal(Plan(), "a" * 64, "b" * 64, 100000)


def Operation(value: journal.IngressJournal) -> IngressOperationReference:
    """Represent one provider acknowledgment without any CLI executable or network call."""

    return IngressOperationReference("example-operation", value.plan.before.resource.reference.resourceId, value.plan.Fingerprint())


@pytest.mark.parametrize("phase", ["prepared", "dispatching", "recorded"])
def test_JournalRoundTripSeparatesImmutableIntentFromMonotonicDispatchAcknowledgment(phase: str) -> None:
    """Operation IDs and phases cannot change the retained plan, original creation or preceding-state binding."""

    prepared = Intent()
    current = replace(prepared, phase=phase, operation=Operation(prepared) if phase == "recorded" else None)
    decoded = journal.DecodeJournal(_Json(current.Record()))

    assert decoded == current and decoded.Bundle() == prepared.Bundle() and decoded.Intent() == prepared.Intent()
    assert decoded.plan.Fingerprint() == prepared.plan.Fingerprint() and decoded.plan.before == prepared.plan.before
    assert all(not item.sensitive for item in decoded.Bundle().files)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("unknown", "suppressed-fixture"), ("identity", {}),
    ("creation_sha256", "../elsewhere"), ("previous_state_sha256", ["b" * 64]),
    ("plan_expires_at", True), ("plan_sha256", "f" * 64), ("phase", "completed"),
    ("phase", "recorded"), ("operation", {}),
    ("operation", {"operation_id": "example-operation", "resource_id": "foreign-group", "plan_sha256": "a" * 64}),
    ("plan_record", {"schema_version": 1, "plan": {}}),
])
def test_JournalCodecRejectsContradictoryOrExtendedMetadataWithoutRawExceptionContext(field: str, value: object) -> None:
    """Neither an invented operation nor missing plan fields become a recoverable known submission."""

    record = Intent().Record()
    record[field] = value

    with pytest.raises(VpnError) as caught:
        journal.DecodeJournal(_Json(record))

    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert "suppressed-fixture" not in str(caught.value)


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"[]", b'{"schema_version":1,"schema_version":1}',
                                 b'{"schema_version":NaN}', b"[" * 1500 + b"]" * 1500])
def test_JournalParserRejectsAmbiguousBytesWithoutAParserCause(raw: bytes) -> None:
    """Duplicate keys and nonstandard/deep input never retain a raw JSON document in exception context."""

    with pytest.raises(VpnError) as caught:
        journal.DecodeJournal(raw)

    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_JournalBoundaryRejectsCredentialBearingExtensions() -> None:
    """Closed models protect nonsecret immutable intent and operation metadata before recursive serialization."""

    @dataclass(frozen=True, slots=True)
    class ExtendedOperation(IngressOperationReference):
        """Model an SDK extension that must not be copied into a journal."""

        privateKey: str = "suppressed-fixture"

    @dataclass(frozen=True, slots=True)
    class ExtendedJournal(journal.IngressJournal):
        """Model a caller extension that the closed metadata boundary must reject."""

        privateKey: str = "suppressed-fixture"

    prepared = Intent()
    reference = Operation(prepared)

    with pytest.raises(VpnError):
        replace(prepared, phase="recorded", operation=ExtendedOperation(reference.operationId, reference.resourceId, reference.planSha256))

    with pytest.raises(VpnError):
        ExtendedJournal(prepared.plan, prepared.creationSha256, prepared.previousStateSha256, prepared.planExpiresAt)


def test_InitialIntentReservesEnoughSpaceForTheLongestPossibleReturnedOperationReference() -> None:
    """A plan must be rejected before submission if its full acknowledgment could exceed the journal's byte limit."""

    base = Intent()
    resource = replace(base.plan.before.resource, labels=(*base.plan.before.resource.labels, ("reserve", "")))
    base = replace(base, plan=replace(base.plan, before=replace(base.plan.before, resource=resource)))
    available = MAX_PLAN_BYTES - len(_Json(base.Record())) - 10
    resource = replace(resource, labels=tuple((key, "x" * available if key == "reserve" else value) for key, value in resource.labels))
    large = replace(base, plan=replace(base.plan, before=replace(base.plan.before, resource=resource)))

    assert len(_Json(large.Record())) <= MAX_PLAN_BYTES

    with pytest.raises(VpnError, match="bounded publication size"):
        large.Bundle()


def Setup(tmpPath: Path, *, large: bool = False) -> tuple[SelectedVpnProject, journal.IngressJournal]:
    """Use a real private project plus a synthetic complete observed group matching its frozen creation spec."""

    project = Project(tmpPath)
    PrepareSelectedProject(project)
    baseline = LoadCreationBaseline(project)
    spec = next(item for item in baseline.plan.resources if item.logicalId == "firewall")
    example = Plan()
    resource = replace(example.before.resource, name=spec.name, labels=spec.OwnershipLabels(project.vpn.identity))
    rules = tuple(replace(rule, ruleId=f"allocated-{index}") for index, rule in enumerate(ExpectedRules(spec)))

    if large:
        rules += tuple(rule for rule in LargePlan().before.rules if rule.ruleId.startswith("extra-"))[:40]

    before = SecurityGroupSnapshot(resource, "example-network", rules)
    listener = next(item for item in project.vpn.listeners if item.transport == "wireguard")
    ids = tuple(rule.ruleId for rule in rules if rule.direction == "ingress" and rule.protocol == listener.protocol and rule.fromPort == listener.port)
    plan = IngressDelta(project.vpn.identity, spec, before.networkId, before, listener, "disable", "a" * 32, ids, listener)
    pending = journal.IngressJournal(plan, BundleDigest(baseline.bundle), revisions.LoadRevisions(project).headDigest, int(time.time()) + 600)

    return project, pending


@POSIX
@pytest.mark.parametrize("large", [False, True])
def test_WriteAheadIntentDispatchAndRetainedOperationPreserveAllOriginalPrivateBytes(tmp_path: Path, large: bool) -> None:
    """Pending intent and its complete manifest precede dispatch; acknowledgment is durable before any future polling."""

    project, prepared = Setup(tmp_path, large=large)
    original = Snapshot(project.Artifacts)
    assert journal.LoadJournal(project) is None

    with revisions.ProjectLock(project, readOnly=False):
        journal.PublishIntent(project, prepared)
        journal.PublishIntent(project, prepared)
        assert journal.LoadJournal(project) == prepared
        dispatched = journal.BeginDispatch(project, prepared)
        assert journal.LoadJournal(project) == dispatched
        recorded = journal.RecordOperation(project, dispatched, Operation(prepared))
        assert journal.RecordOperation(project, dispatched, Operation(prepared)) == recorded

    assert journal.LoadJournal(project) == recorded and recorded.phase == "recorded"
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in original.items())
    assert json.loads(ReadPrivate(project.root / "protocol-ingress-pending.json", limit=1024 * 1024)) == recorded.Record()

    if large:
        assert len(_Json(recorded.Record())) > 65536

    before = Snapshot(project.root)

    with pytest.raises(VpnError, match="cannot be repeated"):
        journal.BeginDispatch(project, prepared)

    with pytest.raises(VpnError, match="integrated protocol workflow"):
        revisions.LoadRevisions(project)

    with pytest.raises(VpnError):
        revisions.AtomicRecord(project, "protocol-ingress-pending.json", None)

    assert Snapshot(project.root) == before


@POSIX
def test_LostProviderResponseCannotAuthorizeASecondDispatchEvenAfterExpiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A timed-out writer leaves dispatching intent, and an old-looking live snapshot cannot reset its authority."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    dispatched = journal.BeginDispatch(project, prepared)
    before = Snapshot(project.root)
    monkeypatch.setattr(journal.time, "time", lambda: prepared.planExpiresAt + 1)

    for candidate in (prepared, dispatched):
        with pytest.raises(VpnError):
            journal.BeginDispatch(project, candidate)

    with pytest.raises(VpnError, match="Another ingress"):
        journal.PublishIntent(project, prepared)

    assert journal.LoadJournal(project) == dispatched and Snapshot(project.root) == before
    assert journal.RecordOperation(project, dispatched, Operation(prepared)).phase == "recorded"


@POSIX
def test_IntentBundleFailureRetainsJournalAndCannotAuthorizeDispatchBeforeExactPublicationRetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pending metadata precedes immutable intent, so a failure between them stays explicit and cannot submit cloud work."""

    project, prepared = Setup(tmp_path)
    original = journal.WriteArtifactBundle

    def Interrupt(*args: Any, **options: Any) -> Any:
        """Model an interrupted immutable publication without touching another project or resource."""

        raise OSError("Synthetic intent publication interruption")

    monkeypatch.setattr(journal, "WriteArtifactBundle", Interrupt)

    with pytest.raises(OSError, match="Synthetic intent"):
        journal.PublishIntent(project, prepared)

    assert journal.LoadJournal(project) == prepared

    with pytest.raises((VpnError, OSError)):
        journal.BeginDispatch(project, prepared)

    monkeypatch.setattr(journal, "WriteArtifactBundle", original)
    journal.PublishIntent(project, prepared)
    dispatched = journal.BeginDispatch(project, prepared)
    recorded = journal.RecordOperation(project, dispatched, Operation(prepared))
    before = Snapshot(project.root)

    with pytest.raises(VpnError, match="exact pending operation"):
        journal.RecordOperation(project, dispatched, replace(Operation(prepared), operationId="different-operation"))

    assert journal.LoadJournal(project) == recorded and Snapshot(project.root) == before


@POSIX
@pytest.mark.parametrize("fault", ["missing-journal", "unrelated-intent"])
def test_UnrecordedImmutableIntentCannotBeAdoptedOrHiddenByASecondJournal(tmp_path: Path, fault: str) -> None:
    """Losing mutable journal metadata does not prove that a queued cloud command can no longer execute."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    journal.BeginDispatch(project, prepared)

    if fault == "missing-journal":
        (project.root / "protocol-ingress-pending.json").unlink()

    else:
        WriteArtifactBundle(project.Artifacts, replace(prepared, previousStateSha256="c" * 64).Bundle())

    before = Snapshot(project.root)

    for read in (lambda: journal.LoadJournal(project), lambda: revisions.LoadRevisions(project),
                 lambda: journal.PublishIntent(project, replace(prepared, previousStateSha256="d" * 64))):
        with pytest.raises(VpnError):
            read()

    assert Snapshot(project.root) == before


@POSIX
@pytest.mark.parametrize("phase", ["prepared", "dispatching", "recorded"])
def test_InterruptedMetadataRenameKeepsTheExactForwardStateWithoutReauthorizingAWrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str,
) -> None:
    """Recognized .new files survive a failed replace and can be durably reconciled without a second provider submission."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    dispatched = replace(prepared, phase="dispatching")
    recorded = replace(dispatched, phase="recorded", operation=Operation(prepared))

    if phase == "recorded":
        dispatched = journal.BeginDispatch(project, prepared)

    original = revisions.os.replace

    def Interrupt(source: Any, destination: Any) -> None:
        """Retain the fully written temporary record before its atomic publication boundary."""

        raise OSError("Synthetic metadata rename interruption")

    monkeypatch.setattr(revisions.os, "replace", Interrupt)

    with pytest.raises(OSError, match="Synthetic metadata"):
        if phase == "prepared":
            journal.PublishIntent(project, prepared)

        elif phase == "dispatching":
            journal.BeginDispatch(project, prepared)

        else:
            journal.RecordOperation(project, dispatched, Operation(prepared))

    monkeypatch.setattr(revisions.os, "replace", original)
    current = journal.LoadJournal(project)
    assert current is not None and current.phase == phase
    journal.ReconcileJournal(project, current)
    assert not (project.root / ".protocol-ingress-pending.json.new").exists()

    if phase == "prepared":
        assert journal.BeginDispatch(project, prepared) == dispatched

    elif phase == "dispatching":
        with pytest.raises(VpnError):
            journal.BeginDispatch(project, prepared)

        assert journal.RecordOperation(project, dispatched, Operation(prepared)) == recorded

    else:
        assert journal.RecordOperation(project, dispatched, Operation(prepared)) == recorded


@POSIX
@pytest.mark.parametrize("fault", ["skipped-phase", "backwards", "different-intent", "foreign-reference", "missing-intent", "extra-file", "symlink-intent"])
def test_DriftedOrIncompletePublicationNeverAdvancesTheRetainedIntent(tmp_path: Path, fault: str) -> None:
    """No guessed operation, missing immutable file or foreign path is accepted as an original known submission."""

    project, prepared = Setup(tmp_path)
    journal.PublishIntent(project, prepared)
    dispatched = replace(prepared, phase="dispatching")
    recorded = replace(dispatched, phase="recorded", operation=Operation(prepared))
    temporary = project.root / ".protocol-ingress-pending.json.new"
    directory = project.Artifacts / ("server-" + prepared.Bundle().name)

    if fault == "skipped-phase":
        WritePrivate(temporary, _Json(recorded.Record()))

    elif fault == "backwards":
        dispatched = journal.BeginDispatch(project, prepared)
        journal.RecordOperation(project, dispatched, Operation(prepared))
        WritePrivate(temporary, _Json(dispatched.Record()))

    elif fault == "different-intent":
        WritePrivate(temporary, _Json(replace(dispatched, previousStateSha256="c" * 64).Record()))

    elif fault == "foreign-reference":
        raw = recorded.Record()
        raw["operation"]["resource_id"] = "different-group"
        WritePrivate(temporary, _Json(raw))

    elif fault == "missing-intent":
        (directory / "intent.json").unlink()

    elif fault == "extra-file":
        WritePrivate(directory / "unknown.json", b"{}\n")

    else:
        directory.rename(directory.with_name(directory.name + "-retained"))
        directory.symlink_to(directory.with_name(directory.name + "-retained"), target_is_directory=True)

    before = Snapshot(project.root)

    with pytest.raises((VpnError, ArtifactError, OSError)):
        journal.BeginDispatch(project, prepared)

    assert Snapshot(project.root) == before


@POSIX
def test_ForeignCreationAndExpiredPlansFailBeforeDispatchOrBundlePublication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The unchanged frozen creation spec and short-lived plan remain prerequisites even for local dispatch authority."""

    project, prepared = Setup(tmp_path)
    before = Snapshot(project.root)

    with pytest.raises(VpnError, match="original project creation"):
        journal.PublishIntent(project, replace(prepared, creationSha256="c" * 64))

    assert Snapshot(project.root) == before
    journal.PublishIntent(project, prepared)
    before = Snapshot(project.root)
    monkeypatch.setattr(journal.time, "time", lambda: prepared.planExpiresAt)

    with pytest.raises(VpnError, match="expired"):
        journal.BeginDispatch(project, prepared)

    assert Snapshot(project.root) == before
