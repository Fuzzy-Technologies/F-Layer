"""Check sealed native authority and service-property parsing without guest access or native commands."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_protocol_generation import Composite
from test_protocol_reservation import Header

from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest


def Record(change: str = "disable", version: int = 3) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind only synthetic metadata; no declared hash attests that a real service is running."""

    request, partial = Composite(change, version)
    intent = {**Header(partial["owner"]), **partial}

    if intent["wireguard_state"] == "absent":
        intent["wireguard_absence_sha256"] = guest._AbsenceDigest(intent["owner"])
    record = {"schema_version": 1, "intent": intent, "request": request, "history_sha256": guest._ProtocolHistory(intent, request),
              "admitted_program_sha256": request["generation"]["candidate_receipt"]["files"]["lifecycle.py"]
              if request["generation"]["candidate_receipt"] is not None else "f" * 64, "phase": "ready", "rollback": False}

    return record, intent


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_SealedGenerationRecordBindsSourceAbiAndBothConsumedHistorySteps(change: str) -> None:
    """The new ABI is explicit; the original fence and candidate fence use the unchanged peer-audit format."""

    record, intent = Record(change)
    assert guest._RuntimeRecord(record, intent) == record
    assert guest._ProtocolIntent(intent) == authority.Intent(intent)
    assert record["history_sha256"] == authority._FencedHistory(guest, intent, record["request"]["generation"]["cached_receipt"]["deployment_sha256"])
    audit = guest._GenerationAudit(intent, record["request"])
    assert audit["previous_history_sha256"] == record["history_sha256"]
    assert audit["receipt_sha256"] == audit["previous_receipt_sha256"]
    assert runtime._FreshHistory(guest, record["request"], intent) == guest._Digest(guest._Encode(audit))


@pytest.mark.parametrize("change", ["enable", "disable"])
@pytest.mark.parametrize("version", [1, 2])
def test_PreviousCacheContractsRemainReadableButCannotAuthorizeANativeJournal(change: str, version: int) -> None:
    """An otherwise well-formed old cache cannot silently acquire the new callback capability under an old plan hash."""

    record, intent = Record(change, version)
    assert cache.Request(guest, policy, record["request"], intent) == record["request"]

    with pytest.raises(guest.GuestError):
        guest._RuntimeRecord(record, intent)


@pytest.mark.parametrize("fault", ["extra", "version", "intent", "history", "program", "phase", "rollback", "abi", "cloud", "input"])
def test_RuntimeMetadataCannotAdoptAnUnboundCallbackCapability(fault: str) -> None:
    """Rehashing an outer plan does not bypass closed schema, recovery history, native ABI or exact input scope."""

    record, intent = Record()

    if fault == "extra":
        record["private_key"] = "suppressed-canary"

    elif fault == "version":
        record["schema_version"] = True

    elif fault == "intent":
        record["intent"] = {**intent, "owner": "1" * 64}

    elif fault in {"history", "program", "phase", "rollback"}:
        record[{"history": "history_sha256", "program": "admitted_program_sha256", "phase": "phase", "rollback": "rollback"}[fault]] = (
            "1" * 64 if fault in {"history", "program"} else "active" if fault == "phase" else 1)

    else:
        if fault == "abi":
            record["request"]["generation"]["callback_abi"] = "unknown/native-abi"

        elif fault == "cloud":
            record["request"]["cloud_plan_sha256"] = []

        else:
            record["request"]["input"]["change"] = "enable"

        intent["plan_sha256"] = guest._Digest(guest._Encode(record["request"]))

    with pytest.raises(guest.GuestError):
        guest._RuntimeRecord(record, intent)


@pytest.mark.parametrize("fault", ["missing", "duplicate", "unknown", "wrong-id", "foreign-path", "empty-loaded-path", "not-found-path", "drop-in", "job-zero", "pid-alias", "foreign-cgroup"])
def test_ServiceStateRequiresCompleteNativeEmptyJobAndCoherentOwnedFragments(fault: str) -> None:
    """The real systemd 255 no-job format is empty; a guessed zero, omitted property or unmanaged loaded definition refuses."""

    unit = Path("/etc/systemd/system/flayer-wg-example.service")
    values = {"Id": unit.name, "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead", "Job": "", "MainPID": "0", "ControlPID": "0",
              "ControlGroup": "", "FragmentPath": str(unit), "DropInPaths": ""}

    if fault == "missing":
        del values["Job"]

    elif fault == "unknown":
        values["Unknown"] = ""

    elif fault == "not-found-path":
        values["LoadState"] = "not-found"

    elif fault != "duplicate":
        key, value = {"wrong-id": ("Id", "foreign.service"), "foreign-path": ("FragmentPath", "/foreign.service"),
                      "empty-loaded-path": ("FragmentPath", ""), "drop-in": ("DropInPaths", "/foreign.conf"), "job-zero": ("Job", "0"),
                      "pid-alias": ("MainPID", "00"), "foreign-cgroup": ("ControlGroup", "/other.slice/foreign.service")}[fault]
        values[key] = value

    content = ("\n".join(key + "=" + value for key, value in values.items()) + "\n" + ("Job=\n" if fault == "duplicate" else "")).encode()

    with pytest.raises(runtime.RuntimeError):
        runtime._Service(SimpleNamespace(_Run=lambda command: (0, content)), unit)
