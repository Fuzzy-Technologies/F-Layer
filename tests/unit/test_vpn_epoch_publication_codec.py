"""Validate retained public epoch candidates without private files, provider operations or guest execution."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from test_vpn_protocol_epochs import Commit

from flayer import _vpn_epoch_publication as publication
from flayer._vpn_creation import _Json


def Candidate() -> tuple[Any, publication.EpochPublication]:
    """Supply only a public synthetic complete epoch and the identity required by its closed decoder."""

    epoch = Commit("enable")

    return SimpleNamespace(vpn=SimpleNamespace(identity=epoch.identity)), publication.EpochPublication(epoch)


@pytest.mark.parametrize("phase", ["prepared", "observed"])
def test_CompletePublicCandidateRoundTripsWithoutAnImplicitObservedAcknowledgment(phase: str) -> None:
    """Predicted completion remains explicitly distinguished from a separately observed response."""

    project, value = Candidate()
    value = replace(value, phase=phase)
    encoded = _Json(value.Record())
    assert publication.DecodePublication(project, encoded) == value
    assert json.loads(encoded)["phase"] == phase
    assert set(value.Record()["files"]) == {"epoch.json", "cloud.json", "input.json", "services.json"}


@pytest.mark.parametrize("fault", ["schema", "extra", "phase", "name", "missing-file", "extra-file", "completion", "cloud", "source", "duplicate", "noncanonical", "oversize"])
def test_MalformedReboundOrAmbiguousPublicationCannotReachAnyFilesystemBoundary(fault: str) -> None:
    """The existing complete epoch codec validates source, intent, known cloud result and exact completion binding again."""

    project, value = Candidate()
    record = copy.deepcopy(value.Record())

    if fault == "schema":
        record["schema_version"] = True

    elif fault == "extra":
        record["private_key"] = "synthetic-forbidden-field"

    elif fault == "phase":
        record["phase"] = "complete"

    elif fault == "name":
        record["name"] = "other-ep-" + "0" * 16

    elif fault == "missing-file":
        del record["files"]["services.json"]

    elif fault == "extra-file":
        record["files"]["server.conf"] = {"forbidden": "synthetic-private-payload"}

    elif fault == "completion":
        record["files"]["epoch.json"]["completion"]["intent_sha256"] = "0" * 64

    elif fault == "cloud":
        record["files"]["cloud.json"]["outcome"] = "unknown"

    elif fault == "source":
        record["files"]["services.json"]["services"][0]["source_sha256"] = "0" * 64

    encoded = _Json(record)

    if fault == "duplicate":
        encoded = encoded.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1)

    elif fault == "noncanonical":
        encoded = json.dumps(record, indent=2).encode()

    elif fault == "oversize":
        encoded = b" " * (publication.MAX_PUBLICATION_BYTES + 1)

    with pytest.raises(ValueError, match="journal"):
        publication.DecodePublication(project, encoded)


def test_MutationConsentAndExactObservedResponseAreRequiredBeforeProjectAccess() -> None:
    """Neither a predicted response nor a local observed phase authorizes guest or cloud work, or bypasses consent."""

    _, value = Candidate()

    with pytest.raises(ValueError, match="consent"):
        publication.PreparePublication(object(), value.epoch)

    for response in (value.epoch.completion, b"other-guest-response"):
        with pytest.raises(ValueError, match="consent"):
            publication.CommitPublication(object(), value, response)

    with pytest.raises(ValueError, match="separately observed"):
        publication.CommitPublication(object(), replace(value, phase="observed"), b"other-response", allowMutation=True)
