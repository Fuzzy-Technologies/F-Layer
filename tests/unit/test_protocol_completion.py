"""Publish native common completion through actual POSIX prefixes with intercepted service/network/cloud boundaries."""

from __future__ import annotations

import copy
import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
import test_protocol_generation_cache as cacheFixtures
import test_protocol_generation_input as inputFixtures
import test_protocol_runtime as nativeFixtures
from test_host_input_transaction import Delta
from test_protocol_runtime import Execute, Input
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Common completion needs POSIX metadata/locks; every native/network operation is intercepted")


def Sources(identity: dict[str, str]) -> list[dict[str, Any]]:
    """Use public synthetic source pins chosen before reservation; private source-file pins still come from the real fixture receipts."""

    return [{"schema_version": 1, "identity": identity, "pin": {"protocol": name, "intent_fingerprint": "1" * 64,
             "material_digest": "2" * 64, "server_digest": "3" * 64}, "kind": "initial", "request_name": "", "request_sha256": ""}
            for name in ("amneziawg", "vless-reality", "wireguard")]


class Services:
    """Model an independent trusted non-WG observer; the request cannot choose this dependency or its measured receipts."""

    def __init__(self, sources: list[dict[str, Any]], proofs: list[dict[str, str]]) -> None:
        """Keep observed service facts independent from the mutable candidate envelope."""

        self.sources, self.proofs, self.calls = copy.deepcopy(sources), copy.deepcopy(proofs), 0
        self.pinned = False

    @contextmanager
    def Pinned(self) -> Iterator[Services]:
        """Model an independently selected trusted observation lease held through immutable completion publication."""

        assert not self.pinned
        self.pinned = True

        try:
            yield self

        finally:
            self.pinned = False

    def Observe(self, receiver: Any, sources: list[dict[str, Any]]) -> list[dict[str, str]]:
        """Validate source selection and return only public measured facts, with no private data or native output."""

        assert self.pinned and receiver is guest and receiver._Encode(sources) == receiver._Encode(self.sources)
        self.calls += 1

        return copy.deepcopy(self.proofs)


def Environment(tmpPath: Path, monkeypatch: pytest.MonkeyPatch, phase: str = "active") -> tuple[Any, Any, Any, dict[str, Any], dict[str, Any], Services]:
    """Reach a real terminal generation/input record while cloud evidence remains the separately trusted controller boundary."""

    sourceRecords = Sources(Delta().Record()["before"]["identity"])
    sourceSha = guest._Digest(guest._Encode(sourceRecords[-1]))

    def Prepared(*args: Any, **kwargs: Any) -> Any:
        """Bind the exact public WG source in the full composite before Reserve/Expose, never by editing reserved authority."""

        return cacheFixtures.Prepared(*args, **kwargs, sourceSha256=sourceSha)

    monkeypatch.setattr(inputFixtures, "Prepared", Prepared)
    change = "enable" if phase in {"active", "rolled-back"} else "disable"
    model, network, controller, request, intent = nativeFixtures.Environment(tmpPath, monkeypatch, change)

    if phase != "unchanged":
        Execute(controller, request, intent)

    if phase == "active":
        Input(request, intent)

    elif phase in {"rolled-back", "restored", "unchanged"}:
        if phase == "rolled-back":
            Input(request, intent, rollback=True)

        Execute(controller, request, intent, rollback=True)

        if phase != "rolled-back":
            Input(request, intent, rollback=True)

    observed = inputs.Status(guest, peers, authority, policy, request, intent, generationCache=cache, runtimeBackend=runtime)
    native = authority._Decode(guest, authority._Root(guest) / "runtime.json")
    assert native["phase"] == phase
    committed = phase in {"active", "inactive"}
    values = policy.Transition(request["input"])
    selected = values[1 if committed else 2]
    active = [item["transport"] for item in selected["listeners"]]
    installed = guest._Digest(guest._Encode({**request["generation"]["candidate_receipt"], "status": "installed"}))
    receipt = installed if phase in {"active", "restored"} else intent["wireguard_receipt_sha256"] if phase == "unchanged" else ""
    history = peers._History(guest, intent["owner"])
    proof = {"schema_version": 1, "transition": request["input"], "outcome": "applied" if committed else "rolled-back",
             **{key: observed[key] for key in ("native_sha256", "journal_sha256", "boot_sha256")}}
    services = [{"protocol": source["pin"]["protocol"], "source_sha256": source["pin"]["server_digest"],
                 "state": "active" if source["pin"]["protocol"] in active else "absent",
                 "receipt_sha256": receipt if source["pin"]["protocol"] == "wireguard" else "c" * 64,
                 "absence_sha256": "" if source["pin"]["protocol"] in active else guest._AbsenceDigest(intent["owner"])} for source in sourceRecords]
    serviceProof = {"schema_version": 1, "services": services}
    configured = {item["transport"]: item for item in [*values[0]["listeners"], request["input"]["listener"]]}
    metadata = {"schema_version": 2, "identity": values[0]["identity"], "creation_sha256": intent["creation_sha256"], "parent": None,
                "closed_peer_head": None, "closed_peer_head_sha256": intent["creation_sha256"], "closed_peer_count": 0,
                "previous_state_sha256": intent["previous_state_sha256"], "sources": sourceRecords,
                "configured_listeners": [configured[source["pin"]["protocol"]] for source in sourceRecords],
                "active_protocols": [source["pin"]["protocol"] for source in sourceRecords if source["pin"]["protocol"] in active],
                "static_fingerprint": "d" * 64, "wireguard_receipt_sha256": receipt, "wireguard_history_sha256": history,
                "generation_receipt_sha256": installed if phase in {"active", "restored", "rolled-back"} else "",
                "reservation": intent, "authority_parent": None, "ingress_intents": [], "cloud_sha256": "a" * 64,
                "input_sha256": guest._Digest(guest._Encode(proof)), "services_sha256": guest._Digest(guest._Encode(serviceProof)),
                "generation": request["generation"], "native_sha256": guest._Digest(guest._Encode(native))}
    value = {"schema_version": 1, "metadata": metadata, "request": request, "input": proof, "services": serviceProof,
             "outcome": "committed" if committed else "not-applied"}
    observer = Services(sourceRecords, [item for item in services if item["protocol"] != "wireguard"])

    return model, network, controller, value, intent, observer


def Complete(value: dict[str, Any], intent: dict[str, Any], observer: Services | None) -> dict[str, Any]:
    """Exercise the real completion module, metadata files, locks and independent observer dependency."""

    return completion.Complete(guest, peers, authority, policy, inputs, cache, runtime, value, intent, allowMutation=True, serviceObserver=observer)


@pytest.mark.parametrize("phase", ["active", "inactive", "restored", "unchanged", "rolled-back"])
def test_ExactCompletionCommitsOnceRetiresOnlySidecarsAndReplaysAsHistoricalMetadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str) -> None:
    """No completion command changes service/kernel/configuration bytes; replay does not manufacture a live health claim."""

    model, network, controller, value, intent, observer = Environment(tmp_path, monkeypatch, phase)
    before = Snapshot(model.root) if model.root.exists() else None
    unrelated, effects = (model.unrelated, network.unrelated), tuple(controller.effects)
    expected = completion.Candidate(guest, authority, policy, cache, value, intent)["record"]
    result = Complete(value, intent, observer)
    assert result == expected and observer.calls == 2 and not observer.pinned
    root = authority._Root(guest)
    assert {path.name for path in root.iterdir()} == {"head.json", "done-" + intent["operation_id"] + ".json"}
    assert json.loads((root / "head.json").read_bytes()) == {"name": "done-" + intent["operation_id"] + ".json", "sha256": guest._Digest(guest._Encode(result))}
    assert (Snapshot(model.root) if model.root.exists() else None) == before
    assert (model.unrelated, network.unrelated) == unrelated and tuple(controller.effects) == effects
    assert authority.Status(guest, peers, intent)["phase"] == "completed"
    assert Complete(value, intent, None) == result and observer.calls == 2
    assert tuple(controller.effects) == effects


@pytest.mark.parametrize("boundary", ["done", "head", "input.json", "generation.json", "runtime.json", "pending.json"])
def test_RecordedCompletionRecoversEveryPublicationAndCleanupBoundaryWithoutRecheckingLiveHealth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """A durable completion is historical evidence: metadata recovery remains possible after a service stops or a reboot blocks its callback."""

    model, _, controller, value, intent, observer = Environment(tmp_path, monkeypatch)
    write, publish, retire = completion._WriteCompletion, authority._Publish, completion._Retire

    def Write(*args: Any) -> None:
        """Die after durable immutable completion but before pointer publication."""

        write(*args)
        raise Interrupted

    def Publish(receiver: Any, filename: str, record: dict[str, Any], **kwargs: Any) -> None:
        """Die after the exact new common pointer is durable."""

        publish(receiver, filename, record, **kwargs)

        if filename == "head.json":
            raise Interrupted

    def Retire(receiver: Any, backend: Any, filename: str, content: bytes) -> None:
        """Die after each individual known sidecar or the final reservation has been retired."""

        retire(receiver, backend, filename, content)

        if filename == boundary:
            raise Interrupted

    with monkeypatch.context() as crash:
        if boundary == "done":
            crash.setattr(completion, "_WriteCompletion", Write)

        elif boundary == "head":
            crash.setattr(authority, "_Publish", Publish)

        else:
            crash.setattr(completion, "_Retire", Retire)

        with pytest.raises(Interrupted):
            Complete(value, intent, observer)

    model.interface, model.addresses, model.network, model.active = None, [], False, False
    controller.active[controller.newUnit.name] = False
    calls, effects = observer.calls, tuple(controller.effects)
    result = Complete(value, intent, None)
    assert result["outcome"] == "committed" and observer.calls == calls
    assert tuple(controller.effects) == effects and model.interface is None and not model.network
    assert not (authority._Root(guest) / "pending.json").exists()


@pytest.mark.parametrize("length", [0, 17, 300])
def test_OnlyAnExactIncompleteCompletionPrefixCanBeFinishedAfterFreshTerminalVerification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, length: int,
) -> None:
    """The partial record blocks ordinary mutation; completion recovery appends no replacement bytes and reattests the live witnesses."""

    _, _, controller, value, intent, observer = Environment(tmp_path, monkeypatch)
    record = completion.Candidate(guest, authority, policy, cache, value, intent)["record"]
    path = authority._Root(guest) / ("done-" + intent["operation_id"] + ".json")
    path.write_bytes(guest._Encode(record)[:length])
    path.chmod(0o600)
    before = Snapshot(tmp_path)

    with pytest.raises(ValueError):
        Execute(controller, value["request"], intent)

    assert Snapshot(tmp_path) == before
    assert Complete(value, intent, observer) == record and observer.calls == 2
    assert path.read_bytes() == guest._Encode(record)


@pytest.mark.parametrize("fault", ["observer-missing", "observer-drift", "input-proof", "sidecar", "native-temp", "prefix", "peer-history"])
def test_UnknownOrReboundEvidenceCannotCommitOrRetireAnyProtection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Keep every original byte when attestation is absent or a public envelope differs from its actual terminal journals."""

    _, _, controller, value, intent, observer = Environment(tmp_path, monkeypatch)
    selected: Services | None = observer
    root = authority._Root(guest)

    if fault == "observer-missing":
        selected = None

    elif fault == "observer-drift":
        observer.proofs[0]["receipt_sha256"] = "0" * 64

    elif fault == "input-proof":
        value["input"]["native_sha256"] = "0" * 64
        value["metadata"]["input_sha256"] = guest._Digest(guest._Encode(value["input"]))

    elif fault == "sidecar":
        record = authority._Decode(guest, root / "input.json")
        record["unknown"] = "preserve unknown metadata"
        (root / "input.json").write_bytes(guest._Encode(record))

    elif fault == "native-temp":
        (root / ".runtime.json.new").write_bytes((root / "runtime.json").read_bytes())
        (root / ".runtime.json.new").chmod(0o600)

    elif fault == "prefix":
        path = root / ("done-" + intent["operation_id"] + ".json")
        path.write_bytes(b"preserve unrelated prefix")
        path.chmod(0o600)

    else:
        monkeypatch.setattr(peers, "_History", lambda *args: "0" * 64)

    before, effects = Snapshot(tmp_path), tuple(controller.effects)

    with pytest.raises(ValueError):
        Complete(value, intent, selected)

    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects
    assert (root / "pending.json").exists()


def test_ACommittedNativeCompletionCanParentALaterHistoricalCancellationWithoutReusingItsNonce(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The original schema-1 cancellation format remains valid after schema-2 completion in the same immutable authority chain."""

    _, _, _, value, intent, observer = Environment(tmp_path, monkeypatch)
    record = Complete(value, intent, observer)
    nextIntent = {**intent, "operation_id": "2" * 32, "previous_authority_sha256": guest._Digest(guest._Encode(record)),
                  "wireguard_state": "active", "wireguard_receipt_sha256": value["metadata"]["wireguard_receipt_sha256"],
                  "wireguard_absence_sha256": "", "wireguard_history_sha256": record["history_sha256"]}
    reserved = authority.Reserve(guest, peers, nextIntent, allowMutation=True)
    assert reserved["status"] == "reserved"
    assert authority.Cancel(guest, peers, nextIntent, allowMutation=True)["status"] == "cancelled"
    assert authority.Status(guest, peers, nextIntent)["completion_count"] == 2

    with pytest.raises(ValueError):
        authority.Reserve(guest, peers, intent, allowMutation=True)


@pytest.mark.parametrize("entry", ["guest", "peer"])
def test_FailedPendingRemovalCannotAdmitAnotherMutationUntilItsNamespaceAbsenceIsDurable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], entry: str,
) -> None:
    """Exercise the actual failed final fsync window, then refuse ordinary maintenance/peer admission before any new write."""

    model, _, _, value, intent, observer = Environment(tmp_path, monkeypatch, "unchanged")
    root = authority._Root(guest)
    identity = root.stat()
    fsync = os.fsync

    def Fail(descriptor: int) -> None:
        """Leave a visible but not acknowledged reservation removal; fail the same required barrier on subsequent admission."""

        info = os.fstat(descriptor)

        if (stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino)
                and not (root / "pending.json").exists()):
            raise OSError("Synthetic common-directory synchronization failure")

        fsync(descriptor)

    writes = []

    def Remove(owner: str, receipt: str) -> None:
        """Observe attempted ordinary runtime mutation without issuing any native command."""

        writes.append((owner, receipt))

    with monkeypatch.context() as fault:
        fault.setattr(os, "fsync", Fail)

        with pytest.raises(OSError):
            Complete(value, intent, observer)

        assert not (root / "pending.json").exists() and (root / "head.json").exists()
        before = Snapshot(tmp_path)

        if entry == "guest":
            fault.setattr(guest, "_Remove", Remove)
            assert guest.Main(["--remove", "--allow-mutation", "--expected-receipt-sha256", value["metadata"]["wireguard_receipt_sha256"]]) == 1
            capsys.readouterr()

        else:
            with authority._Locks(guest, readOnly=False):
                with pytest.raises(OSError):
                    peers._ProtocolGate(guest, mutate=True)
                    writes.append("peer write must remain unreachable")

        assert not writes and Snapshot(tmp_path) == before

    synchronized = []

    def Sync(descriptor: int) -> None:
        """Record a successful common-directory barrier before admission is allowed to return."""

        info = os.fstat(descriptor)

        if stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            synchronized.append(True)

        fsync(descriptor)

    monkeypatch.setattr(os, "fsync", Sync)

    with authority._Locks(guest, readOnly=False):
        (guest._ProtocolGate if entry == "guest" else lambda **kwargs: peers._ProtocolGate(guest, **kwargs))(mutate=True)
        assert synchronized

    assert model.root.exists() and not (root / "pending.json").exists()


@pytest.mark.parametrize("filename", ["input.json", "generation.json", "runtime.json"])
def test_ReappearingCanonicalSidecarKeepsTheReservationUntilExplicitRecovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str,
) -> None:
    """A known name is insufficient: no sidecar may remain when the final reservation is retired."""

    _, _, controller, value, intent, observer = Environment(tmp_path, monkeypatch)
    root = authority._Root(guest)
    content = (root / filename).read_bytes()
    retire = completion._Retire
    effects = tuple(controller.effects)

    def Retire(receiver: Any, currentAuthority: Any, currentName: str, expected: bytes) -> None:
        """Recreate a previously removed canonical sidecar at the final sidecar directory barrier."""

        retire(receiver, currentAuthority, currentName, expected)

        if currentName == "runtime.json":
            (root / filename).write_bytes(content)
            (root / filename).chmod(0o600)

    with monkeypatch.context() as fault:
        fault.setattr(completion, "_Retire", Retire)

        with pytest.raises(ValueError, match="before retirement"):
            Complete(value, intent, observer)

    assert (root / "pending.json").exists() and (root / filename).read_bytes() == content
    assert tuple(controller.effects) == effects
    assert Complete(value, intent, None)["outcome"] == "committed"
    assert not (root / "pending.json").exists() and not (root / filename).exists()


def test_ReadOnlyAdmissionDoesNotSynchronizeOrRepairACompletedNamespace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a subsequent write grants itself the durable-absence barrier; status keeps its no-repair contract."""

    _, _, _, value, intent, observer = Environment(tmp_path, monkeypatch)
    Complete(value, intent, observer)
    before = Snapshot(tmp_path)
    monkeypatch.setattr(os, "fsync", lambda *args: pytest.fail("Read-only admission must not synchronize metadata"))
    guest._ProtocolGate()
    peers._ProtocolGate(guest)
    assert Snapshot(tmp_path) == before


def test_NativeCompletionKeepsTheTrustedServiceLeaseThroughItsImmutableCommitPoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two actual observations and the done write share one lease; historical recovery neither reacquires nor invents live health."""

    _, _, _, value, intent, observer = Environment(tmp_path, monkeypatch)
    write = completion._WriteCompletion
    committed = []

    def Write(*args: Any) -> None:
        """Require the observer's separately selected lease while publishing the first immutable completion bytes."""

        assert observer.pinned and observer.calls == 2
        committed.append(True)
        write(*args)

    with monkeypatch.context() as verify:
        verify.setattr(completion, "_WriteCompletion", Write)
        assert Complete(value, intent, observer)["outcome"] == "committed"

    assert committed == [True] and not observer.pinned
    assert Complete(value, intent, None)["outcome"] == "committed" and observer.calls == 2


def test_DriftAtTheSecondLeasedServiceObservationCannotPublishCompletion(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A first healthy observation is insufficient when a later measured proof changes before the immutable commit point."""

    _, _, _, value, intent, observer = Environment(tmp_path, monkeypatch)
    observe = observer.Observe

    def Observe(*args: Any) -> list[dict[str, str]]:
        """Change only the second independently measured service result without editing the expected candidate."""

        result = observe(*args)

        if observer.calls == 2:
            result[0]["receipt_sha256"] = "0" * 64

        return result

    monkeypatch.setattr(observer, "Observe", Observe)
    before = Snapshot(tmp_path)

    with pytest.raises(ValueError, match="changed before immutable"):
        Complete(value, intent, observer)

    assert Snapshot(tmp_path) == before and not observer.pinned
    assert not (authority._Root(guest) / ("done-" + intent["operation_id"] + ".json")).exists()
