"""Exercise closed protocol operations, request-bound public proofs and private parser refusal without native or network I/O."""

from __future__ import annotations

import base64
import copy
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest
import test_protocol_preparation as preparations
from test_protocol_completion_codec import Envelope
from test_protocol_generation import Composite
from test_protocol_services_codec import Sources

from flayer import _vpn_protocol_receiver as receiver
from flayer import _vpn_protocol_transport as transport
from flayer.core.contracts import ParseIdentity
from flayer.profiles import _protocol_rpc as rpc
from flayer.profiles.vpn import VpnError


def PreparationOperation(action: str) -> dict[str, Any]:
    """Keep preparation origins unreserved and bind cache admission to the later complete composite without inventing paths."""

    request, files = preparations.Request()
    body = request
    intent = None
    bundles = []

    if action == "cache-prepare":
        composite, _ = Composite("enable", version=3)
        composite["generation"] = preparations.Generation(request)
        intent = {**request["origin"], "plan_sha256": transport.guest._Digest(rpc.Json(composite))}
        body = {"request": composite, "preparation": request}

    elif action == "preparation-prepare":
        bundles = [{"protocol": "wireguard", "name": request["identity"]["stack"] + "-wireguard",
                    "files": {name: base64.b64encode(content).decode("ascii") for name, content in files.items()}}]

    return {"schema_version": 1, "identity": request["identity"], "action": action, "allow_mutation": action in rpc.WRITE_ACTIONS,
            "scope_confirm": request["identity"]["scope_id"] if action in rpc.WRITE_ACTIONS else "", "intent": intent, "body": body,
            "expected_reservation_sha256": "", "sources": [], "bundles": bundles}


def Operation(action: str = "native-status", phase: str = "active") -> dict[str, Any]:
    """Build a full synthetic operation with real retained service source bytes only when the selected action needs them."""

    if action.startswith("preparation-") or action == "cache-prepare":
        return PreparationOperation(action)

    candidate, intent, _ = Envelope(phase)
    identity = candidate["metadata"]["identity"]
    sources, bundles = [], []
    body = candidate["request"] if action in rpc._COMPOSITE else None

    if action == "origin-status":
        files = candidate["request"]["generation"]["cached_receipt"]["files"]
        body = {"schema_version": 1, "source_files": {name: files[name] for name in ("server.conf", "deployment.json", "install.py")}
                if intent["wireguard_state"] == "active" else {}}

    if action in {"complete", "services"}:
        _, sources, rawBundles = Sources(stackIdentity=ParseIdentity(identity))
        bundles = [{**bundle, "files": {name: base64.b64encode(content).decode("ascii") for name, content in bundle["files"].items()}} for bundle in rawBundles]

        if action == "complete":
            metadata = candidate["metadata"]
            replacement = {source["pin"]["protocol"]: source for source in sources}
            metadata["sources"] = [replacement.get(source["pin"]["protocol"], source) for source in metadata["sources"]]

            for proof in candidate["services"]["services"]:
                if proof["protocol"] in replacement:
                    proof["source_sha256"] = replacement[proof["protocol"]]["pin"]["server_digest"]

            metadata["services_sha256"] = transport.guest._Digest(rpc.Json(candidate["services"]))
            sources, body = metadata["sources"], candidate

    return {"schema_version": 1, "identity": identity, "action": action, "allow_mutation": action in rpc.WRITE_ACTIONS,
            "scope_confirm": identity["scope_id"] if action in rpc.WRITE_ACTIONS else "", "intent": None if action == "services" else intent,
            "body": body, "expected_reservation_sha256": "a" * 64 if action == "expose" else "", "sources": sources, "bundles": bundles}


def Native(operation: dict[str, Any], phase: str) -> dict[str, str]:
    """Encode a public response independently from the result validator, retaining the exact native journal format."""

    guest = transport.guest
    intent, request = operation["intent"], operation["body"]
    original = guest._ProtocolHistory(intent, request)
    fresh = guest._Digest(rpc.Json(guest._GenerationAudit(intent, request)))
    result = {"status": "native-generation", "phase": phase,
              "history_sha256": original if phase in {"ready", "unchanged", "removing-original", "stopping-original", "inactive"} else fresh}

    if operation["action"] != "native-status":
        record = {"schema_version": 1, "intent": intent, "request": request, "history_sha256": original,
                  "admitted_program_sha256": request["generation"]["candidate_receipt"]["files"]["lifecycle.py"],
                  "phase": phase, "rollback": operation["action"] == "native-rollback"}
        result["journal_sha256"] = guest._Digest(rpc.Json(record))

    return result


def Input(operation: dict[str, Any], phase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Construct a request-bound three-policy journal and its complete public wire witness."""

    modules = transport._Codecs()
    fingerprints = [str(index) * 64 for index in (1, 2, 3)]
    record = {**modules.inputs._Expected(modules.policy, operation["intent"], operation["body"], fingerprints), "phase": phase}
    result = modules.inputs._Result(modules.policy, modules.policy.Transition(operation["body"]["input"]), record)

    return {**result, "fingerprints": fingerprints}, record


def Frame(operation: dict[str, Any], result: object) -> bytes:
    """Model an authenticated response with the same complete operation and installed-package fingerprint."""

    return rpc.Json({"schema_version": 1, "action": operation["action"], "request_sha256": receiver.Fingerprint(operation, receiver.Sources()), "result": result})


@pytest.mark.parametrize("action", sorted(rpc.READ_ACTIONS | rpc.WRITE_ACTIONS))
def test_ClosedOperationsValidateBeforePackingAnyExecutableOrPrivateData(action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The complete consent/identity/source checks are portable pure validation, including real private service bundles."""

    monkeypatch.setattr(transport.authority, "_Root", lambda *args: pytest.fail("Request validation must not read guest state"))
    monkeypatch.setattr(transport.guest, "_Run", lambda *args, **kwargs: pytest.fail("Request validation must not invoke a native program"))
    operation = Operation(action)
    bootstrap, frame = transport.Encode(operation)
    observed, programs = receiver.Envelope(frame)
    assert observed == operation and programs == receiver.Sources()
    assert bootstrap == receiver.Programs()[0] and b"__FLAYER_PROTOCOL_MODULE_PINS__" not in bootstrap


@pytest.mark.parametrize("fault", ["consent", "scope", "owner", "identity", "schema", "command", "path", "action", "body", "reservation", "sources", "bundle"])
def test_InvalidOperationsNeverReachProgramPackingOrTheSshRunner(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """An installed dependency set and reachable server cannot substitute for exact mutation authority."""

    operation = Operation("native-apply")

    if fault == "consent":
        operation["allow_mutation"] = False
    elif fault == "scope":
        operation["scope_confirm"] += "-other"
    elif fault == "owner":
        operation["intent"]["owner"] = "0" * 64
    elif fault == "identity":
        operation["identity"]["owner_id"] += "-other"
    elif fault == "schema":
        operation["schema_version"] = True
    elif fault in {"command", "path"}:
        operation[fault] = "private-marker"
    elif fault == "action":
        operation["action"] = "execute"
    elif fault == "body":
        operation["body"]["cloud_plan_sha256"] = "0" * 64
    elif fault == "reservation":
        operation["expected_reservation_sha256"] = "a" * 64
    elif fault == "sources":
        operation["sources"] = [{"private": "marker"}]
    else:
        operation["bundles"] = [{"private": "marker"}]

    monkeypatch.setattr(receiver, "Programs", lambda: pytest.fail("Invalid operation must be rejected before packing"))
    provisioner = SimpleNamespace(runner=SimpleNamespace(Run=lambda *args: pytest.fail("Invalid operation must not reach SSH")))

    with pytest.raises(VpnError) as failure:
        transport.Execute(provisioner, operation)

    assert failure.value.__context__ is None and failure.value.__cause__ is None


@pytest.mark.parametrize("action", sorted(rpc.READ_ACTIONS))
def test_ReadOnlyActionsRejectMutationConsentRatherThanBroadeningTheirAuthority(action: str) -> None:
    """Every read action must remain distinct from the explicit mutation/scope contract."""

    operation = Operation(action)
    operation.update(allow_mutation=True, scope_confirm=operation["identity"]["scope_id"])

    with pytest.raises(VpnError):
        transport.Encode(operation)


@pytest.mark.parametrize("action,phase", [("native-apply", "active"), ("native-apply", "inactive"), ("native-rollback", "rolled-back"),
                                         ("native-rollback", "restored"), ("native-rollback", "unchanged")])
def test_NativeTerminalRepliesRequireTheExactRequestHistoryAndJournal(action: str, phase: str) -> None:
    """Neither a plausible terminal name nor an arbitrary 64-digit digest is acceptable proof."""

    operation = Operation(action, phase)
    result = Native(operation, phase)
    assert transport.Decode(operation, Frame(operation, result), 0) == result

    for field in ("history_sha256", "journal_sha256"):
        changed = {**result, field: "0" * 64}

        with pytest.raises(VpnError):
            transport.Decode(operation, Frame(operation, changed), 0)


@pytest.mark.parametrize("change,phase", [("enable", "inactive"), ("enable", "restored"), ("enable", "unchanged"), ("disable", "active"),
                                        ("disable", "rolled-back"), ("disable", "removing-candidate"), ("disable", "stopping-candidate")])
def test_NativeStatusRejectsPhasesFromTheOtherChangeStateMachine(change: str, phase: str) -> None:
    """A state known by another workflow remains an impossible result for this reserved operation."""

    operation = Operation(phase="active" if change == "enable" else "inactive")
    result = Native(operation, phase)

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, result), 0)


@pytest.mark.parametrize("phase", ["ready", "publishing", "starting", "active", "restarting-active", "removing-candidate", "stopping-candidate", "rolled-back", "recovery-required"])
def test_NativeStatusBindsEveryKnownPrefixToOneOfItsActualHistoryFences(phase: str) -> None:
    """Observation can report explicit uncertainty, but cannot adopt an unrelated history."""

    operation = Operation()
    result = Native(operation, phase)
    assert transport.Decode(operation, Frame(operation, result), 0) == result

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, {**result, "history_sha256": "0" * 64}), 0)


@pytest.mark.parametrize("phase", ["prepared", "applying", "applied", "rolling-back", "rolled-back"])
def test_InputWitnessReconstructsItsJournalAndBootPolicyRatherThanTrustingClaimedHashes(phase: str) -> None:
    """Three bounded compiler hashes bind all input phases without executing nft on the controller."""

    operation = Operation("input-status")
    result, _ = Input(operation, phase)
    assert transport.Decode(operation, Frame(operation, result), 0) == result

    for field in ("journal_sha256", "boot_sha256", "native_sha256", "fingerprints"):
        changed = {**result, field: ["0" * 64] * 3 if field == "fingerprints" else "0" * 64}

        with pytest.raises(VpnError):
            transport.Decode(operation, Frame(operation, changed), 0)


@pytest.mark.parametrize("action,phase", [("input-apply", "prepared"), ("input-apply", "applying"), ("input-rollback", "rolling-back"), ("input-rollback", "applied")])
def test_MutationRepliesCannotReportAnIntermediateInputPrefixAsSuccess(action: str, phase: str) -> None:
    """A request returning before its terminal boundary must remain an explicit failed/unknown operation."""

    operation = Operation(action)

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, Input(operation, phase)[0]), 0)


@pytest.mark.parametrize("phase", ["preparing", "prepared"])
def test_CacheStatusReconstructsItsExactPlanJournalAndConsumedHistory(phase: str) -> None:
    """A prepared cache response is not transferable to another generation or reservation."""

    operation = Operation("cache-status")
    guest = transport.guest
    history = guest._ProtocolHistory(operation["intent"], operation["body"])
    record = {**transport.cache._Expected(guest, operation["intent"], operation["body"], history), "phase": phase}
    result = {"status": "generation-cache", "phase": phase, "journal_sha256": guest._Digest(rpc.Json(record)), "history_sha256": history}
    assert transport.Decode(operation, Frame(operation, result), 0) == result

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, {**result, "journal_sha256": "0" * 64}), 0)


@pytest.mark.parametrize("fault", ["action", "operation", "package", "extra", "private-result", "status", "boolean-status", "oversize", "json", "duplicate", "nonfinite"])
def test_TransportRejectsReboundOrPrivateResponsesWithoutRetainingParserChains(fault: str) -> None:
    """Authenticated bytes are still parsed as an exact operation/package-bound public response."""

    operation = Operation()
    content = Frame(operation, Native(operation, "active"))
    value = rpc.Decode(content, limit=rpc.MAX_RESULT_BYTES)
    returnCode: Any = 0

    if fault == "action":
        value["action"] = "native-apply"
    elif fault == "operation":
        other = copy.deepcopy(operation)
        other["intent"]["operation_id"] = "e" * 32
        value["request_sha256"] = receiver.Fingerprint(other, receiver.Sources())
    elif fault == "package":
        programs = receiver.Sources()
        programs["guest"] += b"\n"
        value["request_sha256"] = receiver.Fingerprint(operation, programs)
    elif fault == "extra":
        value["private"] = "private-marker"
    elif fault == "private-result":
        value["result"]["private_key"] = "private-marker"
    elif fault in {"status", "boolean-status"}:
        returnCode = 1 if fault == "status" else False

    content = rpc.Json(value)

    if fault == "oversize":
        content = b"private-marker" * 7000
    elif fault == "json":
        content = b'{"private-marker":'
    elif fault == "duplicate":
        content = b'{"private-marker":1,"private-marker":2}'
    elif fault == "nonfinite":
        content = b'{"private-marker":NaN}'

    with pytest.raises(VpnError) as failure:
        transport.Decode(operation, content, returnCode)

    assert "private-marker" not in str(failure.value)
    assert failure.value.__context__ is None and failure.value.__cause__ is None


@pytest.mark.parametrize("content", [b'{"private-marker":', b'{"a":1,"a":2}', b'{"a":Infinity}', b'[]', b'\xff', b'x' * 101])
def test_PrivateJsonRefusalDropsTheOriginalParserExceptionObject(content: bytes) -> None:
    """Suppressing traceback display alone would leave JSONDecodeError.doc reachable through __context__."""

    with pytest.raises(rpc.RpcError) as failure:
        rpc.Decode(content, limit=100)

    assert failure.value.__context__ is None and failure.value.__cause__ is None and "private-marker" not in str(failure.value)


@pytest.mark.parametrize("phase", ["active", "inactive", "restored", "unchanged", "rolled-back"])
def test_CompletionResponseIsTheExactRecordReconstructedFromAllRetainedSources(phase: str) -> None:
    """Full real AWG/VLESS server bytes accompany a completion; source labels and a caller hash alone grant nothing."""

    operation = Operation("complete", phase)
    modules = transport._Codecs()
    result = modules.completion.Candidate(modules.guest, modules.authority, modules.policy, modules.cache, operation["body"], operation["intent"])["record"]
    assert transport.Decode(operation, Frame(operation, result), 0) == result

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, {**result, "history_sha256": "0" * 64}), 0)


@pytest.mark.parametrize("fault", ["source", "file", "encoding", "protocol", "extra"])
def test_ServicePayloadCannotSubstituteForAnExecutableDependencyOrItsFullRetainedSource(fault: str) -> None:
    """Even read-only observation rejects private bytes not pinned to this exact complete stack source."""

    operation = Operation("services")

    if fault == "source":
        operation["sources"][0]["pin"]["server_digest"] = "0" * 64
    elif fault == "file":
        operation["bundles"][0]["files"]["server.conf"] = base64.b64encode(b"private-marker").decode()
    elif fault == "encoding":
        operation["bundles"][0]["files"]["server.conf"] = "private-marker"
    elif fault == "protocol":
        operation["bundles"][0]["protocol"] = "wireguard"
    else:
        operation["bundles"][0]["files"]["/tmp/installer.py"] = base64.b64encode(b"private-marker").decode()

    with pytest.raises(VpnError) as failure:
        transport.Encode(operation)

    assert failure.value.__context__ is None and failure.value.__cause__ is None and "private-marker" not in str(failure.value)


@pytest.mark.parametrize("action", sorted(rpc.READ_ACTIONS | rpc.WRITE_ACTIONS))
def test_DispatchRoutesOnlyTheClosedActionAndFixedTrustedBackendArguments(action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """All native boundaries are intercepted, including service leases and exact installed receiver hash selection."""

    operation = Operation(action)
    modules = transport._Codecs()
    modules.peer = object()
    calls = []
    witnesses = []

    def Reply(*args: Any, **kwargs: Any) -> dict[str, Any]:
        """Keep backend arguments observable without invoking any real guest path or program."""

        calls.append((args, kwargs))

        return result

    if action.startswith("preparation-"):
        result = modules.preparation.Result(modules.guest, modules.authority, modules.completion, operation["body"], preparations.Generation(operation["body"]))
        target, method = "preparation", "Status" if action == "preparation-status" else "Prepare"
    elif action == "origin-status":
        result = {"status": "protocol-origin-observation", "head": None, "authority_sha256": modules.authority._Initial(modules.guest, operation["intent"]),
                  "history_sha256": operation["intent"]["wireguard_history_sha256"], "wireguard_state": "absent", "wireguard_receipt": None, "completion_count": 0}
        target, method = "authority", "OriginStatus"
    elif action == "authority-status":
        result = {"status": "protocol-authority", "authority_sha256": "a" * 64, "history_sha256": "b" * 64,
                  "phase": "initial", "reservation_sha256": "", "completion_count": 0}
        target, method = "authority", "Status"
    elif action in {"reserve", "expose", "cancel"}:
        fields = {"reservation_sha256", "history_sha256", "authority_sha256"} if action == "reserve" else {"reservation_sha256", "history_sha256"} if action == "expose" else {"authority_sha256", "history_sha256"}
        result = {"status": {"reserve": "reserved", "expose": "exposed", "cancel": "cancelled"}[action], **dict.fromkeys(fields, "a" * 64)}
        target, method = "authority", action.title()
    elif action in {"cache-status", "cache-prepare"}:
        request = operation["body"]["request"] if action == "cache-prepare" else operation["body"]
        history = modules.guest._ProtocolHistory(operation["intent"], request)
        record = {**modules.cache._Expected(modules.guest, operation["intent"], request, history), "phase": "prepared"}
        result = {"status": "generation-cache", "phase": "prepared", "history_sha256": history, "journal_sha256": modules.guest._Digest(rpc.Json(record))}
        target, method = "cache", "Prepare" if action == "cache-prepare" else "Status"
    elif action.startswith("input-"):
        wire, _ = Input(operation, "rolled-back" if action == "input-rollback" else "applied" if action == "input-apply" else "prepared")
        result = {key: value for key, value in wire.items() if key != "fingerprints"}
        monkeypatch.setattr(rpc, "_InputWitness", lambda selected, requested, observed: witnesses.append((selected, requested, observed)) or wire)
        target, method = "inputs", "Status" if action == "input-status" else "Prepare" if action == "input-prepare" else "Apply"
    elif action.startswith("native-"):
        result = Native(operation, "rolled-back" if action == "native-rollback" else "active")
        target, method = "runtime", "Status" if action == "native-status" else "Execute"
        modules.guest = SimpleNamespace(**{**vars(modules.guest), "_Read": lambda *args, **kwargs: b"trusted receiver"})
    else:
        proofs = [{"protocol": source["pin"]["protocol"], "source_sha256": source["pin"]["server_digest"], "state": "active",
                   "receipt_sha256": "a" * 64, "absence_sha256": ""} for source in operation["sources"] if source["pin"]["protocol"] != "wireguard"]
        original = modules.services

        class Observer:
            """Validate real retained bytes at construction, then intercept actual service/process/native observation."""

            def __init__(self, *args: Any) -> None:
                original.ServiceObserver(*args)

            def Pinned(self) -> Any:
                witnesses.append("lease")

                return nullcontext()

            def Observe(self, *args: Any) -> list[dict[str, str]]:
                calls.append((args, {}))

                return proofs

        modules.services = SimpleNamespace(ServiceObserver=lambda *args: Observer(*args))

        if action == "services":
            modules.authority = SimpleNamespace(**{**vars(modules.authority), "_Locks": lambda *args, **kwargs: nullcontext()})
            result = {"status": "services", "services": proofs}
            target, method = "completion", "Complete"
        else:
            result = modules.completion.Candidate(modules.guest, modules.authority, modules.policy, modules.cache, operation["body"], operation["intent"])["record"]
            target, method = "completion", "Complete"

    setattr(modules, target, SimpleNamespace(**{**vars(getattr(modules, target)), method: Reply}))
    observed = rpc.Dispatch(modules, operation)
    assert len(calls) == 1

    if action in rpc.WRITE_ACTIONS:
        assert calls[0][1]["allowMutation"] is True

    if action in {"native-apply", "native-rollback"}:
        assert calls[0][1]["expectedProgramSha256"] == modules.guest._Digest(b"trusted receiver")
        assert calls[0][1]["rollback"] == (action == "native-rollback")

    if action.startswith("input-"):
        assert witnesses[0][1]["action"] == action and observed == wire

    elif action == "services":
        assert witnesses == ["lease"] and observed == result

    else:
        assert observed == result


def test_OneSshRoundTripReusesTheProvisionerRouteAndCarriesPrivateSourcesOnlyOnStdin() -> None:
    """The wrapper has no network-policy, proxy, interface, profile-switch or alternate endpoint mechanism."""

    operation = Operation()
    response = Native(operation, "active")
    calls = []

    def Run(command: tuple[str, ...], content: bytes, timeout: int) -> SimpleNamespace:
        """Intercept the entire existing runner boundary; no native command is executed."""

        calls.append((command, content, timeout))
        assert receiver.Envelope(content)[0] == operation

        return SimpleNamespace(stdout=Frame(operation, response), stderr=b"private-marker", returnCode=0)

    provisioner = SimpleNamespace(command=("ssh", "fixed-host-pin", "operator@198.51.100.10"), runner=SimpleNamespace(Run=Run))
    assert transport.Execute(provisioner, operation) == response
    assert len(calls) == 1 and calls[0][0][:-1] == provisioner.command and calls[0][2] == 900
    assert calls[0][0][-1].startswith("sudo -n /usr/bin/python3 -c ")


@pytest.mark.parametrize("fault", ["role", "code", "encoding", "schema", "extra", "duplicate", "private-json", "oversize"])
def test_ReceiverRefusesTheWholeFrameBeforeLoadingAnyDependency(fault: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Program bytes are selected by complete installed hashes, never by a source bundle or caller-provided digest."""

    _, content = transport.Encode(Operation())
    value = rpc.Decode(content, limit=receiver.MAX_REQUEST_BYTES)

    if fault == "role":
        value["programs"]["installer"] = value["programs"].pop("guest")
    elif fault == "code":
        value["programs"]["guest"] = base64.b64encode(b"raise RuntimeError('private-marker')").decode()
    elif fault == "encoding":
        value["programs"]["guest"] = "private-marker"
    elif fault == "schema":
        value["schema_version"] = True
    elif fault == "extra":
        value["helper_pins"] = {}

    content = rpc.Json(value)

    if fault == "duplicate":
        content = b'{"programs":{},"programs":{}}'
    elif fault == "private-json":
        content = b'{"private-marker":'
    elif fault == "oversize":
        content = b"x" * (receiver.MAX_REQUEST_BYTES + 1)

    monkeypatch.setattr(receiver, "Modules", lambda *args: pytest.fail("Invalid frame must not load modules"))

    with pytest.raises(ValueError) as failure:
        receiver.Envelope(content)

    assert failure.value.__context__ is None and failure.value.__cause__ is None and "private-marker" not in str(failure.value)
