"""Bind preparation/cache RPC to complete source evidence and admitted fixed snapshots without any real SSH or networking."""

from __future__ import annotations

import base64
import copy
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_protocol_generation import Composite
from test_protocol_preparation import Generation
from test_protocol_preparation_lifecycle import Root, Setup
from test_protocol_rpc import Frame, PreparationOperation
from test_protocol_runtime import NativeModel

from flayer import _vpn_protocol_receiver as receiver
from flayer import _vpn_protocol_transport as transport
from flayer.profiles import _protocol_preparation as preparation
from flayer.profiles import _protocol_rpc as rpc
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers
from flayer.profiles.vpn import VpnError

POSIX = pytest.mark.skipif(os.name != "posix", reason="Guest locks/helpers need POSIX; no WSL, desktop VPN or real native command is used")
_ACTIONS = ("preparation-status", "preparation-prepare", "cache-prepare")


def Result(operation: dict[str, Any], phase: str = "prepared") -> dict[str, Any]:
    """Reconstruct only complete public preparation or terminal cache facts from synthetic retained evidence."""

    modules = transport._Codecs()

    if operation["action"] != "cache-prepare":
        return preparation.Result(guest, modules.authority, modules.completion, operation["body"], Generation(operation["body"]))

    request = operation["body"]["request"]
    history = guest._ProtocolHistory(operation["intent"], request)
    record = {**modules.cache._Expected(guest, operation["intent"], request, history), "phase": phase}

    return {"status": "generation-cache", "phase": phase, "journal_sha256": guest._Digest(rpc.Json(record)), "history_sha256": history}


@pytest.mark.parametrize("action", _ACTIONS)
def test_OnePreparationRpcUsesOnlyTheExistingPinnedSshRunnerAndClosedPublicResult(action: str) -> None:
    """Full private server data stays on stdin; the command carries only the package bootstrap."""

    operation = PreparationOperation(action)
    result = Result(operation)
    calls = []

    def Run(command: tuple[str, ...], content: bytes, timeout: int) -> SimpleNamespace:
        calls.append((command, content, timeout))
        observed, programs = receiver.Envelope(content)
        assert observed == operation and set(programs) == set(receiver.PROGRAM_FILES) and len(programs) == 13

        if action == "preparation-prepare":
            config = base64.b64decode(operation["bundles"][0]["files"]["server.conf"])
            key = next(line.split(b" = ", 1)[1] for line in config.splitlines() if line.startswith(b"PrivateKey = "))
            assert key.decode() not in command[-1]

        return SimpleNamespace(returnCode=0, stdout=Frame(operation, result), stderr=b"private-marker")

    provisioner = SimpleNamespace(command=("ssh", "exact-host-pin", "operator@198.51.100.10"), runner=SimpleNamespace(Run=Run))
    assert transport.Execute(provisioner, operation) == result
    assert len(calls) == 1 and calls[0][0][:-1] == provisioner.command and calls[0][2] == 900


@pytest.mark.parametrize("fault", ["intent", "bundle", "extra-file", "source", "private-source", "scope", "identity", "helper", "role"])
def test_PreparationMetadataAndPrivateSourcesRefuseBeforePackingOrSsh(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A source can provide neither executable roles nor paths, and an unreserved action cannot smuggle a final intent."""

    operation = PreparationOperation("preparation-prepare")

    if fault == "intent":
        operation["intent"] = PreparationOperation("cache-prepare")["intent"]
    elif fault == "bundle":
        operation["bundles"] = []
    elif fault == "extra-file":
        operation["bundles"][0]["files"]["../../private"] = base64.b64encode(b"private-marker").decode()
    elif fault == "source":
        operation["body"]["source"]["pin"]["server_digest"] = "0" * 64
    elif fault == "private-source":
        operation["sources"] = [operation["body"]["source"]]
    elif fault == "scope":
        operation["scope_confirm"] += "-other"
    elif fault == "identity":
        operation["identity"]["owner_id"] += "-other"
    elif fault == "helper":
        operation["body"]["maintenance_sha256"] = "private-marker"
    else:
        operation["bundles"][0]["protocol"] = "amneziawg"

    monkeypatch.setattr(receiver, "Programs", lambda: pytest.fail("Refused source must not reach packaging"))

    with pytest.raises(VpnError) as failure:
        transport.Encode(operation)

    assert failure.value.__context__ is None and "private-marker" not in str(failure.value)


@pytest.mark.parametrize("fault", ["origin", "source", "helper", "generation", "path", "bundle", "missing"])
def test_RehashedCacheCompositeCannotRebindPreparationSelection(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A correct outer plan hash still needs the same complete source, original generation and callback contract."""

    operation = PreparationOperation("cache-prepare")
    body = operation["body"]

    if fault == "origin":
        body["preparation"]["origin"]["previous_state_sha256"] = "0" * 64
    elif fault == "source":
        body["preparation"]["source"]["pin"]["server_digest"] = "0" * 64
    elif fault == "helper":
        body["request"]["generation"]["candidate_receipt"]["files"]["lifecycle.py"] = "0" * 64
    elif fault == "generation":
        body["preparation"]["cached_receipt"] = copy.deepcopy(body["request"]["generation"]["cached_receipt"])
        body["preparation"]["cached_receipt"]["nonce"] = "9" * 32
    elif fault == "path":
        body["cached_path"] = "/outside"
    elif fault == "bundle":
        operation["bundles"] = PreparationOperation("preparation-prepare")["bundles"]
    else:
        del body["preparation"]

    operation["intent"]["plan_sha256"] = guest._Digest(rpc.Json(body["request"]))
    monkeypatch.setattr(receiver, "Programs", lambda: pytest.fail("Rebound selection must not reach packaging"))

    with pytest.raises(VpnError):
        transport.Encode(operation)


@pytest.mark.parametrize("action", _ACTIONS)
@pytest.mark.parametrize("fault", ["journal", "private", "schema", "package"])
def test_NewRpcRepliesCannotReturnForeignProofsPrivateFieldsOrAnotherPackage(action: str, fault: str) -> None:
    """The shared action/package fingerprint and new result codecs both remain necessary after authenticated transport."""

    operation = PreparationOperation(action)
    result = Result(operation)

    if fault == "journal":
        result["journal_sha256" if action == "cache-prepare" else "preparation_sha256"] = "0" * 64
    elif fault == "private":
        result["private_key"] = "private-marker"
    elif fault == "schema":
        result["schema_version"] = True

    frame = Frame(operation, result)

    if fault == "package":
        value = rpc.Decode(frame, limit=rpc.MAX_RESULT_BYTES)
        programs = receiver.Sources()
        programs["preparation"] += b"\n"
        value["request_sha256"] = receiver.Fingerprint(operation, programs)
        frame = rpc.Json(value)

    with pytest.raises(VpnError) as failure:
        transport.Decode(operation, frame, 0)

    assert failure.value.__context__ is None and "private-marker" not in str(failure.value)


def test_CacheMutationCannotReportItsPreparingPrefixAsACompleteResult() -> None:
    """Cache status may observe a prefix, but cache-prepare success requires the terminal prepared journal."""

    operation = PreparationOperation("cache-prepare")

    with pytest.raises(VpnError):
        transport.Decode(operation, Frame(operation, Result(operation, "preparing")), 0)


@pytest.mark.parametrize("fault", ["consent", "ambiguous", "not-callable"])
def test_TrustedResolverCannotBypassConsentOrCompeteWithLegacyExplicitSources(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """The internal dependency slot is separate from request data and remains closed before any lock or source callback."""

    operation = PreparationOperation("cache-prepare")
    modules = transport._Codecs()
    def Resolve() -> tuple[Path, Path]:
        pytest.fail("Unadmitted selection must not invoke its resolver")

    resolver: Any = Resolve
    cached = Path("/legacy-source") if fault == "ambiguous" else None

    if fault == "not-callable":
        resolver = "private-marker"

    monkeypatch.setattr(modules.authority, "_Locks", lambda *args, **kwargs: pytest.fail("Invalid consent or selection must not lock guest files"))

    with pytest.raises(ValueError):
        modules.cache.Prepare(guest, peers, modules.authority, modules.policy, operation["body"]["request"], operation["intent"], cached,
                               allowMutation=fault != "consent", sourceResolver=resolver, runtimeBackend=runtime)


@POSIX
@pytest.mark.parametrize("action", _ACTIONS)
def test_ActualThirteenStandaloneHelpersValidateNewOperationsWithoutFilesystemOrCommands(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    """Load the real installed helper set; no supplied installer or guest entrypoint guard executes."""

    modules = receiver.Modules(receiver.Sources())
    monkeypatch.setattr(modules.guest, "_Run", lambda *args, **kwargs: pytest.fail("Closed validation cannot run a native command"))
    monkeypatch.setattr(modules.authority, "_Root", lambda *args: pytest.fail("Closed validation cannot read guest files"))
    operation = PreparationOperation(action)
    assert modules.rpc.Request(modules, operation)["action"] == action
    assert modules.rpc.Result(modules, operation, Result(operation)) == Result(operation)


@POSIX
@pytest.mark.parametrize("kind", ["fresh", "disable"])
@pytest.mark.parametrize("fault", ["none", "missing-unprepared", "drifted-unprepared"])
def test_PreparationAndCacheRpcUseRealLockedBackendsAndRecoverAfterSnapshotLoss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, fault: str) -> None:
    """All native effects stay in the established independent model; common/WG locks and actual journals are real isolated files."""

    import fcntl

    model, selected, files = Setup(tmp_path, monkeypatch, kind)
    modules = transport._Codecs()
    modules.peer = peers
    operation = {**PreparationOperation("preparation-prepare"), "identity": selected["identity"], "body": selected,
                 "scope_confirm": selected["identity"]["scope_id"], "bundles": [{"protocol": "wireguard", "name": selected["identity"]["stack"] + "-wireguard",
                 "files": {name: base64.b64encode(content).decode() for name, content in files.items()}}]}
    prepared = rpc.Dispatch(modules, operation)
    status = {**operation, "action": "preparation-status", "allow_mutation": False, "scope_confirm": "", "bundles": []}
    assert rpc.Dispatch(modules, status) == prepared
    composite, _ = Composite("disable" if kind == "disable" else "enable", version=3)
    composite["generation"] = prepared["generation"]
    intent = {**selected["origin"], "plan_sha256": guest._Digest(rpc.Json(composite))}
    controller = NativeModel(model, composite, monkeypatch)
    groups = tmp_path / "rpc-cgroups"
    groups.mkdir(mode=0o755)
    (groups / "cgroup.controllers").write_bytes(b"cpu memory\n")
    monkeypatch.setattr(runtime, "CGROUPS", groups)
    monkeypatch.setattr(guest, "_Run", controller.Run)
    request = {**operation, "action": "cache-prepare", "intent": intent, "body": {"request": composite, "preparation": selected}, "bundles": []}
    original = preparation.Read
    calls = []

    def Read(*args: Any) -> Any:
        """A copied controller cannot enter source selection outside both already-held exclusive locks."""

        for path in (guest.LOCK, guest.LOCK.with_name("flayer-ingress.lock")):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)

            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)

            finally:
                os.close(descriptor)

        calls.append(True)

        return original(*args)

    monkeypatch.setattr(preparation, "Read", Read)

    with pytest.raises(ValueError):
        rpc.Dispatch(modules, request)

    assert not calls
    reserve = {**request, "action": "reserve", "body": None}
    reserved = rpc.Dispatch(modules, reserve)
    rpc.Dispatch(modules, {**reserve, "action": "expose", "expected_reservation_sha256": reserved["reservation_sha256"]})

    if fault != "none":
        if fault == "missing-unprepared":
            Root(selected).rename(tmp_path / "unavailable-unprepared")
        else:
            (Root(selected) / "source/foreign").write_bytes(b"preserve unknown source")

        with pytest.raises((ValueError, OSError)):
            rpc.Dispatch(modules, request)

        assert calls == [True]
        assert modules.authority.Status(guest, peers, intent)["phase"] == "exposed"
        assert not (modules.authority._Root(guest) / "generation.json").exists()

        return

    result = rpc.Dispatch(modules, request)
    assert result["phase"] == "prepared" and calls == [True]
    Root(selected).rename(tmp_path / "unavailable-preparation")
    monkeypatch.setattr(preparation, "Read", lambda *args: pytest.fail("Prepared cache recovery must not need its lost earlier snapshot"))
    assert rpc.Dispatch(modules, request) == result
