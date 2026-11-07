"""Exercise native generation transitions with real POSIX files/locks and entirely simulated PID1/network effects."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import test_protocol_generation_input as generationInputs
from test_protocol_generation_cache import Prepare
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Native generation fixtures need POSIX; every service/network command is intercepted")


class NativeModel:
    """Keep service queue/process state independent of root files, kernel state and the input-policy model."""

    def __init__(self, model: Any, request: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
        """Retain exact old/new names and intercept every native service operation without subprocesses."""

        self.model, self.request, self.monkeypatch = model, request, monkeypatch
        self.original = guest._Run
        old = request["generation"]["cached_receipt"]
        self.oldUnit = guest._Paths(model.owner, nonce=old["nonce"] if old["schema_version"] == 2 else "")[1]
        self.newUnit = guest._Paths(model.owner, nonce=request["generation"]["candidate_receipt"]["nonce"])[1]
        self.active = {self.oldUnit.name: model.active, self.newUnit.name: False}
        self.jobs: dict[str, str] = {}
        self.controls: dict[str, str] = {}
        self.mains: dict[str, str] = {}
        self.effects: list[tuple[str, str]] = []
        self.fault = ""
        self.fired = False
        self.resetPeers = False
        self.program = guest._Digest(Path(guest.__file__).read_bytes())

    def Point(self, name: str) -> None:
        """Model actual process death once at a named native boundary."""

        if self.fault == name and not self.fired:
            self.fired = True

            raise Interrupted

    def Handoff(self, options: dict[str, Any]) -> None:
        """The client retains only common authority; the systemd leaf can acquire the released WG lock."""

        import fcntl

        assert len(options["passFds"]) == 1 and not guest._callbackFds

        for path, busy in ((guest.LOCK.with_name("flayer-ingress.lock"), True), (guest.LOCK, False)):
            descriptor = os.open(path, os.O_RDONLY)

            try:
                if busy:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

                else:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(descriptor, fcntl.LOCK_UN)

            finally:
                os.close(descriptor)

    def Run(self, command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
        """Unknown commands remain confined to the original fixture model, which rejects any real process."""

        if command[0] == "systemctl":
            action, name = command[1], command[-1]
            unit = self.newUnit if name == self.newUnit.name else self.oldUnit

            if action == "show":
                values = {"Id": name, "LoadState": "loaded" if unit.exists() else "not-found", "ActiveState": "active" if self.active.get(name) else "inactive",
                          "SubState": "exited" if self.active.get(name) else "dead", "Job": self.jobs.get(name, ""), "MainPID": self.mains.get(name, "0"),
                          "ControlPID": self.controls.get(name, "0"), "ControlGroup": "", "FragmentPath": str(unit) if unit.exists() else "", "DropInPaths": ""}

                return 0, ("\n".join(key + "=" + value for key, value in values.items()) + "\n").encode()

            if action == "daemon-reload":
                self.Point("before-reload")
                self.effects.append((action, ""))

                return 0, b""

            if action in {"start", "stop"}:
                self.Handoff(options)
                self.Point("before-" + action)
                self.effects.append((action, name))

                if action == "stop":
                    assert not self.model.root.exists(), "Retired root must be disarmed before any WG unlock"
                    assert self.model.interface is None and not self.model.network
                    self.active[name] = False
                    self.model.active = False

                else:
                    assert unit == self.newUnit

                    with self.monkeypatch.context() as callback:
                        callback.setattr(guest, "__file__", str(self.model.root / "lifecycle.py"))
                        guest._GenerationCallback(self.model.root, unit, self.request["generation"]["candidate_receipt"]["nonce"], start=True)

                    self.active[name] = True
                    self.model.active = True

                self.Point("after-" + action)

                return 0, b""

            if action == "is-active":
                assert self.active.get(name), "Synthetic selected service must be active"

                return 0, b""

            if action == "is-enabled":
                assert (guest.SYSTEMD / "multi-user.target.wants" / name).is_symlink()

                return 0, b""

            raise AssertionError("Unrecognized native service command")

        if Path(command[0]).name == "wg" and command[1] == "show" and self.resetPeers:
            return 0, b"(none)\t(none)\t0\toff\n"

        if command[:2] == ["nft", "-f"] and command[-1] != "-":
            self.model.policy = Path(command[-1]).read_bytes()
            self.model.network = True

            return 0, b""

        if command[:3] == ["nft", "delete", "table"]:
            self.model.network = False

            return 0, b""

        return self.original(command, payload=payload, **options)


def Environment(
    tmpPath: Path, monkeypatch: pytest.MonkeyPatch, change: str = "disable", version: int = 3, helper: bytes | None = None,
) -> tuple[Any, Any, NativeModel, dict[str, Any], dict[str, Any]]:
    """Prepare exact generation3 caches and actual input files before admitting the new native backend."""

    model, network, request, intent, cached, candidate = generationInputs.Environment(tmpPath, monkeypatch, change, version, helper)
    controller = NativeModel(model, request, monkeypatch)
    groupRoot = tmpPath / "cgroup"
    groupRoot.mkdir(mode=0o755)
    (groupRoot / "cgroup.controllers").write_bytes(b"cpu memory\n")
    monkeypatch.setattr(runtime, "CGROUPS", groupRoot)
    monkeypatch.setattr(guest, "_Run", controller.Run)
    Prepare(request, intent, cached, candidate)
    inputs.Prepare(guest, peers, authority, policy, request, intent, allowMutation=True, generationCache=cache)

    if change == "disable":
        Input(request, intent)

    return model, network, controller, request, intent


def Input(request: dict[str, Any], intent: dict[str, Any], *, rollback: bool = False) -> dict[str, str]:
    """Change only the owned input policy through the real cache/runtime observation contract."""

    return inputs.Apply(guest, peers, authority, policy, request, intent, allowMutation=True, rollback=rollback,
                        generationCache=cache, runtimeBackend=runtime)


def Execute(controller: NativeModel, request: dict[str, Any], intent: dict[str, Any], *, rollback: bool = False) -> dict[str, str]:
    """Use the actual generation state machine and actual POSIX lock handoff with pinned receiver-source consent."""

    return runtime.Execute(guest, peers, authority, policy, inputs, cache, request, intent, allowMutation=True,
                           rollback=rollback, expectedProgramSha256=controller.program)


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_ExactNativeTransitionAndRetryPreserveKeysOtherTransportsAndSharedForwarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """A cache is not activation: assert independent kernel and service facts and exact key/configuration retention."""

    model, network, controller, request, intent = Environment(tmp_path, monkeypatch, change)
    old = request["generation"]["cached_receipt"]
    source = cache._CachePath(guest, old)
    credentials = {name: (source / name).read_bytes() for name in ("server.conf", "deployment.json", "install.py", "wg", "COPYING")}
    unrelated = model.unrelated, network.unrelated
    result = Execute(controller, request, intent)
    assert result["phase"] == ("active" if change == "enable" else "inactive")
    assert (model.unrelated, network.unrelated) == unrelated and model.forwarding
    assert not controller.oldUnit.exists()

    if change == "enable":
        assert model.interface is not None and model.network and controller.active[controller.newUnit.name]
        assert {name: (model.root / name).read_bytes() for name in credentials} == credentials
        assert Input(request, intent)["phase"] == "applied"
        assert result["history_sha256"] == runtime._FreshHistory(guest, request, intent)

    else:
        assert not model.root.exists() and model.interface is None and not model.network
        assert result["history_sha256"] == guest._ProtocolHistory(intent, request)

    effects = tuple(controller.effects)
    assert Execute(controller, request, intent) == result
    assert tuple(controller.effects) == effects
    before = Snapshot(tmp_path)
    assert runtime.Status(guest, peers, authority, policy, cache, request, intent)["phase"] == result["phase"]
    assert Snapshot(tmp_path) == before and tuple(controller.effects) == effects


@pytest.mark.parametrize("change", ["enable", "disable"])
def test_RollbackUsesFreshRestorationIdentityWithoutRestoringConsumedHistory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    """Original/candidate stop names are permanently retired; restoration retains every credential byte."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, change)
    Execute(controller, request, intent)

    if change == "enable":
        Input(request, intent, rollback=True)

    result = Execute(controller, request, intent, rollback=True)
    assert result["phase"] == ("rolled-back" if change == "enable" else "restored")
    assert result["history_sha256"] == runtime._FreshHistory(guest, request, intent) != intent["wireguard_history_sha256"]

    if change == "disable":
        assert controller.oldUnit != controller.newUnit and not controller.oldUnit.exists()
        assert controller.active[controller.newUnit.name] and model.root.exists()
        assert json.loads((model.root / "receipt.json").read_bytes()) == {**request["generation"]["candidate_receipt"], "status": "installed"}
        assert Input(request, intent, rollback=True)["phase"] == "rolled-back"

    else:
        assert not model.root.exists() and not controller.newUnit.exists()
        assert model.interface is None and not model.network

    assert Execute(controller, request, intent, rollback=True) == result


@pytest.mark.parametrize("boundary", ["before-stop", "after-stop", "before-reload"])
def test_StoppedOldGenerationRetriesEveryDispatchBoundaryWithoutReusingItsUnit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """Unknown stop submission is recoverable because the old root is disarmed and its unit identity is never restored."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch)
    controller.fault = boundary

    with pytest.raises(Interrupted):
        Execute(controller, request, intent)

    result = Execute(controller, request, intent)
    assert result["phase"] == "inactive" and not model.root.exists() and not controller.oldUnit.exists()
    assert Execute(controller, request, intent, rollback=True)["phase"] == "restored"
    assert controller.active[controller.newUnit.name] and not controller.oldUnit.exists()


@pytest.mark.parametrize("boundary", ["before-start", "after-start", "before-reload"])
def test_CandidateActivationResumesWithoutChangingItsPlannedKeysOrNonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str,
) -> None:
    """The fully planned fresh candidate remains recoverable after metadata publication, reload or native job death."""

    model, _, controller, request, intent = Environment(tmp_path, monkeypatch, "enable")
    controller.fault = boundary

    with pytest.raises(Interrupted):
        Execute(controller, request, intent)

    assert Execute(controller, request, intent)["phase"] == "active"
    assert json.loads((model.root / "receipt.json").read_bytes())["nonce"] == intent["operation_id"]
    assert controller.active[controller.newUnit.name]
