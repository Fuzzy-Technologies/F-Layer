"""Run the pinned standalone loader only against synthetic staged files and intercepted backend boundaries on POSIX CI."""

from __future__ import annotations

import copy
import io
import json
import os
import stat
from contextlib import contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_protocol_rpc import Frame, Input, Native, Operation

from flayer import _vpn_protocol_receiver as receiver
from flayer import _vpn_protocol_transport as transport
from flayer.profiles import _protocol_rpc as rpc

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Standalone guest helpers require POSIX; no WSL or local VPN is started")


def test_StandaloneBootstrapLoadsExactlyItsPinnedModulesAndNeverExecutesTheirMainGuards() -> None:
    """Compile the actual frozen source without subprocesses, privilege, host state access or a real RPC dispatch."""

    operation = Operation()
    bootstrap, content = transport.Encode(operation)
    namespace: dict[str, Any] = {"__name__": "protocol_receiver_test", "__package__": ""}
    exec(compile(bootstrap, "pinned-receiver.py", "exec"), namespace)
    observed, programs = namespace["Envelope"](content)
    modules = namespace["Modules"](programs)
    assert observed == operation and set(vars(modules)) == set(receiver.PROGRAM_FILES)
    assert modules.rpc.Request(modules, operation)["intent"] == operation["intent"]
    assert all(getattr(modules, name).__package__ == "" for name in programs)
    assert namespace["Fingerprint"](operation, programs) == receiver.Fingerprint(operation, programs)


@pytest.mark.parametrize("fault", ["scope", "owner", "body", "module", "nonroot"])
def test_ReceiverRefusesInvalidSemanticsOrPrivilegeBeforeCreatingAnyStagedFile(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """No malformed operation may even reach temporary program staging, let alone a native backend."""

    operation = Operation("native-apply")
    _, content = transport.Encode(operation)
    value = json.loads(content)

    if fault == "scope":
        value["operation"]["scope_confirm"] += "-foreign"
    elif fault == "owner":
        value["operation"]["intent"]["owner"] = "0" * 64
    elif fault == "body":
        value["operation"]["body"]["cloud_plan_sha256"] = "0" * 64
    elif fault == "module":
        value["programs"]["guest"] = "Zm9yZWlnbg=="

    monkeypatch.setattr(receiver, "os", SimpleNamespace(**{**vars(os), "geteuid": lambda: 1000 if fault == "nonroot" else 0}))
    monkeypatch.setattr(receiver, "tempfile", SimpleNamespace(TemporaryDirectory=lambda **kwargs: pytest.fail("Rejected request must not stage files")))

    with pytest.raises(ValueError):
        receiver.Receive(rpc.Json(value))


def test_ValidReceiverStagesOnlyPinnedProgramsWithPrivateModesAndReturnsARequestBoundResponse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The root observation is synthetic; every actual file stays inside pytest's temporary directory and native dispatch is intercepted."""

    operation = Operation()
    _, content = transport.Encode(operation)
    load = receiver.Modules
    stages = []

    @contextmanager
    def TemporaryDirectory(**kwargs: Any) -> Any:
        """Redirect the fixed remote staging contract to an isolated test directory without touching /var/tmp."""

        assert kwargs == {"prefix": "flayer-protocol-", "dir": "/var/tmp"}
        stage = tmp_path / "stage"
        stage.mkdir(mode=0o700)
        stages.append(stage)

        try:
            yield str(stage)

        finally:
            for path in stage.iterdir():
                path.unlink()

            stage.rmdir()

    def Modules(programs: dict[str, bytes]) -> SimpleNamespace:
        """Load real package helpers but intercept the sole mutation/observation dispatch boundary."""

        modules = load(programs)

        def Dispatch(selected: Any, requested: object) -> dict[str, str]:
            """Verify staged bytes, filenames and modes before returning only a real closed response model."""

            assert requested == operation and selected is modules
            stage = stages[0]
            assert stat.S_IMODE(stage.stat().st_mode) == 0o700
            assert {path.name for path in stage.iterdir()} == set(receiver.PROGRAM_FILES.values())

            for name, source in programs.items():
                path = Path(getattr(modules, name).__file__)
                assert path == stage / receiver.PROGRAM_FILES[name] and path.read_bytes() == source
                assert stat.S_IMODE(path.stat().st_mode) == 0o600

            return modules.rpc.Result(modules, modules.rpc.Request(modules, requested), Native(operation, "active"))

        modules.rpc.Dispatch = Dispatch

        return modules

    def Fstat(descriptor: int) -> SimpleNamespace:
        """Model root ownership only inside the receiver, retaining the real isolated file's actual mode."""

        return SimpleNamespace(st_uid=0, st_mode=os.fstat(descriptor).st_mode)

    monkeypatch.setattr(receiver, "Modules", Modules)
    monkeypatch.setattr(receiver, "os", SimpleNamespace(**{**vars(os), "geteuid": lambda: 0, "fstat": Fstat}))
    monkeypatch.setattr(receiver, "tempfile", SimpleNamespace(TemporaryDirectory=TemporaryDirectory))
    assert receiver.Receive(content) == Frame(operation, Native(operation, "active"))
    assert not stages[0].exists()


@pytest.mark.parametrize("phase", ["prepared", "applying", "applied", "rolling-back", "rolled-back"])
@pytest.mark.parametrize("fault", ["none", "advanced", "foreign", "partial"])
def test_InputReplyWitnessMustStillMatchItsExactLockedJournal(tmp_path: Path, phase: str, fault: str) -> None:
    """A concurrent advance between backend return and witness readback refuses without modifying either journal copy."""

    operation = Operation("input-status")
    result, record = Input(operation, phase)
    value = copy.deepcopy(record)
    locks = []

    if fault == "advanced":
        value["phase"] = "rolled-back" if phase != "rolled-back" else "applied"
    elif fault == "foreign":
        value["request"]["cloud_plan_sha256"] = "0" * 64

    canonical = tmp_path / "input.json"
    canonical.write_bytes(rpc.Json(value))

    if fault == "partial":
        (tmp_path / ".input.json.new").write_bytes(b'{"private-marker":')

    modules = transport._Codecs()

    def Decode(guest: Any, path: Path) -> dict[str, Any]:
        """Read only this test's fixed bounded journal names; no guest path or native command is consulted."""

        assert path.parent == tmp_path and path.name in {"input.json", ".input.json.new"}

        return rpc.Decode(path.read_bytes(), limit=32768)

    modules.authority = SimpleNamespace(**{**vars(modules.authority), "_Root": lambda guest: tmp_path, "_Decode": Decode,
                                          "_Locks": lambda guest, **kwargs: locks.append(kwargs) or nullcontext()})
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    backend = {key: item for key, item in result.items() if key != "fingerprints"}

    if fault == "none":
        assert rpc._InputWitness(modules, operation, backend) == result

    else:
        with pytest.raises(ValueError):
            rpc._InputWitness(modules, operation, backend)

    assert locks == [{"readOnly": True}] and {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before


@pytest.mark.parametrize("failure", [True, False])
def test_ReceiverMainSuppressesEveryPrivateFailureAndBoundsItsInput(monkeypatch: pytest.MonkeyPatch, failure: bool) -> None:
    """Remote diagnostic output is a fixed failure token; raw exception chains and stderr are never returned."""

    stdin = io.BytesIO(b"x" * (receiver.MAX_REQUEST_BYTES + 2))
    stdout = io.BytesIO()
    stderr = io.StringIO()

    def Receive(content: bytes) -> bytes:
        """Intercept the root receiver before any filesystem or native action."""

        assert len(content) == receiver.MAX_REQUEST_BYTES + 1

        if failure:
            raise ValueError("private-marker")

        return b'{"public":"response"}\n'

    monkeypatch.setattr(receiver, "sys", SimpleNamespace(stdin=SimpleNamespace(buffer=stdin), stdout=SimpleNamespace(buffer=stdout), stderr=stderr))
    monkeypatch.setattr(receiver, "Receive", Receive)
    assert receiver.Main() == (1 if failure else 0)
    assert stdout.getvalue() == (b'{"error":"protocol-operation-failed","schema_version":1}\n' if failure else b'{"public":"response"}\n')
    assert stderr.getvalue() == "" and stdin.read() == b"x"
