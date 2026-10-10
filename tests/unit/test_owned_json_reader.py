"""Bounded regular-file state and journal reads reject hostile path substitutions."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity
from flayer.core.state import MAX_JSON_BYTES, LoadState, StateError

IDENTITY = StackIdentity("example", "sandbox", "fake", "folder-test", "test-owner")
FIFO_SWAP_SCRIPT = '''"""Inject a post-validation FIFO swap under a parent-enforced deadline."""

import os
import sys
from pathlib import Path

import flayer.core.lifecycle as lifecycle
import flayer.core.state as state
from flayer.core.contracts import StackIdentity

identity = StackIdentity("example", "sandbox", "fake", "folder-test", "test-owner")
state_path = Path(sys.argv[1])
mode = sys.argv[2]
plan = lifecycle.DeploymentPlan(identity, ())

if mode == "state":
    state.SaveState(state_path, state.StackState(identity), identity)
    module = state
    target = state_path

else:
    lifecycle._WriteJournal(state_path, lifecycle._Journal(
        identity, plan.Fingerprint(), "create", (), operation_id="a" * 32,
    ))
    module = lifecycle
    target = lifecycle._JournalPath(state_path)

original_validator = module._ValidatePath


def SwapAfterValidation(path):
    """Substitute a FIFO only after the existing regular-file check succeeded."""

    original_validator(path)

    if path == target:
        path.unlink()
        os.mkfifo(path)


module._ValidatePath = SwapAfterValidation

try:
    if mode == "state":
        state.LoadState(state_path, identity)

    else:
        lifecycle._LoadJournal(state_path, plan)

except (state.StateError, lifecycle.LifecycleError):
    print("blocked")

else:
    raise AssertionError("A substituted FIFO must never be accepted")
'''


@pytest.mark.skipif(os.name != "posix", reason="FIFO substitution requires POSIX")
@pytest.mark.parametrize("mode", ["state", "journal"])
def test_PostValidationFifoSwapFailsWithoutBlocking(tmp_path: Path, mode: str) -> None:
    """The deadline prevents a regression from hanging the full test suite."""

    result = subprocess.run(
        [sys.executable, "-c", FIFO_SWAP_SCRIPT, str(tmp_path / "stack.json"), mode],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False, timeout=3,
    )

    assert result.returncode == 0, "The bounded JSON reader must reject a substituted FIFO"
    assert result.stdout.strip() == "blocked"


def test_OversizedRegularSnapshotIsRejectedBeforeDecoding(tmp_path: Path) -> None:
    """Local snapshot size cannot cause an unbounded JSON allocation."""

    path = tmp_path / "state.json"
    path.write_bytes(b" " * (MAX_JSON_BYTES + 1))

    with pytest.raises(StateError, match="bounded regular"):
        LoadState(path, IDENTITY)


def test_StreamGrowthBeyondStatSizeIsBounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrently growing regular file cannot bypass the bounded stream read."""

    import flayer.core.state as state

    path = tmp_path / "state.json"
    path.write_text("{}", encoding="utf-8")

    def GrowingStream(descriptor: int, mode: str) -> io.StringIO:
        """Return simulated post-stat growth after transferring descriptor ownership."""

        os.close(descriptor)

        return io.StringIO(" " * (MAX_JSON_BYTES + 1))

    monkeypatch.setattr(state, "_OpenTextStream", GrowingStream)

    with pytest.raises(StateError, match="bounded read limit"):
        LoadState(path, IDENTITY)


def test_OversizedSnapshotWritePreservesOriginal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A writer cannot produce a successful snapshot that its bounded reader cannot load."""

    import flayer.core.state as state

    path = tmp_path / "state.json"
    snapshot = state.StackState(IDENTITY)
    state.SaveState(path, snapshot, IDENTITY)
    original = path.read_bytes()
    monkeypatch.setattr(state, "MAX_JSON_BYTES", 1)

    with pytest.raises(StateError, match="bounded JSON storage"):
        state.SaveState(path, snapshot, IDENTITY)

    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))
