"""Validate the shared plain guest policy contract without filesystem or network access."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest
from test_host_input_transaction import Delta

from flayer.profiles import _host_input_policy as policy


@pytest.mark.parametrize("fault", ["version", "extra", "owner", "scope", "hash", "nonce", "listeners", "duplicate", "port", "ssh", "dhcp", "source", "overlap", "original"])
def test_GuestPolicyRefusesMalformedOwnershipAndListenerSemanticsBeforeRendering(fault: str) -> None:
    """The stdlib boundary accepts no unknown field, broad ambiguous source or protected listener substitution."""

    record = Delta().Record()["before"]

    if fault == "version":
        record["schema_version"] = True

    elif fault == "extra":
        record["private_key"] = "suppressed-fixture"

    elif fault == "owner":
        record["identity"]["owner_id"] = "../unknown"

    elif fault == "scope":
        record["identity"]["scope_id"] = "bad scope"

    elif fault == "hash":
        record["creation_sha256"] = []

    elif fault == "nonce":
        record["operation_id"] = "../unknown"

    elif fault == "listeners":
        record["listeners"] = tuple(record["listeners"])

    elif fault == "duplicate":
        record["listeners"].append(copy.deepcopy(record["listeners"][0]))

    elif fault in {"port", "ssh", "dhcp"}:
        listener = record["listeners"][1 if fault == "ssh" else 0]
        listener["port"] = True if fault == "port" else 22 if fault == "ssh" else 68

    elif fault == "source":
        record["management_cidrs"] = ["198.51.100.1/24"]

    elif fault == "overlap":
        record["listeners"][0]["source_cidrs"] = ["0.0.0.0/0", "198.51.100.0/24"]

    else:
        record["original_boot_sha256"] = "f" * 64

    with pytest.raises(policy.PolicyError):
        policy.Policy(record)


def test_PublicTypedAndStdlibPoliciesHaveIdenticalBytesAndIndependentReturnedContainers() -> None:
    """Packing the stdlib helper neither regenerates private material nor changes any historical boot/hash convention."""

    transition = Delta()
    before, after, restored = policy.Transition(transition.Record())

    for raw, typed in zip((before, after, restored), (transition.before, transition.After(), transition.Restored()), strict=True):
        assert policy.Table(raw) == typed.Table() and policy.Marker(raw) == typed.Marker
        assert policy.Boot(raw) == (typed.BootFile() if typed.operationId else typed._OriginalFile())

    copied = policy.Policy(before)
    copied["listeners"][0]["source_cidrs"].clear()
    assert before["listeners"][0]["source_cidrs"] == ["0.0.0.0/0"]


@pytest.mark.parametrize("fault", ["unknown", "version", "change", "nonce", "same", "wrong-listener", "already-active"])
def test_SharedTransitionRejectsAmbiguousOrRepeatedListenerChanges(fault: str) -> None:
    """Direct guest decoding enforces the same one-listener generation boundary as the typed facade."""

    record: dict[str, Any] = Delta().Record()

    if fault == "unknown":
        record["extra"] = 1

    elif fault == "version":
        record["schema_version"] = True

    elif fault == "change":
        record["change"] = "replace-all"

    elif fault == "nonce":
        record["operation_id"] = "short"

    elif fault == "same":
        record["before"]["operation_id"] = record["operation_id"]

    elif fault == "wrong-listener":
        record["listener"]["port"] = 51822

    else:
        record["change"] = "enable"

    with pytest.raises(policy.PolicyError):
        policy.Transition(record)


def test_GuestRunPassesOnlyExplicitCoordinationDescriptorsToTheNativeChild(monkeypatch: pytest.MonkeyPatch) -> None:
    """A native writer retains both locks if its SSH parent dies; ordinary commands inherit none by default."""

    from types import SimpleNamespace

    from flayer.profiles import _wireguard_guest as guest

    calls = []

    def Run(command: list[str], **options: Any) -> Any:
        """Observe subprocess admission without executing any desktop command."""

        calls.append(options)

        return SimpleNamespace(stdout=b"", returncode=0)

    monkeypatch.setattr(guest.subprocess, "run", Run)
    guest._Run(["nft", "-f", "-"], payload=b"public fixture", passFds=(10, 11))
    guest._Run(["nft", "-j", "list", "tables"])
    assert calls[0]["pass_fds"] == (10, 11) and calls[1]["pass_fds"] == ()


@pytest.mark.skipif(os.name != "posix", reason="Private compiler scratch files require POSIX; no WSL is started")
@pytest.mark.parametrize("failure", [False, True])
def test_ExpectedInputCompilationUsesCompleteTemporaryFilesAndCleansScratchOnFailure(tmp_path: Path, failure: bool) -> None:
    """The JSON-first native parser may consume stdin; compile the same fixed file form used by existing WG validation."""

    import stat
    from types import SimpleNamespace

    from test_vpn_host_input import Native

    from flayer.profiles import _host_input_guest as inputs

    transition = Delta()
    typed = (transition.before, transition.After(), transition.Restored())
    values = policy.Transition(transition.Record())
    commands = []

    def Run(command: list[str]) -> tuple[int, bytes]:
        """Read complete public source bytes from their private scratch location without starting a real process."""

        path = Path(command[-1])
        assert command[:-1] == ["unshare", "--net", "--", "nft", "-j", "-e", "-f"]
        assert path.parent.parent == tmp_path and stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
        index = len(commands)
        assert path.read_bytes() == typed[index].Table()
        commands.append(command)

        if failure:
            raise ValueError("Synthetic compile failure")

        return 0, policy.Json(Native(typed[index]))

    helper = SimpleNamespace(LOCK=tmp_path / "operation.lock", _Directory=lambda path: None, _Run=Run)

    if failure:
        with pytest.raises(ValueError, match="Synthetic compile failure"):
            inputs._Compiled(helper, policy, values)

    else:
        assert len(inputs._Compiled(helper, policy, values)) == 3 and len(commands) == 3

    assert list(tmp_path.iterdir()) == []
