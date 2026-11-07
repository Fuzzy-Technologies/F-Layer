"""Exercise reserved input boot/live prefixes with private POSIX fixtures and an independent in-memory network model."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import pytest
from test_protocol_reservation import Active
from test_vpn_host_input import Native
from test_vpn_project_v2 import Snapshot
from test_wireguard_peer_lifecycle import Interrupted

from flayer import _vpn_host_input as host
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles import _host_input_guest as inputs
from flayer.profiles import _host_input_policy as policy
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers
from flayer.profiles.vpn import VpnListener

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private input journals require POSIX; no WSL or desktop network is started")


def Delta() -> host.InputTransition:
    """Retain the public frozen input for the same synthetic owner used by the independent WG fixture."""

    identity = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
    listeners = (VpnListener("amneziawg", "udp", 443, ("0.0.0.0/0",)), VpnListener("vless-reality", "tcp", 443, ("0.0.0.0/0",)),
                 VpnListener("wireguard", "udp", 51821, ("0.0.0.0/0",)))
    record = {"identity": _WireDict(identity), "listeners": [_WireDict(item) for item in listeners],
              "management_cidrs": ["198.51.100.0/24"], "operation_id": ""}
    original = host.InputPolicy(identity, "b" * 64, policy.Digest(policy.Boot(record)), ("198.51.100.0/24",), listeners)

    return host.InputTransition(original, listeners[-1], "disable", "e" * 32)


def Composite(transition: host.InputTransition) -> dict[str, Any]:
    """Bind a complete public host delta beside an immutable cloud-plan hash without calling a provider."""

    return {"schema_version": 1, "cloud_plan_sha256": "a" * 64, "input": transition.Record()}


@pytest.mark.parametrize("fault", ["extra", "version", "cloud", "owner", "creation", "operation", "plan"])
def test_InputRequestBindsEveryPublicDeltaBeforeAnyGuestAccess(fault: str) -> None:
    """A copied nonce, changed source or unrelated plan cannot authorize a script through an opaque hash alone."""

    transition = Delta()
    request = Composite(transition)
    intent = {"owner": policy.Owner(request["input"]["before"]), "creation_sha256": transition.before.creationSha256,
              "operation_id": transition.operationId, "plan_sha256": policy.Digest(policy.Json(request))}

    if fault == "extra":
        request["private_key"] = "suppressed-fixture"

    elif fault == "version":
        request["schema_version"] = True

    elif fault == "cloud":
        request["cloud_plan_sha256"] = []

    else:
        intent[{"owner": "owner", "creation": "creation_sha256", "operation": "operation_id", "plan": "plan_sha256"}[fault]] = "f" * (32 if fault == "operation" else 64)

    with pytest.raises(inputs.InputError):
        inputs.Request(policy, request, intent)


class InputModel:
    """Model input tables separately from the installed WG forwarding table, root and credentials."""

    def __init__(self, original: Any, transition: host.InputTransition) -> None:
        """Keep only the known public policy states; synthetic native JSON is independent of journal files."""

        self.original = original
        self.values = (transition.before, transition.After(), transition.Restored())
        self.current = 0
        self.mutations = 0
        self.failAfterLive = False
        self.unrelated = b"unrelated AWG/VLESS services, counters, credentials and forwarding state"

    def Native(self, index: int) -> bytes:
        """Retain expression differences so a wrong listener body cannot compare equal just through its marker."""

        data = Native(self.values[index])
        data["nftables"][-1]["rule"]["expr"] = [{"fixture_policy_sha256": policy.Digest(self.values[index].Table())}]

        return policy.Json(data)

    def Run(self, command: list[str], *, payload: bytes | None = None, **options: Any) -> tuple[int, bytes]:
        """Allow no real process, service, interface or network operation from the input backend."""

        if command[:-1] == ["unshare", "--net", "--", "nft", "-j", "-e", "-f"]:
            program = Path(command[-1]).read_bytes()
            index = next(index for index, value in enumerate(self.values) if value.Table() == program)

            return 0, self.Native(index)

        if command == ["nft", "-j", "list", "table", "inet", "flayer_bootstrap"]:
            return 0, self.Native(self.current)

        if command == ["nft", "-f", "-"]:
            import fcntl

            assert payload is not None and payload.startswith(b"delete table inet flayer_bootstrap\n")
            assert b"flush ruleset" not in payload and b"table ip" not in payload
            descriptors = options["passFds"]
            assert type(descriptors) is tuple and len(descriptors) == 2

            for path in (guest.LOCK.with_name("flayer-ingress.lock"), guest.LOCK):
                descriptor = os.open(path, os.O_RDONLY)

                try:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

                finally:
                    os.close(descriptor)

            self.current = next(index for index, value in enumerate(self.values) if b"delete table inet flayer_bootstrap\n" + value.Table() == payload)
            self.mutations += 1

            if self.failAfterLive:
                self.failAfterLive = False

                raise Interrupted

            return 0, b""

        return self.original(command, payload=payload, **options)


def Environment(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, InputModel, dict[str, Any], dict[str, Any]]:
    """Install only fixture WG files, expose a real reservation, and initialize the independent original input model."""

    model, _, intent = Active(tmpPath, monkeypatch)
    transition = Delta()
    request = Composite(transition)
    intent["plan_sha256"] = policy.Digest(policy.Json(request))
    assert policy.Owner(request["input"]["before"]) == intent["owner"]
    boot = tmpPath / "etc/nftables.conf"
    boot.parent.mkdir(mode=0o755)
    boot.write_bytes(transition.before._OriginalFile())
    boot.chmod(0o644)
    monkeypatch.setattr(inputs, "BOOT", boot)
    inputModel = InputModel(guest._Run, transition)
    monkeypatch.setattr(guest, "_Run", inputModel.Run)
    reserved = authority.Reserve(guest, peers, intent, allowMutation=True)
    authority.Expose(guest, peers, intent, reserved["reservation_sha256"], allowMutation=True)

    return model, inputModel, request, intent


def Prepare(request: dict[str, Any], intent: dict[str, Any]) -> dict[str, str]:
    """Call the real private preparation backend with explicit synthetic mutation consent."""

    return inputs.Prepare(guest, peers, authority, policy, request, intent, allowMutation=True)


def Apply(request: dict[str, Any], intent: dict[str, Any], *, rollback: bool = False) -> dict[str, str]:
    """Call the real private prefix reconciler without a controller/network shortcut."""

    return inputs.Apply(guest, peers, authority, policy, request, intent, allowMutation=True, rollback=rollback)


@POSIX
def test_ApplyRetryAndRollbackRetainSshOtherProtocolsAndAllPrivateWgRuntime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both terminal outcomes are exact and repeatable, and rollback cannot restore an old authority marker or fence."""

    model, network, request, intent = Environment(tmp_path, monkeypatch)
    before = Snapshot(model.root)
    history = peers._History(guest, intent["owner"])
    originalBoot = inputs.BOOT.read_bytes()
    prepared = Prepare(request, intent)
    assert prepared["phase"] == "prepared" and network.mutations == 0 and inputs.BOOT.read_bytes() == originalBoot
    assert Prepare(request, intent) == prepared
    result = Apply(request, intent)
    assert result["phase"] == "applied" and network.current == 1 and network.mutations == 1
    assert inputs.BOOT.read_bytes() == network.values[1].BootFile()
    assert Apply(request, intent) == result and network.mutations == 1
    snapshot = Snapshot(tmp_path)
    assert inputs.Status(guest, peers, authority, policy, request, intent) == result and Snapshot(tmp_path) == snapshot
    rolled = Apply(request, intent, rollback=True)
    assert rolled["phase"] == "rolled-back" and network.current == 2 and network.mutations == 2
    assert network.values[2].listeners == network.values[0].listeners and network.values[2].Marker != network.values[0].Marker
    assert inputs.BOOT.read_bytes() == network.values[2].BootFile() != originalBoot
    assert Apply(request, intent, rollback=True) == rolled and network.mutations == 2

    with pytest.raises(inputs.InputError):
        Apply(request, intent)

    with pytest.raises(authority.ReservationError):
        authority.Cancel(guest, peers, intent, allowMutation=True)

    assert Snapshot(model.root) == before and peers._History(guest, intent["owner"]) == history
    assert network.unrelated == b"unrelated AWG/VLESS services, counters, credentials and forwarding state"


@POSIX
@pytest.mark.parametrize("boundary", ["applying", "boot-temporary", "boot-rename", "live", "applied"])
@pytest.mark.parametrize("rollback", [False, True])
def test_InterruptedInputPrefixesRecoverWithoutRegeneratingMaterialOrReusingAuthority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, rollback: bool) -> None:
    """Process death at actual publication and native boundaries resumes only the exact known input operation."""

    model, network, request, intent = Environment(tmp_path, monkeypatch)
    Prepare(request, intent)
    before, history = Snapshot(model.root), peers._History(guest, intent["owner"])

    with monkeypatch.context() as patch:
        if boundary in {"applying", "applied"}:
            original = authority._Publish

            def Publish(helper: Any, filename: str, record: dict[str, Any], **options: Any) -> None:
                """Die after the requested complete durable journal phase."""

                original(helper, filename, record, **options)

                if filename == "input.json" and record["phase"] == boundary:
                    raise Interrupted

            patch.setattr(authority, "_Publish", Publish)

        elif boundary == "boot-temporary":
            def Finish(helper: Any, content: bytes | None) -> None:
                """Leave the complete new boot bytes visible in their exclusive publication slot."""

                if content is not None:
                    raise Interrupted

            patch.setattr(inputs, "_FinishBoot", Finish)

        elif boundary == "boot-rename":
            originalSync = guest._SyncDirectory

            def Sync(path: Path) -> None:
                """Die after rename but before the boot directory durability barrier."""

                if path == inputs.BOOT.parent:
                    raise Interrupted

                originalSync(path)

            patch.setattr(guest, "_SyncDirectory", Sync)

        else:
            network.failAfterLive = True

        with pytest.raises(Interrupted):
            Apply(request, intent)

    result = Apply(request, intent, rollback=rollback)
    target = 2 if rollback else 1
    assert result["phase"] == ("rolled-back" if rollback else "applied") and network.current == target
    assert inputs.BOOT.read_bytes() == network.values[target].BootFile()
    assert Apply(request, intent, rollback=rollback) == result
    assert not inputs.BOOT.with_name(".flayer-input.new").exists()
    assert Snapshot(model.root) == before and peers._History(guest, intent["owner"]) == history


@POSIX
@pytest.mark.parametrize("fault", ["boot-drift", "native-drift", "temporary", "partial-journal", "wrong-request", "foreign-nonce", "no-consent"])
def test_DriftUnknownPublicationAndCopiedIntentRefuseBeforeAnyInputWrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """No old-looking state, foreign data or caller consent substitution can silently widen the allowed prefixes."""

    _, network, request, intent = Environment(tmp_path, monkeypatch)
    Prepare(request, intent)

    if fault == "boot-drift":
        inputs.BOOT.write_bytes(b"foreign input policy\n")

    elif fault == "native-drift":
        network.current = 2

    elif fault == "temporary":
        temporary = inputs.BOOT.with_name(".flayer-input.new")
        temporary.write_bytes(network.values[1].BootFile())
        temporary.chmod(0o644)

    elif fault == "partial-journal":
        path = authority._Root(guest) / ".input.json.new"
        path.write_bytes(b'{"schema_version":')
        path.chmod(0o600)

    elif fault == "wrong-request":
        request = copy.deepcopy(request)
        request["cloud_plan_sha256"] = "f" * 64

    elif fault == "foreign-nonce":
        intent = {**intent, "operation_id": "f" * 32}

    before = Snapshot(tmp_path)

    with pytest.raises((ValueError, OSError)):
        inputs.Apply(guest, peers, authority, policy, request, intent, allowMutation=fault != "no-consent")

    assert Snapshot(tmp_path) == before and network.mutations == 0


@POSIX
def test_BootDirectoryIsResyncedBeforeLiveMutationAfterARecoveredVisibleRename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Recovery cannot commit based only on new boot bytes that were visible before an interrupted parent fsync."""

    _, network, request, intent = Environment(tmp_path, monkeypatch)
    Prepare(request, intent)
    original = guest._SyncDirectory

    def Sync(path: Path) -> None:
        """Fail every boot-parent barrier, including the retry's already-visible target file."""

        if path == inputs.BOOT.parent:
            raise OSError("Synthetic boot durability barrier failure")

        original(path)

    with monkeypatch.context() as patch:
        patch.setattr(guest, "_SyncDirectory", Sync)

        for _ in range(2):
            with pytest.raises(OSError):
                Apply(request, intent)

        assert network.mutations == 0

    assert Apply(request, intent)["phase"] == "applied" and network.mutations == 1


@POSIX
@pytest.mark.parametrize("filename", ["input.json", ".input.json.new"])
@pytest.mark.parametrize("action", ["status", "apply"])
@pytest.mark.parametrize("field", ["request-version", "delta-version", "policy-version", "listener-port"])
def test_JournalScalarAliasesCannotSubstituteDifferentReservationBoundRequestBytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, action: str, field: str,
) -> None:
    """Python boolean/integer/float equality is not proof that an on-disk public plan has its exact reserved hash."""

    _, network, request, intent = Environment(tmp_path, monkeypatch)
    Prepare(request, intent)
    root = authority._Root(guest)
    record = authority._Decode(guest, root / "input.json")

    if field == "request-version":
        record["request"]["schema_version"] = True

    elif field == "delta-version":
        record["request"]["input"]["schema_version"] = True

    elif field == "policy-version":
        record["request"]["input"]["before"]["schema_version"] = True

    else:
        listener = record["request"]["input"]["listener"]
        listener["port"] = float(listener["port"])

    path = root / filename
    path.write_bytes(policy.Json(record))
    path.chmod(0o600)
    before = Snapshot(tmp_path)

    with pytest.raises(inputs.InputError):
        if action == "status":
            inputs.Status(guest, peers, authority, policy, request, intent)

        else:
            Apply(request, intent)

    assert Snapshot(tmp_path) == before and network.mutations == 0
