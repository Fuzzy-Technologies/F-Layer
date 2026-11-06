"""Exercise peer SSH envelopes and root receiver command vectors without network or guest execution."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import MagicMock

import pytest
from test_selected_guest_contract import Provisioner
from test_wireguard_guest import Prepared

from flayer import _vpn_guest as receiver
from flayer.guest import GuestResult
from flayer.profiles._wireguard_peer import Programs
from flayer.profiles.artifacts import Artifact, ArtifactBundle
from flayer.profiles.vpn import VpnError


def Facts(bundle: ArtifactBundle, *, desired: bool = False, pending: bool = False) -> dict[str, object]:
    """Build only nonsecret status facts bound to the actual synthetic descriptor bytes."""

    digest = hashlib.sha256(next(item.content for item in bundle.files if item.name == "deployment.json")).hexdigest()

    return {"status": "peer-recovery-required" if pending else "active", "receipt_sha256": "a" * 64,
            "previous_receipt_sha256": ("b" if desired else "a") * 64 if pending else "", "deployment_sha256": digest if desired else "c" * 64,
            "history_sha256": "d" * 64, "previous_history_sha256": "d" * 64 if pending else "",
            "desired_deployment_sha256": digest, "is_desired": desired, "action": "enroll", "device_id": "new-phone",
            "tools_version": "1.0.20260223", "kernel_policy": "cached-named-cve-baseline"}


def Options(action: str = "apply") -> dict[str, Any]:
    """Keep current receipt, original receipt and original history as distinct exact operation guards."""

    return {"allowMutation": True, "scopeConfirm": "example-folder", "expectedReceipt": "a" * 64,
            "expectedPrevious": "b" * 64 if action == "recover" else "", "expectedHistory": "d" * 64}


@pytest.mark.parametrize("desired,pending", [(False, False), (True, False), (False, True), (True, True)])
def test_PeerStatusBindsIntentAndReportsExactCurrentAndOriginalProofs(desired: bool, pending: bool) -> None:
    """Private files travel only on stdin; packed maintenance bytes do not replace the installed program pin."""

    bundle = Prepared().serverBundle
    facts = Facts(bundle, desired=desired, pending=pending)
    guest, runner = Provisioner(facts)

    assert guest.WireGuardPeerOperation(bundle, "status", "enroll", "new-phone") == facts
    command, content, timeout = runner.calls[0]
    request = json.loads(content)
    packed = {name: base64.b64decode(value) for name, value in request["bundles"][0]["files"].items()}
    driver, helper = Programs()

    assert set(packed) == {"install.py", "maintenance.py", "server.conf", "deployment.json"}
    assert packed["install.py"] == driver and packed["maintenance.py"] == helper
    assert request["wireguard_peer"]["allow_mutation"] is False
    assert packed["deployment.json"] == next(item.content for item in bundle.files if item.name == "deployment.json")
    assert json.loads(packed["deployment.json"])["program_sha256"] != hashlib.sha256(driver).hexdigest()
    assert packed["server.conf"].decode() not in repr(command) and base64.b64encode(packed["server.conf"]).decode() not in repr(command)
    assert timeout == 420 and command[-1].startswith("sudo -n /usr/bin/python3 -c ")


@pytest.mark.parametrize("action,outcome", [("apply", "committed"), ("recover", "committed"), ("recover", "not-applied")])
def test_PeerMutationPreservesAllPreconditionsAndAcceptsOnlyItsBoundedOutcome(action: str, outcome: str) -> None:
    """A completion acknowledgment remains distinct from a following healthy-service observation."""

    facts = {"status": "complete", "outcome": outcome}
    guest, runner = Provisioner(facts)

    assert guest.WireGuardPeerOperation(Prepared().serverBundle, action, "revoke", "old-phone", **Options(action)) == facts
    options = json.loads(runner.calls[0][1])["wireguard_peer"]

    assert options["expected_receipt_sha256"] == "a" * 64 and options["expected_history_sha256"] == "d" * 64
    assert options["expected_previous_receipt_sha256"] == ("b" * 64 if action == "recover" else "")


@pytest.mark.parametrize("action,override", [
    ("status", {"allowMutation": True}), ("status", {"expectedHistory": "a" * 64}), ("status", {"scopeConfirm": "example-folder"}),
    ("apply", {"allowMutation": False}), ("apply", {"allowMutation": 1}), ("apply", {"scopeConfirm": "foreign"}),
    ("apply", {"expectedReceipt": ""}), ("apply", {"expectedHistory": ""}), ("apply", {"expectedHistory": "A" * 64}),
    ("apply", {"expectedPrevious": "b" * 64}), ("recover", {"expectedPrevious": ""}), ("recover", {"expectedHistory": None}),
])
def test_IncompleteOrAmbiguousPeerConsentFailsBeforeSsh(action: str, override: dict[str, Any]) -> None:
    """A caller must explicitly bind both scope and the ABA-resistant history of the operation."""

    guest, runner = Provisioner({})
    options = {} if action == "status" else Options(action)
    options.update(override)

    with pytest.raises(VpnError):
        guest.WireGuardPeerOperation(Prepared().serverBundle, action, "enroll", "new-phone", **options)

    assert not runner.calls


@pytest.mark.parametrize("action,change,deviceId", [("upgrade", "enroll", "phone"), ("status", "rotate", "phone"), ("status", "enroll", "phone;id"), ("status", "revoke", ""), ("status", "enroll", 42)])
def test_InvalidPeerTargetFailsBeforeSsh(action: str, change: str, deviceId: Any) -> None:
    """Do not interpolate unbounded identifiers or invent unsupported peer operations."""

    guest, runner = Provisioner({})

    with pytest.raises(VpnError):
        guest.WireGuardPeerOperation(Prepared().serverBundle, action, change, deviceId)

    assert not runner.calls


@pytest.mark.parametrize("case", ["owner", "name", "kind", "public", "config", "program", "descriptor", "duplicate"])
@pytest.mark.parametrize("peer", [True, False])
def test_PeerAndServiceOperationsRejectForeignRoleOrUnboundDescriptorBeforeSsh(case: str, peer: bool) -> None:
    """A correct-looking filename suffix cannot authorize another stack's installed owner."""

    guest, runner = Provisioner({})
    bundle = Prepared().serverBundle

    if case == "owner":
        bundle = replace(bundle, identity=replace(bundle.identity, ownerId="another-owner"))

    elif case == "name":
        bundle = replace(bundle, name="foreign-wireguard")

    elif case == "kind":
        bundle = replace(bundle, kind="device")

    elif case == "public":
        bundle = replace(bundle, files=tuple(replace(item, sensitive=False) if item.name == "server.conf" else item for item in bundle.files))

    else:
        name = {"config": "server.conf", "program": "install.py"}.get(case, "deployment.json")
        content = b"suppressed-private-fixture"

        if case == "duplicate":
            original = next(item.content for item in bundle.files if item.name == name)
            content = original.replace(b'{', b'{"owner":"foreign",', 1)

        bundle = replace(bundle, files=tuple(Artifact(name, content) if item.name == name else item for item in bundle.files))

    with pytest.raises(VpnError) as error:
        guest.WireGuardPeerOperation(bundle, "status", "enroll", "new-phone") if peer else guest.WireGuardOperation(bundle, "status")

    assert not runner.calls and "suppressed-private-fixture" not in str(error.value)


@pytest.mark.parametrize("field,value", [
    ("status", "absent"), ("is_desired", 0), ("is_desired", True), ("action", "revoke"), ("device_id", "other"),
    ("tools_version", "latest"), ("kernel_policy", "approved"), ("history_sha256", ""), ("receipt_sha256", "A" * 64),
    ("previous_receipt_sha256", "e" * 64), ("previous_history_sha256", "f" * 64), ("desired_deployment_sha256", "f" * 64),
    ("status", "peer-recovery-required"), ("private_extra", "suppressed-private-fixture"),
])
def test_PeerStatusRejectsMalformedOrUnrelatedFactsWithoutEcho(field: str, value: object) -> None:
    """Permit only the exact requested target, descriptor hash and consistent boolean/proof relationships."""

    bundle = Prepared().serverBundle
    facts = Facts(bundle)
    facts[field] = value
    guest, _ = Provisioner(facts)

    with pytest.raises(VpnError) as error:
        guest.WireGuardPeerOperation(bundle, "status", "enroll", "new-phone")

    assert "suppressed-private-fixture" not in str(error.value)


@pytest.mark.parametrize("response", [GuestResult(1, b"suppressed-private-fixture"), GuestResult(0, b"x" * 4097), GuestResult(0, b"[]"),
                                      GuestResult(0, b'{"status":"complete","outcome":"committed","outcome":"not-applied"}')])
def test_ArbitraryOrDuplicateRemoteOutputIsSuppressed(response: GuestResult) -> None:
    """A successful process exit cannot turn arbitrary stdout into a trusted acknowledgment."""

    guest, runner = Provisioner({})
    runner.result = response

    with pytest.raises(VpnError) as error:
        guest.WireGuardPeerOperation(Prepared().serverBundle, "apply", "enroll", "new-phone", **Options())

    assert "suppressed-private-fixture" not in str(error.value)


@pytest.mark.parametrize("desired,field,value", [(False, "previous_receipt_sha256", "b" * 64),
                                                  (False, "previous_history_sha256", "e" * 64),
                                                  (True, "previous_receipt_sha256", "a" * 64)])
def test_PendingStatusRejectsImpossiblePublicationAndHistoryPhases(desired: bool, field: str, value: str) -> None:
    """An old root retains its original proofs; a published sole-peer delta necessarily changes the receipt."""

    bundle = Prepared().serverBundle
    facts = Facts(bundle, desired=desired, pending=True)
    facts[field] = value
    guest, _ = Provisioner(facts)

    with pytest.raises(VpnError):
        guest.WireGuardPeerOperation(bundle, "status", "enroll", "new-phone")


def Request(action: str) -> bytes:
    """Obtain the actual controller envelope through a fake SSH boundary."""

    bundle = Prepared().serverBundle
    facts = Facts(bundle) if action == "status" else {"status": "complete", "outcome": "committed"}

    if action == "history-status":
        owner = json.loads(next(item.content for item in bundle.files if item.name == "deployment.json"))["owner"]
        facts = {"status": "peer-history", "owner": owner, "history_sha256": "a" * 64, "tools_version": "1.0.20260223"}

    guest, runner = Provisioner(facts)
    guest.WireGuardPeerOperation(bundle, action, "enroll", "new-phone", **({} if action in {"status", "history-status"} else Options(action)))

    return runner.calls[0][1]


@pytest.mark.parametrize("action", ["status", "history-status", "apply", "recover"])
def test_RootReceiverExecutesOnlyExactPeerFlagsAndCleansItsPrivateStage(action: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use a fully in-memory stage boundary and never launch the driver, SSH or any network command."""

    events: list[object] = []
    response = b'{"status":"complete","outcome":"committed"}'

    @contextmanager
    def Stage(contents: dict[str, bytes]) -> Iterator[Path]:
        """Inspect the exact four payload files and model unconditional private-stage cleanup."""

        assert set(contents) == {"install.py", "maintenance.py", "server.conf", "deployment.json"}
        events.append("stage")

        try:
            yield Path("/fixture-private-stage")

        finally:
            events.append("cleanup")

    def Run(command: list[str], **options: Any) -> subprocess.CompletedProcess[bytes]:
        """Inspect an argument vector without spawning a subprocess."""

        assert options["stdin"] == subprocess.DEVNULL and options["capture_output"] is True and options["timeout"] == 300
        events.append(command)

        return subprocess.CompletedProcess(command, 0, response, b"suppressed-private-fixture")

    monkeypatch.setattr(receiver.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(receiver, "_Staged", Stage)
    monkeypatch.setattr(receiver.subprocess, "run", Run)

    assert receiver.WireGuardPeer(Request(action)) == response
    command = events[1]

    assert isinstance(command, list) and command[2:7] == ["--" + action, "--change", "enroll", "--device-id", "new-phone"]
    assert ("--allow-mutation" in command) == (action not in {"status", "history-status"})
    assert ("--expected-previous-receipt-sha256" in command) == (action == "recover")
    assert events[0] == "stage" and events[-1] == "cleanup"


@pytest.mark.parametrize("case", ["consent", "history", "receipt", "previous", "device", "extra", "missing-helper", "mixed", "no-root", "duplicate"])
def test_RootReceiverRefusesBadPeerRequestsBeforeStaging(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """The privileged boundary independently checks all mutation flags and its exact payload shape."""

    data = json.loads(Request("apply"))

    if case in {"consent", "history", "receipt", "previous", "device", "extra"}:
        key, value = {"consent": ("allow_mutation", False), "history": ("expected_history_sha256", ""),
                      "receipt": ("expected_receipt_sha256", ""), "previous": ("expected_previous_receipt_sha256", "a" * 64),
                      "device": ("device_id", "x;id"), "extra": ("unknown", "value")}[case]
        data["wireguard_peer"][key] = value

    elif case == "missing-helper":
        del data["bundles"][0]["files"]["maintenance.py"]

    elif case == "mixed":
        data["wireguard"] = {}

    stage = MagicMock(side_effect=AssertionError("Rejected request reached private staging"))
    monkeypatch.setattr(receiver.os, "geteuid", lambda: 1000 if case == "no-root" else 0, raising=False)
    monkeypatch.setattr(receiver, "_Staged", stage)
    content = json.dumps(data).encode()

    if case == "duplicate":
        content = content.replace(b'"allow_mutation": true', b'"allow_mutation": false, "allow_mutation": true')

    with pytest.raises(ValueError):
        receiver.WireGuardPeer(content)

    stage.assert_not_called()


def test_MainDispatchesPeerEnvelopeAndSuppressesPrivateFailure(monkeypatch: pytest.MonkeyPatch) -> None:
    """The standalone receiver recognizes the distinct peer envelope before ordinary installation."""

    incoming = MagicMock(buffer=io.BytesIO(Request("status")))
    outgoing = MagicMock(buffer=io.BytesIO())
    operation = MagicMock(return_value=b'{"status":"active"}')
    monkeypatch.setattr(receiver.sys, "stdin", incoming)
    monkeypatch.setattr(receiver.sys, "stdout", outgoing)
    monkeypatch.setattr(receiver, "WireGuardPeer", operation)

    assert receiver.Main() == 0 and outgoing.buffer.getvalue() == b'{"status":"active"}'
    operation.assert_called_once()


@pytest.mark.parametrize("failure", [subprocess.TimeoutExpired("fixture", 300), OSError("suppressed-private-fixture"), ValueError("suppressed-private-fixture")])
def test_RootReceiverCleansOnPrivateFailureAndReturnsOnlyAllowlistedLabels(failure: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
    """No failed subprocess or staging diagnostic may become a public connection error."""

    @contextmanager
    def Stage(contents: dict[str, bytes]) -> Iterator[Path]:
        """Model a private staging failure without filesystem or subprocess effects."""

        raise failure

        yield Path("unreachable")

    monkeypatch.setattr(receiver.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(receiver, "_Staged", Stage)

    with pytest.raises(receiver.GuestInstallError) as error:
        receiver.WireGuardPeer(Request("apply"))

    assert error.value.transport == "wireguard" and error.value.phase == "peer"
    assert "suppressed-private-fixture" not in str(error.value)


@pytest.mark.parametrize("field,value", [("owner", "f" * 64), ("history_sha256", "bad"), ("private_extra", "suppressed-private-fixture")])
def test_HistoryOnlySshResultRejectsForeignOwnerOrUnboundedFacts(field: str, value: str) -> None:
    """A metadata-only initial-install guard still binds exact owner and accepts no private or extra output."""

    bundle = Prepared().serverBundle
    owner = json.loads(next(item.content for item in bundle.files if item.name == "deployment.json"))["owner"]
    facts = {"status": "peer-history", "owner": owner, "history_sha256": "a" * 64, "tools_version": "1.0.20260223"}
    facts[field] = value
    guest, _ = Provisioner(facts)

    with pytest.raises(VpnError) as error:
        guest.WireGuardPeerOperation(bundle, "history-status", "enroll", "new-phone")

    assert "suppressed-private-fixture" not in str(error.value)
