"""Exercise selected SSH envelopes without private files, guest execution or local networking."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_vpn_guest import FakeRunner
from test_wireguard_guest import Prepared

from flayer import _vpn_guest as receiver
from flayer.guest import GuestResult, SshGuestProvisioner
from flayer.profiles.vpn import VpnError


def Provisioner(result: dict[str, object]) -> tuple[SshGuestProvisioner, FakeRunner]:
    """Bypass only constructor filesystem validation; exercise the actual envelope/response implementation."""

    runner = FakeRunner(GuestResult(0, json.dumps(result).encode()))
    guest = object.__new__(SshGuestProvisioner)
    guest.command = ("ssh", "fixture-only")
    guest.runner = runner

    return guest, runner


@pytest.mark.parametrize("status", ["active", "recovery-required", "absent"])
def test_StatusAcceptsOnlyBoundedWireGuardFactsAndSendsPrivateBytesOnStdin(status: str) -> None:
    """Keep runtime receipt and absence proof distinct and exclude all private payloads from command arguments."""

    facts: dict[str, object] = {"status": status, "receipt_sha256": "a" * 64,
                                "tools_version": "1.0.20260223", "kernel_policy": "cached-named-cve-baseline"}

    if status == "active":
        facts.update(binary_sha256="b" * 64, kernel_release="6.8.0-999-generic", kernel_package_version="6.8.0-999.999",
                     kernel_cve="CVE-2026-98432", kernel_fixed_version="6.8.0-999.999")

    elif status == "absent":
        facts.update(receipt_sha256="", absence_sha256="c" * 64, kernel_policy="not-assessed", cleanup_required=True)

    guest, runner = Provisioner(facts)
    bundle = Prepared().serverBundle

    assert guest.WireGuardOperation(bundle, "status") == facts
    command, content, _ = runner.calls[0]

    assert next(item.content for item in bundle.files if item.name == "server.conf").decode() not in repr(command)
    assert json.loads(content)["wireguard"] == {"action": "status", "expected_receipt_sha256": "", "expected_absence_sha256": ""}

    facts["unexpected_private_field"] = "suppressed-private-fixture"
    runner.result = GuestResult(0, json.dumps(facts).encode())

    with pytest.raises(VpnError) as error:
        guest.WireGuardOperation(bundle, "status")

    assert "suppressed-private-fixture" not in str(error.value)


@pytest.mark.parametrize("options", [
    {}, {"allowMutation": True}, {"allowMutation": True, "scopeConfirm": "foreign"},
    {"allowMutation": True, "scopeConfirm": "example-folder", "expectedReceipt": "invalid"},
    {"allowMutation": True, "scopeConfirm": "example-folder", "expectedReceipt": "a" * 64, "expectedAbsence": "b" * 64},
])
def test_RecoveryRequiresExplicitScopeAndExactlyOneCurrentProofBeforeSsh(options: dict[str, Any]) -> None:
    """Even possession of server material does not authorize an ambiguous guest transition."""

    guest, runner = Provisioner({})

    with pytest.raises(VpnError):
        guest.WireGuardOperation(Prepared().serverBundle, "recover", **options)

    assert not runner.calls


@pytest.mark.parametrize("proof", ["expectedReceipt", "expectedAbsence"])
def test_RecoveryPreservesItsExactCurrentReceiptOrAbsencePrecondition(proof: str) -> None:
    """A successful mutation response reports operation completion without inventing an absent or healthy service."""

    guest, runner = Provisioner({"action": "recover", "status": "complete"})

    assert guest.WireGuardOperation(Prepared().serverBundle, "recover", allowMutation=True, scopeConfirm="example-folder",
                                    **{proof: "a" * 64}) == {"action": "recover", "status": "complete"}
    assert "a" * 64 in runner.calls[0][1].decode()


def test_ThirdTransportInstallUsesConsentWhileCheckRemainsReadOnly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate the root receiver's actual command vectors, with no subprocess or privilege operation executed."""

    calls: list[list[str]] = []
    bundle = Prepared().serverBundle
    guest, runner = Provisioner({})
    runner.result = GuestResult(0, b"FLAYER_GUEST_INSTALL_OK")
    guest.Install((("wireguard", bundle),), expectedWireGuardHistory="a" * 64)
    request = json.loads(runner.calls[0][1])
    request = json.dumps({"bundles": request["bundles"]}).encode()
    stage = tmp_path / "stage"
    stage.mkdir()
    monkeypatch.setattr(receiver.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(receiver.tempfile, "mkdtemp", lambda **options: str(stage))

    def Run(command: list[str], **options: Any) -> subprocess.CompletedProcess[bytes]:
        """Observe only; never execute the staged installer."""

        calls.append(command)

        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(receiver.subprocess, "run", Run)
    receiver.Install(receiver.DecodeRequest(request), expectedWireGuardHistory="a" * 64)

    assert "--allow-mutation" in calls[0] and "--install" in calls[0] and "--check-install" in calls[1]
    assert "--allow-mutation" not in calls[1] and not stage.exists()
