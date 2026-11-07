"""Verify exact generation templates and descriptor inheritance without running a desktop command."""

from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from test_wireguard_guest import Prepared

from flayer.profiles import _wireguard_guest as guest


def Receipt(schema: int = 2) -> dict[str, Any]:
    """Provide synthetic closed metadata only, without claiming any actual runtime or vendor status."""

    return {"schema_version": schema, "owner": "a" * 64, "nonce": "b" * 32, "status": "installed",
            "files": {name: "c" * 64 for name in (guest._GENERATION_FILES if schema == 2 else guest._FILES)},
            "network_sha256": "d" * 64, "deployment_sha256": "c" * 64,
            "kernel": {"release": "6.8.0-999-generic", "package_version": "6.8.0-999.999",
                       "signature": "Ubuntu 6.8.0-999.999-generic 6.8.12", "module_sha256": "d" * 64,
                       "module_srcversion": "D" * 24, "cve_id": guest.KERNEL_CVE, "source_sha256": "e" * 64,
                       "fixed_version": "6.8.0-999.999", "checked_at": 1},
            "build": {"compiler_version": "synthetic gcc", "compiler_target": "x86_64-linux-gnu",
                      "make_version": "GNU Make fixture", "libc_headers_version": "1.0", "kernel_headers_version": "1.0",
                      "compiler_sha256": "e" * 64, "make_sha256": "f" * 64, "options": list(guest.BUILD_OPTIONS)}}


def test_ExplicitGenerationKeepsTheLegacyUnitContractAndOriginalProgramPin() -> None:
    """Default preparation stays schema 1 while an explicit generation adds exactly one nonce-bound helper."""

    owner = "a" * 64
    root = Path("/opt/flayer/wireguard") / owner
    legacy = guest._Unit(root, owner)
    assert b"lifecycle.py" not in legacy and b"--expected-generation" not in legacy
    assert f"ExecStart=/usr/bin/python3 {root}/install.py --start --allow-mutation\n".encode() in legacy
    assert guest._Unit(root, owner, nonce="") == legacy
    current = guest._Unit(root, owner, nonce="b" * 32)
    assert current.count(b"--expected-generation-nonce " + b"b" * 32) == 2
    assert current.count(b"/lifecycle.py") == 2 and b"/install.py" not in current
    assert {item.name for item in Prepared().serverBundle.files} == {"server.conf", "deployment.json", "install.py"}
    assert guest._ReceiptData(Receipt(1), owner)["schema_version"] == 1
    assert guest._ReceiptData(Receipt(), owner)["schema_version"] == 2


@pytest.mark.parametrize("nonce", [None, False, 0, "z" * 32, "b" * 31, "B" * 32, "b" * 32 + "\n"])
def test_GenerationNonceCannotBeAmbiguous(nonce: Any) -> None:
    """Do not let false or noncanonical values silently select the legacy callback."""

    with pytest.raises(guest.GuestError):
        guest._Unit(Path("/owned"), "a" * 64, nonce=nonce)


@pytest.mark.parametrize("fault", ["bool", "float", "future", "legacy-extra", "generation-missing", "unknown", "path", "digest"])
def test_GenerationReceiptIsClosedAndVersionSpecific(fault: str) -> None:
    """A retained hash set cannot admit extra executables or aliases for its schema."""

    value = copy.deepcopy(Receipt())

    if fault in {"bool", "float", "future"}:
        value["schema_version"] = {"bool": True, "float": 2.0, "future": 3}[fault]

    elif fault == "legacy-extra":
        value["schema_version"] = 1

    elif fault == "generation-missing":
        del value["files"]["lifecycle.py"]

    elif fault == "digest":
        value["files"]["lifecycle.py"] = "private-canary-invalid"

    else:
        value["files"]["../lifecycle.py" if fault == "path" else "extra.py"] = "c" * 64

    with pytest.raises(guest.GuestError):
        guest._ReceiptData(value, "a" * 64)


def test_NativeCallbackChildrenRetainTheProtectingLockDescriptor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Intercept subprocess creation and verify the exact inherited descriptors without executing anything."""

    captured = []

    def Run(command: list[str], **options: Any) -> Any:
        captured.append(options)

        return SimpleNamespace(returncode=0, stdout=b"fixture", stderr=b"")

    monkeypatch.setattr(guest.subprocess, "run", Run)
    monkeypatch.setattr(guest, "_callbackFds", (23,))
    assert guest._Run(["synthetic-command"], passFds=(41, 23)) == (0, b"fixture")
    assert captured[0]["pass_fds"] == (41, 23)
    assert captured[0]["env"]["PATH"] == "/usr/sbin:/usr/bin:/sbin:/bin"


def test_ServiceNamesAreGenerationSpecificWhileLegacyRootAndTransactionStayStable() -> None:
    """A delayed high-level service command names its old unit, never the current generation's unit."""

    owner = "a" * 64
    legacy = guest._Paths(owner)
    first = guest._Paths(owner, nonce="1" * 32)
    second = guest._Paths(owner, nonce="2" * 32)
    assert first[0] == second[0] == legacy[0] and first[2] == second[2] == legacy[2]
    assert len({legacy[1], first[1], second[1]}) == 3
    assert legacy[1].name == "flayer-wg-" + owner[:12] + ".service"
    assert first[1].name == "flayer-wg-" + owner[:12] + "-" + "1" * 32 + ".service"


@pytest.mark.parametrize("nonce", [None, False, "../foreign", "A" * 32, "1" * 31])
def test_ServiceGenerationCannotSupplyAnArbitraryUnitName(nonce: Any) -> None:
    """Unit paths are derived exclusively from validated owner and nonce values."""

    with pytest.raises(guest.GuestError):
        guest._Paths("a" * 64, nonce=nonce)
