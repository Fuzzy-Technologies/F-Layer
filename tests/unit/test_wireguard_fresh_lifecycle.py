"""Build only private fresh snapshots with real POSIX files and a completely intercepted guest/network model."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_wireguard_guest import Vendor
from test_wireguard_lifecycle import Interrupted, Seed

from flayer.profiles import _wireguard_generation as generations
from flayer.profiles import _wireguard_guest as guest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private fresh snapshots require POSIX files; no WSL, desktop VPN or real native command is used")


def Sources(tmpPath: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Path, Path, Path, dict[str, str], bytes]:
    """Retain the original private three-file request before any install or authority reservation exists."""

    source, _, model = Seed(tmpPath, monkeypatch)
    cached, candidate = tmpPath / "fresh-cache", tmpPath / "candidate"
    cached.mkdir(mode=0o700)
    candidate.mkdir(mode=0o700)
    pins = {path.name: guest._Digest(path.read_bytes()) for path in source.iterdir()}

    return model, source, cached, candidate, pins, (source / "install.py").read_bytes()


def Prepare(source: Path, cached: Path, candidate: Path, pins: dict[str, str], callback: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use one explicit operation nonce and approved receiver program without granting runtime or cloud authority."""

    return generations.PrepareFresh(guest, source, cached, candidate, pins, "2" * 32, callback, guest._Digest(callback), allowMutation=True)


def Unpublished(model: Any) -> None:
    """No private snapshot constitutes a managed install, unit, interface, forwarding/NAT table or reservation."""

    assert not guest.BASE.exists() and not model.root.exists() and not model.unit.exists()
    assert not guest._Paths(model.owner)[2].exists() and not guest.LOCK.exists()
    assert not (guest.BASE.parent / "ingress").exists()
    assert not model.active and model.interface is None and not model.network and not model.forwarding
    assert not any(Path(command[0]).name == "systemctl" for command in model.commands)


def test_FirstEverGenerationRetainsExactCredentialsAndBuildEvidenceWithoutPublishingManagedState(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh preparation passes the original vendor/build checks and produces the same private cache contract used by re-enablement."""

    model, source, cached, candidate, pins, callback = Sources(tmp_path, monkeypatch)
    original = {path.name: path.read_bytes() for path in source.iterdir()}
    baseline, desired = Prepare(source, cached, candidate, pins, callback)
    assert baseline["schema_version"] == 1 and baseline["status"] == "staged"
    assert desired["schema_version"] == 2 and desired["status"] == "staged" and desired["nonce"] == "2" * 32
    assert baseline["nonce"] != desired["nonce"] and baseline["kernel"] == desired["kernel"] and baseline["build"] == desired["build"]
    assert desired["files"]["lifecycle.py"] == guest._Digest(callback)

    for name in (*pins, "wg", "COPYING"):
        assert (cached / name).read_bytes() == (candidate / name).read_bytes()

    assert {path.name: path.read_bytes() for path in source.iterdir()} == original
    assert guest._Receipt(cached, cached / ".unpublished-unit", model.owner, staged=True) == baseline
    assert guest._Receipt(candidate, candidate / ".unpublished-unit", model.owner, staged=True) == desired
    intent = {"owner": model.owner, "wireguard_state": "absent", "operation_id": desired["nonce"]}
    generation = {"schema_version": 3, "change": "enable", "callback_abi": guest.PROTOCOL_RUNTIME_ABI,
                  "source_sha256": "f" * 64, "source_files": pins, "cached_receipt": baseline, "candidate_receipt": desired}
    assert guest._GenerationRecord(generation, intent) == generation
    Unpublished(model)


@pytest.mark.parametrize("fault", ["source-pin", "callback", "cached-file", "candidate-file", "extra-source", "alias", "nested", "managed", "mode"])
def test_FreshPreparationRefusesUnboundOrUnsafePathsBeforeBuilding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Preserve supplied foreign content and reject aliases or owned runtime paths instead of adopting them."""

    model, source, cached, candidate, pins, callback = Sources(tmp_path, monkeypatch)
    monkeypatch.setattr(guest, "_BuildTools", lambda *args: pytest.fail("A rejected preflight must not build runtime tools"))

    if fault == "source-pin":
        pins["server.conf"] = "e" * 64

    elif fault == "callback":
        callback = b"different self-consistently hashed callback"

    elif fault in {"cached-file", "candidate-file"}:
        ((cached if fault == "cached-file" else candidate) / "foreign.txt").write_bytes(b"preserve foreign bytes")

    elif fault == "extra-source":
        (source / "foreign.txt").write_bytes(b"preserve foreign source")

    elif fault == "alias":
        alias = tmp_path / "alias"
        alias.symlink_to(cached, target_is_directory=True)
        cached = alias

    elif fault == "nested":
        cached = source

    elif fault == "managed":
        guest.BASE.parent.mkdir(mode=0o700, parents=True)
        cached = guest.BASE.parent / "foreign-empty"
        cached.mkdir(mode=0o700)

    else:
        cached.chmod(0o755)

    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}

    with pytest.raises(guest.GuestError):
        Prepare(source, cached, candidate, pins, callback)

    assert all(path.read_bytes() == content for path, content in before.items())
    Unpublished(model)


@pytest.mark.parametrize("status,version", [("needed", ""), ("pending", "6.8.0-999.999"), ("released", "6.8.0-1000.1000")])
def test_FreshBuildCannotBypassUnfixedVendorKernelEvidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, version: str) -> None:
    """Staging is no exception to the pinned CVE admission rule and never upgrades or reboots the executing kernel."""

    model, source, cached, candidate, pins, callback = Sources(tmp_path, monkeypatch)
    monkeypatch.setattr(guest, "_Fetch", lambda *args: Vendor(status, version))
    monkeypatch.setattr(guest, "_BuildTools", lambda *args: pytest.fail("An unfixed kernel must not build runtime tools"))

    with pytest.raises(guest.GuestError):
        Prepare(source, cached, candidate, pins, callback)

    assert not tuple(cached.iterdir()) and not tuple(candidate.iterdir())
    Unpublished(model)


@pytest.mark.parametrize("fault", ["kernel", "toolchain", "source"])
def test_ChangedBuildInputsCannotProduceAnAcknowledgedFreshSnapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Recheck the executing kernel, build toolchain and retained private source after construction, before publishing snapshot receipts."""

    model, source, cached, candidate, pins, callback = Sources(tmp_path, monkeypatch)
    build, facts = guest._BuildTools, guest._BuildFacts

    def Build(work: Path) -> tuple[bytes, bytes]:
        """Change only the selected intercepted fact during the private build."""

        result = build(work)

        if fault == "kernel":
            monkeypatch.setattr(guest, "_KernelFacts", lambda: {"changed": True})

        elif fault == "toolchain":
            monkeypatch.setattr(guest, "_BuildFacts", lambda: {**facts(), "compiler_sha256": "0" * 64})

        else:
            with (source / "server.conf").open("ab") as stream:
                stream.write(b"\n")

        return result

    monkeypatch.setattr(guest, "_BuildTools", Build)

    with pytest.raises(guest.GuestError):
        Prepare(source, cached, candidate, pins, callback)

    assert not tuple(cached.iterdir()) and not tuple(candidate.iterdir())
    Unpublished(model)


def test_TemporaryValidSourceCannotHideTheInvalidPinnedConfigurationReturnedInASnapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate captured bytes: a valid temporary source followed by restoration of invalid pinned bytes must not receive a receipt."""

    model, source, cached, candidate, _, callback = Sources(tmp_path, monkeypatch)
    valid = (source / "server.conf").read_bytes()
    invalid = valid.replace(b"ListenPort = ", b"InvalidListenPort = ", 1)
    assert invalid != valid
    (source / "server.conf").write_bytes(invalid)
    deployment = json.loads((source / "deployment.json").read_bytes())
    deployment["config_sha256"] = guest._Digest(invalid)
    (source / "deployment.json").write_bytes(guest._Encode(deployment))
    pins = {path.name: guest._Digest(path.read_bytes()) for path in source.iterdir()}
    build, parse = guest._BuildTools, guest._Config

    def Build(work: Path) -> tuple[bytes, bytes]:
        """Expose a different valid file only between payload construction and parsing."""

        result = build(work)
        (source / "server.conf").write_bytes(valid)

        return result

    def Parse(content: bytes, request: dict[str, Any], binary: Path) -> Any:
        """Restore the original invalid source immediately after validation, as if its mutable path had never changed."""

        try:
            return parse(content, request, binary)

        finally:
            (source / "server.conf").write_bytes(invalid)

    monkeypatch.setattr(guest, "_BuildTools", Build)
    monkeypatch.setattr(guest, "_Config", Parse)

    with pytest.raises(guest.GuestError):
        Prepare(source, cached, candidate, pins, callback)

    assert not tuple(cached.iterdir()) and not tuple(candidate.iterdir())
    assert (source / "server.conf").read_bytes() == invalid
    Unpublished(model)


@pytest.mark.parametrize("directory,filename", [("fresh-cache", "wg"), ("fresh-cache", "receipt.json"), ("candidate", "wg"), ("candidate", "receipt.json")])
def test_InterruptedFreshSnapshotsRemainUnpublishedAndCannotBeAdoptedByARetry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directory: str, filename: str,
) -> None:
    """An unacknowledged transient prefix grants no authority and cannot be silently replaced or rebuilt over existing bytes."""

    model, source, cached, candidate, pins, callback = Sources(tmp_path, monkeypatch)
    write = generations._Exclusive

    def Write(path: Path, content: bytes, mode: int) -> None:
        """Die after an exact real file publication, including the final receipt boundary."""

        write(path, content, mode)

        if path.parent.name == directory and path.name == filename:
            raise Interrupted()

    monkeypatch.setattr(generations, "_Exclusive", Write)

    with pytest.raises(Interrupted):
        Prepare(source, cached, candidate, pins, callback)

    before = {path: path.read_bytes() for root in (source, cached, candidate) for path in root.iterdir()}

    with pytest.raises(guest.GuestError):
        Prepare(source, cached, candidate, pins, callback)

    assert {path: path.read_bytes() for root in (source, cached, candidate) for path in root.iterdir()} == before
    assert not tuple(tmp_path.glob(".wg-build-*"))

    if (candidate / "receipt.json").exists():
        assert json.loads((candidate / "receipt.json").read_bytes())["status"] == "staged"

    Unpublished(model)
