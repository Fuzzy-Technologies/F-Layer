"""Check nonauthorizing preparation models and complete source pins without reading any guest path or running a program."""

from __future__ import annotations

import copy
from typing import Any

import pytest
from test_protocol_reservation import Header
from test_wireguard_generations import Receipt
from test_wireguard_guest import Prepared

from flayer.core.contracts import _WireDict
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_generation as cache
from flayer.profiles import _protocol_preparation as preparations
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _wireguard_generation as tools
from flayer.profiles import _wireguard_guest as guest


def Request(kind: str = "fresh", files: dict[str, bytes] | None = None, cached: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Keep every credential synthetic and in memory; a metadata receipt is never a live runtime proof."""

    prepared = Prepared()
    identity = _WireDict(prepared.serverBundle.identity)
    files = {item.name: item.content for item in prepared.serverBundle.files} if files is None else files
    sourceFiles = {name: guest._Digest(content) for name, content in files.items()}
    owner = guest._Json(files["deployment.json"])["owner"]
    origin = Header(owner)
    del origin["plan_sha256"]

    if kind != "disable":
        origin.update(wireguard_state="absent", wireguard_receipt_sha256="", wireguard_absence_sha256=guest._AbsenceDigest(owner))

    if kind != "fresh" and cached is None:
        cached = {**Receipt(1), "owner": owner, "deployment_sha256": sourceFiles["deployment.json"]}
        cached["files"].update(sourceFiles)

    if kind == "disable":
        origin["wireguard_receipt_sha256"] = guest._Digest(guest._Encode(cached))

    digest = guest._Digest(guest._Encode({"identity": identity, "kind": "server", "name": identity["stack"] + "-wireguard", "files": [
        {"name": name, "size": len(data), "sha256": guest._Digest(data), "sensitive": True} for name, data in sorted(files.items())]}))
    source = {"schema_version": 1, "identity": identity, "pin": {"protocol": "wireguard", "intent_fingerprint": "a" * 64,
              "material_digest": "b" * 64, "server_digest": digest}, "kind": "initial", "request_name": "", "request_sha256": ""}

    return {"schema_version": 1, "identity": identity, "origin": origin, "source": source, "source_files": sourceFiles,
            "cached_receipt": cached, "maintenance_sha256": sourceFiles["install.py"]}, files


def Generation(request: dict[str, Any]) -> dict[str, Any]:
    """Model the exact gen3 shape that a successful isolated build must later prove through complete private files."""

    original = copy.deepcopy(request["cached_receipt"])

    if original is None:
        original = {**Receipt(1), "owner": request["origin"]["owner"], "status": "staged", "deployment_sha256": request["source_files"]["deployment.json"]}
        original["files"].update(request["source_files"])

    candidate = {**copy.deepcopy(original), "schema_version": 2, "nonce": request["origin"]["operation_id"], "status": "staged", "network_sha256": "e" * 64}
    candidate["files"].update({"lifecycle.py": request["maintenance_sha256"], "firewall.nft": "e" * 64,
                               "service.service": guest._Digest(guest._Unit(guest._Paths(original["owner"])[0], original["owner"], nonce=candidate["nonce"]))})

    return {"schema_version": 3, "callback_abi": guest.PROTOCOL_RUNTIME_ABI, "change": "disable" if request["origin"]["wireguard_state"] == "active" else "enable",
            "source_sha256": guest._Digest(guest._Encode(request["source"])), "source_files": request["source_files"], "cached_receipt": original, "candidate_receipt": candidate}


@pytest.mark.parametrize("kind", ["fresh", "enable", "disable"])
def test_PublicPreparationResultBindsSourceOriginalRuntimeAndApprovedCallbackWithoutGrantingAuthority(kind: str) -> None:
    """A preparation manifest supplies the future plan's missing generation, never a reservation or a service-health assertion."""

    request, files = Request(kind)
    generation = Generation(request)
    assert preparations.Request(guest, authority, completion, request) == request
    assert preparations._Bundle(guest, request, files) == files
    result = preparations.Result(guest, authority, completion, request, generation)
    manifest = {"schema_version": 1, "request": request, "generation": generation}
    assert set(result) == {"status", "request_sha256", "preparation_sha256", "generation"}
    assert result["preparation_sha256"] == guest._Digest(guest._Encode(manifest))


@pytest.mark.parametrize("fault", ["schema", "identity", "owner", "scope", "source", "source-files", "cached", "helper", "plan", "extra", "consent", "wrong-scope"])
def test_InvalidPreparationOrMissingConsentFailsBeforeAnyGuestFileOrLock(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Neither private source bytes nor a valid tool checksum imply authorization to stage or build anything."""

    request, files = Request("disable")
    allow, scope = True, request["identity"]["scope_id"]

    if fault == "schema":
        request["schema_version"] = True
    elif fault == "identity":
        request["identity"]["owner_id"] += "-other"
    elif fault == "owner":
        request["origin"]["owner"] = "0" * 64
    elif fault == "scope":
        request["identity"]["scope_id"] = "private invalid scope"
    elif fault == "source":
        request["source"]["pin"]["protocol"] = "amneziawg"
    elif fault == "source-files":
        request["source_files"]["server.conf"] = "0" * 64
    elif fault == "cached":
        request["cached_receipt"] = None
    elif fault == "helper":
        request["maintenance_sha256"] = "private-marker"
    elif fault == "plan":
        request["origin"]["plan_sha256"] = "0" * 64
    elif fault == "extra":
        request["path"] = "private-marker"
    elif fault == "consent":
        allow = False
    else:
        scope += "-foreign"

    monkeypatch.setattr(authority, "_Locks", lambda *args, **kwargs: pytest.fail("Invalid preparation must not lock guest files"))
    monkeypatch.setattr(guest, "_Directory", lambda *args, **kwargs: pytest.fail("Invalid preparation must not inspect guest directories"))

    with pytest.raises(ValueError):
        preparations.Prepare(guest, object(), authority, completion, tools, cache, request, files, allowMutation=allow, scopeConfirm=scope)


@pytest.mark.parametrize("fault", ["version", "abi", "source", "source-files", "helper", "cached", "candidate", "credentials", "runtime", "kernel"])
def test_RehashedPublicManifestCannotSubstituteAChangedGeneration(fault: str) -> None:
    """The model checks semantics as well as an outer digest, including preserved credentials and native ABI."""

    request, _ = Request("disable")
    generation = Generation(request)

    if fault == "version":
        generation["schema_version"] = 2
        del generation["callback_abi"]
    elif fault == "abi":
        generation["callback_abi"] = "unknown"
    elif fault == "source":
        generation["source_sha256"] = "0" * 64
    elif fault == "source-files":
        generation["source_files"] = {**generation["source_files"], "server.conf": "0" * 64}
    elif fault == "helper":
        generation["candidate_receipt"]["files"]["lifecycle.py"] = "0" * 64
    elif fault == "cached":
        generation["cached_receipt"]["build"]["compiler_sha256"] = "0" * 64
    elif fault == "candidate":
        generation["candidate_receipt"]["nonce"] = "f" * 32
    elif fault in {"credentials", "runtime"}:
        generation["candidate_receipt"]["files"]["server.conf" if fault == "credentials" else "wg"] = "0" * 64
    else:
        generation["candidate_receipt"]["kernel"]["module_sha256"] = "0" * 64

    with pytest.raises(ValueError):
        preparations.Result(guest, authority, completion, request, generation)
