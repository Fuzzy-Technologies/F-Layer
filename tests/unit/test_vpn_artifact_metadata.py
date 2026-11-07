"""Keep metadata-only authority traversal distinct from private artifact health, reading and deletion."""

from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from flayer import _vpn_artifact_metadata as metadata
from flayer._vpn_creation import BundleDigest, _Json
from flayer.core.contracts import StackIdentity
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
    _Manifest,
)
from flayer.profiles.vpn import VpnError

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private metadata snapshots require POSIX; no WSL or desktop VPN is started")


def Bundle() -> ArtifactBundle:
    """Use synthetic private payloads and a separate nonsecret request inside a normal owned server bundle."""

    identity = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")

    return ArtifactBundle(identity, "server", "gateway-tp-" + "a" * 16, (
        Artifact("material.json", b"synthetic private fixture\n"), Artifact("server.conf", b"synthetic server fixture\n"),
        Artifact("request.json", b'{"schema_version":1}\n', False), Artifact("intent.sha256", ("b" * 64 + "\n").encode(), False)))


def test_SummaryDigestMatchesTheCompleteBundleDigestWithoutManufacturingPrivatePayloads() -> None:
    """File sizes, sensitivity and full hashes use the existing exact bundle hash convention regardless of entry order."""

    bundle = Bundle()
    digest = BundleDigest(bundle)
    value = json.loads(_Manifest(bundle))
    value["files"].reverse()
    summary = metadata.DecodeSummary(_Json(value), bundle.identity, bundle.name, digest)

    assert summary.Digest() == digest and {item.name for item in summary.files} == {item.name for item in bundle.files}
    assert not hasattr(summary.files[0], "content") and "synthetic private fixture" not in repr(summary)


@pytest.mark.parametrize("fault", ["version", "extra", "owner", "role", "name", "files", "duplicate", "filename", "size", "bool-size", "float-size", "digest", "flag", "pin"])
def test_SummaryDecoderRejectsAmbiguousMetadataOrAChangedExternalPin(fault: str) -> None:
    """Unknown fields and Python scalar aliases cannot silently reinterpret an externally pinned artifact manifest."""

    bundle = Bundle()
    raw = json.loads(_Manifest(bundle))
    digest = BundleDigest(bundle)

    if fault == "version":
        raw["schema_version"] = True

    elif fault == "extra":
        raw["private_key"] = "suppressed-fixture"

    elif fault == "owner":
        raw["identity"]["owner_id"] = "foreign-owner"

    elif fault == "role":
        raw["kind"] = "device"

    elif fault == "name":
        raw["name"] = "foreign-bundle"

    elif fault == "files":
        raw["files"] = []

    elif fault == "duplicate":
        raw["files"].append(copy.deepcopy(raw["files"][0]))

    elif fault == "filename":
        raw["files"][0]["name"] = "../material.json"

    elif fault in {"size", "bool-size", "float-size"}:
        raw["files"][0]["size"] = 0 if fault == "size" else True if fault == "bool-size" else float(raw["files"][0]["size"])

    elif fault == "digest":
        raw["files"][0]["sha256"] = "c" * 64

    elif fault == "flag":
        raw["files"][0]["sensitive"] = 1

    else:
        digest = "f" * 64

    with pytest.raises(VpnError) as caught:
        metadata.DecodeSummary(_Json(raw), bundle.identity, bundle.name, digest)

    assert caught.value.__context__ is None and caught.value.__cause__ is None and "suppressed-fixture" not in str(caught.value)


def test_MetadataModelsRejectCredentialBearingScalarOrModelExtensions() -> None:
    """Recursive serialization checks the owner and all hash scalars before any inherited dataclass field could escape."""

    @dataclass(frozen=True, eq=False)
    class ExtendedHash(str):
        """Model a string subtype containing an extra credential-like field."""

        privateKey: str = "suppressed-fixture"

    bundle = Bundle()
    identity = bundle.identity
    unsafe = StackIdentity(identity.project, identity.stack, identity.provider, ExtendedHash(identity.scopeId), identity.ownerId)

    with pytest.raises(VpnError):
        metadata.DecodeSummary(_Manifest(bundle), unsafe, bundle.name, BundleDigest(bundle))

    with pytest.raises(VpnError):
        metadata.FileSummary("request.json", 1, ExtendedHash("a" * 64), False)


@POSIX
def test_PublicTraversalWorksAfterPrivateFilesAreLostAndNeverOpensPrivateBodies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Losing private payloads preserves their pinned references but never grants permission to use/export/delete them."""

    bundle = Bundle()
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    original = metadata._ReadSnapshot
    opened = []

    def Read(descriptor: int, name: str, limit: int) -> Any:
        """Fail the test if the metadata reader attempts any private payload read."""

        assert name in {"manifest.json", "request.json"}
        opened.append(name)

        return original(descriptor, name, limit)

    monkeypatch.setattr(metadata, "_ReadSnapshot", Read)
    (directory / "material.json").unlink()
    summary, content = metadata.ReadSummary(directory, bundle.identity, bundle.name, BundleDigest(bundle), publicFile="request.json")
    assert summary.Digest() == BundleDigest(bundle) and content == b'{"schema_version":1}\n'
    assert opened == ["manifest.json", "request.json"]

    with pytest.raises(VpnError):
        metadata.ReadSummary(directory, bundle.identity, bundle.name, BundleDigest(bundle), publicFile="server.conf")

    with pytest.raises(ValueError):
        ReadOwnedArtifactFile(directory / "request.json", bundle.identity, kind="server", name=bundle.name)


@POSIX
def test_ADeclaredPrivateDigestIsNotAClaimThatTheUnopenedPrivateBodyIsHealthy(tmp_path: Path) -> None:
    """Metadata-only traversal deliberately makes no payload integrity assertion; actual use still calls the full reader."""

    bundle = Bundle()
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    private = directory / "material.json"
    private.write_bytes(b"x" * private.stat().st_size)
    summary, public = metadata.ReadSummary(directory, bundle.identity, bundle.name, BundleDigest(bundle))
    assert summary.Digest() == BundleDigest(bundle) and public is None

    with pytest.raises(ValueError):
        ReadOwnedArtifactFile(private, bundle.identity, kind="server", name=bundle.name)


@POSIX
@pytest.mark.parametrize("fault", ["extra", "link", "hardlink", "permissions", "size", "public-digest", "manifest"])
def test_ForeignDriftedOrUnsafeMetadataCannotAuthorizeNonsecretTraversal(tmp_path: Path, fault: str) -> None:
    """Missing expected private payloads differ from collateral files, altered public authority and unsafe ownership."""

    bundle = Bundle()
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    path = directory / "material.json"

    if fault == "extra":
        (directory / "foreign.txt").write_bytes(b"foreign fixture")

    elif fault == "link":
        path.unlink()
        path.symlink_to(directory / "server.conf")

    elif fault == "hardlink":
        os.link(path, tmp_path / "linked-fixture")

    elif fault == "permissions":
        path.chmod(0o644)

    elif fault == "size":
        path.write_bytes(b"short")

    elif fault == "public-digest":
        path = directory / "request.json"
        path.write_bytes(b"x" * path.stat().st_size)

    else:
        path = directory / "manifest.json"
        value = json.loads(path.read_bytes())
        value["files"][0]["sha256"] = "f" * 64
        path.write_bytes(_Json(value))

    before = {item.name: (metadata._StatKey(item.lstat()), item.lstat().st_mode) for item in directory.iterdir()}

    with pytest.raises(VpnError):
        metadata.ReadSummary(directory, bundle.identity, bundle.name, BundleDigest(bundle), publicFile="request.json")

    assert {item.name: (metadata._StatKey(item.lstat()), item.lstat().st_mode) for item in directory.iterdir()} == before
