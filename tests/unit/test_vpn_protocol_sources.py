"""Retain complete protocol projection bytes and source ownership without cloud, SSH or key rotation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project_selection import PUBLIC_KEY, Configuration
from test_vpn_project_v2 import Project, Snapshot

from flayer import _vpn_protocol_sources as sources
from flayer import _vpn_revisions as revisions
from flayer import vpn_project_v2 as selected
from flayer._vpn_creation import BundleDigest, ProtocolPin, _Json
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles.artifacts import Artifact, ArtifactBundle, WriteArtifactBundle
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject

POSIX = pytest.mark.skipif(os.name != "posix", reason="Private source files require POSIX; no WSL or desktop network is started")


def Projection(root: Path, protocol: str = "wireguard") -> tuple[SelectedVpnProject, ProtocolPin, ArtifactBundle, ArtifactBundle]:
    """Generate only synthetic test material once, independently from the source-retention functions under test."""

    project = selected.ParseSelectedProject(root, Configuration(), PUBLIC_KEY)
    material = selected._Material(project, protocol)
    server = selected._Transport(project, protocol, material).serverBundle
    pin = ProtocolPin(protocol, project.TransportFingerprint(protocol), BundleDigest(material), BundleDigest(server))

    return project, pin, material, server


@pytest.mark.parametrize("protocol", ["amneziawg", "vless-reality", "wireguard"])
def test_PreparedSourceRetainsExactCanonicalRolesWithoutPublicationOrGeneration(
    tmp_path: Path, protocol: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every protocol gets a distinct immutable locator while all input bytes and virtual role names stay unchanged."""

    project, pin, material, server = Projection(tmp_path / "never-created", protocol)

    def Forbidden(*args: Any, **options: Any) -> Any:
        """No source-reference operation may issue credentials, query a provider or regenerate a server program."""

        raise AssertionError("Source retention attempted credential generation or rendering")

    for name in ("GenerateAmneziaWgSecrets", "GenerateVlessMaterial", "GenerateWireGuardMaterial", "_Transport", "_Material"):
        monkeypatch.setattr(selected, name, Forbidden)

    source, request = sources.PrepareProtocolRequest(project, pin, material, server, operationId="a" * 32, previousState="b" * 64)
    again = sources.PrepareProtocolRequest(project, pin, material, server, operationId="a" * 32, previousState="b" * 64)
    contents = {item.name: item.content for item in request.files}

    assert (source, request) == again and source.pin == pin and source.kind == "protocol"
    assert source.requestSha256 == BundleDigest(request) and sources.DecodeSource(source.Record(), project.vpn.identity) == source
    assert len(request.files) <= 8 and not project.root.exists()
    assert all(contents[item.name] == item.content for item in (*material.files, *server.files))
    assert json.loads(contents["request.json"])["pin"] == _WireDict(pin)
    assert sources.ProtocolSource(project.vpn.identity, pin).Record()["request_sha256"] == ""
    assert "material.json" not in json.dumps(source.Record()) and "server.conf" not in json.dumps(source.Record())


@pytest.mark.parametrize("fault", ["version", "owner", "extra", "kind", "initial-redirect", "traversal", "foreign-name", "digest", "pin"])
def test_SourceMetadataRejectsForeignOrRedirectedRolesBeforeAnyPrivateRead(tmp_path: Path, fault: str) -> None:
    """Only one exact nonsecret source schema may locate retained artifacts."""

    project, pin, _, _ = Projection(tmp_path / "never-created")
    record = sources.ProtocolSource(project.vpn.identity, pin).Record()

    if fault == "version":
        record["schema_version"] = True

    elif fault == "owner":
        record["identity"] = _WireDict(replace(project.vpn.identity, ownerId="another-owner"))

    elif fault == "extra":
        record["private_extra"] = "suppressed-private-fixture"

    elif fault == "kind":
        record["kind"] = "filesystem"

    elif fault == "initial-redirect":
        record["request_name"] = "gateway-wp-" + "a" * 16

    elif fault == "pin":
        record["pin"] = {"protocol": "wireguard"}

    else:
        record.update(kind="peer", request_name=project.vpn.identity.stack + "-wp-" + "a" * 16, request_sha256="b" * 64)
        record[{"traversal": "request_name", "foreign-name": "request_name", "digest": "request_sha256"}[fault]] = {
            "traversal": "../outside", "foreign-name": "foreign-wp-" + "a" * 16, "digest": "not-a-digest"}[fault]

    with pytest.raises(VpnError):
        sources.DecodeSource(record, project.vpn.identity)

    assert not project.root.exists()


def test_ForeignSourceCannotSelectAnotherProjectsFiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate source ownership before consulting any original bundle path."""

    project, pin, _, _ = Projection(tmp_path / "never-created")
    foreign = sources.ProtocolSource(replace(project.vpn.identity, ownerId="another-owner"), pin)

    def Forbidden(*args: Any, **options: Any) -> Any:
        """Do not permit even an attempted file lookup after the full source owner has changed."""

        raise AssertionError("Foreign source reached a private reader")

    monkeypatch.setattr(sources, "ReadPinnedBundle", Forbidden)

    with pytest.raises(VpnError):
        sources.ReadSource(project, foreign)


@pytest.mark.parametrize("protocol", [[], {}, True, None])
def test_MalformedProtocolScalarCannotEscapeTheSourceCodecAsATypeError(tmp_path: Path, protocol: Any) -> None:
    """Untrusted complete JSON-shaped pins fail with the source contract error before any file access."""

    project, pin, _, _ = Projection(tmp_path / "never-created")
    record = sources.ProtocolSource(project.vpn.identity, pin).Record()
    record["pin"] = {**_WireDict(pin), "protocol": protocol}

    with pytest.raises(VpnError):
        sources.DecodeSource(record, project.vpn.identity)

    assert not project.root.exists()


def test_ExtendedModelsCannotCopyPrivateFieldsIntoNonsecretSourceMetadata(tmp_path: Path) -> None:
    """Recursive dataclass encoders must never turn a caller's credential-bearing subtype into public metadata."""

    @dataclass(frozen=True, slots=True)
    class ExtendedPin(ProtocolPin):
        """Model an unrelated caller extension that the closed source schema does not authorize."""

        privateKey: str = "suppressed-private-fixture"

    @dataclass(frozen=True, slots=True)
    class ExtendedIdentity(StackIdentity):
        """Keep extra credentials outside the canonical ownership schema."""

        privateToken: str = "suppressed-private-fixture"

    @dataclass(frozen=True, slots=True)
    class ExtendedSource(sources.ProtocolSource):
        """Do not let Record silently serialize fields that DecodeSource would refuse."""

        privateKey: str = "suppressed-private-fixture"

    @dataclass(frozen=True, slots=True)
    class UnvalidatedSource(sources.ProtocolSource):
        """A caller may override construction; the metadata serialization boundary must still reject extra fields."""

        privateKey: str = "suppressed-private-fixture"

        def __post_init__(self) -> None:
            """Represent an extension that omitted its base model's validation."""

    project, pin, material, server = Projection(tmp_path / "never-created")
    extended = ExtendedPin(pin.protocol, pin.intentFingerprint, pin.materialDigest, pin.serverDigest)
    identity = project.vpn.identity
    extendedIdentity = ExtendedIdentity(identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId)

    for candidate in ((identity, extended), (extendedIdentity, pin)):
        with pytest.raises(VpnError):
            sources.ProtocolSource(*candidate)

    with pytest.raises(VpnError):
        ExtendedSource(identity, pin)

    with pytest.raises(VpnError):
        UnvalidatedSource(identity, pin).Record()

    with pytest.raises(VpnError):
        sources.PrepareProtocolRequest(project, extended, material, server, operationId="a" * 32, previousState="b" * 64)

    changed = replace(project, vpn=replace(project.vpn, identity=extendedIdentity))

    with pytest.raises(VpnError):
        sources.PrepareProtocolRequest(changed, pin, material, server, operationId="a" * 32, previousState="b" * 64)

    assert not project.root.exists()


def test_CredentialBearingStringSubclassesCannotHideInsideOtherwiseClosedModels(tmp_path: Path) -> None:
    """Dataclass-aware wire serialization also needs plain scalar fields, not only exact outer model classes."""

    @dataclass(frozen=True, eq=False)
    class CredentialString(str):
        """Model an accepted string value whose extra fields must never enter a nonsecret JSON record."""

        value: str
        privateKey: str = "suppressed-private-fixture"

        def __new__(cls, value: str, privateKey: str = "suppressed-private-fixture") -> CredentialString:
            """Retain ordinary string equality while exposing the unsafe recursive-dataclass shape to the regression."""

            return str.__new__(cls, value)

    project, pin, material, server = Projection(tmp_path / "never-created")

    for field in ("protocol", "intentFingerprint", "materialDigest", "serverDigest"):
        extended = replace(pin, **{field: CredentialString(str(getattr(pin, field)))})

        with pytest.raises(VpnError):
            sources.ProtocolSource(project.vpn.identity, extended)

        with pytest.raises(VpnError):
            sources.PrepareProtocolRequest(project, extended, material, server, operationId="a" * 32, previousState="b" * 64)

    identity = replace(project.vpn.identity, scopeId=CredentialString(project.vpn.identity.scopeId))

    with pytest.raises(VpnError):
        sources.ProtocolSource(identity, pin)

    for operation, previous in ((CredentialString("a" * 32), "b" * 64), ("a" * 32, CredentialString("b" * 64))):
        with pytest.raises(VpnError):
            sources.PrepareProtocolRequest(project, pin, material, server, operationId=operation, previousState=previous)

    assert not project.root.exists()


@pytest.mark.parametrize("fault", ["owner", "material-role", "server-role", "material-proof", "server-proof", "material-public",
                                  "server-public", "missing-file", "operation", "previous-state"])
def test_ProtocolSnapshotRequiresCompleteUnchangedRoleAndOperationProofs(tmp_path: Path, fault: str) -> None:
    """Staging cannot rename another role, truncate its private data or conceal a changed pin."""

    project, pin, material, server = Projection(tmp_path / "never-created")
    operation, previous = "a" * 32, "b" * 64

    if fault == "owner":
        material = replace(material, identity=replace(material.identity, ownerId="another-owner"))

    elif fault == "material-role":
        material = replace(material, name="another-credentials")

    elif fault == "server-role":
        server = replace(server, name="another-server")

    elif fault in {"material-proof", "server-proof"}:
        pin = replace(pin, **{"materialDigest": "f" * 64} if fault == "material-proof" else {"serverDigest": "f" * 64})

    elif fault == "material-public":
        material = replace(material, files=tuple(replace(item, sensitive=False) if item.name == "material.json" else item for item in material.files))

    elif fault == "server-public":
        server = replace(server, files=tuple(replace(item, sensitive=False) for item in server.files))

    elif fault == "missing-file":
        server = replace(server, files=server.files[:1])

    elif fault == "operation":
        operation = "unsafe"

    else:
        previous = "not-a-digest"

    with pytest.raises(VpnError):
        sources.PrepareProtocolRequest(project, pin, material, server, operationId=operation, previousState=previous)

    assert not project.root.exists()


@POSIX
@pytest.mark.parametrize("protocol", ["amneziawg", "vless-reality", "wireguard"])
def test_SourceReaderPreservesOriginalBundlesAndRehydratesTheExactRetainedRoles(tmp_path: Path, protocol: str) -> None:
    """Use real owned private manifests, but no provider, SSH, service or kernel command."""

    project = Project(tmp_path)
    selected.PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    pin = next(pin for pin in state.pins if pin.protocol == protocol)
    initial = sources.ProtocolSource(project.vpn.identity, pin)
    material, server = (sources.ReadSource(project, initial, material=flag) for flag in (True, False))
    before = Snapshot(project.Artifacts)
    source, request = sources.PrepareProtocolRequest(project, pin, material, server, operationId="a" * 32, previousState=state.headDigest)
    WriteArtifactBundle(project.Artifacts, request)

    assert sources.ReadSource(project, source, material=True) == material
    assert sources.ReadSource(project, source) == server
    assert all(Snapshot(project.Artifacts)[name] == entry for name, entry in before.items())


@POSIX
@pytest.mark.parametrize("fault", ["owner", "protocol", "operation", "parent", "pin", "extra", "noncanonical", "material-bytes", "server-bytes"])
def test_RehashedProtocolRequestCannotHideContradictorySnapshotMetadata(tmp_path: Path, fault: str) -> None:
    """An internally owned manifest alone cannot override a source's complete role and projection proof."""

    project = Project(tmp_path, ("wireguard",))
    selected.PrepareSelectedProject(project)
    state = revisions.LoadRevisions(project)
    pin = state.pins[0]
    material = revisions.ReadEffectiveBundle(project, state, pin, material=True)
    server = revisions.ReadEffectiveBundle(project, state, pin)
    source, request = sources.PrepareProtocolRequest(project, pin, material, server, operationId="a" * 32, previousState=state.headDigest)
    metadata = json.loads(next(item.content for item in request.files if item.name == "request.json"))

    if fault in {"material-bytes", "server-bytes"}:
        filename = "material.json" if fault == "material-bytes" else "server.conf"
        request = replace(request, files=tuple(replace(item, content=b"suppressed-private-fixture") if item.name == filename else item for item in request.files))

    elif fault == "owner":
        metadata["identity"] = _WireDict(replace(project.vpn.identity, ownerId="another-owner"))

    elif fault == "pin":
        metadata["pin"] = _WireDict(replace(pin, materialDigest="f" * 64))

    else:
        key, value = {"protocol": ("protocol", "amneziawg"), "operation": ("operation_id", "b" * 32),
                      "parent": ("previous_state_sha256", "invalid"), "extra": ("private_extra", "suppressed-private-fixture"),
                      "noncanonical": ("schema_version", 1)}[fault]
        metadata[key] = value

    content = json.dumps(metadata).encode() if fault == "noncanonical" else _Json(metadata)
    request = replace(request, files=tuple(Artifact(item.name, content, False) if item.name == "request.json" else item for item in request.files))
    source = replace(source, requestSha256=BundleDigest(request))
    WriteArtifactBundle(project.Artifacts, request)
    before = Snapshot(project.Artifacts)

    with pytest.raises(VpnError):
        sources.ReadSource(project, source, material=fault == "server-bytes")

    assert Snapshot(project.Artifacts) == before
