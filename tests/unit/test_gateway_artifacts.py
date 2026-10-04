"""Owned artifact collision, scope, bounded-read, and partial-failure contracts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from flayer.core.contracts import StackIdentity
from flayer.profiles import (
    Artifact,
    ArtifactBundle,
    ArtifactError,
    BuildDeviceBundle,
    RemoveArtifactBundle,
    WriteArtifactBundle,
    artifacts,
)

IDENTITY = StackIdentity("example", "gateway", "yandex-cloud", "example-folder", "example-owner")
SYNTHETIC_SECRET = b"synthetic-credential-not-real"


def Bundle() -> ArtifactBundle:
    """Create a small owned two-file bundle with synthetic sensitive bytes."""

    return ArtifactBundle(IDENTITY, "device", "laptop", (
        Artifact("client.conf", SYNTHETIC_SECRET), Artifact("transport.json", b"{}"),
    ))


def Save(tmp_path: Path) -> tuple[Path, Path]:
    """Publish an explicit private bundle for ownership and cleanup scenarios."""

    root = tmp_path / "artifacts"
    directory = WriteArtifactBundle(root, Bundle())

    return root, directory


def test_PrivateManifestExcludesSensitiveBytesAndCleanupIsExplicit(tmp_path: Path) -> None:
    """Verify restrictive modes, complete ownership, and unchanged exact-file cleanup."""

    root, directory = Save(tmp_path)
    data = json.loads((directory / "manifest.json").read_bytes())

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in directory.iterdir())
    assert data["identity"]["owner_id"] == IDENTITY.owner_id
    assert SYNTHETIC_SECRET not in (directory / "manifest.json").read_bytes()
    assert SYNTHETIC_SECRET.decode() not in repr(Bundle())
    assert SYNTHETIC_SECRET.decode() not in repr(Bundle().files[0])
    assert data["files"][0]["sha256"] == hashlib.sha256(SYNTHETIC_SECRET).hexdigest()
    assert RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")
    assert not directory.exists() and list(root.iterdir()) == []
    assert not RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")
    assert not RemoveArtifactBundle(tmp_path / "absent", IDENTITY, kind="device", name="laptop")


def test_ExpectedBundleAuthorizesExactCleanupContent(tmp_path: Path) -> None:
    """Permit rollback only when the complete current bundle matches caller-held immutable intent."""

    root, directory = Save(tmp_path)

    assert RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop", expected_bundle=Bundle()), "Exact expected bundle content must authorize verified cleanup"
    assert not directory.exists(), "Expected-content cleanup must remove the complete matching bundle"


@pytest.mark.parametrize("replacement_files", [
    (Artifact("client.conf", b"coherent-replacement"), Artifact("transport.json", b"{}")),
    (Artifact("client.conf", SYNTHETIC_SECRET),),
    (Artifact("client.conf", SYNTHETIC_SECRET), Artifact("transport.json", b"{}"), Artifact("added.json", b"{}")),
    (Artifact("transport.json", b"{}"), Artifact("client.conf", SYNTHETIC_SECRET)),
    (Artifact("client.conf", SYNTHETIC_SECRET, sensitive=False), Artifact("transport.json", b"{}")),
])
def test_ExpectedBundlePreservesValidDifferentOwnedContent(tmp_path: Path, replacement_files: tuple[Artifact, ...]) -> None:
    """Reject coherent same-identity replacement bytes, membership, order, or sensitivity metadata."""

    root = tmp_path / "artifacts"
    replacement = replace(Bundle(), files=replacement_files)
    directory = WriteArtifactBundle(root, replacement)
    before = {path.name: path.read_bytes() for path in directory.iterdir()}

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop", expected_bundle=Bundle())

    assert {path.name: path.read_bytes() for path in directory.iterdir()} == before, "Expected-content refusal must preserve every replacement file and manifest"
    assert not (root / ".device-laptop.lock").exists(), "Rejected cleanup must release only its own operation lock"
    assert RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop", expected_bundle=replacement), "Preserved replacement must remain a complete valid owned bundle"


@pytest.mark.parametrize("expected_bundle", [
    "invalid", replace(Bundle(), identity=replace(IDENTITY, owner_id="foreign")),
    replace(Bundle(), kind="server"), replace(Bundle(), name="different"),
])
def test_ExpectedBundleRequiresExactRequestedOwnership(tmp_path: Path, expected_bundle: object) -> None:
    """Reject malformed or foreign expected intent before authorizing a removal lock."""

    root, directory = Save(tmp_path)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop", expected_bundle=expected_bundle)  # type: ignore[arg-type]

    assert (directory / "client.conf").read_bytes() == SYNTHETIC_SECRET, "Invalid expected ownership must not alter current bundle content"
    assert not (root / ".device-laptop.lock").exists(), "Invalid expected intent must not leave an operation lock"


def test_DeviceProfilesAreExplicitExternalSecrets(tmp_path: Path) -> None:
    """Represent externally issued profiles without implying successful transport deployment."""

    bundle = BuildDeviceBundle(IDENTITY, "phone", "example-transport", (Artifact("client.conf", SYNTHETIC_SECRET),))
    directory = WriteArtifactBundle(tmp_path / "artifacts", bundle)
    descriptor = json.loads((directory / "device-info.json").read_bytes())

    assert descriptor["status"] == "externally-issued-unverified"
    assert descriptor["transport"] == "example-transport"
    assert (directory / "client.conf").read_bytes() == SYNTHETIC_SECRET

    for files in ((), [], ("bad",), (Artifact("client.conf", b"data", sensitive=False),), (Artifact("client.conf", b"data"),) * 8):
        with pytest.raises(ValueError):
            BuildDeviceBundle(IDENTITY, "phone", "transport", files)

    with pytest.raises(ValueError):
        BuildDeviceBundle(IDENTITY, "../phone", "transport", (Artifact("client.conf", b"data"),))

    with pytest.raises(ValueError):
        BuildDeviceBundle(IDENTITY, "phone", "bad transport", (Artifact("client.conf", b"data"),))

    with pytest.raises(ValueError):
        BuildDeviceBundle(IDENTITY, "phone", "transport", (Artifact("device-info.json", b"data"),))


@pytest.mark.parametrize("name", ["../client.conf", "/client.conf", "client.conf/extra", "manifest.json", ".client.conf", "client", "Client.conf", "client.conf\n"])
def test_ArtifactFilenameRejectsTraversalAndReservedNames(name: str) -> None:
    """Keep every generated file inside one bounded private bundle."""

    with pytest.raises(ArtifactError):
        Artifact(name, b"data")


@pytest.mark.parametrize("content", [b"", "secret", bytearray(b"data"), b"x" * (1048576 + 1)])
def test_ArtifactPayloadRequiresBoundedImmutableBytes(content: object) -> None:
    """Refuse coercion, mutable payloads, empty content, and unbounded profile responses."""

    with pytest.raises(ArtifactError):
        Artifact("client.conf", content)  # type: ignore[arg-type]

    with pytest.raises(ArtifactError):
        Artifact("client.conf", b"data", sensitive=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("changes", [
    {"identity": "bad"}, {"kind": "unknown"}, {"name": "../device"}, {"files": []},
    {"files": ()}, {"files": ("bad",)}, {"files": (Artifact("client.conf", b"data"),) * 9},
    {"files": (Artifact("client.conf", b"data"), Artifact("client.conf", b"other"))},
    {"files": tuple(Artifact(f"file-{index}.conf", b"x" * 1048576) for index in range(3))},
])
def test_BundleDirectConstructionIsStrict(changes: dict[str, object]) -> None:
    """Protect ownership, file-count, duplicate-name, and aggregate-size invariants."""

    with pytest.raises(ValueError):
        replace(Bundle(), **changes)


def test_BundleCollisionNeverReplacesOwnedOrForeignFiles(tmp_path: Path) -> None:
    """Require deliberate cleanup before replacing a published profile or colliding target."""

    root, directory = Save(tmp_path)
    original = {item.name: item.read_bytes() for item in directory.iterdir()}

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(root, Bundle())

    assert original == {item.name: item.read_bytes() for item in directory.iterdir()}
    assert list(root.glob("*.lock")) == []

    collision = root / "server-foreign"
    collision.write_bytes(b"foreign-content")

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(root, ArtifactBundle(IDENTITY, "server", "foreign", (Artifact("server.json", b"{}"),)))

    assert collision.read_bytes() == b"foreign-content"


def test_ExistingLockIsNeverRemoved(tmp_path: Path) -> None:
    """Preserve competing and crash locks for explicit operator recovery."""

    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    lock = root / ".device-laptop.lock"
    lock.write_bytes(b"foreign-lock")

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(root, Bundle())

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert lock.read_bytes() == b"foreign-lock"


@pytest.mark.parametrize("target", ["root", "parent", "bundle", "file", "manifest"])
def test_SymlinkBoundariesPreserveForeignTargets(tmp_path: Path, target: str) -> None:
    """Refuse following symlinks during writes, reads, and destructive cleanup."""

    foreign = tmp_path / "foreign"
    foreign.mkdir(mode=0o700)
    marker = foreign / "keep.conf"
    marker.write_bytes(b"foreign-content")
    marker.chmod(0o600)
    root = tmp_path / "artifacts"

    if target == "root":
        root.symlink_to(foreign, target_is_directory=True)

        with pytest.raises(ArtifactError):
            WriteArtifactBundle(root, Bundle())

    elif target == "parent":
        link = tmp_path / "link"
        link.symlink_to(foreign, target_is_directory=True)

        with pytest.raises(ArtifactError):
            WriteArtifactBundle(link / "artifacts", Bundle())

    else:
        root, directory = Save(tmp_path)

        if target == "bundle":
            directory.rename(root / "saved-device")
            directory.symlink_to(foreign, target_is_directory=True)

        else:
            path = directory / ("client.conf" if target == "file" else "manifest.json")
            path.unlink()
            path.symlink_to(marker)

        with pytest.raises(ArtifactError):
            RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert marker.read_bytes() == b"foreign-content"


def test_ForeignIdentityAndUnownedExtrasBlockAllCleanup(tmp_path: Path) -> None:
    """Validate complete ownership and the full directory before deleting the first file."""

    root, directory = Save(tmp_path)
    foreign = replace(IDENTITY, owner_id="foreign-owner")

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, foreign, kind="device", name="laptop")

    extra = directory / "unowned.txt"
    extra.write_bytes(b"foreign-content")

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert (directory / "client.conf").read_bytes() == SYNTHETIC_SECRET
    assert extra.read_bytes() == b"foreign-content"


@pytest.mark.parametrize("location", ["root", "bundle", "file", "manifest"])
def test_PermissionsMustRemainPrivate(tmp_path: Path, location: str) -> None:
    """Refuse publishing or deleting storage whose private-permission boundary changed."""

    root, directory = Save(tmp_path)
    target = {"root": root, "bundle": directory, "file": directory / "client.conf", "manifest": directory / "manifest.json"}[location]
    target.chmod(0o755 if target.is_dir() else 0o644)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert (directory / "client.conf").exists()


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("kind", "server"), ("name", "other"),
    ("identity", {}), ("extra", "synthetic-secret"), ("files", []), ("files", {}),
    ("files", [{}] * 9),
])
def test_ManifestSchemaCannotAuthorizeCleanup(tmp_path: Path, field: str, value: object) -> None:
    """Reject unknown fields, versions, missing ownership, and unbounded entries."""

    root, directory = Save(tmp_path)
    manifest = directory / "manifest.json"
    data = json.loads(manifest.read_bytes())
    data[field] = value
    manifest.write_text(json.dumps(data))

    with pytest.raises(ArtifactError) as caught:
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert "synthetic-secret" not in str(caught.value)
    assert (directory / "client.conf").read_bytes() == SYNTHETIC_SECRET


@pytest.mark.parametrize("field,value", [
    ("name", "../foreign.conf"), ("name", "manifest.json"), ("name", 1),
    ("size", True), ("size", 0), ("size", 1048577), ("size", 1),
    ("sensitive", "yes"), ("sha256", "wrong"), ("sha256", 1), ("sha256", "0" * 64),
    ("extra", "synthetic-secret"),
])
def test_ManifestFileClaimsRequireExactContent(tmp_path: Path, field: str, value: object) -> None:
    """Ensure unsafe names, weak digests, malformed sizes, and changes cannot be deleted."""

    root, directory = Save(tmp_path)
    manifest = directory / "manifest.json"
    data = json.loads(manifest.read_bytes())
    data["files"][0][field] = value
    manifest.write_text(json.dumps(data))

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert (directory / "client.conf").read_bytes() == SYNTHETIC_SECRET


def test_CorruptDuplicateChangedAndHardlinkedFilesArePreserved(tmp_path: Path) -> None:
    """Fail closed on corrupt ownership JSON and filesystem aliases or payload tampering."""

    root, directory = Save(tmp_path)
    manifest = directory / "manifest.json"
    original = manifest.read_bytes()

    for content in (b"invalid", b'{"schema_version":1,"schema_version":1}', b"x" * 16385, b"9" * 5000):
        manifest.write_bytes(content)

        with pytest.raises(ArtifactError):
            RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    manifest.write_bytes(original)
    data = json.loads(original)
    data["files"].append(data["files"][0])
    manifest.write_text(json.dumps(data))

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    manifest.write_bytes(original)
    client = directory / "client.conf"
    client.write_bytes(b"changed-content")

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    client.write_bytes(SYNTHETIC_SECRET)
    os.link(client, tmp_path / "outside.conf")

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert client.read_bytes() == SYNTHETIC_SECRET


def test_FifoReadIsRejectedWithoutBlocking(tmp_path: Path) -> None:
    """Avoid indefinite reads when a generated regular file is replaced by a FIFO."""

    root, directory = Save(tmp_path)
    path = directory / "client.conf"
    path.unlink()
    os.mkfifo(path, 0o600)

    with pytest.raises(ArtifactError):
        artifacts.ReadArtifactFile(path)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")


def test_ReadBoundAndFilesystemErrorsAreSanitized(tmp_path: Path) -> None:
    """Reject oversized private artifacts without retaining raw filesystem failure text."""

    root, directory = Save(tmp_path)
    path = directory / "client.conf"
    path.write_bytes(b"x" * 1048577)

    with pytest.raises(ArtifactError):
        artifacts.ReadArtifactFile(path)

    with pytest.raises(ArtifactError):
        artifacts.ReadArtifactFile(root / "missing.conf")

    with pytest.raises(ArtifactError):
        artifacts.ReadArtifactFile(root / ".." / "foreign.conf")


def test_PublishRollbackRemovesOnlyItsCreatedFiles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Clean a failed partial bundle while preserving preexisting unrelated directories."""

    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    preserved = root / "foreign"
    preserved.mkdir()
    original = artifacts._WriteFile

    def FailSecond(directory: int, name: str, content: bytes) -> artifacts._FileReceipt:
        """Inject a failure after one published payload."""

        if name == "transport.json":
            raise OSError("synthetic-secret-command-output")

        return original(directory, name, content)

    monkeypatch.setattr(artifacts, "_WriteFile", FailSecond)

    with pytest.raises(ArtifactError) as caught:
        WriteArtifactBundle(root, Bundle())

    assert "synthetic-secret" not in str(caught.value)
    assert list(root.iterdir()) == [preserved]


def test_FileWriteFailureClosesDescriptorAndUnlinksPartial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Release the descriptor and partial file when a write reports zero progress."""

    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    original_write = artifacts.os.write

    def ZeroWrite(file_descriptor: int, content: object) -> int:
        """Simulate a filesystem refusing forward progress."""

        return 0

    monkeypatch.setattr(artifacts.os, "write", ZeroWrite)

    try:
        with pytest.raises(OSError):
            artifacts._WriteFile(descriptor, "partial.conf", b"data")

        assert list(root.iterdir()) == []

    finally:
        monkeypatch.setattr(artifacts.os, "write", original_write)
        os.close(descriptor)


def test_PrivateStoragePlatformAndOwnerChecks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Declare missing Windows ACL support rather than silently weakening private storage."""

    root, directory = Save(tmp_path)
    info = list((directory / "client.conf").stat())
    info[4] = os.getuid() + 1

    with pytest.raises(ArtifactError):
        artifacts._RequireOwned(os.stat_result(info), directory=False)

    monkeypatch.setattr(artifacts, "os", SimpleNamespace(name="nt"))

    with pytest.raises(ArtifactError):
        with artifacts._Directory(root):
            pytest.fail("Unsupported platform must reject storage before opening it")


def test_ArgumentValidationAndParentCreationRemainBounded(tmp_path: Path) -> None:
    """Reject invalid bundle arguments and recursive parent creation without touching unrelated paths."""

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(tmp_path / "artifacts", "invalid")  # type: ignore[arg-type]

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(tmp_path / "absent-parent" / "artifacts", Bundle())

    for identity, kind, name in (("bad", "device", "laptop"), (IDENTITY, "unknown", "laptop"), (IDENTITY, "device", "../laptop")):
        with pytest.raises(ValueError):
            RemoveArtifactBundle(tmp_path / "artifacts", identity, kind=kind, name=name)  # type: ignore[arg-type]

    foreign = tmp_path / "foreign.conf"
    foreign.write_bytes(b"preserved")

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(foreign, Bundle())

    assert foreign.read_bytes() == b"preserved"


def test_PartialRemovalFailurePreservesManifestForRecovery(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Report interrupted cleanup without recursively deleting remaining or unknown contents."""

    root, directory = Save(tmp_path)
    original = artifacts.os.unlink

    def FailSecond(path: str, *, dir_fd: int | None = None) -> None:
        """Stop deletion after one verified owned file."""

        if path == "transport.json":
            raise OSError("synthetic-secret")

        original(path, dir_fd=dir_fd)

    monkeypatch.setattr(artifacts.os, "unlink", FailSecond)

    with pytest.raises(ArtifactError) as caught:
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert "partial cleanup" in str(caught.value)
    assert "synthetic-secret" not in str(caught.value)
    assert (directory / "manifest.json").exists() and (directory / "transport.json").exists()


def test_OwnedArtifactReadsVerifyEntireBundleBeforeReturningBytes(tmp_path: Path) -> None:
    """Keep deployment inputs bound to unchanged exact stack ownership rather than OS ownership alone."""

    root, directory = Save(tmp_path)
    path = directory / "client.conf"

    assert artifacts.ReadOwnedArtifactFile(path, IDENTITY, kind="device", name="laptop") == SYNTHETIC_SECRET

    for identity, kind, name in (
        (replace(IDENTITY, stack="foreign"), "device", "laptop"),
        (IDENTITY, "server", "laptop"), (IDENTITY, "device", "different"),
        ("invalid", "device", "laptop"), (IDENTITY, "invalid", "laptop"),
    ):
        with pytest.raises(ValueError):
            artifacts.ReadOwnedArtifactFile(path, identity, kind=kind, name=name)  # type: ignore[arg-type]

    with pytest.raises(ArtifactError):
        artifacts.ReadOwnedArtifactFile(directory / "manifest.json", IDENTITY, kind="device", name="laptop")

    (directory / "unowned.txt").write_bytes(b"unowned-content")

    with pytest.raises(ArtifactError):
        artifacts.ReadOwnedArtifactFile(path, IDENTITY, kind="device", name="laptop")

    assert root.is_dir() and path.read_bytes() == SYNTHETIC_SECRET


def test_WriteFailurePreservesAReplacementFile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not delete another inode substituted while an original write fails."""

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    path = root / "client.conf"

    def ReplaceThenFail(descriptor: int, content: object) -> int:
        """Replace the created path with a foreign synthetic file before reporting failure."""

        path.rename(root / "original.conf")
        path.write_bytes(b"foreign-replacement")
        path.chmod(0o600)

        raise OSError("Synthetic write failure")

    monkeypatch.setattr(artifacts.os, "write", ReplaceThenFail)

    with artifacts._Directory(root) as directory:
        with pytest.raises(ArtifactError):
            artifacts._WriteFile(directory, "client.conf", b"owned-data")

    assert path.read_bytes() == b"foreign-replacement"
    assert (root / "original.conf").read_bytes() == b""


def test_ReplacedLockIsPreservedForExplicitRecovery(tmp_path: Path) -> None:
    """Release only the exact original empty lock inode, never a substituted lock."""

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    path = root / ".device-laptop.lock"

    with artifacts._Directory(root) as directory:
        with pytest.raises(ArtifactError):
            with artifacts._BundleLock(directory, "device-laptop"):
                path.rename(root / ".original.lock")
                path.write_bytes(b"foreign-lock")
                path.chmod(0o600)

    assert path.read_bytes() == b"foreign-lock"


def test_RollbackPreservesReplacedPreviouslyCreatedFile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve foreign substitutions during rollback even after the first payload succeeded."""

    root = tmp_path / "private"
    path = root / "device-laptop" / "client.conf"
    original = artifacts._WriteFile

    def ReplaceThenFail(directory: int, name: str, content: bytes) -> artifacts._FileReceipt:
        """Substitute an already-written path before a later file fails."""

        if name == "transport.json":
            path.rename(path.with_name("original.conf"))
            path.write_bytes(b"foreign-replacement")
            path.chmod(0o600)

            raise OSError("Synthetic later write failure")

        return original(directory, name, content)

    monkeypatch.setattr(artifacts, "_WriteFile", ReplaceThenFail)

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(root, Bundle())

    assert path.read_bytes() == b"foreign-replacement"
    assert path.with_name("original.conf").read_bytes() == SYNTHETIC_SECRET


@pytest.mark.parametrize("replace_inode", [False, True])
def test_RemoveRechecksChangesAfterCompleteValidation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, replace_inode: bool) -> None:
    """Stop before any deletion when a validated file is modified or substituted."""

    root, directory = Save(tmp_path)
    path = directory / "client.conf"
    original = artifacts._ValidateManifest

    def ChangeAfterValidation(descriptor: int, identity: StackIdentity, kind: str, name: str) -> artifacts._BundleSnapshot:
        """Inject a noncooperating modification after a legitimate complete snapshot."""

        result = original(descriptor, identity, kind, name)

        if replace_inode:
            path.rename(path.with_name("original.conf"))

        path.write_bytes(b"foreign-replacement")
        path.chmod(0o600)

        return result

    monkeypatch.setattr(artifacts, "_ValidateManifest", ChangeAfterValidation)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert path.read_bytes() == b"foreign-replacement"
    assert (directory / "transport.json").read_bytes() == b"{}"
    assert (directory / "manifest.json").exists()


def test_OwnedReadReturnsVerifiedSnapshotInsteadOfUnboundReread(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Never return foreign bytes swapped in after manifest verification."""

    _, directory = Save(tmp_path)
    path = directory / "client.conf"
    original = artifacts._ValidateManifest

    def ChangeAfterValidation(descriptor: int, identity: StackIdentity, kind: str, name: str) -> artifacts._BundleSnapshot:
        """Modify the file after its immutable validated snapshot was captured."""

        result = original(descriptor, identity, kind, name)
        path.write_bytes(b"foreign-replacement")

        return result

    monkeypatch.setattr(artifacts, "_ValidateManifest", ChangeAfterValidation)
    content = artifacts.ReadOwnedArtifactFile(path, IDENTITY, kind="device", name="laptop")

    assert content == SYNTHETIC_SECRET
    assert path.read_bytes() == b"foreign-replacement"


def test_ReadRejectsConcurrentInPlaceModification(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not authorize a file whose modification metadata changes during the bounded read."""

    _, directory = Save(tmp_path)
    path = directory / "client.conf"
    original = artifacts.os.read
    changed = False

    def ChangeDuringRead(descriptor: int, length: int) -> bytes:
        """Return original bytes once and then simulate another same-user writer."""

        nonlocal changed
        result = original(descriptor, length)

        if not changed:
            changed = True
            path.write_bytes(b"foreign-replacement")

        return result

    monkeypatch.setattr(artifacts.os, "read", ChangeDuringRead)

    with pytest.raises(ArtifactError):
        artifacts.ReadArtifactFile(path)

    assert path.read_bytes() == b"foreign-replacement"


def test_ReplacedBundleDirectoryIsPreservedBeforeCleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not delete a foreign empty directory substituted after complete manifest verification."""

    root, directory = Save(tmp_path)
    saved = root / "saved-owned"
    original = artifacts._ValidateManifest

    def ReplaceAfterValidation(descriptor: int, identity: StackIdentity, kind: str, name: str) -> artifacts._BundleSnapshot:
        """Move the pinned owned directory and replace its name with an empty foreign one."""

        snapshot = original(descriptor, identity, kind, name)
        directory.rename(saved)
        directory.mkdir(mode=0o700)

        return snapshot

    monkeypatch.setattr(artifacts, "_ValidateManifest", ReplaceAfterValidation)

    with pytest.raises(ArtifactError):
        RemoveArtifactBundle(root, IDENTITY, kind="device", name="laptop")

    assert directory.is_dir() and list(directory.iterdir()) == []
    assert (saved / "client.conf").read_bytes() == SYNTHETIC_SECRET
    assert (saved / "manifest.json").exists()


def test_RollbackPreservesReplacedBundleDirectory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse rollback when the named bundle no longer identifies the pinned created directory."""

    root = tmp_path / "artifacts"
    directory = root / "device-laptop"
    saved = root / "saved-owned"
    original = artifacts._WriteFile

    def ReplaceThenFail(descriptor: int, name: str, content: bytes) -> artifacts._FileReceipt:
        """Substitute the bundle name after one successful payload."""

        if name == "transport.json":
            directory.rename(saved)
            directory.mkdir(mode=0o700)

            raise OSError("Synthetic partial publication failure")

        return original(descriptor, name, content)

    monkeypatch.setattr(artifacts, "_WriteFile", ReplaceThenFail)

    with pytest.raises(ArtifactError):
        WriteArtifactBundle(root, Bundle())

    assert directory.is_dir() and list(directory.iterdir()) == []
    assert (saved / "client.conf").read_bytes() == SYNTHETIC_SECRET
