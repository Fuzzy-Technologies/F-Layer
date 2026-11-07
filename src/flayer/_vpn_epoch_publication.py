"""Publish one exact completed protocol epoch through a retained private journal, without dispatching cloud or guest operations."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from flayer import _vpn_protocol_epochs as epochs
from flayer._vpn_creation import BundleDigest, _Decode, _Json
from flayer._vpn_ingress_journal import DecodeJournal, IngressJournal
from flayer.guest import ReadPrivate
from flayer.profiles import artifacts
from flayer.profiles.artifacts import Artifact, ArtifactBundle
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject

MAX_PUBLICATION_BYTES = 2 * 1024 * 1024
_PENDING = "protocol-pending.json"
_HEAD = "protocol-head.json"
_FILES = ("epoch.json", "cloud.json", "input.json", "services.json")


@dataclass(frozen=True, slots=True)
class EpochPublication:
    """Expected public evidence is prepared before completion; observed means an exact authenticated response was supplied separately."""

    epoch: epochs.EpochCommit = field(repr=False)
    phase: str = "prepared"

    def __post_init__(self) -> None:
        """Keep the candidate closed and bounded; its predicted completion alone grants no publication authority."""

        if type(self) is not EpochPublication or type(self.epoch) is not epochs.EpochCommit or type(self.phase) is not str or self.phase not in {"prepared", "observed"}:
            raise VpnError("Epoch publication requires an exact candidate and recognized acknowledgment phase")

        epochs.EpochCommit.__post_init__(self.epoch)

        if len(_Json(self.Record())) > MAX_PUBLICATION_BYTES:
            raise VpnError("Epoch publication exceeds its complete retained evidence bound")

    def Record(self) -> dict[str, Any]:
        """Retain all four canonical public files without storing server payloads, paths or private credentials."""

        bundle = self.epoch.Bundle()

        return {"schema_version": 1, "phase": self.phase, "name": bundle.name,
                "files": {item.name: json.loads(item.content) for item in bundle.files}}


def DecodePublication(project: SelectedVpnProject, content: bytes) -> EpochPublication:
    """Reject duplicate/noncanonical fields and cross-bind all evidence through the existing complete epoch codec."""

    def Unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Accept only one interpretation at every nested JSON boundary."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError

            result[key] = value

        return result

    candidate = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= MAX_PUBLICATION_BYTES:
            raise ValueError

        value = json.loads(content, object_pairs_hook=Unique)

        if (type(value) is not dict or set(value) != {"schema_version", "phase", "name", "files"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or type(value["files"]) is not dict or set(value["files"]) != set(_FILES)):
            raise ValueError

        bundle = ArtifactBundle(project.vpn.identity, "server", value["name"], tuple(Artifact(name, _Json(value["files"][name]), False) for name in _FILES))
        candidate = EpochPublication(epochs.DecodeEpochBundle(bundle), value["phase"])

        if _Json(candidate.Record()) != content:
            raise ValueError

    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        candidate = None

    if candidate is None:
        raise VpnError("Epoch publication journal is malformed, foreign or noncanonical")

    return candidate


def LoadPublication(project: SelectedVpnProject) -> EpochPublication | None:
    """Read only the canonical retained candidate; interrupted temporary publication requires explicit recovery."""

    path = project.root / _PENDING

    return DecodePublication(project, ReadPrivate(path, limit=MAX_PUBLICATION_BYTES)) if path.exists() or path.is_symlink() else None


def _Directory(path: Path, descriptor: int) -> None:
    """Require the pinned private directory to retain its exact public pathname throughout a durability barrier."""

    current, linked = os.fstat(descriptor), path.lstat()
    artifacts._RequireOwned(current, directory=True)
    artifacts._RequireOwned(linked, directory=True)

    if (current.st_dev, current.st_ino) != (linked.st_dev, linked.st_ino):
        raise VpnError("Epoch publication directory was replaced")


def _ExactFile(directory: int, name: str, expected: bytes, *, append: bool = False, sync: bool = False) -> None:
    """Finish only an exact owned byte prefix, or verify a complete immutable file, through one pinned descriptor."""

    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT if append else os.O_RDONLY
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)

    try:
        before = os.fstat(descriptor)
        artifacts._RequireOwned(before, directory=False)
        content = os.pread(descriptor, len(expected) + 1, 0)
        current = os.fstat(descriptor)

        if (artifacts._StatKey(before) != artifacts._StatKey(current) or len(content) != before.st_size
                or (not expected.startswith(content) if append else content != expected)):
            raise VpnError("Epoch publication file differs from its exact authorized bytes")

        linked = os.stat(name, dir_fd=directory, follow_symlinks=False)

        if artifacts._StatKey(before) != artifacts._StatKey(linked):
            raise VpnError("Epoch publication file changed during observation")

        offset = len(content)

        while append and offset < len(expected):
            written = os.write(descriptor, expected[offset:])

            if written <= 0:
                raise VpnError("Epoch publication could not finish its exact byte prefix")

            offset += written

        ready = os.fstat(descriptor)

        if sync or append:
            os.fsync(descriptor)

        current, linked = os.fstat(descriptor), os.stat(name, dir_fd=directory, follow_symlinks=False)
        artifacts._RequireOwned(current, directory=False)
        artifacts._RequireOwned(linked, directory=False)

        if (artifacts._StatKey(current) != artifacts._StatKey(linked) or artifacts._StatKey(ready) != artifacts._StatKey(current)
                or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
                or os.pread(descriptor, len(expected) + 1, 0) != expected):
            raise VpnError("Epoch publication file changed before acknowledgment")

    finally:
        os.close(descriptor)


def _Optional(path: Path, *, limit: int = MAX_PUBLICATION_BYTES) -> bytes | None:
    """Distinguish exact private bytes from true absence without treating a symlink as missing."""

    return ReadPrivate(path, limit=limit) if path.exists() or path.is_symlink() else None


def _Publish(project: SelectedVpnProject, name: str, content: bytes, previous: bytes | None) -> None:
    """Durably replace one fixed mutable record using only its exact authorized temporary prefix and previous bytes."""

    if name not in {_PENDING, _HEAD} or not 1 <= len(content) <= MAX_PUBLICATION_BYTES:
        raise VpnError("Unsupported epoch publication record")

    path, temporary = project.root / name, "." + name + ".new"

    with artifacts._Directory(project.root) as directory:
        _Directory(project.root, directory)

        if _Optional(path) != previous:
            raise VpnError("Epoch publication mutable authority changed before replacement")

        _ExactFile(directory, temporary, content, append=True)
        _Directory(project.root, directory)

        if _Optional(path) != previous:
            raise VpnError("Epoch publication mutable authority changed during preparation")

        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        _Directory(project.root, directory)
        _ExactFile(directory, name, content, sync=True)


def _Retire(project: SelectedVpnProject, name: str, content: bytes) -> None:
    """Unlink only a fixed exact acknowledged journal, retaining any replacement or unexpected temporary file."""

    if name not in {_PENDING, "protocol-ingress-pending.json"}:
        raise VpnError("Unsupported epoch journal retirement")

    with artifacts._Directory(project.root) as directory:
        _Directory(project.root, directory)
        _ExactFile(directory, name, content, sync=True)
        raw, receipt = artifacts._ReadSnapshot(directory, name, MAX_PUBLICATION_BYTES)

        if raw != content or (project.root / ("." + name + ".new")).exists() or (project.root / ("." + name + ".new")).is_symlink():
            raise VpnError("Epoch publication journal changed before retirement")

        artifacts._AssertFile(directory, name, receipt)
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
        _Directory(project.root, directory)

        if (project.root / name).exists() or (project.root / name).is_symlink():
            raise VpnError("Epoch publication journal reappeared during retirement")


def _Head(project: SelectedVpnProject) -> dict[str, str] | None:
    """Read the complete canonical local authority without inferring it from an orphan epoch bundle."""

    raw = _Optional(project.root / _HEAD, limit=65536)

    if raw is None:
        return None

    value = _Decode(raw)
    pointer = epochs._Pointer(value, re.escape(project.vpn.identity.stack) + r"-ep-[0-9a-f]{16}")

    if pointer is None or _Json(pointer) != raw:
        raise VpnError("Epoch publication requires an exact nonempty canonical head")

    return pointer


def _Ingress(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> IngressJournal | None:
    """Require any retained dispatch journal to match a complete known terminal original or compensating operation."""

    path = project.root / ".protocol-ingress-pending.json.new"

    if path.exists() or path.is_symlink():
        raise VpnError("Ingress publication must be reconciled before epoch completion")

    raw = _Optional(project.root / "protocol-ingress-pending.json")

    if raw is None:
        return None

    journal = DecodeJournal(raw)
    metadata = epochs._Metadata(epoch.metadata, epoch.identity)
    original = journal.plan == epoch.cloud.plan
    operation = epoch.cloud.operation if original else epoch.cloud.restorationOperation
    reference = None if operation is None else operation.reference

    if (journal.creationSha256 != metadata["creation_sha256"] or journal.previousStateSha256 != metadata["previous_state_sha256"]
            or not original and journal.plan != epoch.cloud.restoration
            or journal.phase != ("prepared" if reference is None else "recorded") or journal.operation != reference
            or not any(item["name"] == journal.Bundle().name and item["sha256"] == BundleDigest(journal.Bundle()) for item in metadata["ingress_intents"])):
        raise VpnError("Epoch publication cannot retire unknown or differently bound ingress dispatch")

    return journal


def _Before(project: SelectedVpnProject, publication: EpochPublication) -> epochs.ProtocolGraph:
    """Validate the complete old graph plus only this candidate's confined additional artifacts and empty next segment."""

    epoch = publication.epoch
    metadata = epochs._Metadata(epoch.metadata, epoch.identity)
    pointer = {"name": epoch.Bundle().name, "sha256": epoch.Digest()}
    head = _Head(project)

    if (epoch.identity != project.vpn.identity or head not in (metadata["parent"], pointer)
            or head == pointer and publication.phase != "observed"):
        raise VpnError("Epoch publication does not continue its exact retained local head")

    graph = epochs._LoadGraph(project, metadata["parent"], staged=epoch)
    epochs.RequireGraphCapacity(graph, epoch.cloud.plan)
    epochs._Continue(project, graph, epoch)
    epochs._IngressIntents(project, epoch)

    return graph


def _Bundle(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> None:
    """Complete manifest-last public files from their journal-bound exact prefixes; unrelated or replaced files are preserved."""

    bundle = epoch.Bundle()
    name = "server-" + bundle.name
    files = [(item.name, item.content) for item in bundle.files] + [("manifest.json", artifacts._Manifest(bundle))]

    with artifacts._Directory(project.Artifacts) as parent:
        _Directory(project.Artifacts, parent)

        if (project.Artifacts / ("." + name + ".lock")).exists() or (project.Artifacts / ("." + name + ".lock")).is_symlink():
            raise VpnError("Existing epoch artifact publication lock requires inspection")

        try:
            os.mkdir(name, 0o700, dir_fd=parent)

        except FileExistsError:
            pass

        with artifacts._Directory(project.Artifacts / name) as directory:
            artifacts._AssertDirectory(parent, name, directory)
            actual = set(os.listdir(directory))
            names = [filename for filename, _ in files]

            if actual != set(names[:len(actual)]):
                raise VpnError("Epoch bundle contains unknown or out-of-order publication files")

            receipts = []

            for index, (filename, content) in enumerate(files):
                if index < len(actual) - 1:
                    _ExactFile(directory, filename, content)

                else:
                    _ExactFile(directory, filename, content, append=True)

                raw, receipt = artifacts._ReadSnapshot(directory, filename, artifacts.MAX_ARTIFACT_BYTES)

                if raw != content:
                    raise VpnError("Epoch bundle changed during exact publication")

                receipts.append((filename, receipt))
                artifacts._AssertDirectory(parent, name, directory)
                stamp = artifacts._StatKey(os.fstat(directory))
                os.fsync(directory)

                if artifacts._StatKey(os.fstat(directory)) != stamp:
                    raise VpnError("Epoch bundle membership changed during synchronization")

                for currentName, pinned in receipts:
                    artifacts._AssertFile(directory, currentName, pinned)

            stamp = artifacts._StatKey(os.fstat(directory))
            os.fsync(parent)
            artifacts._AssertDirectory(parent, name, directory)

            if artifacts._StatKey(os.fstat(directory)) != stamp:
                raise VpnError("Epoch bundle membership changed at its parent barrier")

            for currentName, pinned in receipts:
                artifacts._AssertFile(directory, currentName, pinned)

            snapshot = artifacts._ValidateManifest(directory, bundle.identity, bundle.kind, bundle.name)

            if {item.name: item.content for item in snapshot.files} != {item.name: item.content for item in bundle.files}:
                raise VpnError("Published epoch bundle differs from its complete retained candidate")

            _Directory(project.Artifacts, parent)

    artifacts._SyncArtifactBundle(project.Artifacts, bundle)


def _Segment(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> None:
    """Prepare only the exact empty next peer namespace, synchronizing its directories before head publication."""

    parent = project.root / "protocol-epochs"

    with artifacts._Directory(project.root) as root:
        try:
            os.mkdir("protocol-epochs", 0o700, dir_fd=root)

        except FileExistsError:
            pass

        with artifacts._Directory(parent) as directory:
            artifacts._AssertDirectory(root, "protocol-epochs", directory)

            try:
                os.mkdir(epoch.Digest(), 0o700, dir_fd=directory)

            except FileExistsError:
                pass

            with artifacts._Directory(parent / epoch.Digest()) as segment:
                artifacts._AssertDirectory(directory, epoch.Digest(), segment)

                if os.listdir(segment):
                    raise VpnError("Unpublished next peer segment must remain empty")

                stamps = [(descriptor, artifacts._StatKey(os.fstat(descriptor))) for descriptor in (segment, directory, root)]
                os.fsync(segment)
                os.fsync(directory)
                os.fsync(root)
                artifacts._AssertDirectory(directory, epoch.Digest(), segment)
                artifacts._AssertDirectory(root, "protocol-epochs", directory)
                _Directory(project.root, root)

                if any(artifacts._StatKey(os.fstat(descriptor)) != stamp for descriptor, stamp in stamps) or os.listdir(segment):
                    raise VpnError("Epoch peer namespace membership changed during synchronization")


@contextmanager
def _PinnedBundle(project: SelectedVpnProject, epoch: epochs.EpochCommit) -> Iterator[Callable[[], None]]:
    """Retain every verified immutable inode across later segment/head/journal barriers, not merely during bundle construction."""

    bundle = epoch.Bundle()
    name = "server-" + bundle.name

    with ExitStack() as stack:
        root = stack.enter_context(artifacts._Directory(project.root))
        parent = stack.enter_context(artifacts._Directory(project.Artifacts))
        directory = stack.enter_context(artifacts._Directory(project.Artifacts / name))
        snapshot = artifacts._ValidateManifest(directory, bundle.identity, bundle.kind, bundle.name)

        if ({item.name: item.content for item in snapshot.files} != {item.name: item.content for item in bundle.files}
                or snapshot.manifest.sha256 != hashlib.sha256(artifacts._Manifest(bundle)).hexdigest()):
            raise VpnError("Epoch publication cannot pin a different immutable bundle")

        stamp = artifacts._StatKey(os.fstat(directory))
        pinned = []

        for filename, receipt in [(item.name, item.receipt) for item in snapshot.files] + [("manifest.json", snapshot.manifest)]:
            descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            stack.callback(os.close, descriptor)

            if artifacts._StatKey(os.fstat(descriptor)) != (receipt.device, receipt.inode, receipt.size, receipt.modifiedNs, receipt.changedNs):
                raise VpnError("Epoch immutable file changed before its lifetime pin")

            pinned.append(descriptor)

        def Verify() -> None:
            """Detect same-byte replacements, in-place edits and directory membership ABA before retiring publication protection."""

            try:
                _Directory(project.root, root)
                _Directory(project.Artifacts, parent)
                artifacts._AssertDirectory(parent, name, directory)

                if (artifacts._StatKey(os.fstat(directory)) != stamp
                        or artifacts._ValidateManifest(directory, bundle.identity, bundle.kind, bundle.name) != snapshot):
                    raise ValueError

            except (OSError, ValueError):
                raise VpnError("Pinned epoch bundle changed during completed-state publication") from None

        Verify()

        for descriptor in pinned:
            os.fsync(descriptor)
            Verify()

        os.fsync(directory)
        os.fsync(parent)
        Verify()
        yield Verify
        Verify()


def _CommitPrepared(
    project: SelectedVpnProject, observed: EpochPublication, current: EpochPublication,
    ingress: IngressJournal | None, pointer: dict[str, str],
) -> epochs.ProtocolGraph:
    """Restore only the same observed protection after snapshot drift, including final traversal and context-exit verification."""

    root = project.root.lstat()

    try:
        return _PublishPrepared(project, observed, current, ingress, pointer)

    except ValueError:
        linked = project.root.lstat()

        if ((root.st_dev, root.st_ino) == (linked.st_dev, linked.st_ino)
                and _Optional(project.root / _PENDING) is None and _Head(project) == pointer):
            _Publish(project, _PENDING, _Json(observed.Record()), None)

        raise


def _PublishPrepared(
    project: SelectedVpnProject, observed: EpochPublication, current: EpochPublication,
    ingress: IngressJournal | None, pointer: dict[str, str],
) -> epochs.ProtocolGraph:
    """Keep the complete immutable snapshot protected until final traversal and the pinned context both return successfully."""

    with _PinnedBundle(project, observed.epoch) as verify:
        _Publish(project, _PENDING, _Json(observed.Record()), _Json(current.Record()))
        verify()
        _Segment(project, observed.epoch)
        verify()
        _Before(project, observed)
        graph = epochs._LoadGraph(project, pointer)

        if graph.epochs[-1] != observed.epoch or graph.revision.recordCount:
            raise VpnError("Epoch publication cannot adopt a changed completed candidate or next peer segment")

        previousHead = _Head(project)
        parent = epochs._Metadata(observed.epoch.metadata, observed.epoch.identity)["parent"]

        if previousHead not in (parent, pointer):
            raise VpnError("Epoch publication head changed before exact replacement")

        verify()
        _Publish(project, _HEAD, _Json(pointer), None if previousHead is None else _Json(previousHead))
        verify()

        if ingress is not None:
            _Retire(project, "protocol-ingress-pending.json", _Json(ingress.Record()))
            verify()

        _Before(project, observed)
        graph = epochs._LoadGraph(project, pointer)

        if (graph.epochs[-1] != observed.epoch or graph.revision.recordCount or _Head(project) != pointer
                or any(_Optional(project.root / name) is not None for name in
                       (".protocol-head.json.new", "protocol-ingress-pending.json", ".protocol-ingress-pending.json.new"))):
            raise VpnError("Epoch publication has unexplained temporary metadata before retirement")

        verify()

        _Retire(project, _PENDING, _Json(observed.Record()))
        verify()

        return epochs.LoadCommittedGraph(project)


def PreparePublication(project: SelectedVpnProject, epoch: epochs.EpochCommit, *, allowMutation: bool = False) -> EpochPublication:
    """Under ProjectLock, retain the full expected public candidate before requesting guest completion; no dispatch or authority is granted."""

    expected = EpochPublication(epoch)

    if allowMutation is not True:
        raise VpnError("Epoch publication preparation requires explicit mutation consent")

    current = LoadPublication(project)

    if current not in (None, expected):
        raise VpnError("Another or already acknowledged epoch publication requires its exact recovery")

    if (current is None and ((project.Artifacts / ("server-" + epoch.Bundle().name)).exists()
                            or (project.Artifacts / ("server-" + epoch.Bundle().name)).is_symlink()
                            or (project.root / "protocol-epochs" / epoch.Digest()).exists()
                            or (project.root / "protocol-epochs" / epoch.Digest()).is_symlink())):
        raise VpnError("An orphan epoch or peer segment cannot reconstruct missing publication authority")

    if _Optional(project.root / ".protocol-head.json.new") is not None:
        raise VpnError("Unacknowledged epoch preparation cannot explain a head publication")

    _Ingress(project, epoch)
    _Before(project, expected)
    raw = None if current is None else _Json(current.Record())
    _Publish(project, _PENDING, _Json(expected.Record()), raw)
    _Bundle(project, epoch)

    return expected


def CommitPublication(
    project: SelectedVpnProject, expected: EpochPublication, completion: bytes, *, allowMutation: bool = False,
) -> epochs.ProtocolGraph:
    """Under ProjectLock, record the exact authenticated guest response before publishing its epoch; this function performs no live attestation."""

    EpochPublication.__post_init__(expected)

    if allowMutation is not True or type(completion) is not bytes or completion != expected.epoch.completion:
        raise VpnError("Epoch publication requires consent and the exact separately observed guest completion")

    observed = replace(expected, phase="observed")
    current = LoadPublication(project)
    pointer = {"name": expected.epoch.Bundle().name, "sha256": expected.epoch.Digest()}

    if current is None:
        if _Head(project) != pointer:
            raise VpnError("Missing epoch publication journal is never reconstructed from a candidate")

        with artifacts._Directory(project.root) as directory:
            os.fsync(directory)
            _Directory(project.root, directory)

        graph = epochs.LoadCommittedGraph(project)

        if graph.epochs[-1] != expected.epoch:
            raise VpnError("Historical publication replay differs from the actual committed epoch")

        return graph

    if current not in (replace(expected, phase="prepared"), observed):
        raise VpnError("Epoch acknowledgment differs from the retained publication candidate")

    temporaryHead = _Optional(project.root / ".protocol-head.json.new", limit=65536)

    if temporaryHead is not None and (current.phase != "observed" or not _Json(pointer).startswith(temporaryHead)):
        raise VpnError("Epoch head temporary bytes differ from the exact acknowledged publication")

    ingress = _Ingress(project, expected.epoch)
    _Before(project, current)
    _Bundle(project, expected.epoch)

    return _CommitPrepared(project, observed, current, ingress, pointer)
