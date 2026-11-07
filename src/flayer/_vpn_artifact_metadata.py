"""Verify retained public artifact summaries without reading private payloads or authorizing their use or deletion."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from flayer._vpn_creation import _Decode, _Json
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles.artifacts import (
    MAX_ARTIFACT_BYTES,
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_FILES,
    MAX_MANIFEST_BYTES,
    _AssertDirectory,
    _AssertFile,
    _Directory,
    _ReadSnapshot,
    _RequireOwned,
    _StatKey,
    _ValidatePath,
)
from flayer.profiles.vpn import VpnError

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILE = re.compile(r"[a-z][a-z0-9-]{0,62}\.[a-z0-9]{1,12}\Z")


@dataclass(frozen=True, slots=True)
class FileSummary:
    """One nonsecret declared file identity; the digest does not assert that its private payload is present or healthy."""

    name: str
    size: int
    sha256: str
    sensitive: bool

    def __post_init__(self) -> None:
        """Exclude scalar/model extensions before serializing a declared file reference."""

        if (type(self) is not FileSummary or type(self.name) is not str or _FILE.fullmatch(self.name) is None or self.name == "manifest.json"
                or type(self.size) is not int or not 1 <= self.size <= MAX_ARTIFACT_BYTES
                or type(self.sha256) is not str or _HASH.fullmatch(self.sha256) is None or type(self.sensitive) is not bool):
            raise VpnError("Artifact summary requires closed bounded file metadata")


@dataclass(frozen=True, slots=True)
class BundleSummary:
    """Complete externally pinned manifest metadata, independent of any private file's availability."""

    identity: StackIdentity
    name: str
    files: tuple[FileSummary, ...]

    def __post_init__(self) -> None:
        """Keep summaries owner-bound and within the same artifact capacities as full private readers."""

        if (type(self) is not BundleSummary or type(self.identity) is not StackIdentity
                or any(type(value) is not str for value in (self.identity.project, self.identity.stack, self.identity.provider,
                                                          self.identity.scopeId, self.identity.ownerId))
                or type(self.name) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.name) is None
                or type(self.files) is not tuple or not 1 <= len(self.files) <= MAX_BUNDLE_FILES
                or any(type(item) is not FileSummary for item in self.files)
                or len({item.name for item in self.files}) != len(self.files)):
            raise VpnError("Artifact summary requires complete bounded owner and file declarations")

        for item in self.files:
            FileSummary.__post_init__(item)

        if sum(item.size for item in self.files) > MAX_BUNDLE_BYTES:
            raise VpnError("Artifact summary exceeds the complete bundle capacity")

    def Digest(self) -> str:
        """Match BundleDigest's complete owner/name/file metadata hash without manufacturing payload bytes."""

        BundleSummary.__post_init__(self)

        return hashlib.sha256(_Json({"identity": _WireDict(self.identity), "kind": "server", "name": self.name,
            "files": [_WireDict(item) for item in sorted(self.files, key=lambda item: item.name)]})).hexdigest()


def DecodeSummary(content: bytes, identity: StackIdentity, name: str, expected: str) -> BundleSummary:
    """Require a complete unchanged owned manifest and full external bundle pin before permitting nonsecret traversal."""

    if (type(identity) is not StackIdentity
            or any(type(value) is not str for value in (identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId))
            or type(name) is not str or type(expected) is not str or _HASH.fullmatch(expected) is None
            or type(content) is not bytes or not 1 <= len(content) <= MAX_MANIFEST_BYTES):
        raise VpnError("Artifact metadata requires explicit bounded ownership and a full external digest")

    result = None

    try:
        value = _Decode(content)

        if (set(value) != {"schema_version", "identity", "kind", "name", "files"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["identity"] != _WireDict(identity) or value["kind"] != "server" or value["name"] != name
                or type(value["files"]) is not list or not 1 <= len(value["files"]) <= MAX_BUNDLE_FILES):
            raise ValueError

        files = []

        for raw in value["files"]:
            if type(raw) is not dict or set(raw) != {"name", "size", "sha256", "sensitive"}:
                raise ValueError

            files.append(FileSummary(raw["name"], raw["size"], raw["sha256"], raw["sensitive"]))

        candidate = BundleSummary(identity, name, tuple(files))

        if candidate.Digest() != expected:
            raise ValueError

        result = candidate

    except (ValueError, TypeError, RecursionError):
        pass

    if result is None:
        raise VpnError("Retained artifact manifest is malformed, foreign or differs from its complete bundle pin")

    return result


def ReadSummary(directory: Path, identity: StackIdentity, name: str, expected: str, *, publicFile: str = "") -> tuple[BundleSummary, bytes | None]:
    """Read only a pinned manifest and optional declared public file; present payloads are inspected with stat, never opened."""

    if (type(directory) is not type(Path()) or type(identity) is not StackIdentity
            or any(type(value) is not str for value in (identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId))
            or type(name) is not str or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name) is None
            or type(expected) is not str or _HASH.fullmatch(expected) is None
            or type(publicFile) is not str or publicFile and _FILE.fullmatch(publicFile) is None
            or directory.name != "server-" + name):
        raise VpnError("Artifact metadata path must select its exact server bundle and public entry")

    result: tuple[BundleSummary, bytes | None] | None = None

    try:
        _ValidatePath(directory / "manifest.json")

        with _Directory(directory.parent) as parent, _Directory(directory) as descriptor:
            content, manifest = _ReadSnapshot(descriptor, "manifest.json", MAX_MANIFEST_BYTES)
            summary = DecodeSummary(content, identity, name, expected)
            names = set(os.listdir(descriptor))

            if names - {"manifest.json", *(item.name for item in summary.files)}:
                raise VpnError("Artifact metadata contains unknown files")

            present = {}

            for item in summary.files:
                if item.name not in names:
                    continue

                info = os.stat(item.name, dir_fd=descriptor, follow_symlinks=False)
                _RequireOwned(info, directory=False)

                if info.st_size != item.size:
                    raise VpnError("Present artifact size differs from its retained metadata")

                present[item.name] = _StatKey(info)

            public = None

            if publicFile:
                entry = next((item for item in summary.files if item.name == publicFile), None)

                if entry is None or entry.sensitive:
                    raise VpnError("Metadata traversal cannot open a private payload or an undeclared file")

                public, receipt = _ReadSnapshot(descriptor, publicFile, MAX_ARTIFACT_BYTES)

                if receipt.sha256 != entry.sha256 or len(public) != entry.size:
                    raise VpnError("Public artifact metadata differs from its pinned payload digest")

                _AssertFile(descriptor, publicFile, receipt)

            _AssertFile(descriptor, "manifest.json", manifest)

            if set(os.listdir(descriptor)) != names:
                raise VpnError("Artifact membership changed during nonsecret traversal")

            for filename, key in present.items():
                info = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
                _RequireOwned(info, directory=False)

                if _StatKey(info) != key:
                    raise VpnError("Artifact metadata changed during nonsecret traversal")

            _AssertDirectory(parent, directory.name, descriptor)
            result = summary, public

    except (OSError, ValueError, RecursionError):
        pass

    if result is None:
        raise VpnError("Unable to read unchanged owned artifact metadata; no private payload was opened")

    return result
