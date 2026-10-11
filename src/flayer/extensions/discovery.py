"""Bounded static discovery from exact caller-selected installed distribution metadata."""

from __future__ import annotations

import configparser
import hashlib
import os
import stat
from collections.abc import Sequence
from email import policy
from email.parser import BytesParser
from pathlib import Path

from .contracts import (
    PROFILE_GROUP,
    PROVIDER_GROUP,
    ExtensionDescriptor,
    ExtensionError,
    ExtensionKind,
)

MAX_METADATA_BYTES = 262144
MAX_METADATA_DIRECTORIES = 128
MAX_EXTENSIONS = 256
METADATA_FILES = ("METADATA", "entry_points.txt", "RECORD")


class _EntryPointsParser(configparser.ConfigParser):
    """Preserve externally declared entry-point names instead of case-folding them."""

    def optionxform(self, optionstr: str) -> str:
        """Honor ConfigParser's callback naming contract while preserving identity."""

        return optionstr


def ReadMetadataFile(path: Path, maximum: int = MAX_METADATA_BYTES) -> bytes:
    """Read one regular non-linked bounded file without following a final symlink."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

        with os.fdopen(descriptor, "rb") as stream:
            receipt = os.fstat(stream.fileno())

            if (
                not stat.S_ISREG(receipt.st_mode) or receipt.st_nlink != 1
                or receipt.st_size > maximum
            ):
                raise ExtensionError("Extension metadata or source must be a bounded regular file")

            content = stream.read(maximum + 1)
            final_receipt = os.fstat(stream.fileno())

            if (
                len(content) > maximum or len(content) != receipt.st_size
                or (receipt.st_ino, receipt.st_size, receipt.st_mtime_ns, receipt.st_ctime_ns)
                != (
                    final_receipt.st_ino, final_receipt.st_size,
                    final_receipt.st_mtime_ns, final_receipt.st_ctime_ns,
                )
            ):
                raise ExtensionError("Extension metadata or source changed during its bounded read")

    except OSError:
        raise ExtensionError("Unable to read exact extension metadata or source") from None

    return content


def ReadMetadataSnapshot(directory: Path) -> tuple[tuple[bytes, ...], str]:
    """Pin only the three explicit metadata files under one selected dist-info directory."""

    try:
        if (
            not isinstance(directory, Path) or not directory.is_absolute()
            or not directory.name.endswith(".dist-info") or directory.is_symlink()
            or directory.resolve() != directory or not directory.is_dir()
        ):
            raise ExtensionError("Discovery requires an exact absolute non-redirected dist-info directory")

    except (OSError, RuntimeError):
        raise ExtensionError("Unable to resolve exact non-redirected extension metadata") from None

    contents = tuple(ReadMetadataFile(directory / name) for name in METADATA_FILES)
    digest = hashlib.sha256()

    for name, content in zip(METADATA_FILES, contents, strict=True):
        digest.update(name.encode("ascii") + b"\x00")
        digest.update(len(content).to_bytes(8, "big") + content)

    return contents, digest.hexdigest()


def DiscoverExtensions(metadata_directories: Sequence[Path]) -> tuple[ExtensionDescriptor, ...]:
    """Parse selected metadata without importing code, calling finders, or searching paths."""

    if (
        not isinstance(metadata_directories, (tuple, list))
        or len(metadata_directories) > MAX_METADATA_DIRECTORIES
        or any(not isinstance(directory, Path) for directory in metadata_directories)
        or len(set(metadata_directories)) != len(metadata_directories)
    ):
        raise ExtensionError("Discovery requires bounded unique explicit metadata directories")

    descriptors: list[ExtensionDescriptor] = []
    identities: set[tuple[ExtensionKind, str]] = set()

    for directory in metadata_directories:
        contents, digest = ReadMetadataSnapshot(directory)

        try:
            metadata = BytesParser(policy=policy.default).parsebytes(contents[0])
            names = metadata.get_all("Name", [])
            versions = metadata.get_all("Version", [])

            if len(names) != 1 or len(versions) != 1 or metadata.defects:
                raise ExtensionError("Distribution metadata requires one valid Name and Version")

            distribution = str(names[0]).lower().replace("_", "-").replace(".", "-")
            version = str(versions[0])
            parser = _EntryPointsParser(interpolation=None, strict=True, delimiters=("=",))
            parser.read_string(contents[1].decode("utf-8"))

            if parser.defaults():
                raise ExtensionError("Entry-point metadata cannot contain default entries")

            for group in parser.sections():
                if not group.startswith("flayer."):
                    continue

                if group not in {PROVIDER_GROUP, PROFILE_GROUP}:
                    raise ExtensionError("Entry-point metadata uses an unsupported F-Layer group")

                kind = ExtensionKind.PROVIDER if group == PROVIDER_GROUP else ExtensionKind.PROFILE

                for plugin_id, target in parser.items(group):
                    descriptor = ExtensionDescriptor(
                        kind, plugin_id, distribution, version, group, target, directory, digest,
                    )
                    identity = (kind, plugin_id)

                    if identity in identities or len(descriptors) >= MAX_EXTENSIONS:
                        raise ExtensionError("Extension metadata contains duplicate or excess identities")

                    identities.add(identity)
                    descriptors.append(descriptor)

        except (UnicodeError, configparser.Error, ValueError):
            raise ExtensionError("Extension metadata is malformed or incompatible") from None

    return tuple(sorted(descriptors, key=lambda item: (item.kind.value, item.plugin_id)))
