"""Verify version ownership, safe artifacts and explicit release publication gates."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import stat
import subprocess
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from tools import release_validation as release

VERSION = "1.2.3"
METADATA_ROOT = f"f_layer-{VERSION}.dist-info/"


def Sources(version: str = VERSION, include_scripts: bool = False) -> dict[str, bytes]:
    """Provide a minimal owned package source set with optional console metadata."""

    project = f'[project]\nname = "f-layer"\nversion = "{version}"\n'

    if include_scripts:
        project += '[project.scripts]\nflayer = "flayer.__main__:Main"\n'

    return {
        "pyproject.toml": project.encode(),
        "src/flayer/__init__.py": f'"""Package fixture."""\n\n__version__ = "{version}"\n'.encode(),
        "src/flayer/py.typed": b"",
        "README.md": b"# Package fixture\n",
        "LICENSE": b"License fixture\n",
    }


def WriteRepository(repo_root: Path, sources: Mapping[str, bytes]) -> None:
    """Write owned file fixtures using only local temporary directories."""

    for name, payload in sources.items():
        target = repo_root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)


def WheelMembers(sources: Mapping[str, bytes], include_scripts: bool = False) -> dict[str, bytes]:
    """Construct an owned wheel fixture with expected generated metadata."""

    members = {name[4:]: payload for name, payload in sources.items() if name.startswith("src/")}
    members.update({
        METADATA_ROOT + "licenses/LICENSE": sources["LICENSE"],
        METADATA_ROOT + "METADATA": b"Metadata-Version: 2.4\nName: f-layer\nVersion: 1.2.3\n\n",
        METADATA_ROOT + "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    })

    if include_scripts:
        members[METADATA_ROOT + "entry_points.txt"] = b"[console_scripts]\nflayer = flayer.__main__:Main\n"

    SetRecord(members)

    return members


def SetRecord(members: dict[str, bytes]) -> None:
    """Bind every fixture wheel payload to a correctly sized SHA256 RECORD entry."""

    record_name = METADATA_ROOT + "RECORD"
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")

    for name, payload in sorted(members.items()):
        if name == record_name:
            continue

        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip("=")
        writer.writerow((name, "sha256=" + digest, len(payload)))

    writer.writerow((record_name, "", ""))
    members[record_name] = stream.getvalue().encode()


def WriteWheel(path: Path, members: Mapping[str, bytes], timestamp: int = 0) -> None:
    """Write controllable ZIP fixture timestamps for byte reproducibility checks."""

    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members.items():
            member = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, timestamp))
            archive.writestr(member, payload)


def WriteSdist(path: Path, members: Mapping[str, bytes]) -> None:
    """Write regular fixture tar members under the canonical source archive root."""

    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members.items():
            member = tarfile.TarInfo(f"f_layer-{VERSION}/{name}")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))


def WriteArtifacts(root: Path, sources: Mapping[str, bytes], include_scripts: bool = False) -> None:
    """Materialize minimal valid wheel and source archives for audit failure tests."""

    root.mkdir(parents=True, exist_ok=True)
    wheel = WheelMembers(sources, include_scripts)
    sdist = dict(sources)
    sdist["PKG-INFO"] = wheel[METADATA_ROOT + "METADATA"]
    WriteWheel(root / f"f_layer-{VERSION}-py3-none-any.whl", wheel)
    WriteSdist(root / f"f_layer-{VERSION}.tar.gz", sdist)


def PublicationEnvironment() -> dict[str, str]:
    """Describe a fully confirmed owner dispatch without real account credentials."""

    return {
        "GITHUB_REPOSITORY": release.REPOSITORY_NAME,
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/master",
        "GITHUB_ACTOR": "fixture-owner",
        "FLAYER_RELEASE_OWNER": "fixture-owner",
        "FLAYER_PYPI_ENABLED": "true",
        "FLAYER_CONFIRM_PUBLICATION": "true",
    }


@pytest.mark.parametrize("source", [
    b'__version__ = "1.2.3"', b'__version__: str = "1.2.3"',
])
def test_LiteralSourceVersion(source: bytes) -> None:
    """An executable import is unnecessary to read one package version literal."""

    assert release.ReadSourceVersion(source) == VERSION, "Literal source version was not read"


@pytest.mark.parametrize("source", [
    b'__version__ = str(123)', b'__version__ = "1.2.3"\n__version__ = "1.2.4"',
    b'__version__ = True', b'__version__ = "01.2.3"', b'__version__ = "1.2.3+build"',
    b'__version__ = "1.2.3rc1"', b'__version__ =', b'__version__: str',
])
def test_AmbiguousSourceVersionRejected(source: bytes) -> None:
    """Computed, duplicate, malformed and non-stable versions cannot own a release."""

    with pytest.raises(ValueError):
        release.ReadSourceVersion(source)


def test_BootstrapPreviewIsNotPublishable(tmp_path: Path) -> None:
    """Legacy bootstrap metadata permits previews while tagged readiness fails closed."""

    sources = Sources("0.0.0")
    sources["src/flayer/__init__.py"] = b'"""Package fixture."""\n'
    WriteRepository(tmp_path, sources)

    assert release.ReadProjectVersion(tmp_path) == ("0.0.0", None), "Bootstrap preview was rejected"

    with pytest.raises(ValueError, match="non-bootstrap"):
        release.ReadProjectVersion(tmp_path, require_source=True)


def test_DynamicMetadataOwnsPackageLiteral(tmp_path: Path) -> None:
    """The package literal owns dynamic Hatch metadata through one canonical path."""

    sources = Sources()
    sources["pyproject.toml"] = (
        b'[project]\nname = "f-layer"\ndynamic = ["version"]\n'
        b'[tool.hatch.version]\nsource = "regex"\npath = "src/flayer/__init__.py"\n'
    )
    WriteRepository(tmp_path, sources)

    assert release.ReadProjectVersion(tmp_path, True) == (VERSION, VERSION), (
        "Dynamic metadata did not use the canonical source version"
    )


@pytest.mark.parametrize("project", [
    'name = "foreign"\nversion = "1.2.3"',
    'name = "f-layer"\nversion = "1.2.4"',
    'name = "f-layer"\nversion = true',
    'name = "f-layer"\ndynamic = ["version"]\n[tool.hatch.version]\npath = "other.py"',
    'name = "f-layer"\ndynamic = true',
    'name = "f-layer"\ndynamic = ["version"]\n[tool]\nhatch = false',
    'name = "f-layer"\ndynamic = ["version"]\n[tool.hatch.version]\n'
    'path = "src/flayer/__init__.py"\nsource = "custom"',
    'name = "f-layer"\ndynamic = ["version"]\n[tool.hatch.version]\n'
    'path = "src/flayer/__init__.py"\npattern = "custom"',
])
def test_ForeignOrInconsistentMetadataRejected(tmp_path: Path, project: str) -> None:
    """A foreign identity, disagreement or unsupported version path blocks release."""

    sources = Sources()
    sources["pyproject.toml"] = ("[project]\n" + project + "\n").encode()
    WriteRepository(tmp_path, sources)

    with pytest.raises(ValueError):
        release.ReadProjectVersion(tmp_path)


@pytest.mark.parametrize(("name", "value"), [
    ("GITHUB_REPOSITORY", "fork/F-Layer"), ("GITHUB_EVENT_NAME", "push"),
    ("GITHUB_REF", "refs/heads/develop"), ("GITHUB_ACTOR", "other-owner"),
    ("FLAYER_RELEASE_OWNER", ""), ("FLAYER_PYPI_ENABLED", ""),
    ("FLAYER_PYPI_ENABLED", "True"), ("FLAYER_CONFIRM_PUBLICATION", "false"),
])
def test_PublicationRequiresEveryExplicitGate(name: str, value: str) -> None:
    """Neither an ambient account nor one permissive setting authorizes publication."""

    environment = PublicationEnvironment()
    environment[name] = value

    with pytest.raises(ValueError):
        release.ValidatePublicationContext(environment)


def test_ConfirmedOwnerPublicationContext() -> None:
    """A fully configured owner can explicitly authorize one manual master run."""

    release.ValidatePublicationContext(PublicationEnvironment())


@pytest.mark.parametrize(("object_type", "head", "tag_head", "master", "accepted"), [
    ("tag", "a", "a", "a", True), ("commit", "a", "a", "a", False),
    ("tag", "a", "b", "a", False), ("tag", "a", "a", "b", False),
])
def test_TagMustOwnExactCurrentMaster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, object_type: str, head: str,
    tag_head: str, master: str, accepted: bool,
) -> None:
    """Annotation and exact tag/checkout/master parity are independent release gates."""

    responses = iter((object_type, head, tag_head, master))

    def Git(_repo_root: Path, *_arguments: str) -> str:
        """Return local Git object fixtures without contacting a remote."""

        return next(responses)

    monkeypatch.setattr(release, "Git", Git)

    if accepted:
        assert release.ValidateTag(tmp_path, "v1.2.3", VERSION) == head, "Valid ownership was lost"

    else:
        with pytest.raises(ValueError):
            release.ValidateTag(tmp_path, "v1.2.3", VERSION)


@pytest.mark.parametrize("tag", ["v1.2.4", "1.2.3", "v1.2.3+1", "v01.2.3", "-v1.2.3"])
def test_TagInputCannotInjectGitOptions(tmp_path: Path, tag: str) -> None:
    """Unowned tag input is rejected before Git can interpret it as an argument."""

    with pytest.raises(ValueError, match="versions"):
        release.ValidateTag(tmp_path, tag, VERSION)


@pytest.mark.parametrize("name", [
    "../file", "/file", "a/./b", "a//b", "a/../b", "a\\b", "C:/file", "a\x00b", "",
    ".env", ".env.example", "docs/.env.production", "state/runtime.json",
    "_build/site/index.html", "flayer/__pycache__/core.pyc", "docs/key.pem", ".ssh/config",
])
def test_UnsafeArtifactPathsRejected(name: str) -> None:
    """Archives cannot carry traversal, ambiguous paths or generated/private files."""

    with pytest.raises(ValueError):
        release.ValidateMemberName(name)


def test_MemberAndExpandedArchiveLimits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Limits apply before large payloads and aggregate archives can be accepted."""

    monkeypatch.setattr(release, "MAX_MEMBER_BYTES", 3)

    with pytest.raises(ValueError, match="size limit"):
        release.AddMember({}, "src/large.py", b"1234")

    monkeypatch.setattr(release, "MAX_ARCHIVE_BYTES", 3)

    with pytest.raises(ValueError, match="archive limit"):
        release.AddMember({"one.txt": b"12"}, "two.txt", b"12")

    monkeypatch.setattr(release, "MAX_MEMBERS", 1)

    with pytest.raises(ValueError, match="archive limit"):
        release.AddMember({"one.txt": b"1"}, "two.txt", b"1")


def test_DuplicateMembersRejected() -> None:
    """Duplicate entry shadowing cannot hide different content behind one member."""

    with pytest.raises(ValueError, match="duplicate"):
        release.AddMember({"README.md": b"one"}, "README.md", b"two")


def test_PrivateKeyMaterialRejectedWithoutEcho() -> None:
    """Recognizable credential material is rejected without exposing its value."""

    private_marker = b"-----BEGIN " + b"PRIVATE KEY-----"

    with pytest.raises(ValueError, match="credential") as captured:
        release.ValidatePayload(private_marker + b"\nfixture-private-material")

    assert "fixture-private-material" not in str(captured.value), "Credential payload leaked"


def test_ZipAndTarLinksRejected(tmp_path: Path) -> None:
    """Archives never follow symbolic or hard links, even with innocuous names."""

    wheel_path = tmp_path / "fixture.whl"

    with zipfile.ZipFile(wheel_path, "w") as archive:
        member = zipfile.ZipInfo("flayer/link.py")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(member, "../../private")

    with pytest.raises(ValueError, match="link"):
        release.ReadWheel(wheel_path)

    sdist_path = tmp_path / "fixture.tar.gz"

    with tarfile.open(sdist_path, "w:gz") as archive:
        member = tarfile.TarInfo(f"f_layer-{VERSION}/src/link.py")
        member.type = tarfile.LNKTYPE
        member.linkname = "../../private"
        archive.addfile(member)

    with pytest.raises(ValueError, match="member type"):
        release.ReadSdist(sdist_path, VERSION)


def test_ValidArtifactOwnershipAndConsoleScripts(tmp_path: Path) -> None:
    """Both distributions retain exact owned package members and declared scripts."""

    sources = Sources(include_scripts=True)
    sources["examples/profiles/fixture.toml"] = b'[fixture]\nname = "example"\n'
    WriteArtifacts(tmp_path, sources, include_scripts=True)
    wheel, sdist = release.AuditArtifacts(tmp_path, sources, VERSION)

    assert wheel["flayer/__init__.py"] == sdist["src/flayer/__init__.py"], "Package source diverged"
    assert "flayer/py.typed" in wheel, "Typing marker was dropped"


@pytest.mark.parametrize("mutation", [
    "extra", "unowned", "changed", "missing", "version", "hash", "size", "incomplete-record",
    "duplicate-record", "record-self-hash", "undeclared-script",
])
def test_ArtifactIntegrityFailures(tmp_path: Path, mutation: str) -> None:
    """Correct filenames alone cannot authorize changed, incomplete or foreign artifacts."""

    sources = Sources()
    WriteArtifacts(tmp_path, sources)
    path = tmp_path / f"f_layer-{VERSION}-py3-none-any.whl"
    members = release.ReadWheel(path)

    if mutation == "extra":
        (tmp_path / "private.txt").write_text("fixture", encoding="utf-8")

    elif mutation == "unowned":
        members["flayer/foreign.py"] = b"fixture"
        SetRecord(members)

    elif mutation == "changed":
        members["flayer/__init__.py"] = b"changed"
        SetRecord(members)

    elif mutation == "missing":
        del members["flayer/py.typed"]
        SetRecord(members)

    elif mutation == "version":
        members[METADATA_ROOT + "METADATA"] = b"Name: f-layer\nVersion: 9.9.9\n"
        SetRecord(members)

    elif mutation == "hash":
        members[METADATA_ROOT + "RECORD"] = members[METADATA_ROOT + "RECORD"].replace(
            b"sha256=", b"sha512=", 1,
        )

    elif mutation == "size":
        record = members[METADATA_ROOT + "RECORD"].decode()
        rows = list(csv.reader(io.StringIO(record)))
        rows[0][2] = "999"
        stream = io.StringIO()
        csv.writer(stream).writerows(rows)
        members[METADATA_ROOT + "RECORD"] = stream.getvalue().encode()

    elif mutation == "incomplete-record":
        lines = members[METADATA_ROOT + "RECORD"].splitlines(keepends=True)
        members[METADATA_ROOT + "RECORD"] = b"".join(lines[1:])

    elif mutation == "duplicate-record":
        record = members[METADATA_ROOT + "RECORD"]
        members[METADATA_ROOT + "RECORD"] += record.splitlines(keepends=True)[0]

    elif mutation == "record-self-hash":
        members[METADATA_ROOT + "RECORD"] = members[METADATA_ROOT + "RECORD"].replace(
            (METADATA_ROOT + "RECORD,,").encode(), (METADATA_ROOT + "RECORD,sha256=fixture,1").encode(),
        )

    else:
        members[METADATA_ROOT + "entry_points.txt"] = b"[console_scripts]\nforeign = foreign:Main\n"
        SetRecord(members)

    WriteWheel(path, members)

    with pytest.raises(ValueError):
        release.AuditArtifacts(tmp_path, sources, VERSION)


@pytest.mark.parametrize("mutation", ["unowned", "changed", "missing", "wrong-root"])
def test_ChangelogOwnershipAndCompleteness(tmp_path: Path, mutation: str) -> None:
    """Shipped changelog bytes must be owned, intact, and present in source archives."""

    sources = Sources()
    sources["CHANGELOG.md"] = b"# F-Layer Changelog\n"
    WriteArtifacts(tmp_path, sources)
    release.AuditArtifacts(tmp_path, sources, VERSION)
    path = tmp_path / f"f_layer-{VERSION}.tar.gz"
    members = release.ReadSdist(path, VERSION)

    if mutation == "unowned":
        del sources["CHANGELOG.md"]

    elif mutation == "changed":
        members["CHANGELOG.md"] = b"Changed history\n"

    elif mutation == "missing":
        del members["CHANGELOG.md"]

    else:
        sources["PRIVATE_NOTES.md"] = members["PRIVATE_NOTES.md"] = b"Unapproved root file\n"

    WriteSdist(path, members)

    with pytest.raises(ValueError):
        release.AuditArtifacts(tmp_path, sources, VERSION)


@pytest.mark.parametrize("mutation", ["unowned", "changed", "missing", "wrong-root"])
def test_SourceArchiveIntegrityFailures(tmp_path: Path, mutation: str) -> None:
    """A release source archive must carry complete reviewed rebuild inputs only."""

    sources = Sources()
    WriteArtifacts(tmp_path, sources)
    path = tmp_path / f"f_layer-{VERSION}.tar.gz"
    members = release.ReadSdist(path, VERSION)

    if mutation == "unowned":
        members["docs/foreign.md"] = b"fixture"

    elif mutation == "changed":
        members["README.md"] = b"changed"

    elif mutation == "missing":
        del members["pyproject.toml"]

    else:
        members["../outside"] = b"fixture"

    WriteSdist(path, members)

    with pytest.raises(ValueError):
        release.AuditArtifacts(tmp_path, sources, VERSION)


def test_CommandFailuresSuppressCapturedPrivateOutput(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed tool cannot surface arbitrary captured build or Git stderr."""

    def Run(*_arguments: object, **_options: object) -> subprocess.CompletedProcess[bytes]:
        """Return a synthetic failed local command with private output."""

        return subprocess.CompletedProcess([], 1, b"fixture-private-stdout", b"fixture-private-stderr")

    monkeypatch.setattr(release.subprocess, "run", Run)

    with pytest.raises(ValueError) as captured:
        release.RunCommand(tmp_path, ("fixture",), {})

    assert "fixture-private" not in str(captured.value), "Captured command output leaked"


def test_ExistingOrRedirectedOutputRejected(tmp_path: Path) -> None:
    """A prior report or symlink cannot be overwritten or redirect release output."""

    WriteRepository(tmp_path, Sources())
    output_parent = tmp_path / "_build"
    output_parent.mkdir()
    (output_parent / "release").mkdir()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(release, "Git", lambda *_arguments: "123")

        with pytest.raises(ValueError, match="output must be absent"):
            release.ValidateRelease(tmp_path, None, False)


def test_CliFailureDoesNotEchoTagOrPayload(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """The public CLI returns failure without replaying sensitive exception details."""

    def Fail(_repo_root: Path, _tag: str | None, _publication: bool) -> dict[str, object]:
        """Represent an untrusted lower-level exception containing a fixture secret."""

        raise ValueError("fixture-private-value")

    monkeypatch.setattr(release, "ValidateRelease", Fail)

    assert release.Main(["--tag", "fixture-private-tag"]) == 1, "Validation failure returned success"
    output = capsys.readouterr()
    assert "fixture-private" not in output.out + output.err, "CLI repeated private error detail"


@pytest.mark.parametrize("failure", [None, "reproducibility", "sdist-parity"])
def test_ReleaseEvidenceRequiresBothBuildComparisons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None,
) -> None:
    """Only matching repeated builds and a matching source rebuild emit artifacts."""

    sources = Sources()
    repo_root = tmp_path / "repository"
    repo_root.mkdir()
    WriteRepository(repo_root, sources)
    fixture_root = tmp_path / "fixture-artifacts"
    WriteArtifacts(fixture_root, sources)

    def Git(_repo_root: Path, *arguments: str) -> str:
        """Provide a fixed local commit and reproducible timestamp."""

        return "1234567890" if arguments[0] == "show" else "fixture-commit"

    def Snapshot(_repo_root: Path, source_root: Path) -> dict[str, bytes]:
        """Copy the fixed owned fixture inputs to each disposable build source."""

        WriteRepository(source_root, sources)

        return sources

    def Build(_source_root: Path, output_root: Path, _epoch: str) -> None:
        """Supply deterministic artifacts with separately controllable parity failures."""

        output_root.mkdir()

        for artifact in fixture_root.iterdir():
            (output_root / artifact.name).write_bytes(artifact.read_bytes())

        wheel_path = output_root / f"f_layer-{VERSION}-py3-none-any.whl"

        if failure == "reproducibility" and output_root.name == "second":
            WriteWheel(wheel_path, release.ReadWheel(wheel_path), timestamp=2)

        elif failure == "sdist-parity" and output_root.name == "rebuilt":
            members = release.ReadWheel(wheel_path)
            members["flayer/__init__.py"] = b"changed during rebuild"
            WriteWheel(wheel_path, members)

    monkeypatch.setattr(release, "Git", Git)
    monkeypatch.setattr(release, "SnapshotTrackedSources", Snapshot)
    monkeypatch.setattr(release, "BuildDistributions", Build)

    if failure is not None:
        with pytest.raises(ValueError):
            release.ValidateRelease(repo_root, None, False)

        assert not (repo_root / "_build/release").exists(), "Failed comparison emitted approved output"

    else:
        evidence = release.ValidateRelease(repo_root, None, False)
        evidence_path = repo_root / "_build/release/build-evidence.json"
        assert json.loads(evidence_path.read_text()) == evidence, "Persisted evidence differs"
        assert evidence["reproducible"] is True and evidence["sdist_wheel_parity"] is True, (
            "Successful comparisons were not recorded"
        )
        assert evidence["published"] is False, "A build-only operation claimed publication"


def test_SnapshotExcludesUntrackedAndIgnoredInputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Private local files never enter a tracked-file build snapshot."""

    WriteRepository(tmp_path, Sources())
    (tmp_path / ".env").write_text("fixture-private-material", encoding="utf-8")
    target_root = tmp_path / "snapshot"

    def Git(_repo_root: Path, *arguments: str) -> str:
        """Represent a clean index containing only the owned fixture package files."""

        return "\x00".join(Sources()) + "\x00" if arguments[0] == "ls-files" else ""

    monkeypatch.setattr(release, "Git", Git)
    snapshot = release.SnapshotTrackedSources(tmp_path, target_root)

    assert snapshot == Sources(), "Snapshot included files outside the tracked source contract"
    assert not (target_root / ".env").exists(), "Untracked private file entered the snapshot"


def test_SnapshotRejectsTrackedSymlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tracked link cannot import file payloads outside the reviewed source tree."""

    target = tmp_path / "original"
    target.write_text("fixture", encoding="utf-8")
    (tmp_path / "linked.txt").symlink_to(target)

    def Git(_repo_root: Path, *arguments: str) -> str:
        """Represent a clean index that contains a symlink entry."""

        return "linked.txt\x00" if arguments[0] == "ls-files" else ""

    monkeypatch.setattr(release, "Git", Git)

    with pytest.raises(ValueError, match="regular file"):
        release.SnapshotTrackedSources(tmp_path, tmp_path / "snapshot")


def test_ByteCounterAndRecordSchemaRejectAmbiguity(tmp_path: Path) -> None:
    """Malformed metadata and RECORD rows cannot silently overwrite ownership."""

    with pytest.raises(ValueError, match="metadata"):
        release.ValidateMetadata(b"Name: f-layer\nName: foreign\nVersion: 1.2.3\n", VERSION)

    members = WheelMembers(Sources())
    members[METADATA_ROOT + "RECORD"] = b"malformed,only-two\n"

    with pytest.raises(ValueError, match="membership"):
        release.ValidateRecord(members, METADATA_ROOT + "RECORD")


@pytest.mark.parametrize("file_type", [stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK])
def test_WheelRejectsAllSpecialUnixMemberTypes(tmp_path: Path, file_type: int) -> None:
    """A ZIP member cannot smuggle a device, socket or FIFO under a source filename."""

    path = tmp_path / "fixture.whl"

    with zipfile.ZipFile(path, "w") as archive:
        member = zipfile.ZipInfo("flayer/source.py")
        member.create_system = 3
        member.external_attr = (file_type | 0o600) << 16
        archive.writestr(member, b"fixture")

    with pytest.raises(ValueError, match="unsupported file type"):
        release.ReadWheel(path)
