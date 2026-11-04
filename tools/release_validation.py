"""Build reproducible, owned F-Layer distributions without publishing them."""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Mapping, Sequence
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_NAME = "Fuzzy-Technologies/F-Layer"
PROJECT_NAME = "f-layer"
BUILD_BACKEND_VERSION = "1.32.0"
VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
FORBIDDEN_PARTS = frozenset({
    ".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "_build", "dist", "build", "node_modules", ".ssh", ".local", "state", "artifacts",
})
FORBIDDEN_SUFFIXES = frozenset({
    ".pyc", ".pyo", ".pem", ".key", ".p12", ".pfx", ".log", ".sqlite", ".sqlite3", ".db",
})
SDIST_ROOTS = frozenset({"src", "tests", "tools", "docs", "examples", ".github"})
SDIST_FILES = frozenset({
    "README.md", "LICENSE", "AGENTS.md", "DEVELOPMENT_PROTOCOL.md", "SECURITY.md",
    "CONTRIBUTING.md", "CHANGELOG.md", "pyproject.toml", ".gitignore", ".gitattributes",
})
SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
)
MAX_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 10000


class ConsoleScriptsParser(configparser.ConfigParser):
    """Preserve exact externally defined console-script names while parsing metadata."""

    def optionxform(self, optionstr: str) -> str:
        """Honor ConfigParser's callback contract without changing script identity."""

        return optionstr


def RunCommand(repoRoot: Path, arguments: Sequence[str], environment: Mapping[str, str]) -> str:
    """Run a bounded build or Git command without exposing captured error payloads."""

    try:
        result = subprocess.run(
            arguments, cwd=repoRoot, env=environment, capture_output=True,
            check=False, timeout=300,
        )

    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Release command could not complete") from None

    if result.returncode != 0:
        raise ValueError("Release command failed")

    return result.stdout.decode("utf-8")


def Git(repoRoot: Path, *arguments: str) -> str:
    """Use Git's local object database without credentials or network access."""

    return RunCommand(repoRoot, ("git", *arguments), os.environ)


def ReadSourceVersion(source: bytes) -> str | None:
    """Read one literal package version without importing executable project code."""

    try:
        module = ast.parse(source)

    except (SyntaxError, ValueError):
        raise ValueError("Package version source is invalid") from None

    values: list[ast.expr | None] = []

    for statement in module.body:
        if isinstance(statement, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == "__version__"
                   for target in statement.targets):
                values.append(statement.value)

        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name) and statement.target.id == "__version__":
                values.append(statement.value)

    if not values:
        return None

    if len(values) != 1 or not isinstance(values[0], ast.Constant):
        raise ValueError("Package version must be one literal assignment")

    value = values[0].value

    if not isinstance(value, str) or VERSION_PATTERN.fullmatch(value) is None:
        raise ValueError("Package version must be a stable SemVer value")

    return value


def ReadProjectVersion(repoRoot: Path, requireSource: bool = False) -> tuple[str, str | None]:
    """Accept static bootstrap metadata or the explicit Hatch package version path."""

    metadata = tomllib.loads((repoRoot / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project", {})

    if not isinstance(project, dict) or project.get("name") != PROJECT_NAME:
        raise ValueError("Release project identity must be f-layer")

    sourceVersion = ReadSourceVersion((repoRoot / "src/flayer/__init__.py").read_bytes())
    version = project.get("version")

    if version is None:
        dynamic = project.get("dynamic", [])
        tool = metadata.get("tool", {})
        hatch = tool.get("hatch", {}) if isinstance(tool, dict) else {}
        hatchVersion = hatch.get("version", {}) if isinstance(hatch, dict) else {}

        if (not isinstance(dynamic, list) or "version" not in dynamic
                or not isinstance(hatchVersion, dict)
                or hatchVersion.get("path") != "src/flayer/__init__.py"
                or hatchVersion.get("source", "regex") != "regex"
                or "pattern" in hatchVersion):
            raise ValueError("Dynamic version must use the canonical package source")

        version = sourceVersion

    if not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("Project version must be a stable SemVer value")

    if sourceVersion is not None and sourceVersion != version:
        raise ValueError("Project and source versions do not match")

    if requireSource and (sourceVersion is None or version == "0.0.0"):
        raise ValueError("Publishing requires a non-bootstrap package source version")

    return version, sourceVersion


def ValidatePublicationContext(environment: Mapping[str, str]) -> None:
    """Require explicit owner opt-in and manual confirmation on the canonical master."""

    if environment.get("GITHUB_REPOSITORY") != REPOSITORY_NAME:
        raise ValueError("Publication requires the canonical repository")

    if environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
        raise ValueError("Publication requires a manual workflow dispatch")

    if environment.get("GITHUB_REF") != "refs/heads/master":
        raise ValueError("Publication requires the master workflow revision")

    owner = environment.get("FLAYER_RELEASE_OWNER", "")

    if not owner or environment.get("GITHUB_ACTOR") != owner:
        raise ValueError("Publication requires the configured release owner")

    if environment.get("FLAYER_PYPI_ENABLED") != "true":
        raise ValueError("PyPI publication is disabled")

    if environment.get("FLAYER_CONFIRM_PUBLICATION") != "true":
        raise ValueError("Publication requires explicit dispatch confirmation")


def ValidateMilestone(payload: object, version: str, milestoneNumber: int) -> dict[str, object]:
    """Bind stable publication to the completed native milestone for this minor version."""

    if (VERSION_PATTERN.fullmatch(version) is None or type(milestoneNumber) is not int
            or milestoneNumber < 1 or not isinstance(payload, dict)):
        raise ValueError("Release milestone identity is invalid")

    expectedTitle = "release-" + ".".join(version.split(".")[:2])
    expectedUrl = f"https://api.github.com/repos/{REPOSITORY_NAME}/milestones/{milestoneNumber}"

    if (type(payload.get("number")) is not int or payload["number"] != milestoneNumber
            or payload.get("title") != expectedTitle or payload.get("url") != expectedUrl):
        raise ValueError("Release milestone does not own this repository and minor version")

    if (payload.get("state") != "closed" or type(payload.get("open_issues")) is not int
            or payload["open_issues"] != 0):
        raise ValueError("Stable publication requires a closed milestone with no open items")

    return {
        "number": milestoneNumber, "title": expectedTitle, "state": "closed",
        "open_issues": 0, "url": expectedUrl,
    }


def CheckReleaseMilestone(repoRoot: Path, version: str, milestoneNumber: int) -> dict[str, object]:
    """Read authoritative GitHub milestone state without changing planning or approvals."""

    if type(milestoneNumber) is not int or milestoneNumber < 1:
        raise ValueError("Release milestone number must be a positive integer")

    response = RunCommand(
        repoRoot, ("gh", "api", f"repos/{REPOSITORY_NAME}/milestones/{milestoneNumber}"),
        os.environ,
    )

    return ValidateMilestone(json.loads(response), version, milestoneNumber)


def ValidateTag(repoRoot: Path, tag: str, version: str) -> str:
    """Require an annotated stable tag owning the exact current master commit."""

    if tag != f"v{version}" or VERSION_PATTERN.fullmatch(tag[1:]) is None:
        raise ValueError("Release tag and package versions do not match")

    reference = f"refs/tags/{tag}"

    if Git(repoRoot, "cat-file", "-t", reference).strip() != "tag":
        raise ValueError("Release tag must be annotated")

    head = Git(repoRoot, "rev-parse", "HEAD^{commit}").strip()
    tagCommit = Git(repoRoot, "rev-parse", f"{reference}^{{commit}}").strip()
    masterCommit = Git(repoRoot, "rev-parse", "refs/remotes/origin/master^{commit}").strip()

    if tagCommit != head or masterCommit != head:
        raise ValueError("Release tag, checkout and master commits do not match")

    return head


def ValidateMemberName(name: str) -> str:
    """Reject traversal, platform ambiguity and generated or credential-shaped paths."""

    path = PurePosixPath(name)

    if (not name or len(name) > 256 or "\\" in name or "\x00" in name
            or path.is_absolute() or any(part in {".", ".."} for part in name.split("/"))
            or ":" in name or name != path.as_posix()):
        raise ValueError("Distribution contains an unsafe member path")

    if (any(part in FORBIDDEN_PARTS or part == ".env" or part.startswith(".env.")
            for part in path.parts) or path.suffix.lower() in FORBIDDEN_SUFFIXES):
        raise ValueError("Distribution contains a private or generated member")

    return name


def ValidatePayload(payload: bytes) -> None:
    """Bound expanded content and reject recognizable committed credential material."""

    if len(payload) > MAX_MEMBER_BYTES:
        raise ValueError("Distribution member exceeds the size limit")

    if any(pattern.search(payload) for pattern in SECRET_PATTERNS):
        raise ValueError("Distribution contains recognizable credential material")


def AddMember(members: dict[str, bytes], name: str, payload: bytes) -> None:
    """Reject duplicate archive entries and bound total expanded distribution size."""

    ValidateMemberName(name)
    ValidatePayload(payload)

    if name in members:
        raise ValueError("Distribution contains duplicate members")

    if len(members) >= MAX_MEMBERS or sum(map(len, members.values())) + len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("Distribution exceeds the expanded archive limit")

    members[name] = payload


def ReadWheel(path: Path) -> dict[str, bytes]:
    """Read regular bounded ZIP members without extracting or following links."""

    members: dict[str, bytes] = {}

    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            mode = member.external_attr >> 16

            if member.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise ValueError("Wheel contains a directory, link or unsupported file type")

            if member.file_size > MAX_MEMBER_BYTES:
                raise ValueError("Distribution member exceeds the size limit")

            AddMember(members, member.filename, archive.read(member))

    return members


def ReadSdist(path: Path, version: str) -> dict[str, bytes]:
    """Read regular bounded tar members under exactly one expected package root."""

    members: dict[str, bytes] = {}
    prefix = f"f_layer-{version}/"

    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or not member.name.startswith(prefix):
                raise ValueError("Source distribution has an unsafe root or member type")

            if member.size > MAX_MEMBER_BYTES:
                raise ValueError("Distribution member exceeds the size limit")

            stream = archive.extractfile(member)

            if stream is None:
                raise ValueError("Source distribution member cannot be read")

            AddMember(members, member.name[len(prefix):], stream.read(MAX_MEMBER_BYTES + 1))

    return members


def ValidateMetadata(payload: bytes, version: str) -> None:
    """Require unambiguous package identity and version in each distribution."""

    metadata = BytesParser(policy=policy.default).parsebytes(payload)

    if metadata.get_all("Name") != [PROJECT_NAME] or metadata.get_all("Version") != [version]:
        raise ValueError("Distribution metadata identity or version does not match")


def ValidateRecord(members: Mapping[str, bytes], recordName: str) -> None:
    """Verify complete SHA256 ownership and sizes using the wheel RECORD contract."""

    rows = csv.reader(io.StringIO(members[recordName].decode("utf-8")))
    listed: set[str] = set()

    for row in rows:
        if len(row) != 3 or row[0] in listed or row[0] not in members:
            raise ValueError("Wheel RECORD membership is invalid")

        name, digest, size = row
        listed.add(name)

        if name == recordName:
            if digest or size:
                raise ValueError("Wheel RECORD must not hash itself")

            continue

        expectedDigest = base64.urlsafe_b64encode(hashlib.sha256(members[name]).digest())

        if digest != "sha256=" + expectedDigest.decode("ascii").rstrip("="):
            raise ValueError("Wheel RECORD content hash does not match")

        if size != str(len(members[name])):
            raise ValueError("Wheel RECORD content size does not match")

    if listed != set(members):
        raise ValueError("Wheel RECORD does not own every member")


def ValidateEntryPoints(
    wheel: Mapping[str, bytes], sources: Mapping[str, bytes], metadataRoot: str,
) -> None:
    """Permit only the reviewed project console scripts in generated wheel metadata."""

    project = tomllib.loads(sources["pyproject.toml"].decode("utf-8"))["project"]
    expected = project.get("scripts", {})
    entryName = metadataRoot + "entry_points.txt"
    parser = ConsoleScriptsParser(interpolation=None)

    if entryName in wheel:
        try:
            parser.read_string(wheel[entryName].decode("utf-8"))

        except configparser.Error:
            raise ValueError("Wheel entry point metadata is invalid") from None

    actual = dict(parser["console_scripts"]) if parser.has_section("console_scripts") else {}

    if (not isinstance(expected, dict) or actual != expected or parser.defaults()
            or set(parser.sections()) - {"console_scripts"}):
        raise ValueError("Wheel entry points do not match reviewed console scripts")


def AuditArtifacts(
    distributionRoot: Path, trackedSources: Mapping[str, bytes], version: str,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Permit only owned source payloads and expected generated package metadata."""

    expectedNames = {f"f_layer-{version}-py3-none-any.whl", f"f_layer-{version}.tar.gz"}

    if {path.name for path in distributionRoot.iterdir()} != expectedNames:
        raise ValueError("Build must produce exactly one wheel and one source distribution")

    wheel = ReadWheel(distributionRoot / f"f_layer-{version}-py3-none-any.whl")
    sdist = ReadSdist(distributionRoot / f"f_layer-{version}.tar.gz", version)
    metadataRoot = f"f_layer-{version}.dist-info/"
    generatedNames = {metadataRoot + name for name in ("METADATA", "WHEEL", "RECORD")}

    for name, payload in wheel.items():
        if name.startswith("flayer/"):
            sourceName = "src/" + name

        elif name == metadataRoot + "licenses/LICENSE":
            sourceName = "LICENSE"

        elif name in generatedNames:
            continue

        elif name == metadataRoot + "entry_points.txt":
            continue

        else:
            raise ValueError("Wheel contains an unexpected package member")

        if sourceName not in trackedSources or payload != trackedSources[sourceName]:
            raise ValueError("Wheel payload does not match owned tracked source")

    for name, payload in sdist.items():
        if name == "PKG-INFO":
            continue

        if PurePosixPath(name).parts[0] not in SDIST_ROOTS and name not in SDIST_FILES:
            raise ValueError("Source distribution contains an unexpected member")

        if name not in trackedSources or payload != trackedSources[name]:
            raise ValueError("Source distribution payload does not match owned tracked source")

    requiredWheel = {name[4:] for name in trackedSources if name.startswith("src/flayer/")}
    requiredWheel.update({"flayer/__init__.py", metadataRoot + "licenses/LICENSE", *generatedNames})
    requiredSdist = {name for name in trackedSources
                      if PurePosixPath(name).parts[0] in SDIST_ROOTS or name in SDIST_FILES}
    requiredSdist.update({"src/flayer/__init__.py", "pyproject.toml", "README.md", "LICENSE", "PKG-INFO"})

    if not requiredWheel <= set(wheel) or not requiredSdist <= set(sdist):
        raise ValueError("Distribution is missing required package members")

    ValidateMetadata(wheel[metadataRoot + "METADATA"], version)
    ValidateMetadata(sdist["PKG-INFO"], version)
    ValidateRecord(wheel, metadataRoot + "RECORD")
    ValidateEntryPoints(wheel, trackedSources, metadataRoot)

    return wheel, sdist


def SnapshotTrackedSources(repoRoot: Path, targetRoot: Path) -> dict[str, bytes]:
    """Build from clean regular tracked files, excluding all ignored and untracked data."""

    Git(repoRoot, "diff", "--quiet")
    Git(repoRoot, "diff", "--cached", "--quiet")
    sources: dict[str, bytes] = {}

    for name in Git(repoRoot, "ls-files", "-z").split("\x00"):
        if not name:
            continue

        ValidateMemberName(name)
        sourcePath = repoRoot / name

        if (sourcePath.is_symlink() or not sourcePath.is_file()
                or not sourcePath.resolve().is_relative_to(repoRoot.resolve())):
            raise ValueError("Tracked release source must be a regular file")

        payload = sourcePath.read_bytes()
        ValidatePayload(payload)
        sources[name] = payload
        target = targetRoot / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)

    return sources


def BuildDistributions(sourceRoot: Path, outputRoot: Path, epoch: str) -> None:
    """Use the exact installed backend with fixed timestamps and no network build isolation."""

    if importlib.metadata.version("hatchling") != BUILD_BACKEND_VERSION:
        raise ValueError("Release build requires the exact pinned Hatchling version")

    environment = dict(os.environ)
    environment.update({
        "SOURCE_DATE_EPOCH": epoch, "PYTHONHASHSEED": "0", "TZ": "UTC",
        "PIP_NO_INDEX": "1", "PIP_CONFIG_FILE": os.devnull,
    })
    environment.pop("PYTHONPATH", None)
    RunCommand(
        sourceRoot,
        (sys.executable, "-m", "hatchling", "build", "-t", "wheel", "-t", "sdist",
         "-d", str(outputRoot)),
        environment,
    )


def ValidateRelease(repoRoot: Path, tag: str | None, publication: bool) -> dict[str, object]:
    """Produce artifacts only after ownership, version, reproducibility and rebuild parity pass."""

    if publication:
        ValidatePublicationContext(os.environ)

        if tag is None:
            raise ValueError("Publication requires an explicit stable release tag")

    version, sourceVersion = ReadProjectVersion(repoRoot, requireSource=tag is not None)
    milestone = None

    if publication:
        milestoneNumber = os.environ.get("FLAYER_RELEASE_MILESTONE", "")

        if re.fullmatch(r"[1-9][0-9]*", milestoneNumber) is None:
            raise ValueError("Publication requires an explicit native release milestone number")

        milestone = CheckReleaseMilestone(repoRoot, version, int(milestoneNumber))

    commit = (ValidateTag(repoRoot, tag, version) if tag is not None
              else Git(repoRoot, "rev-parse", "HEAD^{commit}").strip())
    epoch = Git(repoRoot, "show", "-s", "--format=%ct", "HEAD").strip()
    outputRoot = repoRoot / "_build/release"

    if outputRoot.parent.is_symlink() or outputRoot.is_symlink() or outputRoot.exists():
        raise ValueError("Release output must be absent; remove the previous generated output first")

    with tempfile.TemporaryDirectory(prefix="flayer-release-") as temporaryDirectory:
        temporaryRoot = Path(temporaryDirectory)
        sourceRoot = temporaryRoot / "source"
        sourceRoot.mkdir()
        sources = SnapshotTrackedSources(repoRoot, sourceRoot)
        firstRoot = temporaryRoot / "first"
        secondRoot = temporaryRoot / "second"
        BuildDistributions(sourceRoot, firstRoot, epoch)
        wheel, sdist = AuditArtifacts(firstRoot, sources, version)
        BuildDistributions(sourceRoot, secondRoot, epoch)
        AuditArtifacts(secondRoot, sources, version)
        hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in firstRoot.iterdir()}

        if any(hashlib.sha256((secondRoot / name).read_bytes()).hexdigest() != digest
               for name, digest in hashes.items()):
            raise ValueError("Repeated release builds are not byte reproducible")

        rebuildRoot = temporaryRoot / "sdist-source"
        rebuildRoot.mkdir()

        for name, payload in sdist.items():
            if name == "PKG-INFO":
                continue

            target = rebuildRoot / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)

        rebuiltRoot = temporaryRoot / "rebuilt"
        BuildDistributions(rebuildRoot, rebuiltRoot, epoch)
        rebuiltWheel = ReadWheel(rebuiltRoot / f"f_layer-{version}-py3-none-any.whl")

        if rebuiltWheel != wheel:
            raise ValueError("Wheel rebuilt from the source distribution differs")

        artifacts = [{"name": name, "sha256": digest, "bytes": (firstRoot / name).stat().st_size}
                     for name, digest in sorted(hashes.items())]
        evidence: dict[str, object] = {
            "schema_version": 1, "project": PROJECT_NAME, "version": version,
            "source_version": sourceVersion, "commit": commit, "tag": tag,
            "source_date_epoch": int(epoch), "hatchling": BUILD_BACKEND_VERSION,
            "reproducible": True, "sdist_wheel_parity": True,
            "wheel_members": len(wheel), "sdist_members": len(sdist), "artifacts": artifacts,
            "publication_requested": publication, "published": False,
        }

        if milestone is not None:
            evidence["release_milestone"] = milestone

        outputRoot.mkdir(parents=True)
        shutil.copytree(firstRoot, outputRoot / "dist")
        (outputRoot / "build-evidence.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )

    return evidence


def Main(arguments: Sequence[str] | None = None) -> int:
    """Validate local artifacts or explicitly authorized manual publication readiness."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Annotated stable tag owning the exact current master commit")
    parser.add_argument("--publication", action="store_true", help="Require manual owner publication gates")
    parser.add_argument("--check-milestone", type=int, metavar="NUMBER",
                        help="Check stable release milestone readiness without building or publishing", dest='checkMilestone')
    options = parser.parse_args(arguments)

    try:
        if options.check_milestone is not None:
            if options.tag is not None or options.publication:
                raise ValueError("Milestone-only checking cannot request artifacts or publication")

            version, _sourceVersion = ReadProjectVersion(REPOSITORY_ROOT, requireSource=True)
            evidence = {"version": version, "published": False,
                        "release_milestone": CheckReleaseMilestone(
                            REPOSITORY_ROOT, version, options.check_milestone,
                        )}

        else:
            evidence = ValidateRelease(REPOSITORY_ROOT, options.tag, options.publication)

    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile,
            importlib.metadata.PackageNotFoundError):
        print("Release validation failed; milestone, ownership, metadata or artifact checks did not pass.",
              file=sys.stderr)

        return 1

    print(json.dumps(evidence, indent=2, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
