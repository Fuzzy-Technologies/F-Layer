"""Verify bounded static-site intent, exact artifacts, and fixed guest bootstrap offline."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

from flayer.core.contracts import StackIdentity
from flayer.core.lifecycle import LoadDeploymentPlan
from flayer.profiles.artifacts import (
    ArtifactBundle,
    ArtifactError,
    RemoveArtifactBundle,
    WriteArtifactBundle,
)
from flayer.profiles.static_site import (
    CLOUD_INIT_FILENAME,
    MAX_PROFILE_BYTES,
    BuildStaticSiteBundle,
    CompileStaticSite,
    LoadStaticSiteProfile,
    Main,
    ParseStaticSiteProfile,
    PrepareStaticSite,
    RenderStaticSitePlan,
    StaticSiteError,
    StaticSitePlan,
    StaticSiteProfile,
)

PUBLIC_KEY = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
).decode("ascii")
IDENTITY = StackIdentity("example", "site", "yandex-cloud", "example-folder", "example-owner")


def ProfileData() -> dict[str, object]:
    """Supply synthetic placement and publishable text with no cloud or credential lookup."""

    return {
        "schema_version": 1, "profile": "static-site", "guest_contract": "ubuntu-24.04-cloud-init",
        "identity": {
            "project": "example", "stack": "site", "provider": "yandex-cloud",
            "scope_id": "example-folder", "owner_id": "example-owner",
        },
        "placement": {"zone_id": "example-zone", "image_id": "example-image", "subnet_cidr": "10.43.0.0/24"},
        "admin": {"username": "site-admin", "public_key": PUBLIC_KEY, "source_cidrs": ["198.51.100.42/32"]},
        "site": {"title": "Example site", "body": "A small public page.", "http_source_cidrs": ["0.0.0.0/0"]},
    }


def Profile() -> StaticSiteProfile:
    """Construct validated immutable intent for deterministic local tests."""

    return ParseStaticSiteProfile(ProfileData())


def CloudData(profile: StaticSiteProfile | None = None) -> dict[str, object]:
    """Decode generated JSON cloud-config without executing a guest operation."""

    return json.loads(BuildStaticSiteBundle(profile or Profile()).files[0].content.removeprefix(b"#cloud-config\n"))


def GuestFiles(profile: StaticSiteProfile | None = None) -> dict[str, dict[str, str]]:
    """Index fixed generated paths for syntax and authorization assertions."""

    return {item["path"]: item for item in CloudData(profile)["write_files"]}  # type: ignore[union-attr]


def test_StaticOutcomeHasOnePageAndSeparateAdministratorAuthority() -> None:
    """Provide nginx content rather than gateway transport, with exact root-owned SSH keys."""

    profile = Profile()
    data = CloudData(profile)
    files = GuestFiles(profile)
    ssh = files["/etc/ssh/sshd_config"]["content"]
    firewall = files["/etc/nftables.conf"]["content"]
    keys = files["/etc/ssh/f-layer-static-admin-keys"]

    assert data["packages"] == ["nginx", "nftables", "unattended-upgrades"], "Static profile must install its concrete web listener"
    assert data["ssh_pwauth"] is False and data["disable_root"] is True, "Guest must disable password and root login"
    assert len(data["users"]) == 1, "Static sites must not create device or tunnel accounts"  # type: ignore[arg-type]
    assert "ssh_authorized_keys" not in data["users"][0], "Home keys must not become an authorization fallback"  # type: ignore[index]
    assert keys["owner"] == "root:root" and keys["permissions"] == "0644", "Exact administrator key file must be root owned"
    assert keys["content"] == PUBLIC_KEY + "\n", "Administrator authorization must use the exact declared public key"

    for directive in (
        "AuthorizedKeysFile /etc/ssh/f-layer-static-admin-keys", "AuthorizedKeysCommand none",
        "TrustedUserCAKeys none", "AuthorizedPrincipalsFile none", "AllowTcpForwarding no",
        "AllowStreamLocalForwarding no", "PermitTunnel no", "AllowAgentForwarding no",
        "AllowUsers site-admin@198.51.100.42/32",
    ):
        assert directive in ssh, "SSH must keep administrator authority separate from HTTP ingress"

    assert "ip saddr 0.0.0.0/0 tcp dport 80 accept" in firewall, "Declared HTTP sources must receive HTTP only"
    assert "ip saddr 0.0.0.0/0 tcp dport 22" not in firewall, "Public HTTP must not widen administrator ingress"
    assert "listen 80 default_server;" in files["/etc/nginx/nginx.conf"]["content"], "Production nginx must retain the declared HTTP port 80 listener"
    assert "policy drop" in firewall and "net.ipv4.ip_forward=0" in files["/etc/sysctl.d/90-f-layer-static.conf"]["content"], "Static site must not route packets"
    assert PUBLIC_KEY not in repr(profile) and profile.body not in repr(profile), "Public payloads must stay out of object representations"


def test_PageEscapesMarkupAndLeavesGuestCommandsFixed() -> None:
    """Treat HTML, quotes, template tokens, and shell text only as literal published text."""

    payload = '<script>alert("x")</script>\n$(touch /tmp/no) & ${SHELL} {{x}}'
    profile = replace(Profile(), title='<img src="x"> & title', body=payload)
    files = GuestFiles(profile)
    page = files["/var/www/f-layer-static/index.html"]["content"]

    assert "<script>" not in page and "&lt;script&gt;" in page, "Page text must not become active markup"
    assert "&quot;" in page and "&amp;" in page and "&lt;img" in page, "Both title and body must escape HTML metacharacters"
    assert "$(touch /tmp/no)" in page, "Shell-looking page text must remain literal text"
    assert files["/usr/local/sbin/f-layer-static-bootstrap"]["content"] == GuestFiles()["/usr/local/sbin/f-layer-static-bootstrap"]["content"], "Body text must never change bootstrap commands"
    assert files["/etc/nginx/nginx.conf"]["content"] == GuestFiles()["/etc/nginx/nginx.conf"]["content"], "Profile text must never modify nginx directives"


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("profile", "secure-gateway"),
    ("guest_contract", "ubuntu-latest"), ("identity", []), ("placement", []),
    ("admin", []), ("site", []), ("transport", {}), ("runcmd", ["synthetic-secret"]),
    ("credentials", {"token": "synthetic-secret"}),
])
def test_RootSchemaRejectsUnsupportedAndSecretFields(field: str, value: object) -> None:
    """Prevent implicit deployment outcomes, arbitrary commands, and schema coercion."""

    data = ProfileData()
    data[field] = value

    with pytest.raises(StaticSiteError) as caught:
        ParseStaticSiteProfile(data)

    assert "synthetic-secret" not in str(caught.value), "Rejected input bytes must not enter errors"


@pytest.mark.parametrize("section,field,value", [
    ("identity", "provider", "other"), ("identity", "scope_id", ""), ("identity", "owner_id", "Bad"),
    ("placement", "zone_id", "bad zone"), ("placement", "image_id", ""),
    ("placement", "subnet_cidr", "8.8.0.0/24"), ("placement", "subnet_cidr", "10.43.0.1/24"),
    ("placement", "subnet_cidr", "10.0.0.0/8"), ("placement", "subnet_cidr", "10.43.0.0/29"),
    ("placement", "subnet_cidr", "::/0"), ("placement", "subnet_cidr", 1),
    ("placement", "cores", True), ("placement", "cores", 33), ("placement", "memory_gib", 0),
    ("placement", "memory_gib", 65), ("placement", "boot_disk_gib", 9), ("placement", "boot_disk_gib", 257),
    ("admin", "username", "root"), ("admin", "username", "www-data"), ("admin", "username", "nginx"),
    ("admin", "username", "admin;reboot"), ("admin", "username", 1),
    ("admin", "source_cidrs", ["0.0.0.0/0"]), ("admin", "source_cidrs", ["::/0"]),
    ("admin", "source_cidrs", []), ("admin", "source_cidrs", "198.51.100.42/32"),
    ("admin", "source_cidrs", ["198.51.100.0/24", "198.51.100.42/32"]),
    ("admin", "source_cidrs", ["198.51.100.42/32"] * 2),
    ("site", "http_source_cidrs", []), ("site", "http_source_cidrs", "0.0.0.0/0"),
    ("site", "http_source_cidrs", ["0.0.0.0/0", "192.0.2.0/24"]),
    ("site", "title", ""), ("site", "title", "x" * 161), ("site", "title", "a\nb"),
    ("site", "title", "a\x00b"), ("site", "body", " "), ("site", "body", "x" * 8193),
    ("site", "body", "x\ry"), ("site", "body", "\ud800"), ("site", "body", 1),
    ("site", "body", "é" * 4097), ("site", "command", "synthetic-secret"),
    ("site", "nginx_config", "synthetic-secret"), ("admin", "private_key", "synthetic-secret"),
])
def test_ConcreteSectionsRejectUnsafeOrUnboundedIntent(section: str, field: str, value: object) -> None:
    """Exercise placement, sources, sizing, text, and arbitrary execution rejection."""

    data = ProfileData()
    table = dict(data[section])  # type: ignore[arg-type]
    table[field] = value
    data[section] = table

    with pytest.raises(StaticSiteError) as caught:
        ParseStaticSiteProfile(data)

    assert "synthetic-secret" not in str(caught.value), "Unknown field values must remain sanitized"


@pytest.mark.parametrize("value", [
    "", "ssh-rsa AAAA", "ssh-ed25519 !!!!", "ssh-ed25519 AAAA", PUBLIC_KEY + " comment",
    PUBLIC_KEY.replace("ssh-ed25519 ", "ssh-ed25519  "), PUBLIC_KEY + "=",
    "PRIVATE KEY synthetic-secret", 1, "x" * 257,
])
def test_CanonicalPublicKeyBoundary(value: object) -> None:
    """Exclude key comments, SSH options, private material, and malformed wire encodings."""

    data = ProfileData()
    data["admin"]["public_key"] = value  # type: ignore[index]

    with pytest.raises(StaticSiteError):
        ParseStaticSiteProfile(data)


def test_RequiredFieldsAndDirectConstructionAreStrict() -> None:
    """Do not let immutable construction bypass validated profile intent."""

    data = ProfileData()

    for key in data:
        incomplete = copy.deepcopy(data)
        incomplete.pop(key)

        with pytest.raises(StaticSiteError):
            ParseStaticSiteProfile(incomplete)

    for changes in (
        {"identity": "invalid"}, {"schema_version": True}, {"guest_contract": "other"},
        {"admin_source_cidrs": ["198.51.100.42/32"]}, {"http_source_cidrs": (1,)},
        {"http_source_cidrs": tuple(f"192.0.2.{index}/32" for index in range(17))},
        {"admin_public_key": "ssh-ed25519 " + base64.b64encode(b"invalid").decode("ascii")},
    ):
        with pytest.raises(ValueError):
            replace(Profile(), **changes)

    with pytest.raises(StaticSiteError):
        StaticSitePlan("invalid")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        CompileStaticSite(replace(Profile(), identity=replace(IDENTITY, stack="x" * 63)))


def test_ProfileInputIsBoundedAndErrorsSuppressBytes(tmp_path: Path) -> None:
    """Reject unreadable or invalid TOML without exposing input or local paths."""

    path = tmp_path / "profile.toml"

    for content in (b"[bad", b"\xff", b"x" * (MAX_PROFILE_BYTES + 1), b"x=" + b"9" * 5000):
        path.write_bytes(content)

        with pytest.raises(StaticSiteError):
            LoadStaticSiteProfile(path)

    with pytest.raises(StaticSiteError):
        LoadStaticSiteProfile(tmp_path / "absent")

    link = tmp_path / "link.toml"
    link.symlink_to(path)

    with pytest.raises(StaticSiteError):
        LoadStaticSiteProfile(link)

    fifo = tmp_path / "input.pipe"
    os.mkfifo(fifo)

    with pytest.raises(StaticSiteError):
        LoadStaticSiteProfile(fifo)

    with pytest.raises(StaticSiteError):
        LoadStaticSiteProfile(tmp_path / ".." / "profile.toml")


def test_PreparationProducesTwoPrivateOwnedBundlesAndLoadedPlan(tmp_path: Path) -> None:
    """Exercise user preparation, existing lifecycle parsing, digest binding, and cleanup."""

    profile = Profile()
    root = tmp_path / "artifacts-🚀"
    prepared = PrepareStaticSite(profile, artifact_root=root)
    plan = LoadDeploymentPlan(prepared.PlanFile)
    data = tomllib.loads(prepared.PlanFile.read_text())
    resources = {item["logical_id"]: item for item in data["resources"]}
    parameters = resources["instance"]["parameters"]
    initialization = prepared.server_directory / CLOUD_INIT_FILENAME
    rules = resources["firewall"]["parameters"]["rules"]

    assert plan.identity == IDENTITY and len(plan.resources) == 6, "New profile must use the existing complete lifecycle contract"
    assert parameters["user_data_file"] == str(initialization.absolute()), "Lifecycle must reference the exact owned artifact"
    assert parameters["user_data_sha256"] == hashlib.sha256(initialization.read_bytes()).hexdigest(), "Plan must bind actual initialization bytes"
    assert rules == [
        {"direction": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr": "198.51.100.42/32"},
        {"direction": "ingress", "protocol": "tcp", "from_port": 80, "to_port": 80, "cidr": "0.0.0.0/0"},
        {"direction": "egress", "protocol": "any", "cidr": "0.0.0.0/0"},
    ], "HTTP allowances must remain distinct from administrator SSH"
    assert resources["instance"]["dependencies"] == ["subnet", "firewall", "address", "boot-disk"], "Instance must depend on separately owned disk and network resources"
    assert resources["boot-disk"]["parameters"]["image_id"] == "example-image", "Image placement must remain explicit"
    assert RenderStaticSitePlan(CompileStaticSite(profile), user_data_file=initialization) == prepared.PlanFile.read_text(), "Serialization must be deterministic"

    for directory in (prepared.server_directory, prepared.plan_directory):
        assert directory.stat().st_mode & 0o777 == 0o700, "Owned bundle directories must remain private"
        manifest = json.loads((directory / "manifest.json").read_text())
        assert all(not item["sensitive"] for item in manifest["files"]), "Static profile must generate no secret artifact"
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in directory.iterdir()), "Owned files must remain private"

    RemoveArtifactBundle(root, profile.identity, kind="server", name=profile.identity.stack + "-plan")
    RemoveArtifactBundle(root, profile.identity, kind="server", name=profile.identity.stack)
    assert list(root.iterdir()) == [], "Prepared-artifact cleanup must remove only both exact owned bundles"


def test_PlanRenderingRefusesForeignChangedOrWrongArtifacts(tmp_path: Path) -> None:
    """Preserve explicit ownership and semantic equality before plan preparation."""

    profile = Profile()

    for index, other in enumerate((
        replace(profile, identity=replace(IDENTITY, owner_id="foreign")),
        replace(profile, body="Different publishable body"),
    )):
        directory = WriteArtifactBundle(tmp_path / f"root-{index}", BuildStaticSiteBundle(other))

        with pytest.raises(StaticSiteError):
            RenderStaticSitePlan(CompileStaticSite(profile), user_data_file=directory / CLOUD_INIT_FILENAME)

    directory = WriteArtifactBundle(tmp_path / "root", BuildStaticSiteBundle(profile))
    path = directory / CLOUD_INIT_FILENAME
    path.write_bytes(b"synthetic-secret")

    with pytest.raises(StaticSiteError) as caught:
        RenderStaticSitePlan(CompileStaticSite(profile), user_data_file=path)

    assert "synthetic-secret" not in str(caught.value), "Changed artifact bytes must remain outside failures"

    with pytest.raises(StaticSiteError):
        RenderStaticSitePlan(CompileStaticSite(profile), user_data_file=directory / "wrong.json")

    with pytest.raises(StaticSiteError):
        RenderStaticSitePlan("invalid", user_data_file=path)  # type: ignore[arg-type]


def test_PlanCollisionRollsBackServerWithoutReplacingForeignBytes(tmp_path: Path) -> None:
    """Reject plan collisions and clean only the server bundle created by this preparation."""

    profile = Profile()
    root = tmp_path / "artifacts"
    root.mkdir(mode=0o700)
    foreign = root / "server-site-plan"
    foreign.mkdir(mode=0o700)
    marker = foreign / "foreign.txt"
    marker.write_bytes(b"foreign-value")

    with pytest.raises(ArtifactError):
        PrepareStaticSite(profile, artifact_root=root)

    assert marker.read_bytes() == b"foreign-value", "Plan collision must preserve foreign bytes"
    assert not (root / "server-site").exists(), "Failed preparation must roll back its new server bundle"
    assert list(root.iterdir()) == [foreign], "Preparation must not leave an operation lock"


def test_PreparationRejectsTraversalSymlinksAndServerCollision(tmp_path: Path) -> None:
    """Keep both plan and cloud-init within the existing bounded private artifact writer."""

    root = tmp_path / "artifacts"
    prepared = PrepareStaticSite(Profile(), artifact_root=root)
    original = prepared.PlanFile.read_bytes()

    with pytest.raises(ArtifactError):
        PrepareStaticSite(Profile(), artifact_root=root)

    assert prepared.PlanFile.read_bytes() == original, "Repeated preparation must never overwrite an existing plan"

    with pytest.raises(ArtifactError):
        PrepareStaticSite(Profile(), artifact_root=tmp_path / ".." / "escape")

    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)

    with pytest.raises(ArtifactError):
        PrepareStaticSite(Profile(), artifact_root=link)


def test_ChangedServerDuringFailedPreparationIsPreserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not remove a detected same-user replacement during preparation rollback."""

    root = tmp_path / "artifacts"

    def FailRender(*arguments: object, **options: object) -> str:
        """Replace the just-published artifact and emulate a preparation failure."""

        path = Path(options["user_data_file"])  # type: ignore[arg-type]
        path.write_bytes(b"changed-by-other-writer")

        raise StaticSiteError("Synthetic preparation failure")

    monkeypatch.setattr("flayer.profiles.static_site.RenderStaticSitePlan", FailRender)

    with pytest.raises(ArtifactError):
        PrepareStaticSite(Profile(), artifact_root=root)

    assert (root / "server-site" / CLOUD_INIT_FILENAME).read_bytes() == b"changed-by-other-writer", "Rollback must preserve detected replacement bytes"


def test_ValidSameIdentityReplacementSurvivesPreparationRollback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve a coherent replacement bundle rather than reauthorizing it by identity alone."""

    profile = Profile()
    replacement = replace(profile, body="Replacement published by another cooperative writer")
    root = tmp_path / "artifacts"
    expected = BuildStaticSiteBundle(replacement).files[0].content

    def ReplaceThenFailRender(*arguments: object, **options: object) -> str:
        """Publish a valid same-identity different-outcome bundle before rendering fails."""

        RemoveArtifactBundle(root, profile.identity, kind="server", name=profile.identity.stack)
        WriteArtifactBundle(root, BuildStaticSiteBundle(replacement))

        raise StaticSiteError("Synthetic preparation failure")

    monkeypatch.setattr("flayer.profiles.static_site.RenderStaticSitePlan", ReplaceThenFailRender)

    with pytest.raises(ArtifactError):
        PrepareStaticSite(profile, artifact_root=root)

    path = root / "server-site" / CLOUD_INIT_FILENAME
    assert path.read_bytes() == expected, "Rollback must preserve valid replacement bytes despite matching ownership"
    assert not (root / ".server-site.lock").exists(), "Refused rollback must release only its own cooperative lock"
    assert RemoveArtifactBundle(root, profile.identity, kind="server", name=profile.identity.stack), "Replacement must remain a complete valid owned bundle for later explicit cleanup"


def test_PublishedOwnedPlanPreservesReferencedServerOnLateFailure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a coherent verified bundle pair when publication fails after the plan becomes visible."""

    root = tmp_path / "artifacts"

    def FailAfterPlanPublication(artifact_root: str | Path, bundle: ArtifactBundle) -> Path:
        """Emulate a final writer failure only after publishing the owned plan successfully."""

        directory = WriteArtifactBundle(artifact_root, bundle)

        if bundle.name.endswith("-plan"):
            raise ArtifactError("Synthetic final publication failure")

        return directory

    monkeypatch.setattr("flayer.profiles.static_site.WriteArtifactBundle", FailAfterPlanPublication)

    with pytest.raises(ArtifactError):
        PrepareStaticSite(Profile(), artifact_root=root)

    assert LoadDeploymentPlan(root / "server-site-plan" / "deployment-plan.toml").identity == IDENTITY, "Late failure must preserve the fully verified published plan"
    assert (root / "server-site" / CLOUD_INIT_FILENAME).is_file(), "Rollback must not remove initialization referenced by an exact owned published plan"


def test_PreparationCliReadsExampleAndReportsOnlyLocalPreparedStatus(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Offer a usable local entry point with no readiness or cloud mutation claim."""

    example = Path(__file__).resolve().parents[2] / "examples" / "static-site.toml"
    assert LoadStaticSiteProfile(example).identity == IDENTITY, "Tracked example must satisfy its concrete profile schema"
    assert Main((str(example), "--artifact-root", str(tmp_path / "artifacts"))) == 0, "CLI must prepare a local lifecycle plan"
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "prepared-unverified", "CLI must not claim deployed guest readiness"
    assert LoadDeploymentPlan(result["plan_file"]).identity == IDENTITY, "CLI output must reference a usable lifecycle plan"
    assert Main((str(example), "--artifact-root", str(tmp_path / "artifacts"))) == 1, "CLI must report exclusive publication failures"
    assert json.loads(capsys.readouterr().out)["status"] == "failed", "CLI failure must remain structured and sanitized"
    result_process = subprocess.run([sys.executable, "-m", "flayer.profiles.static_site", "--help"], env={**os.environ, "PYTHONPATH": str(example.parents[1] / "src")}, capture_output=True, text=True, check=False, timeout=5)
    assert result_process.returncode == 0 and "RuntimeWarning" not in result_process.stderr, "Module entry point must work without preloaded-module warnings"


@pytest.mark.parametrize("failed_command", ["none", "sshd", "nft", "nginx"])
def test_FixedBootstrapStopsOnSyntaxFailureBeforeServiceActivation(tmp_path: Path, failed_command: str) -> None:
    """Execute sequencing only through isolated command fakes, never host services or files."""

    script = tmp_path / "bootstrap.sh"
    script.write_text(GuestFiles()["/usr/local/sbin/f-layer-static-bootstrap"]["content"])
    syntax = subprocess.run(["/bin/sh", "-n", str(script)], capture_output=True, check=False, timeout=5)
    assert syntax.returncode == 0, "Fixed bootstrap must have valid POSIX shell syntax"
    commands = tmp_path / "commands"
    commands.mkdir()
    trace = tmp_path / "calls.txt"

    for name in ("install", "chown", "chmod", "sshd", "nft", "nginx", "sysctl", "systemctl"):
        command = commands / name
        command.write_text("#!/bin/sh\nprintf '%s %s\\n' \"${0##*/}\" \"$*\" >> \"$STATIC_SITE_TRACE\"\n" + f"[ '{name}' != \"$STATIC_SITE_FAIL\" ]\n")
        command.chmod(0o700)

    result = subprocess.run(["/bin/sh", str(script)], env={**os.environ, "PATH": str(commands), "STATIC_SITE_TRACE": str(trace), "STATIC_SITE_FAIL": failed_command}, capture_output=True, check=False, timeout=5)
    calls = trace.read_text().splitlines()

    if failed_command == "none":
        assert result.returncode == 0, "All validated fake operations must complete bootstrap sequencing"
        assert calls.index("nginx -t -c /etc/nginx/nginx.conf") < calls.index("systemctl enable --now nftables"), "All syntax checks must precede explicit service activation"
        assert "systemctl disable --now ssh.socket" in calls and "systemctl enable --now ssh.service" in calls, "SSH service must persist after socket activation is disabled"
        assert "systemctl enable --now nginx.service" in calls, "Concrete HTTP listener must be enabled for subsequent boots"

    else:
        assert result.returncode != 0 and not any(line.startswith("systemctl ") for line in calls), "A syntax failure must stop before explicit service operations"


@pytest.mark.skipif(shutil.which("sshd") is None, reason="OpenSSH is an optional offline syntax validator")
def test_OpenSshParsesExactAdministratorConfiguration(tmp_path: Path) -> None:
    """Check actual SSH parser output without keys, a network connection, or daemon startup."""

    path = tmp_path / "sshd_config"
    path.write_text(GuestFiles()["/etc/ssh/sshd_config"]["content"])
    result = subprocess.run([str(shutil.which("sshd")), "-G", "-f", str(path)], capture_output=True, text=True, check=False, timeout=5)

    if result.returncode and "unknown option -- G" in result.stderr:
        pytest.skip("Installed OpenSSH predates offline -G configuration validation")

    assert result.returncode == 0, "Generated SSH config must parse without starting a daemon"
    assert "authorizedkeysfile /etc/ssh/f-layer-static-admin-keys\n" in result.stdout, "Effective SSH authorization must use only the exact root-owned key path"
    assert "allowtcpforwarding no\n" in result.stdout and "permittunnel no\n" in result.stdout, "Effective configuration must deny gateway transport"


@pytest.mark.skipif(shutil.which("cloud-init") is None, reason="Cloud-init is an optional offline schema validator")
def test_CloudInitValidatesGeneratedSchemaWithoutGuestExecution(tmp_path: Path) -> None:
    """Validate cloud-config with the optional actual tool without installing or running it."""

    path = tmp_path / CLOUD_INIT_FILENAME
    path.write_bytes(BuildStaticSiteBundle(Profile()).files[0].content)
    result = subprocess.run([str(shutil.which("cloud-init")), "schema", "--config-file", str(path)], capture_output=True, text=True, check=False, timeout=10)

    assert result.returncode == 0, "Generated static-site cloud-config must satisfy cloud-init schema"


@pytest.mark.skipif(shutil.which("nginx") is None, reason="Nginx is an optional offline configuration validator")
def test_NginxParsesFixedConfigurationWithoutDaemonStartup(tmp_path: Path) -> None:
    """Run nginx test mode with owned scratch paths and a Unix socket, never a host TCP listener."""

    config = GuestFiles()["/etc/nginx/nginx.conf"]["content"]
    config = config.replace("pid /run/nginx.pid;", "\n".join((
        f"pid {json.dumps(str(tmp_path / 'nginx.pid'))};", "error_log stderr;",
        f"lock_file {json.dumps(str(tmp_path / 'nginx.lock'))};",
    )))
    temporary_directives: list[str] = []

    for module in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
        directory = tmp_path / (module + "-temp")
        directory.mkdir(mode=0o700)
        temporary_directives.append(f"    {module}_temp_path {json.dumps(str(directory))};")

    config = config.replace("http {\n", "http {\n" + "\n".join(temporary_directives) + "\n", 1)
    socket_listener = "listen " + json.dumps("unix:" + str(tmp_path / "n.sock")) + " default_server;"
    config = config.replace("listen 80 default_server;", socket_listener, 1)
    path = tmp_path / "nginx.conf"
    path.write_text(config)
    result = subprocess.run([str(shutil.which("nginx")), "-t", "-e", "stderr", "-p", str(tmp_path), "-c", str(path)], capture_output=True, text=True, check=False, timeout=5)

    assert result.returncode == 0, "Fixed nginx configuration must parse without startup: " + result.stderr


def test_NginxValidatorIsolatesWritablePathsAndRetainsServerGrammar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the optional validator boundary through a fake installed executable without startup."""

    calls: list[list[str]] = []

    def FakeRun(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        """Inspect the complete test configuration and require bounded parser-only invocation."""

        calls.append(command)
        assert command[0] == "/synthetic/nginx" and "-t" in command, "Validator must invoke installed nginx only in test mode"
        assert command[command.index("-e") + 1] == "stderr", "Early nginx diagnostics must not open a host error log"
        assert Path(command[command.index("-p") + 1]) == tmp_path, "Relative nginx paths must use the owned sandbox prefix"
        config = Path(command[command.index("-c") + 1]).read_text()
        original = GuestFiles()["/etc/nginx/nginx.conf"]["content"]
        socket_listener = "listen " + json.dumps("unix:" + str(tmp_path / "n.sock")) + " default_server;"
        assert socket_listener in config and config.count("listen ") == 1, "Nginx test mode must have only the caller-owned Unix socket listener"
        restored = config.replace(socket_listener, "listen 80 default_server;", 1)
        assert restored[restored.index("    default_type text/html;"):] == original[original.index("    default_type text/html;"):], "Validation must retain generated HTTP and server grammar except its isolated listen endpoint"
        assert "error_log stderr;" in config and "access_log off;" in config, "Nginx must have no writable default host logs"

        for filename, directive in (("nginx.pid", "pid"), ("nginx.lock", "lock_file")):
            assert f"{directive} {json.dumps(str(tmp_path / filename))};" in config, "Main nginx writable paths must remain sandbox owned"

        for module in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"):
            directory = tmp_path / (module + "-temp")
            assert f"{module}_temp_path {json.dumps(str(directory))};" in config, "Every compiled HTTP temporary path must have an explicit sandbox override"
            assert directory.is_dir() and directory.stat().st_mode & 0o777 == 0o700, "Temporary nginx paths must be precreated as private owned directories"

        return subprocess.CompletedProcess(command, 0, stdout="", stderr="synthetic configuration test passed")

    monkeypatch.setattr(shutil, "which", lambda name: "/synthetic/nginx")
    monkeypatch.setattr(subprocess, "run", FakeRun)
    test_NginxParsesFixedConfigurationWithoutDaemonStartup(tmp_path)
    assert len(calls) == 1, "Configuration validation must not start another executable or service"


def test_MaximumTextAndSourceBudgetsRemainWithinProviderArtifactLimit(tmp_path: Path) -> None:
    """Exercise bounded maximum expansion and exact sizing without provider execution."""

    profile = replace(Profile(), title="t" * 160, body="&" * 8192,
                      admin_source_cidrs=tuple(f"198.51.100.{index}/32" for index in range(16)),
                      http_source_cidrs=tuple(f"192.0.2.{index}/32" for index in range(16)),
                      cores=32, memory_gib=64, boot_disk_gib=256)
    prepared = PrepareStaticSite(profile, artifact_root=tmp_path / "maximum")
    resources = tomllib.loads(prepared.PlanFile.read_text())["resources"]
    firewall = next(item for item in resources if item["kind"] == "security-group")

    assert len(firewall["parameters"]["rules"]) == 33, "Maximum profile must remain inside the provider 64-rule contract"
    assert len((prepared.server_directory / CLOUD_INIT_FILENAME).read_bytes()) < 262144, "Maximum escaped page must remain within the provider metadata bound"
