"""Compose the second profile with actual lifecycle and Yandex adapters through a fake CLI."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from flayer.core.lifecycle import LifecycleEngine, LoadDeploymentPlan
from flayer.core.state import LoadState
from flayer.profiles.artifacts import RemoveArtifactBundle
from flayer.profiles.static_site import (
    CLOUD_INIT_FILENAME,
    LoadStaticSiteProfile,
    PrepareStaticSite,
)
from flayer.providers.yandex import CommandResult, YandexCloudSettings
from flayer.providers.yandex_lifecycle import YandexLifecycleProvider


class StaticSiteRunner:
    """Emulate the six resource kinds in memory without credentials, sockets, or a real CLI."""

    def __init__(self) -> None:
        """Initialize isolated command evidence and fake cloud observations."""

        self.calls: list[tuple[str, ...]] = []
        self.resources: dict[str, dict[str, object]] = {}
        self.metadata: bytes | None = None
        self.temporary_path: Path | None = None
        self.temporary_mode: int | None = None

    def Run(self, command: tuple[str, ...], timeout: float) -> CommandResult:
        """Return synthetic scoped observations and capture temporary metadata during dispatch."""

        assert timeout == 45.0, "Adapter must retain its bounded command deadline"
        assert command[command.index("--folder-id") + 1] == "example-folder", "Every fake command must use explicit profile placement"

        self.calls.append(command)
        kind, operation = command[2:4]

        if operation == "list":
            rows = [row for row in self.resources.values() if row["test_kind"] == kind]

            return CommandResult(0, json.dumps(rows))

        if operation == "get":
            resource_id = command[command.index("--id") + 1]

            if resource_id not in self.resources:
                return CommandResult(1, stderr="NOT_FOUND synthetic resource")

            return CommandResult(0, json.dumps(self.resources[resource_id]))

        if operation == "delete":
            resource_id = command[command.index("--id") + 1]
            self.resources.pop(resource_id, None)

            return CommandResult(0)

        assert operation == "create", "Fake runner must not accept an unmodeled cloud operation"

        resource_id = f"resource-{len(self.resources) + 1}"
        row: dict[str, object] = {
            "id": resource_id, "name": command[command.index("--name") + 1],
            "folder_id": "example-folder", "test_kind": kind,
            "labels": dict(item.split("=", 1) for item in command[command.index("--labels") + 1].split(",")),
        }

        if "--zone" in command:
            row["zone_id"] = command[command.index("--zone") + 1]

        if kind == "address":
            row["external_ipv4_address"] = {"address": "192.0.2.10", "zone_id": "example-zone"}

        if kind == "instance":
            row["status"] = "RUNNING"
            row["network_interfaces"] = [{"primary_v4_address": {"one_to_one_nat": {"address": "192.0.2.10"}}}]
            self.temporary_path = Path(command[command.index("--metadata-from-file") + 1].removeprefix("user-data="))
            self.metadata = self.temporary_path.read_bytes()
            self.temporary_mode = self.temporary_path.stat().st_mode & 0o777

        elif kind == "disk":
            row["status"] = "READY"

        self.resources[resource_id] = row

        return CommandResult(0, json.dumps(row))


def test_SecondProfileComposesWithYandexAndDurableLifecycle(tmp_path: Path) -> None:
    """Run real engine create/status/idempotency/destroy and clean exact prepared artifacts."""

    example = Path(__file__).resolve().parents[2] / "examples" / "static-site.toml"
    profile = LoadStaticSiteProfile(example)
    artifact_root = tmp_path / "artifacts"
    prepared = PrepareStaticSite(profile, artifact_root=artifact_root)
    plan = LoadDeploymentPlan(prepared.PlanFile)
    runner = StaticSiteRunner()
    provider = YandexLifecycleProvider(YandexCloudSettings(profile.identity.scope_id), runner)
    state_path = tmp_path / "stack.json"
    engine = LifecycleEngine(plan, provider, state_path)

    assert runner.calls == [], "Plan parsing and provider validation must remain offline"
    assert engine.Create().status == "complete", "Static-site plan must compose with existing owned create semantics"

    creates = [command for command in runner.calls if command[3] == "create"]

    assert len(creates) == 6, "New profile must use six separately owned resources without hidden creation"
    assert {command[2] for command in creates} == {"network", "subnet", "security-group", "address", "disk", "instance"}, "Static site must reuse existing provider resource kinds"

    instance = creates[-1]

    assert "--create-boot-disk" not in instance and "auto-delete=false" in instance[instance.index("--use-boot-disk") + 1], "Boot disk cleanup must remain an explicit lifecycle operation"
    assert instance[instance.index("--metadata") + 1].startswith("ssh-keys=site-admin:"), "Metadata must use the same explicit administrator as guest authorization"

    expected = (prepared.server_directory / CLOUD_INIT_FILENAME).read_bytes()

    assert runner.metadata == expected, "Actual provider metadata reader must dispatch exact profile bytes"
    assert runner.temporary_mode == 0o600 and runner.temporary_path is not None and not runner.temporary_path.exists(), "Provider temporary metadata copy must remain private and be removed after dispatch"

    state = LoadState(state_path, profile.identity)

    assert state is not None and len(state.resources) == 6, "Actual engine must persist all owned resources"
    assert "public_key" not in state_path.read_text() and "A small public page" not in state_path.read_text(), "Observed state must not absorb profile content or public credentials"

    status = engine.Status()

    assert status.status == "complete" and all(item.status == "present" for item in status.resources), "Status must report cloud existence without claiming HTTP readiness"
    assert "RUNNING" in {item.provider_status for item in status.resources}, "Fake guest state must remain a provider observation"
    assert engine.Create().status == "complete", "Repeated create must be idempotent"
    assert len([command for command in runner.calls if command[3] == "create"]) == 6, "Idempotent create must not mutate another resource"
    assert engine.Destroy().status == "complete", "Actual destroy must remove the complete owned graph"

    deletions = [command for command in runner.calls if command[3] == "delete"]

    assert deletions[0][2] == "instance" and deletions[-1][2] == "network", "Destroy must obey reverse dependencies"
    assert not runner.resources and engine.Destroy().status == "complete", "Destroy must be idempotent after verified absence"

    RemoveArtifactBundle(artifact_root, profile.identity, kind="server", name=profile.identity.stack + "-plan")
    RemoveArtifactBundle(artifact_root, profile.identity, kind="server", name=profile.identity.stack)

    assert list(artifact_root.iterdir()) == [], "Local cleanup must remove both exact owned prepared bundles"


def test_ActualYandexDigestReaderRejectsChangedInitializationBeforeInstanceMutation(tmp_path: Path) -> None:
    """Detect stale metadata through the existing adapter and roll back earlier owned resources."""

    profile = LoadStaticSiteProfile(Path(__file__).resolve().parents[2] / "examples" / "static-site.toml")
    prepared = PrepareStaticSite(profile, artifact_root=tmp_path / "artifacts")
    plan = LoadDeploymentPlan(prepared.PlanFile)
    path = prepared.server_directory / CLOUD_INIT_FILENAME
    expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_bytes(b"#cloud-config\n{}\n")
    runner = StaticSiteRunner()
    engine = LifecycleEngine(plan, YandexLifecycleProvider(YandexCloudSettings(profile.identity.scope_id), runner), tmp_path / "state.json")
    result = engine.Create()

    assert expected_digest != hashlib.sha256(path.read_bytes()).hexdigest(), "Test must change exact metadata content after plan preparation"
    assert result.status == "rolled-back" and not result.recovery_required, "Provider preflight rejection must compose with safe rollback"
    assert not any(command[2:4] == ("instance", "create") for command in runner.calls), "Changed metadata must be rejected before guest mutation"
    assert not runner.resources, "Earlier fake resources must be cleaned by actual lifecycle rollback"
    assert path.read_bytes() == b"#cloud-config\n{}\n", "Provider rejection must preserve externally changed local bytes"
