"""Offline CLI authorization and adapter dispatch without real cloud mutation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flayer.__main__ import Main
from flayer.core.lifecycle import LifecycleReport
from flayer.providers.contracts import ProviderError, ProviderErrorCode
from flayer.providers.yandex import YandexCloudSettings

PLAN_TEXT = '''schema_version = 1
resources = []
[identity]
project = "example"
stack = "sandbox"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"
'''


class FakeEngine:
    """Record dispatch and return fixed outcomes independently from cloud resources."""

    calls: list[str] = []

    def __init__(self, plan: object, provider: object, state_path: str) -> None:
        """Accept only the already-validated explicit inputs passed by the CLI."""

        self.state_path = state_path

    def Create(self) -> LifecycleReport:
        """Record an explicit create call."""

        self.calls.append("create")

        return LifecycleReport("create", "complete")

    def Status(self) -> LifecycleReport:
        """Record a read-only stack status call."""

        self.calls.append("status")

        return LifecycleReport("status", "incomplete")

    def Destroy(self) -> LifecycleReport:
        """Record an explicit destroy call."""

        self.calls.append("destroy")

        return LifecycleReport("destroy", "complete")

    def Recover(self, rollback: bool = False) -> LifecycleReport:
        """Record whether explicit interrupted recovery requested rollback."""

        self.calls.append("rollback" if rollback else "recover")

        return LifecycleReport("recover", "uncertain", recovery_required=True)


def Arguments(tmp_path: Path, action: str) -> list[str]:
    """Write a portable local plan and return fully explicit CLI arguments."""

    path = tmp_path / "plan.toml"
    path.write_text(PLAN_TEXT, encoding="utf-8")
    result = ["lifecycle", action, "--config", str(path), "--state", str(tmp_path / "stack.json"),
              "--yc-profile", "sandbox", "--format", "json"]

    if action != "status":
        result.extend(["--allow-mutation", "--scope-confirm", "example-folder"])

    return result


@pytest.mark.parametrize("action,expected,exit_code", [
    ("create", "create", 0), ("status", "status", 1), ("destroy", "destroy", 0),
    ("recover", "recover", 1), ("recover", "rollback", 1),
])
def test_ExplicitLifecycleDispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    action: str, expected: str, exit_code: int,
) -> None:
    """The CLI passes selected scope and profile only after concrete authorization checks."""

    import flayer.core.lifecycle as lifecycle
    import flayer.providers.yandex_lifecycle as yandex

    seen: list[YandexCloudSettings] = []

    def Provider(settings: YandexCloudSettings) -> object:
        """Record non-secret provider selectors without invoking yc."""

        seen.append(settings)

        return object()

    FakeEngine.calls = []
    monkeypatch.setattr(lifecycle, "LifecycleEngine", FakeEngine)
    monkeypatch.setattr(yandex, "YandexLifecycleProvider", Provider)
    arguments = Arguments(tmp_path, action)

    if expected == "rollback":
        arguments.append("--rollback")

    assert Main(arguments) == exit_code
    assert FakeEngine.calls == [expected]
    assert seen[0].folder_id == "example-folder" and seen[0].profile == "sandbox"
    assert json.loads(capsys.readouterr().out)["action"] == action


@pytest.mark.parametrize("change", ["no-opt-in", "wrong-scope", "unsupported-provider", "bad-file"])
def test_BlockedMutationNeverConstructsProvider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], change: str
) -> None:
    """Missing authorization or invalid plan blocks dispatch before cloud adapter construction."""

    import flayer.providers.yandex_lifecycle as yandex

    def ForbiddenProvider(settings: YandexCloudSettings) -> object:
        """Fail the test if blocked input can construct a cloud execution adapter."""

        raise AssertionError("Blocked mutation must never construct the provider")

    monkeypatch.setattr(yandex, "YandexLifecycleProvider", ForbiddenProvider)
    arguments = Arguments(tmp_path, "create")

    if change == "no-opt-in":
        arguments.remove("--allow-mutation")

    elif change == "wrong-scope":
        arguments[-1] = "foreign-folder"

    elif change == "unsupported-provider":
        (tmp_path / "plan.toml").write_text(PLAN_TEXT.replace("yandex-cloud", "unsupported"),
                                          encoding="utf-8")

    else:
        (tmp_path / "plan.toml").unlink()

    assert Main(arguments) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "failed"


def test_LifecycleProviderFailureAndTextOutputAreSanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Provider failure produces a stable public outcome without raw command details."""

    import flayer.core.lifecycle as lifecycle
    import flayer.providers.yandex_lifecycle as yandex

    def FailedProvider(settings: YandexCloudSettings) -> object:
        """Inject a sanitized provider failure before a cloud call can occur."""

        raise ProviderError(ProviderErrorCode.PERMISSION_DENIED, "fixture")

    monkeypatch.setattr(yandex, "YandexLifecycleProvider", FailedProvider)
    arguments = Arguments(tmp_path, "status")
    arguments[-1] = "text"

    assert Main(arguments) == 2
    assert capsys.readouterr().out == "Lifecycle operation blocked or failed\n"

    monkeypatch.setattr(yandex, "YandexLifecycleProvider", lambda settings: object())
    monkeypatch.setattr(lifecycle, "LifecycleEngine", FakeEngine)

    assert Main(arguments) == 1
    assert "Lifecycle status: incomplete" in capsys.readouterr().out


@pytest.mark.parametrize("arguments", [
    ["--help"], ["lifecycle", "--help"], ["lifecycle", "create", "--help"],
    ["lifecycle", "destroy", "--help"], ["lifecycle", "recover", "--help"],
    ["lifecycle", "status", "--help"],
])
def test_AllLifecycleHelpIsOffline(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    """Every help surface succeeds without plan, credentials, yc, or cloud access."""

    with pytest.raises(SystemExit) as result:
        Main(arguments)

    assert result.value.code == 0
    assert "usage:" in capsys.readouterr().out


def test_MissingRequiredSelectorsFailWithoutEchoingRawInput(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """Argument errors keep argparse's exit code without exposing an untrusted path."""

    with pytest.raises(SystemExit) as result:
        Main(["lifecycle", "create", "--config", "synthetic-private-path"])

    assert result.value.code == 2
    assert "synthetic-private-path" not in capsys.readouterr().err
