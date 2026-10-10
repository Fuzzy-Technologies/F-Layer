"""Safety contracts for portable desired configuration and credential references."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from flayer.core.config import (
    ConfigError,
    DesiredConfig,
    DesiredResource,
    LoadConfig,
    ParseConfig,
    SecretReference,
)
from flayer.core.contracts import ContractError, StackIdentity


def ConfigData() -> dict[str, object]:
    """Return a synthetic provider-independent configuration with no infrastructure access."""

    return {
        "schema_version": 1,
        "profile": "secure-gateway",
        "identity": {
            "project": "example",
            "stack": "demo",
            "provider": "example-cloud",
            "scope_id": "example-scope",
            "owner_id": "example-owner",
        },
        "resources": [{"logical_id": "gateway", "kind": "instance", "name": "demo-gateway"}],
        "credentials": [{"name": "cloud-auth", "source": "env", "reference": "EXAMPLE_AUTH"}],
    }


def test_LoadExplicitConfigWithoutReadingCredentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loading records credential locations without reading environment values or files."""

    path = tmp_path / "stack.toml"
    path.write_text(
        'schema_version = 1\nprofile = "secure-gateway"\n'
        '[identity]\nproject = "example"\nstack = "demo"\nprovider = "example-cloud"\n'
        'scope_id = "example-scope"\nowner_id = "example-owner"\n'
        '[[resources]]\nlogical_id = "gateway"\nkind = "instance"\nname = "demo-gateway"\n'
        '[[credentials]]\nname = "cloud-auth"\nsource = "env"\nreference = "EXAMPLE_AUTH"\n'
        '[[credentials]]\nname = "ssh-auth"\nsource = "file"\nreference = "./missing-key"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("EXAMPLE_AUTH", "synthetic-secret-must-not-be-loaded")
    config = LoadConfig(path)

    assert config.identity.provider == "example-cloud", "Provider identity was changed"
    assert config.resources[0].logical_id == "gateway", "Logical resource identity was lost"
    assert config.credentials[0].reference == "EXAMPLE_AUTH", "Credential reference was resolved"
    assert config.credentials[1].reference == "./missing-key", "Credential file was resolved"
    assert "synthetic-secret" not in repr(config), "Secret material entered the desired model"


def test_MinimalConfigHasNoImplicitProviderResources() -> None:
    """Optional resource and credential arrays default to empty, without implicit infrastructure."""

    data = ConfigData()
    del data["resources"]
    del data["credentials"]
    config = ParseConfig(data)

    assert config.resources == (), "Minimal config unexpectedly requests infrastructure"
    assert config.credentials == (), "Minimal config unexpectedly adds credential references"


@pytest.mark.parametrize("schema_version", [True, False, 0, 2, "1", 1.0, None])
def test_UnknownSchemaVersionsFailClosed(schema_version: object) -> None:
    """Unsupported versions and coercible values cannot reach provider code."""

    data = ConfigData()
    data["schema_version"] = schema_version

    with pytest.raises(ConfigError, match="schema_version"):
        ParseConfig(data)


@pytest.mark.parametrize("field", ["schema_version", "identity", "profile"])
def test_RequiredFieldsCannotDefaultToAnotherStack(field: str) -> None:
    """Missing ownership and profile values never select another implicit stack."""

    data = ConfigData()
    del data[field]

    with pytest.raises(ConfigError, match="required"):
        ParseConfig(data)


@pytest.mark.parametrize("section", ["root", "identity", "resources", "credentials"])
def test_UnknownFieldsRejectInlineSecrets(section: str) -> None:
    """Unexpected credential payloads and misspelled settings fail without echoing values."""

    data = ConfigData()

    if section == "root":
        table = data

    elif section == "identity":
        table = data[section]

    else:
        table = data[section][0]  # type: ignore[index]

    assert isinstance(table, dict), "Synthetic table construction failed"

    table["token"] = "synthetic-secret"

    with pytest.raises(ConfigError, match="unknown") as captured:
        ParseConfig(data)

    assert "synthetic-secret" not in str(captured.value), "Error leaked an inline secret value"


@pytest.mark.parametrize("section", ["identity", "resources", "credentials"])
@pytest.mark.parametrize("value", [None, "unexpected", 7])
def test_WrongSectionTypesFailClosed(section: str, value: object) -> None:
    """Malformed section types never degrade into empty or default settings."""

    data = ConfigData()
    data[section] = value

    with pytest.raises(ConfigError, match="table"):
        ParseConfig(data)


@pytest.mark.parametrize("section", ["resources", "credentials"])
def test_ArrayEntriesRequireTables(section: str) -> None:
    """Every resource and credential entry must have a typed object boundary."""

    data = ConfigData()
    data[section] = ["unexpected"]

    with pytest.raises(ConfigError, match="table"):
        ParseConfig(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [("project", "Bad_Name"), ("stack", ""), ("provider", 7), ("owner_id", "../escape"),
     ("scope_id", "line\nbreak"), ("scope_id", ""), ("scope_id", "x" * 257)],
)
def test_InvalidIdentityFieldsAreRejected(field: str, value: object) -> None:
    """Ownership identity must remain explicit, portable, and unambiguous."""

    data = ConfigData()
    identity = data["identity"]

    assert isinstance(identity, dict), "Synthetic identity construction failed"

    identity[field] = value

    with pytest.raises(ConfigError, match=field):
        ParseConfig(data)


@pytest.mark.parametrize(
    ("source", "reference"),
    [("inline", "synthetic-secret"), ("env", "lower-case"), ("env", ""),
     ("file", ""), ("file", " path "), ("file", "line\nbreak"),
     ("file", "x" * 4097), (7, "EXAMPLE_AUTH"), ("env", True)],
)
def test_InvalidCredentialSourcesNeverResolve(source: object, reference: object) -> None:
    """Only named environment variables and bounded file paths are credential sources."""

    data = ConfigData()
    data["credentials"] = [{"name": "auth", "source": source, "reference": reference}]

    with pytest.raises(ConfigError, match="credentials"):
        ParseConfig(data)


@pytest.mark.parametrize("section", ["resources", "credentials"])
def test_DuplicateLogicalNamesAreRejected(section: str) -> None:
    """Duplicate logical identifiers cannot select ambiguous resources or credentials."""

    data = ConfigData()
    values = data[section]

    assert isinstance(values, list), "Synthetic array construction failed"

    values.append(values[0].copy())

    with pytest.raises(ConfigError, match="unique"):
        ParseConfig(data)


@pytest.mark.parametrize(
    "content",
    [b"[broken", b"\xff", b"schema_version=1\nschema_version=1\n",
     b"schema_version=" + b"9" * 5000 + b"\n",
     b"nested=" + b"[" * 2000 + b"0" + b"]" * 2000 + b"\n"],
)
def test_MalformedTomlIsReportedAsConfigurationError(tmp_path: Path, content: bytes) -> None:
    """Malformed syntax, encoding, and duplicate fields fail before desired-state construction."""

    path = tmp_path / "broken.toml"
    path.write_bytes(content)

    with pytest.raises(ConfigError, match="valid TOML"):
        LoadConfig(path)


def test_MissingConfigDoesNotUseMachineDefaults(tmp_path: Path) -> None:
    """A missing explicit file is an error instead of a request for default infrastructure."""

    with pytest.raises(ConfigError, match="valid TOML"):
        LoadConfig(tmp_path / "missing.toml")


def test_ModelConstructionPreservesInvariants() -> None:
    """Direct callers receive the same validation and immutable data as TOML callers."""

    config = ParseConfig(ConfigData())

    with pytest.raises(FrozenInstanceError):
        config.profile = "other"  # type: ignore[misc]

    with pytest.raises(ContractError, match="StackIdentity"):
        DesiredConfig(identity="wrong", profile="demo")  # type: ignore[arg-type]

    with pytest.raises(ContractError, match="tuple of DesiredResource"):
        DesiredConfig(
            identity=config.identity, profile="demo", resources=("wrong",)  # type: ignore[arg-type]
        )

    with pytest.raises(ContractError, match="tuple of SecretReference"):
        DesiredConfig(
            identity=config.identity, profile="demo", credentials=("wrong",)  # type: ignore[arg-type]
        )

    with pytest.raises(ContractError, match="logical_id"):
        DesiredResource(logical_id="BAD", kind="instance", name="demo")

    with pytest.raises(ContractError, match="environment"):
        SecretReference(name="auth", source="env", reference=7)  # type: ignore[arg-type]


def test_OwnershipLabelsContainExactProjectStackAndOwner() -> None:
    """Provider adapters get stable ownership labels without private or cloud-specific defaults."""

    identity = StackIdentity("example", "demo", "example-cloud", "example-scope", "owner")

    assert identity.OwnershipLabels() == {
        "managed-by": "f-layer",
        "flayer-project": "example",
        "flayer-stack": "demo",
        "flayer-owner": "owner",
    }, "Ownership labels do not identify the exact stack owner"
