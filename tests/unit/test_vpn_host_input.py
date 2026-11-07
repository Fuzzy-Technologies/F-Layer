"""Retain frozen host input semantics and scope one protocol delta without any filesystem or network mutation."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from test_vpn_project_selection import PUBLIC_KEY, Configuration

from flayer import _vpn_host_input as host
from flayer._vpn_creation import CreationBaseline, ProtocolPin, StaticFingerprint, _Json
from flayer.core.contracts import StackIdentity
from flayer.profiles.artifacts import Artifact, ArtifactBundle
from flayer.profiles.vpn import VpnListener
from flayer.vpn_project import SelectedVpnProject, _Bootstrap, _CompileOwnedResources
from flayer.vpn_project_v2 import ParseSelectedProject


def Policy(root: Path, protocols: tuple[str, ...] = ("amneziawg", "vless-reality", "wireguard")) -> tuple[SelectedVpnProject, CreationBaseline, host.InputPolicy]:
    """Use the real original bootstrap/compiler with synthetic nonsecret projection pins, entirely in memory."""

    project = ParseSelectedProject(root, Configuration(protocols), PUBLIC_KEY)
    content = _Bootstrap(project).files[0].content
    plan = _CompileOwnedResources(project, root / "cloud-init.json", content)
    bundle = ArtifactBundle(project.vpn.identity, "server", project.vpn.identity.stack + "-creation", (
        Artifact("creation.json", b"{}\n", False), Artifact("cloud-init.json", content, False)))
    pins = tuple(ProtocolPin(item.protocol, project.TransportFingerprint(item.protocol), "a" * 64, "b" * 64) for item in project.protocolSelections)
    baseline = CreationBaseline(plan, project.Fingerprint(), StaticFingerprint(project), pins, bundle)

    return project, baseline, host.BindBootstrap(baseline, project.cloud.managementCidrs, project.vpn.listeners)


def Native(policy: host.InputPolicy) -> dict[str, Any]:
    """Model only the native document shape; actual compiler/live rule conformance runs in isolated Linux CI."""

    table = {"family": "inet", "name": "flayer_bootstrap", "handle": 1}

    if policy.Marker:
        table["comment"] = policy.Marker

    chain = {"family": "inet", "table": "flayer_bootstrap", "name": "input", "handle": 2,
             "type": "filter", "hook": "input", "prio": 0, "policy": "drop"}
    rule = {"family": "inet", "table": "flayer_bootstrap", "chain": "input", "handle": 3,
            "expr": [{"match": {"op": "==", "left": {"ct": {"key": "state"}}, "right": "invalid"}}, {"drop": None}]}

    return {"nftables": [{"metainfo": {"json_schema_version": 1}}, {"table": table}, {"chain": chain}, {"rule": rule}]}


@pytest.mark.parametrize("protocols", [("amneziawg",), ("vless-reality",), ("wireguard",), ("amneziawg", "vless-reality", "wireguard")])
def test_OriginalPolicyBindsExactFrozenBootstrapWithoutRegenerationOrPublication(tmp_path: Path, protocols: tuple[str, ...]) -> None:
    """Original template bytes remain unchanged while their creation owner and digest become explicit public policy data."""

    project, baseline, policy = Policy(tmp_path / "absent", protocols)
    document = json.loads(next(item.content for item in baseline.bundle.files if item.name == "cloud-init.json").removeprefix(b"#cloud-config\n"))
    expected = next(item["content"] for item in document["write_files"] if item["path"] == "/etc/nftables.conf").encode()

    assert policy._OriginalFile() == expected and policy.listeners == project.vpn.listeners
    assert policy.managementCidrs == project.cloud.managementCidrs and not policy.Marker
    assert policy.originalBootSha256 == host._Digest(expected) and policy.Record()["schema_version"] == 1
    assert not project.root.exists()

    with pytest.raises(host.VpnError, match="explicit protocol operation"):
        policy.BootFile()


@pytest.mark.parametrize("fault", ["foreign-role", "private-flag", "missing-source", "bad-header", "missing-input", "duplicate-input", "owner", "permissions", "content", "extra-rule", "protocol-attribution"])
def test_UnsupportedOrDriftedBootstrapCannotBeReinterpretedAsAnOriginalInputPolicy(tmp_path: Path, fault: str) -> None:
    """The original source and protocol order are proved independently from a port number or current desired configuration."""

    project, baseline, _ = Policy(tmp_path / "absent")
    raw = baseline.bundle.files[-1].content
    document = json.loads(raw.removeprefix(b"#cloud-config\n"))
    entry = next(item for item in document["write_files"] if item["path"] == "/etc/nftables.conf")
    listeners = project.vpn.listeners

    if fault == "foreign-role":
        baseline = replace(baseline, bundle=replace(baseline.bundle, name="different-creation"))

    elif fault == "private-flag":
        baseline = replace(baseline, bundle=replace(baseline.bundle, files=(baseline.bundle.files[0], replace(baseline.bundle.files[-1], sensitive=True))))

    elif fault == "missing-source":
        baseline = replace(baseline, bundle=replace(baseline.bundle, files=baseline.bundle.files[:1]))

    elif fault == "bad-header":
        raw = b"unsupported\n" + raw

    elif fault == "missing-input":
        document["write_files"].remove(entry)

    elif fault == "duplicate-input":
        document["write_files"].append(dict(entry))

    elif fault in {"owner", "permissions", "content"}:
        entry[fault] = 1 if fault == "content" else "unsupported"

    elif fault == "extra-rule":
        entry["content"] = entry["content"].replace("    ct state invalid drop", "    accept\n    ct state invalid drop")

    else:
        listeners = tuple(replace(listener, transport="wireguard" if listener.transport == "amneziawg" else "amneziawg")
                          if listener.transport in {"amneziawg", "wireguard"} else listener for listener in listeners)

    if fault not in {"foreign-role", "private-flag", "missing-source", "protocol-attribution"}:
        if fault != "bad-header":
            raw = b"#cloud-config\n" + _Json(document)

        baseline = replace(baseline, bundle=replace(baseline.bundle, files=(baseline.bundle.files[0], Artifact("cloud-init.json", raw, False))))

    with pytest.raises(host.VpnError):
        host.BindBootstrap(baseline, project.cloud.managementCidrs, listeners)

    assert not project.root.exists()


def test_OneListenerChangePreservesSshOtherTransportsAndOriginalCreationIdentity(tmp_path: Path) -> None:
    """Live replacement is one owned-table batch, and persistent/replayed boot overlay never flushes unrelated tables."""

    project, baseline, before = Policy(tmp_path / "absent")
    listener = next(item for item in before.listeners if item.transport == "wireguard")
    transition = host.InputTransition(before, listener, "disable", "a" * 32)
    after, restored = transition.After(), transition.Restored()

    assert tuple(item for item in before.listeners if item.transport != "wireguard") == after.listeners
    assert after.identity == before.identity and after.creationSha256 == before.creationSha256
    assert after.originalBootSha256 == before.originalBootSha256 and after.managementCidrs == before.managementCidrs
    assert restored.listeners == before.listeners and restored.Marker != before.Marker
    assert after.Marker == restored.Marker and after.Table() != restored.Table()
    assert transition.LiveScript().startswith(b"delete table inet flayer_bootstrap\n")
    assert transition.LiveScript(rollback=True).endswith(restored.Table())
    assert after.BootFile().startswith(b"#!/usr/sbin/nft -f\ndestroy table inet flayer_bootstrap\n")

    for content in (transition.LiveScript(), transition.LiveScript(rollback=True), after.BootFile(), restored.BootFile()):
        assert b"flush ruleset" not in content and b"systemctl" not in content and b"sysctl" not in content
        assert all(f"ip saddr {cidr} tcp dport 22 accept".encode() in content for cidr in before.managementCidrs)

    assert baseline.bundle.files[-1].content == _Bootstrap(project).files[0].content and not project.root.exists()


def test_DisablingTheFinalListenerRetainsSshAndExplicitReenableKeepsTheRetainedPublicListener(tmp_path: Path) -> None:
    """No active VPN listener is a valid input policy, and a later explicit generation can reopen the same declared port/sources."""

    _, _, before = Policy(tmp_path / "absent", ("wireguard",))
    listener = before.listeners[0]
    closed = host.InputTransition(before, listener, "disable", "a" * 32).After()
    enabled = host.InputTransition(closed, listener, "enable", "b" * 32).After()

    assert not closed.listeners and b"tcp dport 22 accept" in closed.Table()
    assert enabled.listeners == before.listeners and enabled.Marker not in {before.Marker, closed.Marker}
    assert enabled.originalBootSha256 == before.originalBootSha256


def test_DhcpClientPortCannotBeEnabledWithARestrictedSourceOrAcceptedAsADisabledProtocol(tmp_path: Path) -> None:
    """The unconditional UDP67→68 DHCP exception must never bypass a protocol ACL or remain after a claimed protocol disable."""

    project, baseline, before = Policy(tmp_path / "absent", ("wireguard",))
    listener = before.listeners[0]
    closed = host.InputTransition(before, listener, "disable", "a" * 32).After()
    reserved = replace(listener, port=68, sourceCidrs=("198.51.100.0/24",))

    with pytest.raises(host.VpnError, match="reserved"):
        host.InputTransition(closed, reserved, "enable", "b" * 32)

    modified = replace(project, vpn=replace(project.vpn, listeners=(reserved,)))
    raw = _Bootstrap(modified).files[0].content
    unsafe = replace(baseline, bundle=replace(baseline.bundle, files=(baseline.bundle.files[0], Artifact("cloud-init.json", raw, False))))

    with pytest.raises(host.VpnError, match="reserved"):
        host.BindBootstrap(unsafe, project.cloud.managementCidrs, (reserved,))

    with pytest.raises(host.VpnError, match="reserved"):
        host.InputTransition(before, reserved, "disable", "c" * 32)


@pytest.mark.parametrize("field", ["transport", "protocol", "source"])
def test_DisableRejectsScalarSubclassesBeforeEqualityOrFilteringCanRemoveMultipleListeners(tmp_path: Path, field: str) -> None:
    """An input removed by After() still needs full validation; custom equality must not broaden the sole target."""

    class AnyString(str):
        """Model a string subtype that can compare equal to unrelated transport and L4 protocol names."""

        __hash__ = str.__hash__

        def __eq__(self, other: object) -> bool:
            """Demonstrate the danger of using an unvalidated subtype in dataclass tuple equality."""

            return isinstance(other, str)

    _, _, initial = Policy(tmp_path / "absent")
    vless = next(item for item in initial.listeners if item.transport == "vless-reality")
    wireguard = replace(next(item for item in initial.listeners if item.transport == "wireguard"), port=vless.port)
    before = replace(initial, operationId="a" * 32, listeners=(vless, wireguard))
    changes: dict[str, Any] = {field: AnyString(getattr(wireguard, field))} if field != "source" else {"sourceCidrs": (AnyString("0.0.0.0/0"),)}
    unsafe = replace(wireguard, **changes)

    with pytest.raises(host.VpnError):
        host.InputTransition(before, unsafe, "disable", "b" * 32)

    both = replace(wireguard, transport=AnyString(wireguard.transport), protocol=AnyString(wireguard.protocol))
    assert all(item == both for item in before.listeners)

    with pytest.raises(host.VpnError):
        host.InputTransition(before, both, "disable", "c" * 32)

    assert before.listeners == (vless, wireguard)


@pytest.mark.parametrize("fault", ["wrong-disable", "already-active", "port-collision", "ssh", "same-generation", "invalid-generation"])
def test_TransitionRefusesCollateralOrStaleChangesBeforeAnyCommandCouldBePrepared(tmp_path: Path, fault: str) -> None:
    """Transport identity, full source policy and a fresh operation marker cannot be substituted by a matching L4 port alone."""

    _, _, before = Policy(tmp_path / "absent")
    before = replace(before, operationId="a" * 32)
    listener = next(item for item in before.listeners if item.transport == "wireguard")
    change, operation = "disable", "b" * 32

    if fault == "wrong-disable":
        listener = replace(listener, sourceCidrs=("198.51.100.0/24",))

    elif fault == "already-active":
        change = "enable"

    elif fault == "port-collision":
        change, listener = "enable", VpnListener("openvpn", "udp", listener.port, listener.sourceCidrs)

    elif fault == "ssh":
        change, listener = "enable", VpnListener("openvpn", "tcp", 22, listener.sourceCidrs)

    elif fault == "same-generation":
        operation = before.operationId

    else:
        operation = "../foreign"

    with pytest.raises(host.VpnError):
        host.InputTransition(before, listener, change, operation)


def test_NativeFingerprintRetainsAllRuleExpressionsWhileIgnoringOnlyHandlesAndKernelMetainfo(tmp_path: Path) -> None:
    """A fingerprint is not a health claim; the future guest must compare it with the isolated compiled expected table."""

    _, _, initial = Policy(tmp_path / "absent")
    policy = replace(initial, operationId="a" * 32)
    data = Native(policy)
    expected = policy.NativeFingerprint(_Json(data))
    echo = {"nftables": [entry if "metainfo" in entry else {"add": entry} for entry in data["nftables"]]}

    for entry in echo["nftables"]:
        if "add" in entry:
            next(iter(entry["add"].values()))["handle"] = 999

    assert policy.NativeFingerprint(_Json(echo)) == expected
    changed = json.loads(_Json(data))
    changed["nftables"][-1]["rule"]["expr"][-1] = {"accept": None}
    assert policy.NativeFingerprint(_Json(changed)) != expected
    changed["nftables"].append(json.loads(_Json(changed["nftables"][-1])))
    assert policy.NativeFingerprint(_Json(changed)) != expected


@pytest.mark.parametrize("fault", ["foreign-table", "foreign-family", "marker", "extra-chain", "hook", "policy", "bool-priority", "unknown-object", "rule-comment", "empty", "duplicate-metadata"])
def test_NativeObservationCannotCrossTheOwnedTableOrAcceptAnUnsupportedInputPipeline(tmp_path: Path, fault: str) -> None:
    """Only one fixed dropping input chain and its complete ordered rule bodies participate in a verified expected/live comparison."""

    _, _, initial = Policy(tmp_path / "absent")
    policy = replace(initial, operationId="a" * 32)
    data = Native(policy)

    if fault == "foreign-table":
        data["nftables"][-1]["rule"]["table"] = "foreign"

    elif fault == "foreign-family":
        data["nftables"][1]["table"]["family"] = "ip"

    elif fault == "marker":
        data["nftables"][1]["table"]["comment"] = "foreign"

    elif fault == "extra-chain":
        data["nftables"].append(data["nftables"][2])

    elif fault in {"hook", "policy", "bool-priority"}:
        key = "prio" if fault == "bool-priority" else fault
        data["nftables"][2]["chain"][key] = False if fault == "bool-priority" else "unsupported"

    elif fault == "unknown-object":
        data["nftables"].append({"set": {"family": "inet", "table": "flayer_bootstrap", "name": "unproved"}})

    elif fault == "rule-comment":
        data["nftables"][-1]["rule"]["comment"] = "foreign"

    elif fault == "empty":
        data["nftables"] = []

    else:
        data["nftables"].append(data["nftables"][0])

    with pytest.raises(host.VpnError):
        policy.NativeFingerprint(_Json(data))


@pytest.mark.parametrize("content", [b"{", b"\xff", b"[]", b'{"nftables":[],"nftables":[]}',
                                     b'{"nftables":[{"metainfo":{"rate":NaN}}]}', b"[" * 1500 + b"]" * 1500])
def test_NativeJsonErrorsNeverRetainRawParserContext(tmp_path: Path, content: bytes) -> None:
    """A malformed native reply has a fixed diagnostic without raw JSONDecodeError.doc or nested causes."""

    _, _, policy = Policy(tmp_path / "absent")

    with pytest.raises(host.VpnError) as caught:
        policy.NativeFingerprint(content)

    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_ExtendedPublicModelsCannotCopyHiddenFieldsIntoPolicyMetadata(tmp_path: Path) -> None:
    """Only exact owner/listener/policy models reach nonsecret recursive serialization."""

    @dataclass(frozen=True, slots=True)
    class ExtendedIdentity(StackIdentity):
        """Model an unwanted credential extension at the owner boundary."""

        privateKey: str = "suppressed-fixture"

    _, _, policy = Policy(tmp_path / "absent")
    identity = policy.identity

    with pytest.raises(host.VpnError):
        replace(policy, identity=ExtendedIdentity(identity.project, identity.stack, identity.provider, identity.scopeId, identity.ownerId))
