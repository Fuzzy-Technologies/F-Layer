"""Traverse immutable protocol/peer epochs with real private fixtures, without any cloud, guest or networking operation."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_vpn_peer_revisions import Change
from test_vpn_project_selection import Configuration
from test_vpn_project_v2 import Project, Snapshot
from test_vpn_protocol_epochs import Operation

from flayer import _vpn_protocol_epochs as epochs
from flayer import _vpn_revisions as revisions
from flayer import vpn_project_v2 as selected
from flayer._vpn_creation import BundleDigest, ProtocolPin, StaticFingerprint, _Json
from flayer._vpn_host_input import BindBootstrap, InputTransition
from flayer._vpn_ingress_journal import IngressJournal
from flayer._vpn_protocol_sources import PrepareProtocolRequest, ReadSource, ReadSourceMetadata
from flayer.core.contracts import _WireDict
from flayer.guest import WritePrivate
from flayer.profiles import _host_input_policy as inputCodec
from flayer.profiles.artifacts import WriteArtifactBundle
from flayer.providers._yandex_firewall import ExpectedRules, SecurityGroupSnapshot
from flayer.providers._yandex_ingress import IngressDelta
from flayer.providers.contracts import ProviderResource, ResourceKind, ResourceReference
from flayer.vpn_project import SelectedVpnProject

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Private protocol graph fixtures require POSIX; no WSL or desktop VPN is started")


def Initial(tmpPath: Path) -> SelectedVpnProject:
    """Prepare only the original AWG/VLESS private project, retaining its exact immutable creation identity."""

    project = Project(tmpPath, ("amneziawg", "vless-reality"))
    selected.PrepareSelectedProject(project)

    return selected.ParseSelectedProject(project.root, Configuration(), project.sshPublicKey)


def Commit(project: SelectedVpnProject, graph: epochs.ProtocolGraph, target: str, change: str, nonce: str) -> epochs.EpochCommit:
    """Prepare complete public synthetic operation/guest facts against real retained source manifests and peer heads."""

    sources = list(graph.sources)
    oldNames = {source.pin.protocol for source in sources}

    if target not in oldNames:
        material = selected._Material(project, target)
        server = selected._Transport(project, target, material).serverBundle
        pin = ProtocolPin(target, project.TransportFingerprint(target), BundleDigest(material), BundleDigest(server))
        source, request = PrepareProtocolRequest(project, pin, material, server, operationId=nonce, previousState=graph.Fingerprint())
        WriteArtifactBundle(project.Artifacts, request)
        sources.append(source)

    firewall = next(spec for spec in graph.baseline.plan.resources if spec.logicalId == "firewall")
    identity = project.vpn.identity
    original = (graph.epochs[0].input.transition.before if graph.epochs else
                BindBootstrap(graph.baseline, project.cloud.managementCidrs, tuple(item for item in project.vpn.listeners if item.transport in oldNames)))
    beforeInput = graph.epochs[-1].input.Policy() if graph.epochs else original
    listener = next(item for item in project.vpn.listeners if item.transport == target)

    if graph.epochs:
        beforeCloud = graph.epochs[-1].cloud.result

    else:
        resource = ProviderResource(ResourceReference(identity.provider, identity.scopeId, ResourceKind.SECURITY_GROUP, "example-group"),
                                    firewall.name, "ACTIVE", labels=firewall.OwnershipLabels(identity))
        beforeCloud = SecurityGroupSnapshot(resource, "example-network", tuple(replace(rule, ruleId="original-rule-" + str(index))
            for index, rule in enumerate(ExpectedRules(firewall))))

    ids = tuple(rule.ruleId for rule in beforeCloud.rules if rule.direction == "ingress" and rule.protocol == listener.protocol
                and rule.fromPort == listener.port and rule.toPort == listener.port) if change == "disable" else ()
    creationListener = next((item for item in original.listeners if item == listener), None) if change == "disable" else None
    plan = IngressDelta(identity, firewall, beforeCloud.networkId, beforeCloud, listener, change, nonce, ids, creationListener)

    if change == "enable":
        assert plan.Addition is not None
        result = replace(beforeCloud, rules=(*beforeCloud.rules, replace(plan.Addition, ruleId="new-rule-" + nonce)))

    else:
        result = replace(beforeCloud, rules=tuple(rule for rule in beforeCloud.rules if rule.ruleId not in ids))

    cloud = epochs.CloudEvidence(plan, result, "committed", Operation(plan, result, "operation-" + nonce))
    transition = InputTransition(beforeInput, listener, change, nonce)
    inputProof = epochs.InputEvidence(transition, "applied", "a" * 64, "b" * 64)
    owner = inputCodec.Owner(transition.Record()["before"])
    absence = hashlib.sha256(_Json({"domain": "f-layer/wireguard/absent/v1", "owner": owner})).hexdigest()
    active = set(graph.activeProtocols)
    active = active | {target} if change == "enable" else active - {target}
    generation = hashlib.sha256(("fixture-generation:" + nonce).encode()).hexdigest() if target == "wireguard" and change == "enable" else ""
    receipt = generation if generation else graph.revision.receipt if "wireguard" in active else ""
    history = graph.revision.history
    oldReceipt = graph.revision.receipt if "wireguard" in graph.activeProtocols else ""

    if generation or oldReceipt:
        wg = next(source for source in sources if source.pin.protocol == "wireguard")
        _, summary, _ = ReadSourceMetadata(project, wg)
        deployment = next(item.sha256 for item in summary.files if item.name == "deployment.json")
        fenced = generation or oldReceipt
        history = revisions.CommittedHistory(project, "revoke", "protocol-" + nonce, fenced, fenced, deployment, history)

    if graph.epochs:
        previous = json.loads(graph.epochs[-1].completion)
        authority = {"name": "done-" + previous["operation_id"] + ".json", "sha256": hashlib.sha256(graph.epochs[-1].completion).hexdigest()}
        previousAuthority = authority["sha256"]

    else:
        authority = None
        previousAuthority = hashlib.sha256(_Json({"domain": "f-layer/ingress/authority/v1", "owner": owner,
                                                  "creation_sha256": BundleDigest(graph.baseline.bundle)})).hexdigest()

    reservation = {"schema_version": 1, "owner": owner, "creation_sha256": BundleDigest(graph.baseline.bundle),
                   "previous_authority_sha256": previousAuthority, "previous_state_sha256": graph.Fingerprint(), "operation_id": nonce, "plan_expires_at": 1,
                   "plan_sha256": hashlib.sha256(_Json({"schema_version": 1, "cloud_plan_sha256": plan.Fingerprint(), "input": transition.Record()})).hexdigest(),
                   "wireguard_state": "active" if oldReceipt else "absent", "wireguard_receipt_sha256": oldReceipt,
                   "wireguard_absence_sha256": "" if oldReceipt else absence, "wireguard_history_sha256": graph.revision.history}
    services = tuple(epochs.ServiceProof(source.pin.protocol, source.pin.serverDigest, "active" if source.pin.protocol in active else "absent",
        receipt if source.pin.protocol == "wireguard" else "c" * 64 if source.pin.protocol in active else "",
        "" if source.pin.protocol in active else absence) for source in sources)
    serviceBytes = _Json({"schema_version": 1, "services": [proof.Record() for proof in services]})
    intent = IngressJournal(plan, BundleDigest(graph.baseline.bundle), graph.Fingerprint(), 1).Bundle()
    WriteArtifactBundle(project.Artifacts, intent)
    metadata = {"schema_version": 1, "identity": _WireDict(identity), "creation_sha256": BundleDigest(graph.baseline.bundle), "parent": graph.head,
                "closed_peer_head": graph.revision.head, "closed_peer_head_sha256": graph.revision.headDigest, "closed_peer_count": graph.revision.recordCount,
                "previous_state_sha256": graph.Fingerprint(), "sources": [source.Record() for source in sources],
                "configured_listeners": [_WireDict(item) for item in project.vpn.listeners], "active_protocols": [source.pin.protocol for source in sources if source.pin.protocol in active],
                "static_fingerprint": StaticFingerprint(project), "wireguard_receipt_sha256": receipt, "wireguard_history_sha256": history,
                "generation_receipt_sha256": generation, "reservation": reservation, "authority_parent": authority,
                "ingress_intents": [{"role": "change", "name": intent.name, "sha256": BundleDigest(intent)}],
                "cloud_sha256": hashlib.sha256(_Json(cloud.Record())).hexdigest(), "input_sha256": hashlib.sha256(_Json(inputProof.Record())).hexdigest(),
                "services_sha256": hashlib.sha256(serviceBytes).hexdigest()}
    encoded = _Json(metadata)
    completion = {"schema_version": 2, "owner": owner, "creation_sha256": metadata["creation_sha256"], "operation_id": nonce,
                  "intent_sha256": hashlib.sha256(encoded).hexdigest(), "parent": authority,
                  "previous_authority_sha256": previousAuthority, "history_sha256": history, "outcome": "committed"}

    return epochs.EpochCommit(identity, encoded, cloud, inputProof, services, _Json(completion))


def Publish(project: SelectedVpnProject, commit: epochs.EpochCommit) -> None:
    """Publish only a synthetic already-completed fixture; production coordination/journaling remains a separate integration."""

    WriteArtifactBundle(project.Artifacts, commit.Bundle())
    directory = project.root / "protocol-epochs" / commit.Digest()
    directory.parent.mkdir(mode=0o700, exist_ok=True)
    directory.mkdir(mode=0o700)
    path = project.root / "protocol-head.json"

    if path.exists():
        path.unlink()

    WritePrivate(path, _Json({"name": commit.Bundle().name, "sha256": commit.Digest()}))


def test_WholeGraphClosesEachSegmentRetainsOriginalCreationAndCanDisableEveryTransport(tmp_path: Path) -> None:
    """Local metadata models real source identities and actual restored/opened rule IDs while no guest/cloud call exists."""

    project = Initial(tmp_path)
    graph = epochs.LoadCommittedGraph(project)
    creation = Snapshot(project.Artifacts)
    steps = [("wireguard", "enable"), ("wireguard", "disable"), ("wireguard", "enable"),
             ("wireguard", "disable"), ("amneziawg", "disable"), ("vless-reality", "disable")]

    for index, (target, change) in enumerate(steps):
        commit = Commit(project, graph, target, change, format(index, "032x"))
        Publish(project, commit)
        graph = epochs.LoadCommittedGraph(project)
        assert len(graph.epochs) == index + 1 and graph.revision.segment is not None
        assert graph.revision.segment.genesis == commit.Digest() and graph.revision.head is None

    assert not graph.activeProtocols and graph.sources and graph.revision.receipt == ""
    assert all(Snapshot(project.Artifacts)[name] == value for name, value in creation.items())

    with pytest.raises(ValueError, match="integrated"):
        revisions.LoadRevisions(project)


def test_PeerSegmentClosureAndMetadataTraversalSurviveLossOfEveryPrivateSourceBody(tmp_path: Path) -> None:
    """A mixed peer/protocol history retains complete parent authority and nonsecret role hashes without client keys."""

    project = Initial(tmp_path)
    initial = epochs.LoadCommittedGraph(project)
    first = Commit(project, initial, "wireguard", "enable", "0" * 32)
    Publish(project, first)
    graph = epochs.LoadCommittedGraph(project)
    changed, pending, material, server, pin, facts = Change(project, graph.revision)
    segment = graph.revision.segment
    assert segment is not None
    revisions.AtomicRecord(changed, "wireguard-pending.json", pending, segment=segment)
    digest = revisions.PublishRequest(changed, pending, material, server, segment=segment)
    pending = {**pending, "request_sha256": digest}
    revisions.AtomicRecord(changed, "wireguard-pending.json", pending, segment=segment)
    revisions.Commit(changed, graph.revision, pending, pin, facts, outcome="committed")
    graph = epochs.LoadCommittedGraph(changed)
    second = Commit(changed, graph, "wireguard", "disable", "1" * 32)
    Publish(changed, second)
    before = epochs.LoadCommittedGraph(changed).Fingerprint()

    for directory in changed.Artifacts.iterdir():
        if not directory.is_dir():
            continue

        manifest = json.loads((directory / "manifest.json").read_bytes())

        for entry in manifest["files"]:
            if entry["sensitive"]:
                (directory / entry["name"]).unlink()

    retained = epochs.LoadCommittedGraph(changed)
    assert retained.Fingerprint() == before and len(retained.epochs) == 2 and "wireguard" not in retained.activeProtocols

    with pytest.raises(ValueError):
        ReadSource(changed, next(source for source in retained.sources if source.pin.protocol == "wireguard"))


@pytest.mark.parametrize("fault", ["lost-head", "lost-parent", "lost-segment", "orphan-peer", "orphan-epoch", "orphan-ingress",
                                  "lost-public-source", "public-drift", "pending", "operation-bound", "byte-bound"])
def test_MissingParentsUnknownNamespacesAndPendingOrOversizedGraphsFailClosed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str,
) -> None:
    """No orphan, missing authority or old-looking artifact can infer a replacement epoch head."""

    project = Initial(tmp_path)
    first = Commit(project, epochs.LoadCommittedGraph(project), "wireguard", "enable", "0" * 32)
    Publish(project, first)

    if fault == "lost-head":
        (project.root / "protocol-head.json").unlink()

    elif fault == "lost-parent":
        second = Commit(project, epochs.LoadCommittedGraph(project), "wireguard", "disable", "1" * 32)
        Publish(project, second)
        (project.Artifacts / ("server-" + first.Bundle().name) / "epoch.json").unlink()

    elif fault == "lost-segment":
        (project.root / "protocol-epochs" / first.Digest()).rmdir()

    elif fault.startswith("orphan-"):
        role = {"orphan-peer": "wp", "orphan-epoch": "ep", "orphan-ingress": "ip"}[fault]
        (project.Artifacts / ("server-" + project.vpn.identity.stack + "-" + role + "-" + "f" * 16)).mkdir(mode=0o700)

    elif fault == "lost-public-source":
        source = next(item for item in epochs.LoadCommittedGraph(project).sources if item.pin.protocol == "wireguard")
        (project.Artifacts / ("server-" + source.requestName) / "intent.sha256").unlink()

    elif fault == "public-drift":
        path = project.Artifacts / ("server-" + first.Bundle().name) / "input.json"
        path.write_bytes(b"x" * path.stat().st_size)

    elif fault == "pending":
        WritePrivate(project.root / "protocol-pending.json", b"{}\n")

    elif fault == "operation-bound":
        monkeypatch.setattr(epochs, "MAX_PROTOCOL_EPOCHS", 0)

    else:
        monkeypatch.setattr(epochs, "MAX_GRAPH_BYTES", 1)

    before = Snapshot(project.root)

    with pytest.raises(ValueError):
        epochs.LoadCommittedGraph(project)

    assert Snapshot(project.root) == before


def test_EpochCannotCloseCopiedOrStalePeerAndGuestAuthorityEvenWithRehashedOwnedBundle(tmp_path: Path) -> None:
    """A caller can rewrite an owned manifest, but it cannot change the graph's independently verified preceding state."""

    project = Initial(tmp_path)
    commit = Commit(project, epochs.LoadCommittedGraph(project), "wireguard", "enable", "0" * 32)
    metadata = epochs._Decode(commit.metadata)
    metadata["previous_state_sha256"] = "f" * 64
    metadata["reservation"]["previous_state_sha256"] = "f" * 64
    encoded = _Json(metadata)
    completion = epochs._Decode(commit.completion)
    completion["intent_sha256"] = hashlib.sha256(encoded).hexdigest()
    altered = replace(commit, metadata=encoded, completion=_Json(completion))
    Publish(project, altered)
    before = Snapshot(project.root)

    with pytest.raises(ValueError, match="closed peer"):
        epochs.LoadCommittedGraph(project)

    assert Snapshot(project.root) == before


def test_MetadataGraphDoesNotRecompileCreationFromEditedDesiredCloudSettings(tmp_path: Path) -> None:
    """Read-only metadata/cleanup authority remains the original creation even if current desired placement was edited."""

    project = Initial(tmp_path)
    commit = Commit(project, epochs.LoadCommittedGraph(project), "wireguard", "enable", "0" * 32)
    Publish(project, commit)
    original = epochs.LoadCommittedGraph(project)
    changed = replace(project, cloud=replace(project.cloud, imageId="different-example-image"))
    after = epochs.LoadCommittedGraph(changed)

    assert original.Fingerprint() == after.Fingerprint() and original.baseline == after.baseline
    assert after.baseline.plan.resources == original.baseline.plan.resources
