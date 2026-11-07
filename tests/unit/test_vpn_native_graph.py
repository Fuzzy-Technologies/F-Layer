"""Traverse native-generation epochs through actual retained metadata while never touching a guest or provider."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import test_vpn_native_epochs as nativeFixtures
import test_vpn_protocol_graph as graphFixtures

from flayer import _vpn_protocol_epochs as epochs
from flayer._vpn_ingress_journal import IngressJournal
from flayer._vpn_protocol_sources import DecodeSource, ReadSourceMetadata
from flayer.profiles.artifacts import WriteArtifactBundle
from flayer.providers._yandex_ingress import IngressDelta
from flayer.vpn_project import SelectedVpnProject

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Native graph fixtures need POSIX private files; no cloud, guest, WSL or desktop network is used")


def Commit(project: SelectedVpnProject, graph: epochs.ProtocolGraph, change: str, nonce: str, *, restored: bool = False) -> epochs.EpochCommit:
    """Bind real source-manifest hashes to synthetic complete native receipts and guest proof bytes."""

    base = graphFixtures.Commit(project, graph, "wireguard", change, nonce)
    metadata = epochs._Decode(base.metadata)
    old: dict[str, Any] | None = None

    for previous in reversed(graph.epochs):
        value = epochs._Decode(previous.metadata)

        if value["schema_version"] == 2:
            old = ({**value["generation"]["candidate_receipt"], "status": "installed"} if "wireguard" in graph.activeProtocols
                   else value["generation"]["cached_receipt"])

            break

    generation = nativeFixtures.Generation(metadata, change, nonce, cached=old)
    source = next(DecodeSource(value, project.vpn.identity) for value in metadata["sources"] if value["pin"]["protocol"] == "wireguard")
    _, summary, _ = ReadSourceMetadata(project, source)
    files = {value.name: value.sha256 for value in summary.files}

    for receipt in (generation["cached_receipt"], generation["candidate_receipt"]):
        receipt["files"].update(files)
        receipt["deployment_sha256"] = files["deployment.json"]

    generation["source_files"] = files

    phase = "active" if change == "enable" else "inactive"

    if restored:
        assert change == "disable"
        plan = base.cloud.plan
        inverse = IngressDelta(plan.identity, plan.creationSpec, plan.networkId, base.cloud.result, plan.listener, "enable", epochs.RestorationNonce(nonce))
        assert inverse.Addition is not None
        final = replace(base.cloud.result, rules=(*base.cloud.result.rules, replace(inverse.Addition, ruleId="restored-wg-rule-" + nonce)))
        cloud = epochs.CloudEvidence(plan, final, "not-applied", base.cloud.operation, base.cloud.result, inverse,
                                     graphFixtures.Operation(inverse, final, "restoration-" + nonce))
        carrier = SimpleNamespace(identity=base.identity, metadata=base.metadata, cloud=cloud,
                                  input=epochs.InputEvidence(base.input.transition, "rolled-back", "a" * 64, "b" * 64),
                                  services=base.services, completion=base.completion)
        value = nativeFixtures.Native(carrier, generation, phase="restored")
        WriteArtifactBundle(project.Artifacts, IngressJournal(inverse, metadata["creation_sha256"], metadata["previous_state_sha256"], 1).Bundle())

        return value

    return nativeFixtures.Native(base, generation, phase=phase)


def test_NativeGraphRetainsExactSourcePinsAndHistoryAcrossRepeatedDisableAndEnable(tmp_path: Path) -> None:
    """Every completed native epoch closes its own peer segment without changing original creation or retained source artifacts."""

    project = graphFixtures.Initial(tmp_path)
    graph = epochs.LoadCommittedGraph(project)
    creation = graph.baseline.bundle

    for index, change in enumerate(("enable", "disable", "enable", "disable")):
        value = Commit(project, graph, change, format(index, "032x"))
        graphFixtures.Publish(project, value)
        graph = epochs.LoadCommittedGraph(project)
        assert graph.epochs[-1] == value and graph.revision.history == epochs._Decode(value.metadata)["wireguard_history_sha256"]
        assert graph.revision.segment is not None and graph.revision.segment.genesis == value.Digest()
        assert graph.baseline.bundle == creation


def test_NativeEpochMetadataTraversalSurvivesLossOfPrivateSourceBodies(tmp_path: Path) -> None:
    """Generation receipts and fences bind public source hashes; they confer no permission to reconstruct private credentials."""

    project = graphFixtures.Initial(tmp_path)
    value = Commit(project, epochs.LoadCommittedGraph(project), "enable", "0" * 32)
    graphFixtures.Publish(project, value)
    fingerprint = epochs.LoadCommittedGraph(project).Fingerprint()

    for directory in project.Artifacts.iterdir():
        if not directory.is_dir():
            continue

        manifest = json.loads((directory / "manifest.json").read_bytes())

        for entry in manifest["files"]:
            if entry["sensitive"]:
                (directory / entry["name"]).unlink()

    assert epochs.LoadCommittedGraph(project).Fingerprint() == fingerprint


def test_RestoredDisableTraversesBothOriginalAndFreshFencesBeforeAnotherTransition(tmp_path: Path) -> None:
    """A compensated cloud change restores new provider rule IDs and a new WG unit identity while preserving the creation baseline."""

    project = graphFixtures.Initial(tmp_path)
    first = Commit(project, epochs.LoadCommittedGraph(project), "enable", "0" * 32)
    graphFixtures.Publish(project, first)
    before = epochs.LoadCommittedGraph(project)
    restored = Commit(project, before, "disable", "1" * 32, restored=True)
    graphFixtures.Publish(project, restored)
    current = epochs.LoadCommittedGraph(project)
    assert "wireguard" in current.activeProtocols and current.revision.receipt != before.revision.receipt
    assert current.revision.history != before.revision.history and current.baseline == before.baseline
    final = Commit(project, current, "disable", "2" * 32)
    graphFixtures.Publish(project, final)
    assert "wireguard" not in epochs.LoadCommittedGraph(project).activeProtocols


def test_NativeGenerationCannotRebindRehashedSourceFilePinsToAnotherPublicServerManifest(tmp_path: Path) -> None:
    """A structurally valid receipt plus rehashed outer metadata is still checked against the retained exact original source."""

    project = graphFixtures.Initial(tmp_path)
    graph = epochs.LoadCommittedGraph(project)
    value = Commit(project, graph, "enable", "0" * 32)
    metadata = epochs._Decode(value.metadata)
    generation = metadata["generation"]

    for receipt in (generation["cached_receipt"], generation["candidate_receipt"]):
        receipt["files"]["install.py"] = "1" * 64

    generation["source_files"]["install.py"] = "1" * 64
    rebound = nativeFixtures.Native(value, generation, phase="active")
    graphFixtures.Publish(project, rebound)

    with pytest.raises(ValueError, match="source pins"):
        epochs.LoadCommittedGraph(project)


def test_LegacyEpochCanFollowNativeGenerationWithoutRewritingItsRootReceipt(tmp_path: Path) -> None:
    """An unrelated transport change retains WG configuration/receipt and consumes exactly one additional v1-compatible fence."""

    project = graphFixtures.Initial(tmp_path)
    first = Commit(project, epochs.LoadCommittedGraph(project), "enable", "0" * 32)
    graphFixtures.Publish(project, first)
    before = epochs.LoadCommittedGraph(project)
    second = graphFixtures.Commit(project, before, "amneziawg", "disable", "1" * 32)
    graphFixtures.Publish(project, second)
    after = epochs.LoadCommittedGraph(project)
    assert after.revision.receipt == before.revision.receipt and after.revision.history != before.revision.history
    assert "wireguard" in after.activeProtocols and "amneziawg" not in after.activeProtocols
