"""Compose immutable local peer revisions with observed cloud ownership and receipt-bound guest operations."""

from __future__ import annotations

import base64
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any

from flayer import _vpn_revisions as revisions
from flayer._vpn_creation import BundleDigest, ProtocolPin, _Json
from flayer._vpn_observation import CreationProvider
from flayer._vpn_peer_transport import ValidateBundle
from flayer.core.contracts import _WireDict
from flayer.core.lifecycle import LifecycleEngine, _LoadJournal
from flayer.core.state import LoadState
from flayer.guest import SshGuestProvisioner
from flayer.profiles.artifacts import Artifact, ArtifactBundle, ReadOwnedArtifactFile
from flayer.profiles.vpn import VpnDevice, VpnEndpoint, VpnError, VpnProfile
from flayer.profiles.wireguard import (
    DecodeWireGuardMaterial,
    EncodeWireGuardMaterial,
    PrepareWireGuard,
    PrepareWireGuardPeerEnrollment,
    PrepareWireGuardPeerRevocation,
    RenderWireGuardServer,
    WireGuardMaterial,
    WireGuardPeer,
    _PrivateKey,
)
from flayer.providers.yandex import YandexCloudSettings
from flayer.vpn_peers import VpnPeerReport
from flayer.vpn_project import (
    ADMIN_USERNAME,
    SelectedVpnProject,
    VpnYandexProvider,
    _CheckCloudAccess,
    _OwnedEndpoints,
    _VerifyAdministrationKey,
)

PLAN_SECONDS = 600


def _Fingerprint(project: SelectedVpnProject, profile: VpnProfile) -> str:
    """Use the exact schema-2 WireGuard projection algorithm, including shared DNS and route intent."""

    return revisions.Digest(json.dumps({"schema_version": 2, "vpn": _WireDict(profile), "settings": _WireDict(project.wireguard)},
                                       sort_keys=True, separators=(",", ":")).encode())


def OldProfile(project: SelectedVpnProject, pin: ProtocolPin, server: ArtifactBundle) -> VpnProfile:
    """Reconstruct only verified old membership, proving all current settings except the intended peer delta unchanged."""

    contents = ValidateBundle(server)
    descriptor = json.loads(contents["deployment.json"])

    try:
        profile = replace(project.ProtocolProfile("wireguard"), devices=tuple(
            VpnDevice(peer["device_id"], peer["ipv4_address"]) for peer in descriptor["peers"]))

        if _Fingerprint(project, profile) != pin.intentFingerprint:
            raise ValueError

        return profile

    except (ValueError, TypeError, KeyError):
        raise VpnError("Peer transition cannot change listener, tunnel, MTU, DNS, routes or existing device addresses") from None


def _Delta(project: SelectedVpnProject, old: VpnProfile, change: str, deviceId: str) -> VpnDevice | None:
    """Require exactly one named membership change while preserving every other device and explicit address."""

    before = {device.deviceId: device for device in old.devices}
    after = {device.deviceId: device for device in project.ProtocolProfile("wireguard").devices}
    names = set(before) | {deviceId} if change == "enroll" else set(before) - {deviceId}

    if (set(after) != names or (deviceId in before) != (change == "revoke")
            or any(before[name] != after[name] for name in set(before) & set(after))):
        raise VpnError("Edit only the named WireGuard membership/address before planning; existing peers and other protocols must stay unchanged")

    return after.get(deviceId)


def Connection(
    project: SelectedVpnProject, state: revisions.RevisionState, provider: VpnYandexProvider | None,
    guestFactory: Callable[..., SshGuestProvisioner],
) -> tuple[SshGuestProvisioner, str, str]:
    """Observe the full frozen cloud graph and existing IAM-authenticated host pin without creating trust or resources."""

    _VerifyAdministrationKey(project)
    cloudState = LoadState(project.root / "state.json", project.vpn.identity)

    if cloudState is None or _LoadJournal(project.root / "state.json", state.baseline.plan) is not None:
        raise VpnError("Peer maintenance requires a complete owned deployment without an interrupted cloud operation")

    provider = provider or VpnYandexProvider(YandexCloudSettings(project.vpn.identity.scopeId, project.cloud.ycProfile))
    _CheckCloudAccess(provider)
    owned = CreationProvider(provider, state.baseline)

    if LifecycleEngine(state.baseline.plan, owned, project.root / "state.json").Status().status != "complete":
        raise VpnError("Peer maintenance requires all original cloud resources with exact ownership, policy and attachments")

    instance, endpoint = _OwnedEndpoints(project, owned)
    name = project.vpn.identity.stack + "-trust"
    trust = project.Artifacts / ("server-" + name) / "known-hosts.txt"
    pinned = ReadOwnedArtifactFile(trust, project.vpn.identity, kind="server", name=name)
    key = provider.ReadHostKey(instance, state.baseline.projectFingerprint)

    if key is None or pinned != f"{endpoint} {key}\n".encode("ascii"):
        raise VpnError("Peer maintenance requires the unchanged independently authenticated guest host pin")

    proof = revisions.Digest(_Json({"creation_sha256": BundleDigest(state.baseline.bundle), "cloud": _WireDict(cloudState),
                                    "endpoint": endpoint, "host_pin_sha256": revisions.Digest(pinned)}))

    return guestFactory(VpnEndpoint(endpoint, 22), ADMIN_USERNAME, project.root / "admin-key", trust), endpoint, proof


def Observe(guest: SshGuestProvisioner, state: revisions.RevisionState, server: ArtifactBundle) -> dict[str, object]:
    """Verify the exact active projection and chained history before unrelated installers or any peer change."""

    facts = guest.WireGuardPeerOperation(server, "status", "enroll", "flayer-observation")

    if (facts["status"] != "active" or facts["is_desired"] is not True or facts["history_sha256"] != state.history
            or state.receipt and facts["receipt_sha256"] != state.receipt):
        raise VpnError("WireGuard guest differs from its committed controller projection/history; retain artifacts and recover explicitly")

    return facts


def ObserveHistory(guest: SshGuestProvisioner, state: revisions.RevisionState, server: ArtifactBundle) -> None:
    """Refuse retained or changed revocation history before any installer, including an absent owned root."""

    facts = guest.WireGuardPeerOperation(server, "history-status", "enroll", "flayer-observation")

    if facts["history_sha256"] != state.history:
        raise VpnError("WireGuard guest peer history differs from the controller; no installer was started")


def _Baseline(project: SelectedVpnProject, state: revisions.RevisionState, cloud: str, facts: dict[str, object], change: str, deviceId: str, expires: int) -> str:
    """Bind a short-lived reviewed plan to exact desired intent, cloud/trust, local history and guest proofs."""

    return revisions.Digest(_Json({"schema_version": 1, "identity": _WireDict(project.vpn.identity), "head_sha256": state.headDigest,
                                  "desired_fingerprint": project.TransportFingerprint("wireguard"), "cloud_sha256": cloud,
                                  "receipt_sha256": facts["receipt_sha256"], "history_sha256": facts["history_sha256"],
                                  "change": change, "device_id": deviceId, "expires_at": expires}))


def _NewMaterial(
    project: SelectedVpnProject, state: revisions.RevisionState, old: VpnProfile, oldMaterial: ArtifactBundle, change: str, deviceId: str,
) -> tuple[ArtifactBundle, ArtifactBundle, ProtocolPin]:
    """Generate at most one new device key, retaining server/all old peers and any identical rolled-back candidate."""

    material = DecodeWireGuardMaterial(next(item.content for item in oldMaterial.files if item.name == "material.json"))
    assert project.wireguard is not None

    if change == "enroll":
        previous = state.lastRecord
        retained: WireGuardPeer | None = None

        if (previous is not None and previous["outcome"] == "not-applied" and previous["request_sha256"]
                and previous["desired_fingerprint"] == project.TransportFingerprint("wireguard")
                and (previous["change"], previous["device_id"]) == (change, deviceId)):
            candidate, _ = revisions.RequestBundles(project, previous["request_name"], previous["request_sha256"])
            decoded = DecodeWireGuardMaterial(next(item.content for item in candidate.files if item.name == "material.json"))
            retained = next(peer for peer in decoded.peers if peer.deviceId == deviceId)

        peer = retained or WireGuardPeer(deviceId, _PrivateKey(), base64.b64encode(secrets.token_bytes(32)).decode())
        device = next(device for device in project.ProtocolProfile("wireguard").devices if device.deviceId == deviceId)
        profile, updated = PrepareWireGuardPeerEnrollment(old, project.wireguard, material, device, peer)

    else:
        profile, updated = PrepareWireGuardPeerRevocation(old, project.wireguard, material, deviceId)

    if profile != project.ProtocolProfile("wireguard"):
        raise VpnError("Prepared peer change differs from exact desired membership")

    original = revisions.ReadEffectiveBundle(project, state, next(pin for pin in state.pins if pin.protocol == "wireguard"))
    prepared = PrepareWireGuard(profile, VpnEndpoint("192.0.2.1", profile.listeners[0].port), project.wireguard, updated).serverBundle
    contents = {item.name: item.content for item in prepared.files}
    contents["install.py"] = next(item.content for item in original.files if item.name == "install.py")
    descriptor = json.loads(contents["deployment.json"])
    descriptor["program_sha256"] = revisions.Digest(contents["install.py"])
    contents["deployment.json"] = _Json(descriptor)
    server = replace(prepared, files=tuple(Artifact(item.name, contents[item.name]) for item in prepared.files))
    credentials = replace(oldMaterial, files=(Artifact("material.json", EncodeWireGuardMaterial(updated)),
        Artifact("intent.sha256", (project.TransportFingerprint("wireguard") + "\n").encode(), False)))

    return credentials, server, ProtocolPin("wireguard", project.TransportFingerprint("wireguard"), BundleDigest(credentials), BundleDigest(server))


def _Report(action: str, change: str, deviceId: str, facts: dict[str, object], *, baseline: str = "", expires: int = 0, pending: bool = False, details: str = "") -> VpnPeerReport:
    """Keep all user-visible evidence nonsecret and distinguish pending work from client connectivity."""

    return VpnPeerReport(action, "incomplete" if pending else "complete", "complete", "peer-recovery-required" if pending else "services-active",
                         recoveryRequired=pending, details=details, change=change, deviceId=deviceId, baselineSha256=baseline, planExpiresAt=expires,
                         receiptSha256=str(facts["receipt_sha256"]), historySha256=str(facts["history_sha256"]))


def _PendingPin(project: SelectedVpnProject, pending: dict[str, Any]) -> ProtocolPin:
    """Identify exact staged server/material bytes without generating a replacement key."""

    material, server = revisions.RequestBundles(project, pending["request_name"], pending["request_sha256"])

    return ProtocolPin("wireguard", pending["desired_fingerprint"], BundleDigest(material), BundleDigest(server))


def _Recover(
    project: SelectedVpnProject, state: revisions.RevisionState, pending: dict[str, Any], action: str, change: str, deviceId: str,
    expectedBaseline: str, provider: VpnYandexProvider | None, guestFactory: Callable[..., SshGuestProvisioner], oldServer: ArtifactBundle,
) -> VpnPeerReport:
    """Recover only retained original intent; complete a published guest root or roll back its proved uncommitted prefix."""

    if ((pending["change"], pending["device_id"], pending["desired_fingerprint"]) != (change, deviceId, project.TransportFingerprint("wireguard"))
            or action == "recover" and expectedBaseline != revisions.Digest(_Json(pending))):
        raise VpnError("Peer recovery requires the exact retained target/intent and baseline from peer status")

    guest, _, cloud = Connection(project, state, provider, guestFactory)
    original = replace(state, headDigest=pending["previous_head_sha256"])
    originalFacts = {"receipt_sha256": pending["previous_receipt_sha256"], "history_sha256": pending["previous_history_sha256"]}

    if _Baseline(project, original, cloud, originalFacts, change, deviceId, pending["plan_expires_at"]) != pending["baseline_sha256"]:
        raise VpnError("Peer recovery cloud resources, endpoint or host pin differ from its original plan; no guest mutation was requested")

    if not pending["request_sha256"]:
        if action == "status":
            facts = Observe(guest, state, oldServer)

            return _Report(action, change, deviceId, facts, baseline=revisions.Digest(_Json(pending)), pending=True,
                           details="Peer preparation journal retained; no remote activation was authorized before its complete request digest")

        stage = project.Artifacts / ("server-" + pending["request_name"])

        if not stage.exists() and not stage.is_symlink():
            facts = Observe(guest, state, oldServer)
            oldPin = next(pin for pin in state.pins if pin.protocol == "wireguard")
            revisions.Commit(project, state, pending, oldPin, facts, outcome="not-applied")

            return _Report(action, change, deviceId, facts, details="Unstaged peer attempt archived as not-applied; no guest mutation or credential regeneration")

        pending = {**pending, "request_sha256": revisions.RecoverStaging(project, pending)}
        revisions.AtomicRecord(project, "wireguard-pending.json", pending)

    pin = _PendingPin(project, pending)
    _, server = revisions.ValidateRequest(project, pending, pin)
    facts = guest.WireGuardPeerOperation(server, "status", change, deviceId)

    if action == "status":
        return _Report(action, change, deviceId, facts, baseline=revisions.Digest(_Json(pending)), pending=True,
                       details="Peer recovery is required; use this exact journal baseline with explicit scope and mutation consent")

    outcome = guest.WireGuardPeerOperation(server, "recover", change, deviceId, allowMutation=True, scopeConfirm=project.vpn.identity.scopeId,
        expectedReceipt=str(facts["receipt_sha256"]), expectedPrevious=pending["previous_receipt_sha256"], expectedHistory=pending["previous_history_sha256"])
    facts = guest.WireGuardPeerOperation(server, "status", change, deviceId)
    revisions.Commit(project, state, pending, pin, facts, outcome=str(outcome["outcome"]))

    return _Report(action, change, deviceId, facts, details="Exact peer recovery completed: " + str(outcome["outcome"]) + "; retained private request preserved for audit")


def Run(
    project: SelectedVpnProject, action: str, change: str, deviceId: str, *, expectedBaseline: str, planExpiresAt: int,
    provider: VpnYandexProvider | None, guestFactory: Callable[..., SshGuestProvisioner],
) -> VpnPeerReport:
    """Execute one fully locked project peer workflow, refusing all unrelated protocol/cloud intent changes."""

    state = revisions.LoadRevisions(project)
    state.ValidateCurrent(project, peerChange=True)
    pin = next((pin for pin in state.pins if pin.protocol == "wireguard"), None)

    if pin is None:
        raise VpnError("WireGuard must already be selected and deployed; protocol activation is a separate explicit workflow")

    server = revisions.ReadEffectiveBundle(project, state, pin)
    pending = revisions.Pending(project)

    if pending is not None:
        if action not in {"status", "recover"}:
            raise VpnError("A pending peer operation requires peer status and explicit recovery before another plan or mutation")

        return _Recover(project, state, pending, action, change, deviceId, expectedBaseline, provider, guestFactory, server)

    if action == "recover":
        raise VpnError("No interrupted peer operation is recorded; no guest mutation was requested")

    previous = state.lastRecord
    identical = (action in {"enroll", "revoke"} and previous is not None and previous["outcome"] == "committed"
                 and (previous["change"], previous["device_id"], previous["baseline_sha256"], previous["plan_expires_at"])
                 == (change, deviceId, expectedBaseline, planExpiresAt) and project.TransportFingerprint("wireguard") == pin.intentFingerprint)
    material: ArtifactBundle | None = None
    old: VpnProfile | None = None

    if action != "status" and not identical:
        revisions.RequireCapacity(state)
        material = revisions.ReadEffectiveBundle(project, state, pin, material=True)
        old = OldProfile(project, pin, server)
        decoded: WireGuardMaterial = DecodeWireGuardMaterial(next(item.content for item in material.files if item.name == "material.json"))
        assert project.wireguard is not None

        if RenderWireGuardServer(old, project.wireguard, decoded) != next(item.content for item in server.files if item.name == "server.conf"):
            raise VpnError("Retained WireGuard server and private client material disagree")

        _Delta(project, old, change, deviceId)

    guest, _, cloud = Connection(project, state, provider, guestFactory)
    facts = Observe(guest, state, server)

    if action == "status":
        return _Report(action, change, deviceId, facts, details="Committed WireGuard peer projection/history verified; authenticated client traffic remains unverified")

    if identical:
        return _Report(action, change, deviceId, facts, details="The exact latest peer operation is already committed; no key generation or guest mutation")

    assert old is not None and material is not None
    now = int(time.time())
    expires = now + PLAN_SECONDS if action == "plan" else planExpiresAt
    baseline = _Baseline(project, state, cloud, facts, change, deviceId, expires)

    if action == "plan":
        return _Report(action, change, deviceId, facts, baseline=baseline, expires=expires,
                       details="One named peer change planned; no keys generated, project artifacts changed or remote mutation performed. Echo baseline and expiry within 600 seconds")

    if expires <= now or expires > now + PLAN_SECONDS or baseline != expectedBaseline:
        raise VpnError("Peer plan expired or its exact baseline changed; run peer plan again before any key generation or mutation")

    credentials, desired, desiredPin = _NewMaterial(project, state, old, material, change, deviceId)
    pending = {"schema_version": 1, "identity": _WireDict(project.vpn.identity), "creation_sha256": BundleDigest(state.baseline.bundle),
               "parent": state.head, "previous_head_sha256": state.headDigest, "previous_pin": _WireDict(pin),
               "desired_fingerprint": desiredPin.intentFingerprint, "request_name": project.vpn.identity.stack + "-wp-" + secrets.token_hex(8),
               "request_sha256": "", "change": change, "device_id": deviceId, "previous_receipt_sha256": facts["receipt_sha256"],
               "previous_history_sha256": facts["history_sha256"], "baseline_sha256": baseline, "plan_expires_at": expires}
    revisions.AtomicRecord(project, "wireguard-pending.json", pending)
    pending = {**pending, "request_sha256": revisions.PublishRequest(project, pending, credentials, desired)}
    revisions.AtomicRecord(project, "wireguard-pending.json", pending)
    guest, _, currentCloud = Connection(project, state, provider, guestFactory)
    current = Observe(guest, state, server)

    if (_Baseline(project, state, currentCloud, current, change, deviceId, expires) != baseline or expires <= int(time.time())):
        raise VpnError("Peer baseline changed during staging; retained keys/journal require explicit peer recovery")

    guest.WireGuardPeerOperation(desired, "apply", change, deviceId, allowMutation=True, scopeConfirm=project.vpn.identity.scopeId,
        expectedReceipt=str(facts["receipt_sha256"]), expectedHistory=str(facts["history_sha256"]))
    facts = guest.WireGuardPeerOperation(desired, "status", change, deviceId)
    revisions.Commit(project, state, pending, desiredPin, facts, outcome="committed")

    return _Report(action, change, deviceId, facts, details="One peer change committed and retained; all unrelated keys, services and cloud resources preserved")
