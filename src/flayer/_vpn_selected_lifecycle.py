"""Compose selected transports with immutable creation ownership and explicit guest recovery."""

from __future__ import annotations

from collections.abc import Callable

from flayer._vpn_observation import CreationProvider
from flayer._vpn_revisions import LoadRevisions, Pending, ProjectLock, ReadEffectiveBundle
from flayer.core.lifecycle import LifecycleEngine, _LoadJournal
from flayer.core.state import LoadState
from flayer.guest import PrivatePath, SshGuestProvisioner
from flayer.profiles import _wireguard_guest as wireguardGuest
from flayer.profiles.amneziawg import AmneziaWgServiceName
from flayer.profiles.artifacts import ArtifactBundle, ReadOwnedArtifactFile
from flayer.profiles.vless import VlessServiceName
from flayer.profiles.vpn import VpnEndpoint, VpnError
from flayer.profiles.wireguard import WireGuardServiceName
from flayer.providers.yandex import YandexCloudSettings
from flayer.vpn_project import (
    ADMIN_USERNAME,
    SelectedVpnProject,
    VpnProjectReport,
    VpnYandexProvider,
    _CheckCloudAccess,
    _HostTrust,
    _Incomplete,
    _OwnedEndpoints,
    _Publish,
    _VerifyAdministrationKey,
)
from flayer.vpn_project_v2 import ValidateSelectedProject, _PrepareSelectedProject, _Transport


def _FreshKernelGate() -> None:
    """Require a released named Ubuntu fix before a paid VM can be submitted; assess the executing kernel on the guest."""

    try:
        wireguardGuest._ReleasedKernelEvidence(wireguardGuest._Fetch(wireguardGuest.KERNEL_CVE_URL, 1048576))

    except (ValueError, OSError):
        raise VpnError("Fresh WireGuard VM creation is blocked until the named Ubuntu noble/linux fix is released and verifiable. No cloud creation started; installed services and cleanup remain available") from None


def _Services(project: SelectedVpnProject) -> tuple[str, ...]:
    """Observe exactly the explicitly selected service set without inferring client connectivity."""

    names = {"amneziawg": AmneziaWgServiceName, "vless-reality": VlessServiceName, "wireguard": WireGuardServiceName}

    return tuple(names[selection.protocol](project.ProtocolProfile(selection.protocol))
                 + ("" if selection.protocol == "vless-reality" else ".service") for selection in project.protocolSelections)


def _GuestRecovery(guest: SshGuestProvisioner, bundle: ArtifactBundle, scope: str) -> bool:
    """Recover only an observed interrupted operation, preserving a healthy committed service."""

    status = guest.WireGuardOperation(bundle, "status")

    if status["status"] == "recovery-required":
        guest.WireGuardOperation(bundle, "recover", allowMutation=True, scopeConfirm=scope,
                                 expectedReceipt=str(status["receipt_sha256"]))

        return True

    if status["status"] == "absent" and status["cleanup_required"] is True:
        guest.WireGuardOperation(bundle, "recover", allowMutation=True, scopeConfirm=scope,
                                 expectedAbsence=str(status["absence_sha256"]))

        return True

    return False


def RunSelectedProject(
    project: SelectedVpnProject, action: str, *, allowMutation: bool, scopeConfirm: str, rollback: bool,
    provider: VpnYandexProvider | None, guestFactory: Callable[..., SshGuestProvisioner],
) -> VpnProjectReport:
    """Use only original resource specs, server bytes and SSH fingerprint across deploy, retry and cleanup."""

    ValidateSelectedProject(project)
    PrivatePath(project.root, directory=True)

    if action not in {"deploy", "status", "destroy", "recover"}:
        raise VpnError("Selected project lifecycle action is unsupported")

    if action != "status" and (allowMutation is not True or scopeConfirm != project.vpn.identity.scopeId):
        raise VpnError("Cloud mutation requires --allow-mutation and exact --scope-confirm folder ID")

    if action == "status" and (allowMutation or scopeConfirm or rollback):
        raise VpnError("Selected project status is read-only and does not accept mutation consent")

    if rollback and action != "recover":
        raise VpnError("Rollback applies only to an interrupted cloud recovery")

    with ProjectLock(project, readOnly=action == "status"):
        return _RunSelectedProject(project, action, allowMutation=allowMutation, scopeConfirm=scopeConfirm, rollback=rollback,
                                   provider=provider, guestFactory=guestFactory)


def _RunSelectedProject(
    project: SelectedVpnProject, action: str, *, allowMutation: bool, scopeConfirm: str, rollback: bool,
    provider: VpnYandexProvider | None, guestFactory: Callable[..., SshGuestProvisioner],
) -> VpnProjectReport:
    """Keep the complete cloud, guest and artifact operation under the common project lock."""

    creation = project.Artifacts / ("server-" + project.vpn.identity.stack + "-creation")

    if action == "deploy" and not creation.exists() and not creation.is_symlink():
        _PrepareSelectedProject(project)

    revision = LoadRevisions(project)
    baseline = revision.baseline
    statePath = project.root / "state.json"
    state = LoadState(statePath, project.vpn.identity)
    journal = _LoadJournal(statePath, baseline.plan)
    cleaning = action == "destroy" or action == "recover" and (rollback or journal is not None and journal.action in {"rollback", "destroy"})
    servers: list[tuple[str, ArtifactBundle]] = []
    materials: dict[str, ArtifactBundle] = {}

    if not cleaning:
        if Pending(project) is not None:
            raise VpnError("Pending peer revision requires flayer vpn peer status and explicit peer recovery before this operation")

        revision.ValidateCurrent(project)
        _VerifyAdministrationKey(project)

        for pin in revision.pins:
            materials[pin.protocol] = ReadEffectiveBundle(project, revision, pin, material=True)
            servers.append((pin.protocol, ReadEffectiveBundle(project, revision, pin)))

    if action == "deploy" and (state is None or not state.resources) and any(
        path.name.startswith("device-") or path.name == "server-" + project.vpn.identity.stack + "-trust"
        for path in project.Artifacts.iterdir()
    ):
        raise VpnError("Previous trust or client exports remain after cloud cleanup; initialize a new private project before redeployment")

    if (project.wireguard is not None and not cleaning
            and (action == "deploy" and journal is None or action == "recover" and journal is not None)
            and (state is None or not any(item.logicalId == "instance" for item in state.resources))):
        _FreshKernelGate()

    provider = provider or VpnYandexProvider(YandexCloudSettings(project.vpn.identity.scopeId, project.cloud.ycProfile))
    _CheckCloudAccess(provider)
    owned = CreationProvider(provider, baseline)
    engine = LifecycleEngine(baseline.plan, owned, statePath)

    if cleaning:
        recorded = {item.logicalId: item.resourceId for item in state.resources} if state is not None else {}

        for spec in baseline.plan.resources:
            observed = owned.FindResource(spec, baseline.plan.identity)

            if action == "destroy" and observed is not None and recorded.get(spec.logicalId) != observed.reference.resourceId:
                raise VpnError("Cloud cleanup cannot adopt an unrecorded or replaced resource; retain state and recover explicitly")

    if action == "destroy" or action == "recover" and journal is not None:
        report = engine.Destroy() if action == "destroy" else engine.Recover(rollback=rollback)

        if report.status != "complete":
            return _Incomplete(action, report)

        return VpnProjectReport(action, "complete", "complete", "destroyed" if action == "destroy" else "not-checked",
                                details="Owned cloud operation completed using its original creation plan; private local artifacts retained")

    if rollback:
        raise VpnError("No interrupted cloud operation is recorded; guest rollback requires a distinct receipt-bound transition")

    report = engine.Create() if action == "deploy" else engine.Status()

    if report.status != "complete":
        return _Incomplete(action, report)

    instance, endpoint = _OwnedEndpoints(project, owned)

    if action != "deploy":
        name = project.vpn.identity.stack + "-trust"
        ReadOwnedArtifactFile(project.Artifacts / ("server-" + name) / "known-hosts.txt", project.vpn.identity, kind="server", name=name)

    trust = _HostTrust(project, provider, instance, endpoint, wait=action == "deploy", originalFingerprint=baseline.projectFingerprint)
    guest = guestFactory(VpnEndpoint(endpoint, 22), ADMIN_USERNAME, project.root / "admin-key", trust)
    wireguard = next((bundle for protocol, bundle in servers if protocol == "wireguard"), None)

    if action == "recover":
        if wireguard is None or not _GuestRecovery(guest, wireguard, project.vpn.identity.scopeId):
            raise VpnError("No interrupted WireGuard guest operation is recorded; no guest mutation was requested")

        return VpnProjectReport(action, "complete", "complete", "not-checked",
                                details="Receipt-bound guest recovery completed; run deploy to verify or install the selected services")

    if action == "deploy":
        if wireguard is not None:
            from flayer._vpn_peer_controller import ObserveHistory

            ObserveHistory(guest, revision, wireguard)
            before = guest.WireGuardOperation(wireguard, "status")

            if before["status"] == "active":
                from flayer._vpn_peer_controller import Observe

                Observe(guest, revision, wireguard)

            elif revision.receipt:
                raise VpnError("Previously committed WireGuard peer state is absent or interrupted; retain its history and recover explicitly")

        # Refuse an interrupted WG transaction before invoking an unrelated protocol's installer.
        guest.Install(tuple(sorted(servers, key=lambda item: item[0] != "wireguard")),
                      expectedWireGuardHistory=revision.history if wireguard is not None else "")

    if wireguard is not None:
        status = guest.WireGuardOperation(wireguard, "status")

        if status["status"] != "active":
            return VpnProjectReport(action, "incomplete", "complete", "recovery-required" if status["status"] == "recovery-required" else "absent",
                                    recoveryRequired=status["status"] == "recovery-required" or status.get("cleanup_required") is True,
                                    details="WireGuard is not verified active; retain the project and use explicit recovery when required")

        from flayer._vpn_peer_controller import Observe

        Observe(guest, revision, wireguard)

    services = _Services(project)
    observations = guest.ServiceStatus(services)

    if tuple(name for name, _ in observations) != services or not all(active for _, active in observations):
        return VpnProjectReport(action, "incomplete", "complete", "inactive", details="Cloud resources exist but a selected VPN service is not active")

    exports = []

    if action == "deploy":
        for protocol, _ in servers:
            for bundle in _Transport(project, protocol, materials[protocol], endpoint).deviceBundles:
                exports.append(str(_Publish(project, bundle).relative_to(project.root)))

    return VpnProjectReport(action, "complete", "complete", "services-active", tuple(exports),
                            details="Selected guest services are active; authenticated client traffic, DNS, media and Internet access are not verified")
