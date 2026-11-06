"""Explicit plan and recovery for named standard WireGuard peers in an owned private project."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from flayer.guest import SshGuestProvisioner, ValidateSshPathSyntax
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import SelectedVpnProject, VpnProject, VpnProjectReport, VpnYandexProvider


@dataclass(frozen=True, slots=True)
class VpnPeerReport(VpnProjectReport):
    """Report bounded peer plan/recovery proofs without client material or a claim of traffic acceptance."""

    protocol: str = "wireguard"
    change: str = ""
    deviceId: str = ""
    baselineSha256: str = ""
    planExpiresAt: int = 0
    receiptSha256: str = ""
    historySha256: str = ""


def RunVpnPeer(
    project: VpnProject | SelectedVpnProject, action: str, change: str, deviceId: str, *, protocol: str = "wireguard",
    allowMutation: bool = False, scopeConfirm: str = "", expectedBaseline: str = "", planExpiresAt: int = 0,
    provider: VpnYandexProvider | None = None, guestFactory: Callable[..., SshGuestProvisioner] = SshGuestProvisioner,
) -> VpnPeerReport:
    """Plan, observe or explicitly apply/recover one peer change without rotating unrelated keys or recreating cloud resources."""

    if (not isinstance(project, SelectedVpnProject) or protocol != "wireguard"
            or not isinstance(action, str) or action not in {"plan", "status", "enroll", "revoke", "recover"}
            or not isinstance(change, str) or change not in {"enroll", "revoke"}
            or action in {"enroll", "revoke"} and action != change
            or not isinstance(deviceId, str) or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", deviceId) is None
            or type(allowMutation) is not bool or type(planExpiresAt) is not int
            or any(not isinstance(value, str) for value in (scopeConfirm, expectedBaseline))):
        raise VpnError("Peer operations require schema 2, standard WireGuard and one explicit supported named change")

    if action in {"plan", "status"}:
        if allowMutation or scopeConfirm or expectedBaseline or planExpiresAt:
            raise VpnError("Peer plan/status are read-only and accept no mutation preconditions")

    elif (allowMutation is not True or scopeConfirm != project.vpn.identity.scopeId
          or re.fullmatch(r"[0-9a-f]{64}", expectedBaseline) is None
          or (planExpiresAt != 0 if action == "recover" else planExpiresAt <= 0)):
        raise VpnError("Peer mutation requires explicit consent, exact scope and expected baseline; enrollment/revocation also requires its plan expiry")

    from flayer._vpn_peer_controller import Run
    from flayer._vpn_revisions import ProjectLock

    ValidateSshPathSyntax(project.root)

    with ProjectLock(project, readOnly=action in {"plan", "status"}):
        return Run(project, action, change, deviceId, expectedBaseline=expectedBaseline, planExpiresAt=planExpiresAt,
                   provider=provider, guestFactory=guestFactory)
