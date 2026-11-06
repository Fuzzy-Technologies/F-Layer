"""Offline export of existing owned VPN device files with native AmneziaVPN profiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flayer.core.contracts import ValidateName
from flayer.guest import PrivatePath
from flayer.profiles._amnezia_export import (
    BuildAmneziaArtifacts,
    BuildAmneziaQrArtifacts,
    BuildAmneziaWgArtifacts,
)
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import VpnEndpoint, VpnError
from flayer.vpn_project import VpnProject, VpnProjectReport


def _VlessClient(client: bytes) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Select one unchained Reality TCP Vision outbound without exposing private JSON errors."""

    try:
        data = json.loads(client)

        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            raise ValueError

        outbounds = data["outbounds"]

        if any(not isinstance(item, dict) for item in outbounds):
            raise ValueError

        tags = [item["tag"] for item in outbounds if "tag" in item]

        if any(not isinstance(tag, str) or not tag for tag in tags) or len(tags) != len(set(tags)):
            raise ValueError

        candidates = [item for item in outbounds if item.get("protocol") == "vless"]

        if len(candidates) != 1:
            raise ValueError

        outbound = candidates[0]
        stream = outbound["streamSettings"]
        destinations = outbound["settings"]["vnext"]

        if (not isinstance(outbound.get("tag"), str) or not outbound["tag"]
                or not isinstance(stream, dict) or stream.get("security") != "reality"
                or stream.get("network") != "tcp" or not isinstance(stream.get("realitySettings"), dict)
                or not isinstance(destinations, list) or len(destinations) != 1
                or not isinstance(destinations[0], dict)):
            raise ValueError

        destination = destinations[0]
        endpoint = VpnEndpoint(destination["address"], destination["port"])
        users = destination["users"]

        if (not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], dict)
                or not isinstance(users[0].get("id"), str) or not users[0]["id"]
                or users[0].get("encryption") != "none"
                or users[0].get("flow") not in {"xtls-rprx-vision", "xtls-rprx-vision-udp443"}):
            raise ValueError

        sockopt = stream.get("sockopt", {})

        if not isinstance(sockopt, dict) or "dialerProxy" in sockopt or "proxySettings" in outbound:
            raise ValueError

        return data, outbound, endpoint.host

    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        raise VpnError("Transport options require one unchained VLESS Reality TCP Vision client") from None


def _AllowQuicVlessClient(client: bytes) -> tuple[bytes, str]:
    """Opt the selected Vision client into UDP 443 while retaining the exact other policy."""

    data, outbound, host = _VlessClient(client)
    outbound["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision-udp443"

    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"), host


def _FragmentVlessClient(client: bytes) -> tuple[bytes, str]:
    """Fragment only the VPN transport and preserve unrelated outbound, DNS and route policy."""

    data, outbound, host = _VlessClient(client)

    if any(item.get("tag") == "tls-fragment" for item in data["outbounds"]):
        raise VpnError("TLS fragmentation requires an unused tls-fragment outbound tag")

    outbound["streamSettings"].setdefault("sockopt", {})["dialerProxy"] = "tls-fragment"
    data["outbounds"].append({
        "tag": "tls-fragment", "protocol": "freedom",
        "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}},
    })

    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"), host


def ExportVpnDevice(
    project: VpnProject, deviceId: str, protocol: str, output: str | Path, *, qr: bool = False,
    tlsFragment: bool = False, allowQuic: bool = False,
) -> VpnProjectReport:
    """Export one verified device with optional client policies and no source writes."""

    ValidateName(deviceId, "device_id")

    if deviceId not in {device.deviceId for device in project.vpn.devices}:
        raise VpnError("Export requires a device declared in project.toml")

    if protocol not in {"amneziawg", "vless-reality"} or any(
        type(value) is not bool for value in (qr, tlsFragment, allowQuic)
    ):
        raise VpnError("Export requires a supported protocol and boolean QR/fragmentation/QUIC options")

    if protocol != "vless-reality" and (tlsFragment or allowQuic):
        raise VpnError("TLS fragmentation and QUIC options are available only for VLESS Reality exports")

    outputRoot = Path(output).absolute()

    if ".." in outputRoot.parts or outputRoot.is_relative_to(project.Artifacts.absolute()):
        raise VpnError("Export output must be separate from the source artifact store and contain no traversal")

    if outputRoot.exists() or outputRoot.is_symlink():
        PrivatePath(outputRoot, directory=True)

    name = f"{deviceId}-{protocol}"
    ValidateName(name, "artifact name")
    source = project.Artifacts / f"device-{name}"
    filenames = ("amneziawg.conf",) if protocol == "amneziawg" else ("client.json", "import.txt", "amnezia.vpn")
    artifacts = tuple(Artifact(filename, ReadOwnedArtifactFile(
        source / filename, project.vpn.identity, kind="device", name=name,
    )) for filename in filenames)

    if protocol == "amneziawg":
        artifacts += BuildAmneziaWgArtifacts(artifacts[0].content, deviceId, qr=qr)

    elif tlsFragment or allowQuic:
        client = artifacts[0].content

        if allowQuic:
            client, host = _AllowQuicVlessClient(client)

        if tlsFragment:
            client, host = _FragmentVlessClient(client)

        artifacts = (Artifact("client.json", client), *BuildAmneziaArtifacts(
            client, host, deviceId, project.vpn.routes.dnsServers, qr=qr,
        ))

    elif qr:
        artifacts += BuildAmneziaQrArtifacts(artifacts[-1].content)

    bundle = ArtifactBundle(project.vpn.identity, "device", name, artifacts)
    destination = outputRoot / f"device-{name}"

    if destination.exists() or destination.is_symlink():
        for artifact in artifacts:
            actual = ReadOwnedArtifactFile(destination / artifact.name, bundle.identity, kind="device", name=name)

            if actual != artifact.content:
                raise VpnError("Existing export differs; choose a separate output directory")

        if {item.name for item in destination.iterdir()} != {"manifest.json", *(item.name for item in artifacts)}:
            raise VpnError("Existing export has a different file selection; choose a separate output directory")

    else:
        WriteArtifactBundle(outputRoot, bundle)

    return VpnProjectReport("export", "complete", clientExports=(str(destination),),
                            details="Existing device files exported privately; no connectivity check was performed")
