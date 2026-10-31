"""Offline export of existing owned VPN device files with native AmneziaVPN profiles."""

from __future__ import annotations

import json
from pathlib import Path

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
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import VpnProject, VpnProjectReport


def _AllowQuicVlessClient(client: bytes) -> tuple[bytes, str]:
    """Allow UDP 443 on one existing Vision client without changing its server credentials."""

    try:
        data = json.loads(client)

        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            raise ValueError

        outbounds = data["outbounds"]

        if any(not isinstance(item, dict) for item in outbounds):
            raise ValueError

        candidates = [item for item in outbounds if item.get("protocol") == "vless"]

        if len(candidates) != 1:
            raise ValueError

        outbound = candidates[0]
        stream = outbound["streamSettings"]
        destinations = outbound["settings"]["vnext"]

        if stream["security"] != "reality" or stream["network"] != "tcp" or len(destinations) != 1:
            raise ValueError

        host = destinations[0]["address"]
        users = destinations[0]["users"]

        if not isinstance(host, str) or not host or len(users) != 1 or users[0]["flow"] != "xtls-rprx-vision":
            raise ValueError

        users[0]["flow"] = "xtls-rprx-vision-udp443"

        return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"), host

    except (ValueError, TypeError, KeyError, IndexError):
        raise VpnError("QUIC export requires one VLESS Reality TCP Vision client") from None


def _FragmentVlessClient(client: bytes) -> tuple[bytes, str]:
    """Fragment only the encrypted VPN transport while preserving device and routing policy."""

    try:
        data = json.loads(client)

        if not isinstance(data, dict) or not isinstance(data.get("outbounds"), list):
            raise ValueError

        outbounds = data["outbounds"]

        if any(not isinstance(item, dict) or item.get("tag") == "tls-fragment" for item in outbounds):
            raise ValueError

        candidates = [item for item in outbounds if item.get("protocol") == "vless"]

        if len(candidates) != 1:
            raise ValueError

        outbound = candidates[0]
        stream = outbound["streamSettings"]

        if stream["security"] != "reality" or stream["network"] != "tcp":
            raise ValueError

        sockopt = stream.setdefault("sockopt", {})

        if not isinstance(sockopt, dict) or "dialerProxy" in sockopt:
            raise ValueError

        host = outbound["settings"]["vnext"][0]["address"]

        if not isinstance(host, str) or not host:
            raise ValueError

        sockopt["dialerProxy"] = "tls-fragment"
        outbounds.append({
            "tag": "tls-fragment", "protocol": "freedom",
            "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}},
        })

        return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"), host

    except (ValueError, TypeError, KeyError, IndexError):
        raise VpnError("TLS fragmentation requires an unchained VLESS Reality TCP client profile") from None


def ExportVpnDevice(
    project: VpnProject, device_id: str, protocol: str, output: str | Path, *, qr: bool = False,
    tls_fragment: bool = False, allow_quic: bool = False,
) -> VpnProjectReport:
    """Copy one manifest-verified device without cloud calls, key generation, or source writes."""

    ValidateName(device_id, "device_id")

    if device_id not in {device.device_id for device in project.vpn.devices}:
        raise VpnError("Export requires a device declared in project.toml")

    if protocol not in {"amneziawg", "vless-reality"} or any(
        type(value) is not bool for value in (qr, tls_fragment, allow_quic)
    ):
        raise VpnError("Export requires a supported protocol and boolean QR/fragmentation/QUIC options")

    if tls_fragment and protocol != "vless-reality":
        raise VpnError("TLS fragmentation is available only for VLESS Reality exports")

    if allow_quic and protocol != "vless-reality":
        raise VpnError("QUIC transport selection is available only for VLESS Reality exports")

    output_root = Path(output).absolute()

    if ".." in output_root.parts or output_root.is_relative_to(project.Artifacts.absolute()):
        raise VpnError("Export output must be separate from the source artifact store and contain no traversal")

    if output_root.exists() or output_root.is_symlink():
        PrivatePath(output_root, directory=True)

    name = f"{device_id}-{protocol}"
    ValidateName(name, "artifact name")
    source = project.Artifacts / f"device-{name}"
    filenames = ("amneziawg.conf",) if protocol == "amneziawg" else ("client.json", "import.txt", "amnezia.vpn")
    artifacts = tuple(Artifact(filename, ReadOwnedArtifactFile(
        source / filename, project.vpn.identity, kind="device", name=name,
    )) for filename in filenames)

    if protocol == "amneziawg":
        artifacts += BuildAmneziaWgArtifacts(artifacts[0].content, device_id, qr=qr)

    elif tls_fragment or allow_quic:
        client = artifacts[0].content

        if allow_quic:
            client, host = _AllowQuicVlessClient(client)

        if tls_fragment:
            client, host = _FragmentVlessClient(client)

        artifacts = (Artifact("client.json", client), *BuildAmneziaArtifacts(
            client, host, device_id, project.vpn.routes.dns_servers, qr=qr,
        ))

    elif qr:
        artifacts += BuildAmneziaQrArtifacts(artifacts[-1].content)

    bundle = ArtifactBundle(project.vpn.identity, "device", name, artifacts)
    destination = output_root / f"device-{name}"

    if destination.exists() or destination.is_symlink():
        for artifact in artifacts:
            actual = ReadOwnedArtifactFile(destination / artifact.name, bundle.identity, kind="device", name=name)

            if actual != artifact.content:
                raise VpnError("Existing export differs; choose a separate output directory")

        if {item.name for item in destination.iterdir()} != {"manifest.json", *(item.name for item in artifacts)}:
            raise VpnError("Existing export has a different file selection; choose a separate output directory")

    else:
        WriteArtifactBundle(output_root, bundle)

    return VpnProjectReport("export", "complete", client_exports=(str(destination),),
                            details="Existing device files exported privately; no connectivity check was performed")
