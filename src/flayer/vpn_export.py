"""Offline export of existing owned VPN device files with native AmneziaVPN profiles."""

from __future__ import annotations

from pathlib import Path

from flayer.core.contracts import ValidateName
from flayer.guest import PrivatePath
from flayer.profiles._amnezia_export import BuildAmneziaQrArtifacts, BuildAmneziaWgArtifacts
from flayer.profiles.artifacts import (
    Artifact,
    ArtifactBundle,
    ReadOwnedArtifactFile,
    WriteArtifactBundle,
)
from flayer.profiles.vpn import VpnError
from flayer.vpn_project import VpnProject, VpnProjectReport


def ExportVpnDevice(
    project: VpnProject, device_id: str, protocol: str, output: str | Path, *, qr: bool = False,
) -> VpnProjectReport:
    """Copy one manifest-verified device without cloud calls, key generation, or source writes."""

    ValidateName(device_id, "device_id")

    if device_id not in {device.device_id for device in project.vpn.devices}:
        raise VpnError("Export requires a device declared in project.toml")

    if protocol not in {"amneziawg", "vless-reality"} or type(qr) is not bool:
        raise VpnError("Export requires a supported protocol and boolean QR option")

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
