"""Manage one owned Ubuntu kernel WireGuard service without changing other transports."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import io
import ipaddress
import json
import os
import platform
import re
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

TOOLS_VERSION = "1.0.20260223"
TOOLS_SHA256 = "af459827b80bfd31b83b08077f4b5843acb7d18ad9a33a2ef532d3090f291fbf"
TOOLS_URL = "https://git.zx2c4.com/wireguard-tools/snapshot/wireguard-tools-1.0.20260223.tar.xz"
KERNEL_CVE = "CVE-2026-98432"
KERNEL_CVE_URL = "https://ubuntu.com/security/cves/CVE-2026-98432.json"
PROTOCOL_RUNTIME_ABI = "f-layer/wireguard/protocol-runtime/v1"
BASE = Path("/opt/flayer/wireguard")
SYSTEMD = Path("/etc/systemd/system")
LOCK = Path("/run/flayer-wireguard.lock")
KERNEL_SIGNATURE = Path("/proc/version_signature")
MODULES = Path("/lib/modules")
MODULE_STATE = Path("/sys/module/wireguard")
BUILD_OPTIONS = ("WIREGUARD_TOOLS_VERSION=" + TOOLS_VERSION, "CC=/usr/bin/cc", "PLATFORM=linux",
                 "PKG_CONFIG=/usr/bin/false", "WITH_WGQUICK=no", "WITH_SYSTEMDUNITS=no", "WITH_BASHCOMPLETION=no")
_ROOT_UID = 0
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FILES = frozenset({"server.conf", "deployment.json", "install.py", "firewall.nft", "service.service", "wg", "COPYING"})
_GENERATION_FILES = _FILES | {"lifecycle.py"}
_callbackFds: tuple[int, ...] = ()


class GuestError(ValueError):
    """A fixed guest-side contract failure that contains no private request or command output."""


def _Digest(content: bytes) -> str:
    """Bind exact configuration, binary, policy and ownership bytes."""

    return hashlib.sha256(content).hexdigest()


def _Json(content: bytes) -> Any:
    """Decode bounded JSON without duplicate fields or private parser diagnostics."""

    def Unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Require one interpretation of each nested field."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError

            result[key] = value

        return result

    try:
        if not 1 <= len(content) <= 1048576:
            raise ValueError

        return json.loads(content, object_pairs_hook=Unique)

    except (ValueError, TypeError, RecursionError):
        raise GuestError("Managed JSON is invalid or ambiguous") from None


def _Encode(value: object) -> bytes:
    """Write deterministic private records without logging their contents."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _Key(value: object) -> str:
    """Require a canonical nonzero WireGuard key without revealing rejected bytes."""

    try:
        if not isinstance(value, str):
            raise ValueError

        raw = base64.b64decode(value, validate=True)

        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
            raise ValueError

    except (ValueError, UnicodeError):
        raise GuestError("WireGuard key encoding is invalid") from None

    return value


def _Directory(path: Path, *, create: bool = False, private: bool = False) -> None:
    """Require a root-owned directory without writable or symbolic-link managed ancestry."""

    if any(item.is_symlink() for item in (path, *path.parents)):
        raise GuestError("Managed directory contains a symbolic link")

    managed = {BASE, BASE.parent, BASE.parent.parent, SYSTEMD, SYSTEMD.parent, SYSTEMD.parent.parent}

    for parent in path.parents:
        if parent in managed:
            info = parent.stat()

            if not stat.S_ISDIR(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022:
                raise GuestError("Managed ancestor ownership or permissions are unsafe")

    existed = path.exists()

    if create:
        path.mkdir(mode=0o700 if private else 0o755, exist_ok=True)

    info = path.stat()

    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022
            or private and stat.S_IMODE(info.st_mode) != 0o700):
        raise GuestError("Managed directory ownership or permissions are unsafe")

    if create and not existed:
        _SyncDirectory(path.parent)


def _Read(path: Path, *, limit: int = 1048576, mode: int = 0o600) -> bytes:
    """Read only a bounded owned regular file, rejecting links and unexpected permissions."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != _ROOT_UID
                or stat.S_IMODE(info.st_mode) != mode or not 0 < info.st_size <= limit):
            raise GuestError("Managed file ownership, size or permissions are unsafe")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)

        if len(content) > limit:
            raise GuestError("Managed file exceeds its size bound")

        return content

    finally:
        os.close(descriptor)


def _SyncDirectory(path: Path) -> None:
    """Persist a directory boundary before exposing changes or retiring recovery evidence."""

    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    try:
        os.fsync(descriptor)

    finally:
        os.close(descriptor)


def _Publish(source: Path, destination: Path) -> None:
    """Durably move an already verified complete directory between owned parents."""

    os.replace(source, destination)
    _SyncDirectory(destination.parent)

    if source.parent != destination.parent:
        _SyncDirectory(source.parent)


def _Atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Publish one file durably, keeping crash leftovers outside exact managed file sets."""

    descriptor, temporary = tempfile.mkstemp(prefix=".wg-write-", dir=BASE)

    try:
        os.fchmod(descriptor, mode)

        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary, path)
        _SyncDirectory(path.parent)

    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _Run(command: list[str], *, payload: bytes | None = None, timeout: int = 30, required: bool = True, passFds: tuple[int, ...] = ()) -> tuple[int, bytes]:
    """Capture bounded private command output without a shell or inherited standard input."""

    try:
        result = subprocess.run(command, input=payload, stdin=subprocess.DEVNULL if payload is None else None,
                                capture_output=True, check=False, timeout=timeout, pass_fds=tuple(dict.fromkeys((*passFds, *_callbackFds))),
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})

    except (OSError, subprocess.SubprocessError):
        raise GuestError("Required guest command failed or timed out") from None

    if len(result.stdout) > 1048576 or required and result.returncode != 0:
        raise GuestError("Required guest command did not satisfy its contract")

    return result.returncode, result.stdout


def _Fetch(url: str, limit: int) -> bytes:
    """Fetch only fixed HTTPS upstream data with no redirects, proxy credentials or unbounded read."""

    if url not in {TOOLS_URL, KERNEL_CVE_URL}:
        raise GuestError("Unrecognized upstream source")

    parsed = urlsplit(url)

    if parsed.hostname is None:
        raise GuestError("Upstream source has no authenticated host")

    connection = http.client.HTTPSConnection(parsed.hostname, timeout=30, context=ssl.create_default_context())

    try:
        connection.request("GET", parsed.path, headers={"User-Agent": "F-Layer WireGuard guest"})
        response = connection.getresponse()

        if response.status != 200:
            raise GuestError("Upstream source is unavailable or redirected")

        content = response.read(limit + 1)

        if not 1 <= len(content) <= limit:
            raise GuestError("Upstream source exceeds its size bound")

        return content

    except (OSError, http.client.HTTPException):
        raise GuestError("Authenticated upstream source could not be read") from None

    finally:
        connection.close()


def _KernelVersion(value: object) -> tuple[int, int]:
    """Accept only supported noble GA package versions, without epochs or inferred HWE families."""

    match = re.fullmatch(r"6\.8\.0-([0-9]{1,5})\.([0-9]{1,5})", value) if isinstance(value, str) else None

    if match is None:
        raise GuestError("Kernel package is outside the supported Ubuntu GA policy")

    return int(match[1]), int(match[2])


def _KernelSignature(signature: str, packageVersion: str) -> None:
    """Bind the complete executing Ubuntu revision, not just uname's shared ABI, to the package."""

    _KernelVersion(packageVersion)

    if not isinstance(signature, str):
        raise GuestError("Executing Ubuntu build identity is invalid")

    parts = signature.split()

    if (len(parts) != 3 or parts[:2] != ["Ubuntu", packageVersion + "-generic"]
            or re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", parts[2]) is None):
        raise GuestError("Executing Ubuntu build differs from the installed image; explicit kernel maintenance is required")


def _SystemText(path: Path) -> str:
    """Read bounded root-owned proc/sys evidence, whose virtual files may report zero size."""

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        info = os.fstat(descriptor)

        if not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022:
            raise GuestError("Kernel identity evidence has unsafe ownership")

        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(4097)

        if not 1 <= len(content) <= 4096:
            raise GuestError("Kernel identity evidence is missing or unbounded")

        return content.decode("ascii").strip()

    finally:
        os.close(descriptor)


def _LoadedSource(sourceVersion: str, *, required: bool = False) -> None:
    """Allow an unloaded module during admission, but require matching loaded source before traffic."""

    if MODULE_STATE.exists() or MODULE_STATE.is_symlink():
        if MODULE_STATE.is_symlink() or _SystemText(MODULE_STATE / "srcversion") != sourceVersion:
            raise GuestError("Loaded WireGuard source identity differs from the available module")

    elif required:
        raise GuestError("Executing WireGuard module source identity is unavailable")


def _ReleasedKernelEvidence(content: bytes) -> dict[str, object]:
    """Require authoritative released noble/linux evidence without claiming any host meets it yet."""

    data = _Json(content)

    try:
        if not isinstance(data, dict) or data.get("id") != KERNEL_CVE or not isinstance(data.get("packages"), list):
            raise ValueError

        packages = [item for item in data["packages"] if isinstance(item, dict) and item.get("name") == "linux"]

        if len(packages) != 1 or not isinstance(packages[0].get("statuses"), list):
            raise ValueError

        rows = [item for item in packages[0]["statuses"] if isinstance(item, dict) and item.get("release_codename") == "noble"]

        if len(rows) != 1 or rows[0].get("status") != "released":
            raise GuestError("Ubuntu has not confirmed a released kernel fix; activation is blocked")

        fixedVersion = rows[0]["description"]

        _KernelVersion(fixedVersion)

        return {"cve_id": KERNEL_CVE, "source_sha256": _Digest(content), "fixed_version": fixedVersion,
                "checked_at": int(time.time())}

    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, GuestError):
            raise

        raise GuestError("Ubuntu kernel evidence is unavailable or ambiguous") from None


def _VendorEvidence(content: bytes, packageVersion: str) -> dict[str, object]:
    """Bind Ubuntu's released fix to an observed running package, never a pending target or disk-only revision."""

    evidence = _ReleasedKernelEvidence(content)

    if _KernelVersion(packageVersion) < _KernelVersion(evidence["fixed_version"]):
        raise GuestError("The running kernel package predates Ubuntu's confirmed fix")

    return evidence


def _KernelFacts() -> dict[str, str]:
    """Observe the exact supported platform and kernel module without installing or loading anything."""

    release = platform.freedesktop_os_release()
    kernelRelease = platform.release()

    if (release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04"
            or platform.machine() != "x86_64" or re.fullmatch(r"6\.8\.0-[0-9]{1,5}-generic", kernelRelease) is None):
        raise GuestError("WireGuard supports only Ubuntu 24.04 amd64 with its approved GA kernel")

    _, rawVersion = _Run(["dpkg-query", "-W", "-f=${Version}", "linux-image-" + kernelRelease])
    packageVersion = rawVersion.decode("ascii").strip()
    abi, _ = _KernelVersion(packageVersion)

    if kernelRelease != f"6.8.0-{abi}-generic":
        raise GuestError("Running kernel and installed package identity disagree")

    signature = _SystemText(KERNEL_SIGNATURE)
    _KernelSignature(signature, packageVersion)
    _, rawModulesVersion = _Run(["dpkg-query", "-W", "-f=${Version}", "linux-modules-" + kernelRelease])

    if rawModulesVersion.decode("ascii").strip() != packageVersion:
        raise GuestError("Kernel image and modules packages have different revisions")

    _, rawModule = _Run(["modinfo", "-n", "wireguard"])
    module = Path(rawModule.decode("utf-8").strip()).resolve(strict=True)
    allowed = (MODULES / kernelRelease).resolve(strict=True)

    if not module.is_relative_to(allowed):
        raise GuestError("WireGuard module is outside the running kernel package")

    info = module.stat()

    if not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022 or info.st_size > 8 * 1024 * 1024:
        raise GuestError("WireGuard kernel module ownership is unsafe")

    _, rawSource = _Run(["modinfo", "-F", "srcversion", str(module)])
    sourceVersion = rawSource.decode("ascii").strip()

    if re.fullmatch(r"[0-9A-F]{24}", sourceVersion) is None:
        raise GuestError("Available WireGuard module has no unambiguous source identity")

    _LoadedSource(sourceVersion)

    return {"release": kernelRelease, "package_version": packageVersion, "signature": signature,
            "module_sha256": _Digest(module.read_bytes()), "module_srcversion": sourceVersion}


def _Request(stage: Path) -> tuple[dict[str, Any], bytes, bytes]:
    """Validate every public field and private file digest before managed guest mutation."""

    _Directory(stage, private=True)

    if set(path.name for path in stage.iterdir()) not in (
        {"server.conf", "deployment.json", "install.py"}, _FILES | {"receipt.json"}, _GENERATION_FILES | {"receipt.json"},
    ):
        raise GuestError("WireGuard stage has unknown or missing files")

    raw = _Read(stage / "deployment.json")
    request = _Json(raw)
    fields = {"schema_version", "owner", "port", "tunnel_cidr", "mtu", "ipv4_routes", "peers",
              "config_sha256", "program_sha256", "tools_version", "tools_sha256"}

    if (not isinstance(request, dict) or set(request) != fields or type(request["schema_version"]) is not int
            or request["schema_version"] != 1 or not isinstance(request["owner"], str) or _HASH.fullmatch(request["owner"]) is None
            or type(request["port"]) is not int or not 1 <= request["port"] <= 65535
            or type(request["mtu"]) is not int or not 576 <= request["mtu"] <= 1420
            or request["tools_version"] != TOOLS_VERSION or request["tools_sha256"] != TOOLS_SHA256):
        raise GuestError("WireGuard deployment descriptor is invalid")

    network = ipaddress.IPv4Network(request["tunnel_cidr"], strict=True)
    private = tuple(ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

    if (str(network) != request["tunnel_cidr"] or not 16 <= network.prefixlen <= 28
            or not any(network.subnet_of(item) for item in private)):
        raise GuestError("WireGuard tunnel subnet is invalid")

    routes = request["ipv4_routes"]

    if not isinstance(routes, list) or not 1 <= len(routes) <= 16 or any(not isinstance(item, str) for item in routes):
        raise GuestError("WireGuard destinations must be bounded explicit IPv4 routes")

    parsedRoutes = [ipaddress.IPv4Network(item, strict=True) for item in routes]

    if any(str(network) != value for network, value in zip(parsedRoutes, routes)) or any(
        left.overlaps(right) for index, left in enumerate(parsedRoutes) for right in parsedRoutes[index + 1:]
    ):
        raise GuestError("WireGuard destination routes are ambiguous")

    peers = request["peers"]

    if not isinstance(peers, list) or not 1 <= len(peers) <= 16:
        raise GuestError("WireGuard requires bounded explicit peer metadata")

    names, keys, addresses = set(), set(), set()

    for peer in peers:
        if (not isinstance(peer, dict) or set(peer) != {"device_id", "public_key", "ipv4_address"}
                or not isinstance(peer["device_id"], str) or _NAME.fullmatch(peer["device_id"]) is None):
            raise GuestError("WireGuard peer metadata is invalid")

        key = _Key(peer["public_key"])
        address = ipaddress.IPv4Address(peer["ipv4_address"])

        if (str(address) != peer["ipv4_address"] or address not in network
                or address in {network.network_address, network.network_address + 1, network.broadcast_address}
                or peer["device_id"] in names or key in keys or str(address) in addresses):
            raise GuestError("WireGuard peer identity or address is ambiguous")

        names.add(peer["device_id"])
        keys.add(key)
        addresses.add(str(address))

    config, program = _Read(stage / "server.conf", limit=65536), _Read(stage / "install.py")

    if request["config_sha256"] != _Digest(config) or request["program_sha256"] != _Digest(program):
        raise GuestError("WireGuard staged configuration or program digest differs")

    return request, config, raw


def _Service(owner: str) -> str:
    """Use the stable complete-owner namespace without trusting a supplied path or service name."""

    return "flayer-wg-" + owner[:12]


def _Interface(owner: str) -> str:
    """Keep the owned kernel interface within Linux's 15-byte limit."""

    return "fwg" + owner[:12]


def _Table(owner: str) -> str:
    """Give each stack a separate IPv4 forwarding/NAT table."""

    return "flayer_wg_" + owner[:12]


def _Unit(root: Path, owner: str, *, nonce: str = "") -> bytes:
    """Keep legacy unit bytes stable; explicit new generations bind callbacks to their exact nonce."""

    program = "install.py"
    guard = ""

    if type(nonce) is not str:
        raise GuestError("WireGuard unit generation nonce is invalid")

    if nonce:
        _Nonce(nonce)
        program = "lifecycle.py"
        guard = " --expected-generation-nonce " + nonce

    rootText = root.as_posix()

    return (f"# F-Layer WireGuard owner {owner}\n[Unit]\nDescription=F-Layer standard WireGuard\n"
            "Wants=network-online.target\nAfter=network-online.target nftables.service\n[Service]\n"
            "Type=oneshot\nRemainAfterExit=yes\nUMask=0077\n"
            "StandardOutput=null\nStandardError=null\n"
            f"ExecStart=/usr/bin/python3 {rootText}/{program} --start --allow-mutation{guard}\n"
            f"ExecStop=/usr/bin/python3 {rootText}/{program} --stop --allow-mutation{guard}\n"
            "[Install]\nWantedBy=multi-user.target\n").encode()


def _Firewall(request: dict[str, Any], nonce: str) -> bytes:
    """Compile interface-scoped forwarding and NAT from validated data, never a supplied script."""

    owner = request["owner"]
    interface, table = _Interface(owner), _Table(owner)
    sources = ", ".join(sorted(peer["ipv4_address"] for peer in request["peers"]))
    destinations = ", ".join(request["ipv4_routes"])
    lines = [f"table ip {table} {{", f'  comment "flayer:wireguard:{owner}:{nonce}"',
             "  chain forward {", "    type filter hook forward priority -10; policy accept;",
             f'    iifname "{interface}" oifname "{interface}" drop',
             f'    iifname "{interface}" ip daddr {{ 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 }} drop',
             f'    iifname "{interface}" ip saddr {{ {sources} }} ip daddr {{ {destinations} }} accept',
             f'    oifname "{interface}" ip daddr {{ {sources} }} ct state established,related accept',
             f'    iifname "{interface}" drop', f'    oifname "{interface}" drop', "  }", "  chain postrouting {",
             "    type nat hook postrouting priority srcnat; policy accept;",
             f'    iifname "{interface}" ip saddr {{ {sources} }} ip daddr {{ {destinations} }} masquerade',
             "  }", "}", ""]

    return "\n".join(lines).encode()


def _NftFingerprint(content: bytes, owner: str, nonce: str) -> str:
    """Normalize only kernel handles/metainfo while retaining every chain and ordered rule expression."""

    data = _Json(content)

    if not isinstance(data, dict) or set(data) != {"nftables"} or not isinstance(data["nftables"], list):
        raise GuestError("Owned nftables observation is invalid")

    tables: list[dict[str, Any]] = []
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {}
    sets: list[dict[str, Any]] = []

    for entry in data["nftables"]:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise GuestError("Owned nftables observation is ambiguous")

        if "metainfo" in entry:
            continue

        if "add" in entry:
            entry = entry["add"]

        if not isinstance(entry, dict) or len(entry) != 1:
            raise GuestError("Owned nftables notification is invalid")

        kind, value = next(iter(entry.items()))

        if kind not in {"table", "chain", "rule", "set", "element"} or not isinstance(value, dict):
            raise GuestError("Unexpected nftables object in owned table")

        value = {key: item for key, item in value.items() if key != "handle"}

        if value.get("family") != "ip" or value.get("name" if kind == "table" else "table") != _Table(owner):
            raise GuestError("nftables observation crosses the owned namespace")

        if kind == "table":
            if value.get("comment") != f"flayer:wireguard:{owner}:{nonce}":
                raise GuestError("nftables table has a foreign ownership marker")

            tables.append(value)

        elif kind == "chain":
            if value.get("name") not in {"forward", "postrouting"} or value["name"] in chains:
                raise GuestError("Unexpected owned chain")

            chains[value["name"]] = value

        elif kind == "rule":
            if value.get("chain") not in {"forward", "postrouting"}:
                raise GuestError("Unexpected owned rule chain")

            rules.setdefault(value["chain"], []).append(value)

        else:
            sets.append({kind: value})

    if len(tables) != 1 or set(chains) != {"forward", "postrouting"} or set(rules) != set(chains):
        raise GuestError("Owned nftables table is incomplete")

    return _Digest(_Encode({"table": tables[0], "chains": chains, "rules": rules, "sets": sets}))


def _BuildTools(work: Path) -> tuple[bytes, bytes]:
    """Build the exact pinned upstream tools privately, without package installation or system replacement."""

    content = _Fetch(TOOLS_URL, 4 * 1024 * 1024)

    if _Digest(content) != TOOLS_SHA256:
        raise GuestError("WireGuard tools source checksum differs")

    prefix = "wireguard-tools-" + TOOLS_VERSION

    with tarfile.open(fileobj=io.BytesIO(content), mode="r:xz") as archive:
        expanded, count = 0, 0

        for member in archive:
            parts = member.name.rstrip("/").split("/")
            expanded += member.size
            count += 1

            # The pinned upstream archive contains this unused wg-quick convenience link.
            # Verify its exact identity and skip it; never materialize or follow archive links.
            unusedLink = member.name == prefix + "/src/wg-quick/wg" and member.issym() and member.linkname == "../wg"

            if (count > 2048 or member.size < 0 or expanded > 32 * 1024 * 1024 or not parts or parts[0] != prefix
                    or len(parts) > 12 or any(part in {"", ".", ".."} or "\\" in part for part in parts)
                    or not member.isdir() and not member.isfile() and not unusedLink):
                raise GuestError("WireGuard source archive contains unsafe entries")

            if unusedLink:
                continue

            destination = work.joinpath(*parts)

            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)

            else:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stream = archive.extractfile(member)

                if stream is None:
                    raise GuestError("WireGuard source archive entry is unavailable")

                data = stream.read(member.size + 1)

                if len(data) != member.size:
                    raise GuestError("WireGuard source archive entry length differs")

                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

                with os.fdopen(descriptor, "wb") as output:
                    output.write(data)

    source = work / prefix
    _Run(["make", "-s", "-C", str(source / "src"), *BUILD_OPTIONS, "wg"], timeout=300)
    binary = source / "src/wg"
    binary.chmod(0o755)
    data = _Read(binary, limit=8 * 1024 * 1024, mode=0o755)

    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or int.from_bytes(data[18:20], "little") != 62:
        raise GuestError("WireGuard tool is not the expected Linux amd64 executable")

    _, version = _Run([str(binary), "--version"])

    if not version.startswith(("wireguard-tools v" + TOOLS_VERSION + " ").encode()):
        raise GuestError("WireGuard tool version differs from the pin")

    return data, _Read(source / "COPYING")


def _BuildRecord(value: Any) -> dict[str, Any]:
    """Validate bounded nonsecret provenance without requiring the original toolchain to remain installed."""

    labels = {"compiler_version", "compiler_target", "make_version", "libc_headers_version", "kernel_headers_version"}
    hashes = {"compiler_sha256", "make_sha256"}

    if (not isinstance(value, dict) or set(value) != labels | hashes | {"options"}
            or value["options"] != list(BUILD_OPTIONS) or value["compiler_target"] != "x86_64-linux-gnu"
            or any(not isinstance(value[key], str) or re.fullmatch(r"[a-zA-Z0-9 ._+():~,/-]{1,200}", value[key]) is None for key in labels)
            or any(not isinstance(value[key], str) or _HASH.fullmatch(value[key]) is None for key in hashes)):
        raise GuestError("WireGuard build provenance is invalid")

    return value


def _BuildFacts() -> dict[str, Any]:
    """Bind the exact compiler/make binaries, versions, headers and fixed upstream build options."""

    result: dict[str, Any] = {"options": list(BUILD_OPTIONS)}

    for key, command in (
        ("compiler_version", ["/usr/bin/cc", "--version"]),
        ("compiler_target", ["/usr/bin/cc", "-dumpmachine"]),
        ("make_version", ["/usr/bin/make", "--version"]),
        ("libc_headers_version", ["dpkg-query", "-W", "-f=${Version}", "libc6-dev"]),
        ("kernel_headers_version", ["dpkg-query", "-W", "-f=${Version}", "linux-libc-dev"]),
    ):
        _, raw = _Run(command)
        lines = raw.decode("ascii").splitlines()
        result[key] = lines[0].strip() if lines else ""

    for key, path in (("compiler_sha256", Path("/usr/bin/cc")), ("make_sha256", Path("/usr/bin/make"))):
        path = path.resolve(strict=True)
        info = path.stat()

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_mode & 0o022
                or not 1 <= info.st_size <= 64 * 1024 * 1024):
            raise GuestError("WireGuard build tool ownership or size is unsafe")

        result[key] = _Digest(path.read_bytes())

    return _BuildRecord(result)


def _Config(config: bytes, request: dict[str, Any], binary: Path) -> tuple[str, str, dict[str, tuple[str, str]]]:
    """Validate server-only directives and bind private/preshared roles to exact public peer metadata."""

    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for line in config.decode("ascii").splitlines():
        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        if line == "[Interface]" and current is None:
            current = interface

            continue

        if line == "[Peer]" and current is not None:
            current = {}
            peers.append(current)

            continue

        if current is None or "=" not in line:
            raise GuestError("WireGuard configuration contains unsupported directives")

        key, value = (part.strip() for part in line.split("=", 1))

        if key in current:
            raise GuestError("WireGuard configuration repeats a directive")

        current[key] = value

    if (set(interface) != {"PrivateKey", "ListenPort"} or interface["ListenPort"] != str(request["port"])
            or len(peers) != len(request["peers"]) or not peers):
        raise GuestError("WireGuard server interface or peer count differs")

    privateKey = _Key(interface["PrivateKey"])
    _, rawPublic = _Run([str(binary), "pubkey"], payload=(privateKey + "\n").encode())
    serverPublic = _Key(rawPublic.decode("ascii").strip())
    expected = {peer["public_key"]: peer["ipv4_address"] + "/32" for peer in request["peers"]}
    observed = {}
    allPublic = {serverPublic, *expected}
    preshared = set()

    if len(allPublic) != len(expected) + 1:
        raise GuestError("WireGuard server and peer identities overlap")

    for peer in peers:
        if set(peer) != {"PublicKey", "PresharedKey", "AllowedIPs"}:
            raise GuestError("WireGuard peer contains unsupported directives")

        publicKey, presharedKey = _Key(peer["PublicKey"]), _Key(peer["PresharedKey"])
        _, rawIdentity = _Run([str(binary), "pubkey"], payload=(presharedKey + "\n").encode())

        if (publicKey not in expected or publicKey in observed or presharedKey in preshared
                or peer["AllowedIPs"] != expected[publicKey] or presharedKey in {privateKey, *allPublic}
                or _Key(rawIdentity.decode("ascii").strip()) in allPublic):
            raise GuestError("WireGuard peer policy or credential roles differ")

        observed[publicKey] = presharedKey, peer["AllowedIPs"]
        preshared.add(presharedKey)

    return privateKey, serverPublic, observed


def _Paths(owner: str, *, nonce: str = "") -> tuple[Path, Path, Path]:
    """Keep root/transaction identity stable and give each explicit generation a distinct systemd name."""

    if not isinstance(owner, str) or _HASH.fullmatch(owner) is None:
        raise GuestError("WireGuard owner identity is invalid")

    if type(nonce) is not str:
        raise GuestError("WireGuard service generation is invalid")

    name = _Service(owner) + ("-" + _Nonce(nonce) if nonce else "") + ".service"

    return BASE / owner, SYSTEMD / name, BASE / ("txn-" + owner)


def _ActivePaths(owner: str) -> tuple[Path, Path, Path]:
    """Select a unit from bounded owned root metadata; complete receipt/runtime checks still establish authority."""

    root, unit, transaction = _Paths(owner)

    if root.exists() or root.is_symlink():
        _Directory(root, private=True)
        path = root / "receipt.json"

        if path.exists() or path.is_symlink():
            receipt = _ReceiptData(_Json(_Read(path)), owner, staged=True)

            if receipt["schema_version"] == 2:
                return _Paths(owner, nonce=receipt["nonce"])

    return root, unit, transaction


def _OwnedUnits(owner: str) -> frozenset[Path]:
    """Observe bounded legacy/generation unit and enablement names, including broken links and unknown suffixes."""

    _Paths(owner)
    prefix = _Service(owner)
    found = set()

    for parent in (SYSTEMD, SYSTEMD / "multi-user.target.wants"):
        if not parent.exists() and not parent.is_symlink():
            continue

        _Directory(parent)

        for index, path in enumerate(parent.iterdir()):
            if index >= 4096:
                raise GuestError("WireGuard service namespace observation exceeds its bound")

            if path.name.startswith(prefix):
                found.add(path)

    return frozenset(found)


def _Nonce(value: object) -> str:
    """Bind transient kernel objects to one unambiguous owned installation attempt."""

    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise GuestError("WireGuard operation identity is invalid")

    return value


def _Alias(owner: str, nonce: str) -> str:
    """Mark interface ownership atomically at creation, including an interrupted empty interface."""

    return "flayer:wireguard:" + owner + ":" + _Nonce(nonce)


def _InterfaceState(owner: str) -> dict[str, Any] | None:
    """Observe only the selected interface without changing host routes or adapters."""

    code, content = _Run(["ip", "-j", "link", "show", "dev", _Interface(owner)], required=False)

    if code != 0:
        # Confirm absence through a successful inventory, not an arbitrary command failure.
        _, content = _Run(["ip", "-j", "link", "show"])
        entries = _Json(content)

        if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
            raise GuestError("Kernel interface inventory is invalid")

        if any(item.get("ifname") == _Interface(owner) for item in entries):
            raise GuestError("Selected interface could not be observed")

        return None

    entries = _Json(content)

    if (not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict)
            or entries[0].get("ifname") != _Interface(owner)):
        raise GuestError("Kernel interface observation is ambiguous")

    return entries[0]


def _NftState(owner: str, nonce: str) -> str | None:
    """Require a complete successful inventory before declaring an owned table absent."""

    _, content = _Run(["nft", "-j", "list", "tables"])
    data = _Json(content)

    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise GuestError("nftables inventory is invalid")

    if any(not isinstance(item, dict) or len(item) != 1 or next(iter(item)) not in {"table", "metainfo"}
           or not isinstance(next(iter(item.values())), dict) for item in data["nftables"]):
        raise GuestError("nftables inventory is ambiguous")

    tables = [item["table"] for item in data["nftables"] if "table" in item]

    if not any(isinstance(table, dict) and table.get("family") == "ip" and table.get("name") == _Table(owner) for table in tables):
        return None

    _, content = _Run(["nft", "-j", "list", "table", "ip", _Table(owner)])

    return _NftFingerprint(content, owner, nonce)


def _KernelMatches(receipt: dict[str, Any]) -> None:
    """Reuse confirmed kernel evidence only for the exact installed image/module facts."""

    facts = _KernelFacts()

    if any(receipt["kernel"].get(key) != value for key, value in facts.items()):
        raise GuestError("Running kernel changed; explicit policy maintenance is required")


def _ReceiptData(receipt: Any, owner: str, *, staged: bool = False) -> dict[str, Any]:
    """Validate a nonsecret ownership record independently of crash-interrupted file cleanup."""
    fields = {"schema_version", "owner", "nonce", "status", "files", "network_sha256", "kernel", "build", "deployment_sha256"}

    if (not isinstance(receipt, dict) or set(receipt) != fields or type(receipt["schema_version"]) is not int
            or receipt["schema_version"] not in {1, 2} or receipt["owner"] != owner
            or receipt["status"] not in ({"staged", "installed"} if staged else {"installed"})
            or not isinstance(receipt["files"], dict) or set(receipt["files"]) != (_GENERATION_FILES if receipt["schema_version"] == 2 else _FILES)
            or not isinstance(receipt["network_sha256"], str) or _HASH.fullmatch(receipt["network_sha256"]) is None):
        raise GuestError("WireGuard ownership receipt is invalid")

    _Nonce(receipt["nonce"])

    if any(not isinstance(digest, str) or _HASH.fullmatch(digest) is None for digest in receipt["files"].values()):
        raise GuestError("WireGuard receipt file digests are invalid")

    if (receipt["deployment_sha256"] != receipt["files"]["deployment.json"]
            or not isinstance(receipt["kernel"], dict)
            or set(receipt["kernel"]) != {"release", "package_version", "signature", "module_sha256", "module_srcversion",
                                         "cve_id", "source_sha256", "fixed_version", "checked_at"}
            or receipt["kernel"].get("cve_id") != KERNEL_CVE
            or type(receipt["kernel"].get("checked_at")) is not int
            or not isinstance(receipt["kernel"].get("module_sha256"), str)
            or _HASH.fullmatch(receipt["kernel"]["module_sha256"]) is None
            or not isinstance(receipt["kernel"].get("source_sha256"), str)
            or _HASH.fullmatch(receipt["kernel"]["source_sha256"]) is None
            or not isinstance(receipt["kernel"].get("module_srcversion"), str)
            or re.fullmatch(r"[0-9A-F]{24}", receipt["kernel"]["module_srcversion"]) is None
            or _KernelVersion(receipt["kernel"]["package_version"]) < _KernelVersion(receipt["kernel"]["fixed_version"])):
        raise GuestError("Cached WireGuard kernel-policy receipt is invalid")

    _KernelSignature(receipt["kernel"]["signature"], receipt["kernel"]["package_version"])
    _BuildRecord(receipt["build"])

    return receipt


def _Receipt(root: Path, unit: Path, owner: str, *, staged: bool = False) -> dict[str, Any]:
    """Verify all private files, unit bytes and cached kernel-policy fields before trusting ownership."""

    _Directory(root, private=True)

    receipt = _ReceiptData(_Json(_Read(root / "receipt.json")), owner, staged=staged)

    if {path.name for path in root.iterdir()} != set(receipt["files"]) | {"receipt.json"}:
        raise GuestError("Owned WireGuard directory has changed or unknown files")

    for name, digest in receipt["files"].items():
        content = _Read(root / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                        mode=0o755 if name == "wg" else 0o600)

        if digest != _Digest(content):
            raise GuestError("Owned WireGuard file changed")

    if _Read(root / "service.service") != _Unit(_Paths(owner)[0], owner, nonce=receipt["nonce"] if receipt["schema_version"] == 2 else ""):
        raise GuestError("Owned WireGuard unit template differs")

    if unit.exists() or unit.is_symlink():
        if unit != _Paths(owner, nonce=receipt["nonce"] if receipt["schema_version"] == 2 else "")[1]:
            raise GuestError("WireGuard unit path differs from its exact installation generation")

        if _Read(unit, mode=0o644) != _Read(root / "service.service"):
            raise GuestError("WireGuard systemd unit is foreign or changed")

    elif not staged:
        raise GuestError("Owned WireGuard systemd unit is absent")

    return receipt


def _GenerationRecord(value: object, intent: dict[str, Any]) -> dict[str, Any]:
    """Bind versioned activation/restoration receipts for both cache preparation and host-input admission."""

    sourceFiles = {"server.conf", "deployment.json", "install.py"}
    fields = {"schema_version", "change", "source_sha256", "source_files", "cached_receipt", "candidate_receipt"}

    if (type(value) is not dict or type(value.get("schema_version")) is not int or value["schema_version"] not in {1, 2, 3}
            or set(value) != fields | ({"callback_abi"} if value["schema_version"] == 3 else set())
            or value["schema_version"] == 3 and value["callback_abi"] != PROTOCOL_RUNTIME_ABI
            or type(value["change"]) is not str or value["change"] not in {"enable", "disable"}
            or type(value["source_sha256"]) is not str or _HASH.fullmatch(value["source_sha256"]) is None
            or type(value["source_files"]) is not dict or set(value["source_files"]) != sourceFiles
            or any(type(digest) is not str or _HASH.fullmatch(digest) is None for digest in value["source_files"].values())):
        raise GuestError("WG generation requires closed versioned source and receipt metadata")

    cached = _ReceiptData(value["cached_receipt"], intent["owner"], staged=True)
    candidate = value["candidate_receipt"]

    if any(cached["files"][name] != digest for name, digest in value["source_files"].items()):
        raise GuestError("Cached generation does not retain its exact source file pins")

    if value["change"] == "disable":
        if (intent["wireguard_state"] != "active" or cached["status"] != "installed"
                or _Digest(_Encode(cached)) != intent["wireguard_receipt_sha256"]
                or value["schema_version"] == 1 and candidate is not None):
            raise GuestError("WG disable requires its actual installed receipt and a versioned restoration contract")

    elif intent["wireguard_state"] != "absent":
        raise GuestError("WG activation requires its exact original namespace absence")

    if candidate is None:
        if value["schema_version"] >= 2 or value["change"] == "enable":
            raise GuestError("Native generation capability requires a preplanned fresh activation or restoration receipt")

    else:
        desired = _ReceiptData(candidate, intent["owner"], staged=True)

        if (desired["schema_version"] != 2 or desired["status"] != "staged"
                or desired["nonce"] != intent["operation_id"] or desired["nonce"] == cached["nonce"]
                or {key: item for key, item in desired.items() if key not in {"schema_version", "nonce", "status", "files", "network_sha256"}}
                != {key: item for key, item in cached.items() if key not in {"schema_version", "nonce", "status", "files", "network_sha256"}}
                or any(desired["files"][name] != cached["files"][name] for name in sourceFiles | {"wg", "COPYING"})
                or desired["files"]["firewall.nft"] == cached["files"]["firewall.nft"] or desired["network_sha256"] == cached["network_sha256"]
                or desired["files"]["service.service"] != _Digest(_Unit(_Paths(intent["owner"])[0], intent["owner"], nonce=intent["operation_id"]))):
            raise GuestError("WG generation must retain cached credentials, runtime and kernel facts under its fresh exact nonce")

    return value


def _ProtocolIntent(value: object) -> dict[str, Any]:
    """Validate standalone callback authority without importing or executing a retained controller program."""

    fields = {"schema_version", "owner", "creation_sha256", "previous_authority_sha256", "previous_state_sha256", "operation_id",
              "plan_sha256", "plan_expires_at", "wireguard_state", "wireguard_receipt_sha256", "wireguard_absence_sha256", "wireguard_history_sha256"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or any(type(value[key]) is not str or _HASH.fullmatch(value[key]) is None for key in
                   ("owner", "creation_sha256", "previous_authority_sha256", "previous_state_sha256", "plan_sha256", "wireguard_history_sha256"))
            or type(value["operation_id"]) is not str or re.fullmatch(r"[0-9a-f]{32}", value["operation_id"]) is None
            or type(value["plan_expires_at"]) is not int or value["plan_expires_at"] <= 0
            or type(value["wireguard_state"]) is not str or value["wireguard_state"] not in {"active", "absent"}
            or type(value["wireguard_receipt_sha256"]) is not str or type(value["wireguard_absence_sha256"]) is not str
            or value["wireguard_state"] == "active" and (_HASH.fullmatch(value["wireguard_receipt_sha256"]) is None or value["wireguard_absence_sha256"] != "")
            or value["wireguard_state"] == "absent" and (_HASH.fullmatch(value["wireguard_absence_sha256"]) is None or value["wireguard_receipt_sha256"] != "")):
        raise GuestError("Protocol callback intent is invalid")

    return value


def _ProtocolHistory(intent: dict[str, Any], request: dict[str, Any]) -> str:
    """Derive the original consumed history without resetting the retained v1 peer-audit chain."""

    if intent["wireguard_state"] == "absent":
        return str(intent["wireguard_history_sha256"])

    return _Digest(_Encode({"schema_version": 1, "owner": intent["owner"], "action": "revoke", "device_id": "protocol-" + intent["operation_id"],
        "previous_receipt_sha256": intent["wireguard_receipt_sha256"], "receipt_sha256": intent["wireguard_receipt_sha256"],
        "deployment_sha256": request["generation"]["cached_receipt"]["deployment_sha256"], "previous_history_sha256": intent["wireguard_history_sha256"]}))


def _GenerationAudit(intent: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Preplan the new generation's fence using its installed receipt, independently of activation success."""

    receipt = {**request["generation"]["candidate_receipt"], "status": "installed"}
    digest = _Digest(_Encode(receipt))

    return {"schema_version": 1, "owner": intent["owner"], "action": "revoke", "device_id": "protocol-" + intent["operation_id"],
            "previous_receipt_sha256": digest, "receipt_sha256": digest, "deployment_sha256": receipt["deployment_sha256"],
            "previous_history_sha256": _ProtocolHistory(intent, request)}


def _RuntimeRecord(value: object, intent: dict[str, Any]) -> dict[str, Any]:
    """Decode one exact native generation intent; a phase or cache receipt alone never grants a callback capability."""

    fields = {"schema_version", "intent", "request", "history_sha256", "admitted_program_sha256", "phase", "rollback"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or _Encode(_ProtocolIntent(value["intent"])) != _Encode(intent) or type(value["request"]) is not dict
            or set(value["request"]) != {"schema_version", "cloud_plan_sha256", "input", "generation"}
            or type(value["request"]["schema_version"]) is not int or value["request"]["schema_version"] != 2
            or type(value["request"]["cloud_plan_sha256"]) is not str or _HASH.fullmatch(value["request"]["cloud_plan_sha256"]) is None
            or _Digest(_Encode(value["request"])) != intent["plan_sha256"] or len(_Encode(value["request"])) > 32768
            or type(value["rollback"]) is not bool or type(value["phase"]) is not str):
        raise GuestError("Native generation journal differs from its complete reserved intent")

    generation = _GenerationRecord(value["request"]["generation"], intent)
    transition = value["request"]["input"]

    if (type(transition) is not dict or set(transition) != {"schema_version", "before", "listener", "change", "operation_id"}
            or type(transition["schema_version"]) is not int or transition["schema_version"] != 1
            or transition["change"] != generation["change"] or transition["operation_id"] != intent["operation_id"]
            or type(transition["listener"]) is not dict or transition["listener"].get("transport") != "wireguard"):
        raise GuestError("Native generation callback input scope differs from its complete request")
    phases = ({"ready", "publishing", "starting", "active", "restarting-active"} if generation["change"] == "enable"
              else {"ready", "removing-original", "stopping-original", "inactive"})

    if value["rollback"]:
        phases |= ({"removing-candidate", "stopping-candidate", "rolled-back"} if generation["change"] == "enable"
                   else {"publishing", "starting", "restored", "unchanged", "restarting-restored"})

    if (generation["schema_version"] != 3 or value["phase"] not in phases or value["history_sha256"] != _ProtocolHistory(intent, value["request"])
            or value["admitted_program_sha256"] != generation["candidate_receipt"]["files"]["lifecycle.py"]):
        raise GuestError("Native generation phase, restoration contract or original fence is invalid")

    return value


def _PeerAudit(owner: str) -> dict[str, Any] | None:
    """Share the unchanged closed v1 peer proof with standalone nonce-bound callbacks."""

    path = BASE / ("peer-" + owner + ".json")

    if not path.exists() and not path.is_symlink():
        return None

    content = _Read(path)
    value = _Json(content)

    if (not isinstance(value, dict) or set(value) != {"schema_version", "owner", "action", "device_id", "previous_receipt_sha256",
                                                    "receipt_sha256", "deployment_sha256", "previous_history_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["owner"] != owner
            or value["action"] not in {"enroll", "revoke"} or not isinstance(value["device_id"], str)
            or _NAME.fullmatch(value["device_id"]) is None or content != _Encode(value)):
        raise GuestError("WireGuard peer commit proof is invalid or noncanonical")

    for key in ("previous_receipt_sha256", "receipt_sha256", "deployment_sha256", "previous_history_sha256"):
        _RequireDigest(value[key])

    return value


def _PeerHistory(owner: str) -> str:
    """Preserve the historical audit/genesis bytes understood by every retained old peer driver."""

    audit = _PeerAudit(owner)

    return _Digest(_Encode(audit if audit is not None else {"domain": "f-layer/wireguard/peer-history/v1", "owner": owner}))


def _RuntimeContext(root: Path, unit: Path, nonce: str, *, start: bool) -> dict[str, Any] | None:
    """Admit only the exact sealed callback while the parent retains common coordination and releases the WG leaf lock."""

    authority = BASE.parent / "ingress"

    if not (authority / "pending.json").exists() and not (authority / "pending.json").is_symlink():
        return None

    _Directory(authority, private=True)

    if not (authority / "runtime.json").exists() or (authority / "runtime.json").is_symlink():
        raise GuestError("Pending protocol reservation has no sealed native generation authority")

    if any((authority / name).exists() or (authority / name).is_symlink() for name in
           (".pending.json.new", ".head.json.new", ".generation.json.new", ".runtime.json.new")):
        raise GuestError("Protocol callback requires complete canonical authority publications")

    def Record(name: str) -> dict[str, Any]:
        """Read bounded canonical public metadata, never loading a cached executable."""

        content = _Read(authority / name, limit=65536)
        value = _Json(content)

        if type(value) is not dict or content != _Encode(value):
            raise GuestError("Protocol callback metadata is not canonical")

        return value

    pending = Record("pending.json")
    intent = _ProtocolIntent(pending.get("intent"))
    record = _RuntimeRecord(Record("runtime.json"), intent)
    request = record["request"]
    headPath = authority / "head.json"
    head = Record("head.json") if headPath.exists() or headPath.is_symlink() else None
    initial = _Digest(_Encode({"domain": "f-layer/ingress/authority/v1", "owner": intent["owner"], "creation_sha256": intent["creation_sha256"]}))

    if head is not None:
        if (set(head) != {"name", "sha256"} or type(head["name"]) is not str or re.fullmatch(r"done-[0-9a-f]{32}\.json", head["name"]) is None
                or type(head["sha256"]) is not str or _HASH.fullmatch(head["sha256"]) is None
                or _Digest(_Encode(Record(head["name"]))) != head["sha256"]):
            raise GuestError("Protocol callback has invalid current common authority")

    candidate = request["generation"]["candidate_receipt"]
    generation = {"schema_version": 1, "intent_sha256": _Digest(_Encode(intent)), "request": request,
                  "history_sha256": record["history_sha256"], "phase": "prepared"}
    expected = {"schema_version": 1, "intent": intent, "parent": head,
                "deployment_sha256": request["generation"]["cached_receipt"]["deployment_sha256"] if intent["wireguard_state"] == "active" else "",
                "phase": "exposed", "fenced": intent["wireguard_state"] == "active"}

    if (_Encode(pending) != _Encode(expected) or intent["previous_authority_sha256"] != (head["sha256"] if head is not None else initial)
            or _Encode(Record("generation.json")) != _Encode(generation) or candidate["nonce"] != nonce
            or root != _Paths(intent["owner"])[0] or unit != _Paths(intent["owner"], nonce=nonce)[1]
            or _PeerAudit(intent["owner"]) != _GenerationAudit(intent, request)
            or record["phase"] not in ({"starting", "active", "restored", "restarting-active", "restarting-restored"} if start else {"removing-candidate"})):
        raise GuestError("Protocol callback does not match its exact generation, consumed history or native phase")

    receipt = _Receipt(root, unit, intent["owner"], staged=True)

    if receipt not in (candidate, {**candidate, "status": "installed"}):
        raise GuestError("Protocol callback root differs from its preplanned complete candidate")

    return record


def _WireGuardState(root: Path, request: dict[str, Any], *, partial: bool = False) -> None:
    """Compare live private/peer policy while ignoring only endpoints, counters and handshake times."""

    privateKey, publicKey, expected = _Config(_Read(root / "server.conf"), request, root / "wg")
    _, raw = _Run([str(root / "wg"), "show", _Interface(request["owner"]), "dump"])
    lines = raw.decode("ascii").strip().splitlines()

    if not lines:
        raise GuestError("WireGuard kernel state is unavailable")

    interface = lines[0].split("\t")

    if partial and interface == ["(none)", "(none)", "0", "off"] and len(lines) == 1:
        return

    if (len(interface) != 4 or interface[:2] != [privateKey, publicKey]
            or interface[2] not in ({"0", str(request["port"])} if partial else {str(request["port"])}) or interface[3] != "off"):
        raise GuestError("WireGuard live interface differs from owned policy")

    peers = {}

    for line in lines[1:]:
        fields = line.split("\t")

        if len(fields) != 8 or fields[0] in peers or fields[7] != "off":
            raise GuestError("WireGuard live peer state is invalid")

        peers[fields[0]] = fields[1], fields[3]

    if partial:
        if any(key not in expected or value[0] not in {"(none)", expected[key][0]}
               or value[1] not in {"(none)", expected[key][1]} for key, value in peers.items()):
            raise GuestError("Interrupted WireGuard interface has unknown peer policy")

    elif peers != expected:
        raise GuestError("WireGuard live peers differ from owned policy")


def _AddressState(owner: str, request: dict[str, Any], *, partial: bool = False) -> None:
    """Reject extra addresses before deleting an interface or reporting the tunnel healthy."""

    _, raw = _Run(["ip", "-j", "address", "show", "dev", _Interface(owner)])
    data = _Json(raw)
    network = ipaddress.IPv4Network(request["tunnel_cidr"])

    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict) or not isinstance(data[0].get("addr_info"), list):
        raise GuestError("WireGuard address observation is invalid")

    addresses = [(item.get("family"), item.get("local"), item.get("prefixlen")) for item in data[0]["addr_info"] if isinstance(item, dict)]
    expected = [("inet", str(network.network_address + 1), network.prefixlen)]

    if addresses != expected and not (partial and not addresses):
        raise GuestError("WireGuard interface has changed or unknown addresses")


def _NamespaceAvailable(
    owner: str, request: dict[str, Any], *, nonce: str = "0" * 32, networkSha256: str | None = None,
) -> None:
    """Refuse occupied interface/table/UDP/subnet intent before package builds or managed writes."""

    if _InterfaceState(owner) is not None:
        raise GuestError("WireGuard interface name is already occupied")

    if _NftState(owner, nonce) not in {None, networkSha256}:
        raise GuestError("WireGuard firewall table name is already occupied")

    _, raw = _Run(["ss", "-H", "-lnu"])

    for line in raw.decode("ascii").splitlines():
        columns = line.split()
        port = re.search(r":([0-9]{1,5})\Z", columns[3]) if len(columns) >= 5 else None

        if port is None:
            raise GuestError("UDP listener inventory is invalid")

        if int(port[1]) == request["port"]:
            raise GuestError("WireGuard UDP port is already occupied")

    _, raw = _Run(["ip", "-j", "-4", "route", "show", "table", "all"])
    data = _Json(raw)
    network = ipaddress.IPv4Network(request["tunnel_cidr"])

    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise GuestError("IPv4 route inventory is invalid")

    for route in data:
        destination = route.get("dst", "default")

        if destination == "default":
            continue

        observed = ipaddress.IPv4Network(destination, strict=False)

        if observed.prefixlen and network.overlaps(observed):
            raise GuestError("WireGuard tunnel overlaps an existing guest route")

    _, disabled = _Run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"])

    if disabled.strip() != b"1":
        raise GuestError("Guest IPv6 policy must be configured before WireGuard activation")


def _Check(root: Path, unit: Path, request: dict[str, Any], *, staged: bool = False) -> dict[str, Any]:
    """Verify the exact owned running service without downloads, repairs or restarts."""

    owner = request["owner"]
    receipt = _Receipt(root, unit, owner, staged=staged)

    if (unit != _Paths(owner, nonce=receipt["nonce"] if receipt["schema_version"] == 2 else "")[1]
            or _OwnedUnits(owner) - {unit, SYSTEMD / "multi-user.target.wants" / unit.name}):
        raise GuestError("WireGuard service namespace contains another generation or unknown unit")

    _EnabledLink(unit)

    if not (SYSTEMD / "multi-user.target.wants" / unit.name).is_symlink():
        raise GuestError("WireGuard service has no exact owned enablement link")

    if (receipt["files"]["server.conf"] != request["config_sha256"]
            or _Json(_Read(root / "deployment.json")) != request):
        raise GuestError("Prepared WireGuard configuration differs from the active receipt")

    _KernelMatches(receipt)
    _Run(["systemctl", "is-active", "--quiet", unit.name])
    _Run(["systemctl", "is-enabled", "--quiet", unit.name])
    state = _InterfaceState(owner)

    if (state is None or state.get("ifalias") != _Alias(owner, receipt["nonce"]) or state.get("mtu") != request["mtu"]
            or not isinstance(state.get("flags"), list) or "UP" not in state["flags"]):
        raise GuestError("WireGuard interface ownership, MTU or active state differs")

    _WireGuardState(root, request)
    _AddressState(owner, request)
    _LoadedSource(receipt["kernel"]["module_srcversion"], required=True)

    if _NftState(owner, receipt["nonce"]) != receipt["network_sha256"]:
        raise GuestError("WireGuard firewall differs from its owned policy")

    _, forwarding = _Run(["sysctl", "-n", "net.ipv4.ip_forward"])

    if forwarding.strip() != b"1":
        raise GuestError("IPv4 forwarding is inactive")

    return receipt


def _Start(root: Path, unit: Path, request: dict[str, Any]) -> None:
    """Activate only this receipt's interface/table, preserving other services and global forwarding users."""

    owner = request["owner"]
    receipt = _Receipt(root, unit, owner, staged=True)
    _KernelMatches(receipt)
    state = _InterfaceState(owner)
    networkState = _NftState(owner, receipt["nonce"])

    if networkState not in {None, receipt["network_sha256"]}:
        raise GuestError("Owned WireGuard table has drifted")

    if state is not None:
        if (state.get("ifalias") != _Alias(owner, receipt["nonce"]) or state.get("mtu") != request["mtu"]
                or not isinstance(state.get("flags"), list) or "UP" not in state["flags"]):
            raise GuestError("WireGuard interface ownership or active state differs")

        _WireGuardState(root, request)
        _AddressState(owner, request)
        _LoadedSource(receipt["kernel"]["module_srcversion"], required=True)

        if networkState != receipt["network_sha256"]:
            raise GuestError("Running WireGuard interface has incomplete firewall policy")

        return

    _NamespaceAvailable(owner, request, nonce=receipt["nonce"], networkSha256=receipt["network_sha256"])
    interface = _Interface(owner)
    _Run(["ip", "link", "add", "name", interface, "alias", _Alias(owner, receipt["nonce"]), "type", "wireguard"])
    # Creating the interface may load the kernel module; verify its executing source identity before activation.
    _KernelMatches(receipt)
    _LoadedSource(receipt["kernel"]["module_srcversion"], required=True)
    _Run([str(root / "wg"), "syncconf", interface, str(root / "server.conf")])
    network = ipaddress.IPv4Network(request["tunnel_cidr"])
    _Run(["ip", "address", "add", f"{network.network_address + 1}/{network.prefixlen}", "dev", interface])
    if networkState is None:
        _Run(["nft", "-f", str(root / "firewall.nft")])

    if _NftState(owner, receipt["nonce"]) != receipt["network_sha256"]:
        raise GuestError("WireGuard firewall did not match its staged policy before activation")

    _Run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])
    _Run(["ip", "link", "set", "dev", interface, "mtu", str(request["mtu"]), "up"])


def _Stop(root: Path, unit: Path, request: dict[str, Any], *, partial: bool = False, recovering: bool = False) -> None:
    """Validate all selected resources before deleting any; never reset shared forwarding or input policy."""

    owner = request["owner"]
    receipt = _Receipt(root, unit, owner, staged=partial or recovering)
    state = _InterfaceState(owner)
    networkState = _NftState(owner, receipt["nonce"])

    if networkState not in {None, receipt["network_sha256"]}:
        raise GuestError("WireGuard firewall has changed; cleanup is blocked")

    if state is not None:
        if state.get("ifalias") != _Alias(owner, receipt["nonce"]):
            raise GuestError("WireGuard interface has foreign ownership; cleanup is blocked")

        _WireGuardState(root, request, partial=partial)
        _AddressState(owner, request, partial=partial)

    if state is not None:
        _Run(["ip", "link", "delete", "dev", _Interface(owner)])

    if networkState is not None:
        _Run(["nft", "delete", "table", "ip", _Table(owner)])


def _ExpectedNetwork(path: Path, owner: str, nonce: str) -> str:
    """Compile the exact policy in an ephemeral network namespace before touching the guest namespace."""

    _, raw = _Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", str(path)])

    return _NftFingerprint(raw, owner, nonce)


def _EraseRoot(root: Path, receipt: dict[str, Any]) -> None:
    """Resume deletion of only journal-proved flat files, with no recursive or wildcard deletion."""

    active, _, transaction = _Paths(receipt["owner"])

    if root not in {active, transaction / "new"} or root.is_symlink():
        raise GuestError("WireGuard cleanup path is outside its exact ownership boundary")

    _Directory(root, private=True)
    names = {path.name for path in root.iterdir()}

    _ReceiptData(receipt, receipt["owner"], staged=True)

    if not names <= set(receipt["files"]) | {"receipt.json"}:
        raise GuestError("WireGuard cleanup found unknown files")

    for name in names - {"receipt.json"}:
        if _Digest(_Read(root / name, limit=8 * 1024 * 1024 if name == "wg" else 1048576,
                         mode=0o755 if name == "wg" else 0o600)) != receipt["files"][name]:
            raise GuestError("WireGuard cleanup found changed files")

    if "receipt.json" in names and _Read(root / "receipt.json") != _Encode(receipt):
        raise GuestError("WireGuard cleanup receipt changed")

    for name in (*sorted(names - {"receipt.json"}), "receipt.json"):
        if name in names:
            (root / name).unlink()

    _SyncDirectory(root)
    root.rmdir()
    _SyncDirectory(root.parent)


def _EnabledLink(unit: Path) -> None:
    """Refuse a foreign enablement link before asking systemd to change this service."""

    parent = SYSTEMD / "multi-user.target.wants"

    if not parent.exists() and not parent.is_symlink():
        return

    _Directory(parent)
    link = parent / unit.name

    if link.exists() or link.is_symlink():
        info = link.lstat()
        valid = False

        try:
            valid = stat.S_ISLNK(info.st_mode) and info.st_uid == _ROOT_UID and link.resolve(strict=True) == unit.resolve(strict=True)

        except (OSError, RuntimeError):
            pass

        if not valid:
            raise GuestError("WireGuard enablement link has foreign ownership")


def _Transaction(owner: str) -> tuple[dict[str, Any], Path]:
    """Load one complete pre-published recovery journal without accepting unknown state."""

    _, _, path = _Paths(owner)
    _Directory(path, private=True)
    names = {item.name for item in path.iterdir()}

    if names not in ({"transaction.json"}, {"transaction.json", "new"}):
        raise GuestError("WireGuard transaction has changed or unknown files")

    data = _Json(_Read(path / "transaction.json"))

    if (not isinstance(data, dict) or set(data) != {"schema_version", "owner", "phase", "receipt"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["owner"] != owner
            or data["phase"] not in {"prepared", "cleanup"}):
        raise GuestError("WireGuard recovery journal is invalid")

    _ReceiptData(data["receipt"], owner, staged=True)

    return data, path


def _ClearTransaction(owner: str) -> None:
    """Remove only an empty completed journal directory after its published state is verified."""

    _, path = _Transaction(owner)

    if {item.name for item in path.iterdir()} != {"transaction.json"}:
        raise GuestError("WireGuard staged files remain in the transaction")

    # A resumed cleanup may observe an already-unlinked unit/root whose parent fsync was interrupted.
    # Persist the complete current namespace before irreversibly retiring its only recovery record.
    for parent in (SYSTEMD, BASE, path):
        _Directory(parent)
        _SyncDirectory(parent)

    (path / "transaction.json").unlink()
    _SyncDirectory(path)
    path.rmdir()
    _SyncDirectory(path.parent)


def _BuildPayload(
    stage: Path, request: dict[str, Any], root: Path, work: Path, kernel: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Build and validate private runtime bytes; the caller supplies verified vendor/kernel evidence and owns publication."""

    owner = request["owner"]
    buildFacts = _BuildFacts()
    binary, licenseText = _BuildTools(work)

    if _BuildFacts() != buildFacts:
        raise GuestError("WireGuard toolchain changed during the private build")

    tool = work / "wg"
    tool.write_bytes(binary)
    tool.chmod(0o755)
    _Config(_Read(stage / "server.conf"), request, tool)
    nonce = os.urandom(16).hex()
    firewall = _Firewall(request, nonce)
    policy = work / "firewall.nft"
    policy.write_bytes(firewall)
    policy.chmod(0o600)
    network = _ExpectedNetwork(policy, owner, nonce)
    payload = {name: _Read(stage / name) for name in ("server.conf", "deployment.json", "install.py")}
    payload.update({"wg": binary, "COPYING": licenseText, "firewall.nft": firewall, "service.service": _Unit(root, owner)})
    receipt: dict[str, Any] = {"schema_version": 1, "owner": owner, "nonce": nonce, "status": "staged",
                             "files": {name: _Digest(content) for name, content in payload.items()},
                             "network_sha256": network, "kernel": kernel, "build": buildFacts,
                             "deployment_sha256": _Digest(payload["deployment.json"])}

    return receipt, payload


def _PrepareRoot(stage: Path, request: dict[str, Any], root: Path, unit: Path) -> tuple[dict[str, Any], Path]:
    """Stage a complete verified binary/configuration/policy before publishing any service or interface."""

    owner = request["owner"]
    facts = _KernelFacts()
    evidence = _VendorEvidence(_Fetch(KERNEL_CVE_URL, 1048576), facts["package_version"])
    _NamespaceAvailable(owner, request)
    _EnabledLink(unit)

    for directory in (BASE.parent.parent, BASE.parent, BASE):
        _Directory(directory, create=True)

    _Directory(SYSTEMD)

    with tempfile.TemporaryDirectory(prefix=".wg-build-", dir=BASE) as temporary:
        work = Path(temporary)
        os.chmod(work, 0o700)
        receipt, payload = _BuildPayload(stage, request, root, work, {**facts, **evidence})
        _, _, transaction = _Paths(owner)

        if transaction.exists() or transaction.is_symlink():
            raise GuestError("An unresolved WireGuard transaction already exists")

        container = work / "transaction"
        container.mkdir(mode=0o700)
        staged = container / "new"
        staged.mkdir(mode=0o700)

        for name, content in payload.items():
            _Atomic(staged / name, content, 0o755 if name == "wg" else 0o600)

        _Atomic(staged / "receipt.json", _Encode(receipt))
        _Receipt(staged, unit, owner, staged=True)
        _Atomic(container / "transaction.json", _Encode({"schema_version": 1, "owner": owner,
                "phase": "prepared", "receipt": receipt}))
        # Publish the journal and every staged file together; no incomplete journal is observable.
        _Publish(container, transaction)

    return receipt, transaction


def _RequireDigest(value: str) -> None:
    """Reject ambiguous mutation consent before any external command or managed write."""

    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise GuestError("WireGuard mutation requires an exact previous receipt digest")


def _AbsenceDigest(owner: str) -> str:
    """Bind explicit empty-namespace recovery to its full owner without inventing a previous receipt."""

    _Paths(owner)

    return _Digest(_Encode({"domain": "f-layer/wireguard/absent/v1", "owner": owner}))


def _RequireAbsent(owner: str) -> None:
    """Prove the complete selected live namespace absent before touching only empty recovery metadata."""

    root, unit, _ = _Paths(owner)

    if any(path.is_symlink() for path in (BASE, *BASE.parents)):
        raise GuestError("WireGuard managed namespace has symbolic ancestry")

    if BASE.exists():
        _Directory(BASE)

    if (root.exists() or root.is_symlink() or _OwnedUnits(owner)
            or _InterfaceState(owner) is not None or _NftState(owner, "0" * 32) is not None):
        raise GuestError("WireGuard namespace is not completely absent")

    _EnabledLink(unit)

    if (SYSTEMD / "multi-user.target.wants" / unit.name).is_symlink():
        raise GuestError("WireGuard absent namespace retains an enablement link")


def _Recover(owner: str, expectedReceipt: str, *, expectedAbsence: str = "") -> None:
    """Roll an interrupted fresh installation back to absence using only proved owned state."""

    root, unit, transaction = _ActivePaths(owner)

    if expectedAbsence:
        if expectedReceipt or expectedAbsence != _AbsenceDigest(owner):
            raise GuestError("WireGuard absence recovery requires the exact observed namespace proof")

        _RequireAbsent(owner)

        if transaction.exists() or transaction.is_symlink():
            _Directory(transaction, private=True)

            if tuple(transaction.iterdir()):
                raise GuestError("WireGuard absence recovery cannot erase a nonempty journal")

            _SyncDirectory(SYSTEMD)
            _SyncDirectory(BASE)
            transaction.rmdir()
            _SyncDirectory(BASE)

        return

    _RequireDigest(expectedReceipt)

    if not transaction.exists() and not transaction.is_symlink():
        raise GuestError("No WireGuard recovery journal exists")

    _Directory(transaction, private=True)

    if not tuple(transaction.iterdir()):
        if root.exists() or root.is_symlink():
            receipt = _Receipt(root, unit, owner)

            if receipt["schema_version"] == 2:
                raise GuestError("Protocol generation recovery requires the protocol coordinator")

            if _Digest(_Read(root / "receipt.json")) != expectedReceipt:
                raise GuestError("WireGuard receipt changed before recovery")

            request, _, _ = _Request(root)
            _Check(root, unit, request)
            _SyncDirectory(root)

        elif (_OwnedUnits(owner) or _InterfaceState(owner) is not None
              or _NftState(owner, "0" * 32) is not None):
            raise GuestError("Empty WireGuard journal has unexpected remaining resources")

        transaction.rmdir()
        _SyncDirectory(transaction.parent)

        return

    journal, transaction = _Transaction(owner)

    if journal["receipt"]["schema_version"] == 2:
        raise GuestError("Protocol generation recovery requires the protocol coordinator")

    staged = transaction / "new"

    if (root.exists() or root.is_symlink()) and (staged.exists() or staged.is_symlink()):
        raise GuestError("WireGuard recovery found two candidate roots")

    selected = root if root.exists() or root.is_symlink() else staged
    recorded = journal["receipt"]
    permitted = {_Digest(_Encode({**recorded, "status": status})) for status in ("staged", "installed")}

    if expectedReceipt not in permitted:
        raise GuestError("WireGuard recovery receipt or operation identity changed")

    if journal["phase"] == "cleanup":
        if (unit.exists() or unit.is_symlink() or _InterfaceState(owner) is not None
                or _NftState(owner, recorded["nonce"]) is not None):
            raise GuestError("WireGuard cleanup journal has unexpected live resources")

        _EnabledLink(unit)

        if (SYSTEMD / "multi-user.target.wants" / unit.name).is_symlink():
            raise GuestError("WireGuard cleanup still has an enablement link")

        if selected.exists() or selected.is_symlink():
            _EraseRoot(selected, recorded)

        _ClearTransaction(owner)

        return

    receipt = _Receipt(selected, unit, owner, staged=True)
    digest = _Digest(_Read(selected / "receipt.json"))

    if digest != expectedReceipt or {**receipt, "status": "staged"} != {**recorded, "status": "staged"}:
        raise GuestError("WireGuard recovery found a changed receipt")

    request, _, _ = _Request(selected)

    if recorded["status"] == "staged" and receipt["status"] == "installed":
        _Check(root, unit, request)
        _SyncDirectory(root)
        _ClearTransaction(owner)

        return

    _EnabledLink(unit)

    if selected == root:
        # Validate all live objects before systemd can invoke the owned stop entrypoint.
        state = _InterfaceState(owner)
        network = _NftState(owner, receipt["nonce"])

        if network not in {None, receipt["network_sha256"]}:
            raise GuestError("WireGuard recovery found drifted firewall state")

        if state is not None:
            if state.get("ifalias") != _Alias(owner, receipt["nonce"]):
                raise GuestError("WireGuard recovery found a foreign interface")

            _WireGuardState(root, request, partial=receipt["status"] == "staged")
            _AddressState(owner, request, partial=receipt["status"] == "staged")

        if unit.exists() or unit.is_symlink():
            _Run(["systemctl", "stop", unit.name])

        _Stop(root, unit, request, partial=receipt["status"] == "staged", recovering=True)

    elif _InterfaceState(owner) is not None or _NftState(owner, receipt["nonce"]) is not None:
        raise GuestError("Unpublished WireGuard stage has unexpected live resources")

    if unit.exists() or unit.is_symlink():
        _Run(["systemctl", "disable", unit.name])
        wants = SYSTEMD / "multi-user.target.wants"

        if wants.exists():
            _Directory(wants)
            _SyncDirectory(wants)

        if _Read(unit, mode=0o644) != _Read(selected / "service.service"):
            raise GuestError("WireGuard unit changed before cleanup")

        unit.unlink()
        _SyncDirectory(SYSTEMD)
        _Run(["systemctl", "daemon-reload"])

    _Atomic(transaction / "transaction.json", _Encode({**journal, "phase": "cleanup", "receipt": receipt}))
    _EraseRoot(selected, receipt)
    _ClearTransaction(owner)


def _Remove(owner: str, expectedReceipt: str) -> None:
    """Journal one explicitly consented removal without touching another transport's resources."""

    _RequireDigest(expectedReceipt)
    root, unit, transaction = _ActivePaths(owner)

    if transaction.exists() or transaction.is_symlink():
        raise GuestError("WireGuard recovery is required before removal")

    receipt = _Receipt(root, unit, owner)

    if receipt["schema_version"] == 2:
        raise GuestError("Protocol generation removal requires the protocol coordinator")

    if _Digest(_Read(root / "receipt.json")) != expectedReceipt:
        raise GuestError("WireGuard receipt changed before removal")

    # Publish the intent atomically before invoking systemd or deleting a single live object.
    with tempfile.TemporaryDirectory(prefix=".wg-remove-", dir=BASE) as temporary:
        container = Path(temporary) / "transaction"
        container.mkdir(mode=0o700)
        _Atomic(container / "transaction.json", _Encode({"schema_version": 1, "owner": owner,
                "phase": "prepared", "receipt": receipt}))
        _Publish(container, transaction)

    _Recover(owner, expectedReceipt)


def _Install(stage: Path, request: dict[str, Any]) -> None:
    """Install only an absent namespace or verify an identical healthy deployment without restart."""

    owner = request["owner"]
    root, unit, transaction = _ActivePaths(owner)

    if transaction.exists() or transaction.is_symlink():
        raise GuestError("WireGuard recovery is required before another installation")

    if root.exists() or root.is_symlink():
        receipt = _Receipt(root, unit, owner)

        if (receipt["files"]["deployment.json"] != _Digest(_Read(stage / "deployment.json"))
                or receipt["files"]["install.py"] != _Digest(_Read(stage / "install.py"))):
            raise GuestError("WireGuard replacement requires an explicit expected-receipt transition")

        _Check(root, unit, request)

        return

    if _OwnedUnits(owner):
        raise GuestError("WireGuard unit name is already occupied")

    receipt, transaction = _PrepareRoot(stage, request, root, unit)
    expected = _Digest(_Encode(receipt))

    try:
        _Publish(transaction / "new", root)
        _Atomic(unit, _Read(root / "service.service"), 0o644)
        _EnabledLink(unit)
        _Run(["systemctl", "daemon-reload"])
        _Run(["systemctl", "enable", unit.name])
        _EnabledLink(unit)
        _SyncDirectory(SYSTEMD / "multi-user.target.wants")
        _SyncDirectory(SYSTEMD)
        _Start(root, unit, request)
        _Run(["systemctl", "start", unit.name])
        _Check(root, unit, request, staged=True)
        installed = {**receipt, "status": "installed"}
        _Atomic(root / "receipt.json", _Encode(installed))
    except Exception:
        if root.exists() and not root.is_symlink():
            expected = _Digest(_Read(root / "receipt.json"))

        try:
            _Recover(owner, expected)

        except Exception:
            raise GuestError("WireGuard installation interrupted; explicit receipt-bound recovery is required") from None

        if root.exists():
            # Recovery re-established and durably committed the healthy installation after publication.
            return

        raise GuestError("WireGuard installation failed and its owned changes were rolled back") from None

    # A cleanup failure after commit is recoverable metadata, never an unrequested rollback of a healthy service.
    _ClearTransaction(owner)


def _Status(stage: Path, request: dict[str, Any]) -> dict[str, object]:
    """Return bounded nonsecret runtime facts while retaining exact recovery consent hashes."""

    owner = request["owner"]
    root, unit, transaction = _ActivePaths(owner)

    if transaction.exists() or transaction.is_symlink():
        _Directory(transaction, private=True)

        if not tuple(transaction.iterdir()):
            if root.exists() or root.is_symlink():
                _Check(root, unit, request)

                return {"status": "recovery-required", "receipt_sha256": _Digest(_Read(root / "receipt.json")),
                        "tools_version": TOOLS_VERSION, "kernel_policy": "cached-named-cve-baseline"}

            if (_OwnedUnits(owner) or _InterfaceState(owner) is not None
                    or _NftState(owner, "0" * 32) is not None):
                raise GuestError("Empty WireGuard journal has unexpected remaining resources")

            _RequireAbsent(owner)

            return {"status": "absent", "receipt_sha256": "", "absence_sha256": _AbsenceDigest(owner), "tools_version": TOOLS_VERSION,
                    "kernel_policy": "not-assessed", "cleanup_required": True}

        journal, _ = _Transaction(owner)
        candidate = root if root.exists() or root.is_symlink() else transaction / "new"
        receipt = journal["receipt"]
        digest = _Digest(_Encode(receipt))

        if (candidate / "receipt.json").exists():
            _Directory(candidate, private=True)
            raw = _Read(candidate / "receipt.json")
            observed = _ReceiptData(_Json(raw), owner, staged=True)

            if {**observed, "status": "staged"} != {**receipt, "status": "staged"}:
                raise GuestError("WireGuard recovery status found a changed receipt")

            digest = _Digest(raw)

        return {"status": "recovery-required", "receipt_sha256": digest,
                "tools_version": TOOLS_VERSION, "kernel_policy": "cached-named-cve-baseline"}

    if not root.exists() and not root.is_symlink():
        _RequireAbsent(owner)

        return {"status": "absent", "receipt_sha256": "", "absence_sha256": _AbsenceDigest(owner),
                "tools_version": TOOLS_VERSION, "kernel_policy": "not-assessed", "cleanup_required": False}

    receipt = _Check(root, unit, request)

    if _Read(stage / "deployment.json") != _Read(root / "deployment.json"):
        raise GuestError("Prepared WireGuard descriptor differs from the active receipt")

    return {"status": "active", "receipt_sha256": _Digest(_Read(root / "receipt.json")),
            "tools_version": TOOLS_VERSION, "binary_sha256": receipt["files"]["wg"],
            "kernel_release": receipt["kernel"]["release"],
            "kernel_package_version": receipt["kernel"]["package_version"],
            "kernel_policy": "cached-named-cve-baseline", "kernel_cve": KERNEL_CVE,
            "kernel_fixed_version": receipt["kernel"]["fixed_version"]}


def _OpenLock(*, readOnly: bool) -> int:
    """Validate the runtime coordination file, including recreation by an authorized service boot callback."""

    _Directory(LOCK.parent)
    descriptor = os.open(LOCK, (os.O_RDONLY if readOnly else os.O_RDWR | os.O_CREAT) | os.O_NOFOLLOW, 0o600)

    try:
        info = os.fstat(descriptor)

        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _ROOT_UID or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise GuestError("WireGuard operation lock is not a private owned regular file")

    except BaseException:
        os.close(descriptor)

        raise

    return descriptor


def _ProtocolGate() -> None:
    """Under WG coordination, refuse a common protocol reservation before ordinary maintenance; service callbacks stay separate."""

    root = BASE.parent / "ingress"

    if root.exists() or root.is_symlink():
        _Directory(root, private=True)

        if any((root / name).exists() or (root / name).is_symlink() for name in ("pending.json", ".pending.json.new", ".head.json.new")):
            raise GuestError("Pending protocol reservation requires explicit protocol recovery before WireGuard maintenance")


def _GenerationCallback(root: Path, unit: Path, nonce: str, *, start: bool) -> None:
    """Serialize a nonce-bound leaf callback with WG mutations; native children retain its protecting descriptor."""

    global _callbackFds

    import fcntl

    _Nonce(nonce)
    descriptor = _OpenLock(readOnly=False)

    try:
        # A protocol parent retains common coordination but releases WG for the leaf callback.
        # Its complete sealed journal must authorize this exact nonce and consumed history.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        protocol = _RuntimeContext(root, unit, nonce, start=start)

        if protocol is None:
            _ProtocolGate()
        request = _Request(root)[0]
        owner = request["owner"]
        installed, expectedUnit, transaction = _ActivePaths(owner)

        if root != installed or unit != expectedUnit or Path(__file__).absolute() != root / "lifecycle.py":
            raise GuestError("Generation callback requires the exact installed lifecycle executable")

        receipt = _Receipt(root, unit, owner, staged=transaction.exists() or protocol is not None)

        if receipt["schema_version"] != 2 or receipt["nonce"] != nonce or _callbackFds:
            raise GuestError("Generation callback is stale or has unsupported authority")

        if receipt["status"] == "staged" and protocol is None:
            journal, _ = _Transaction(owner)

            if journal["phase"] != "prepared" or journal["receipt"] != receipt:
                raise GuestError("Provisional generation has no exact prepared journal")

        _callbackFds = (descriptor,)

        if start:
            _Start(root, unit, request)

        else:
            _Stop(root, unit, request, partial=receipt["status"] == "staged")

    finally:
        _callbackFds = ()
        os.close(descriptor)


def Main(argv: list[str] | None = None) -> int:
    """Require exact owned inputs and explicit mutation consent before running privileged operations."""

    parser = argparse.ArgumentParser(description="Manage one owned F-Layer kernel WireGuard service")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check", action="store_true")
    action.add_argument("--status", action="store_true")
    action.add_argument("--remove", action="store_true")
    action.add_argument("--recover", action="store_true")
    action.add_argument("--start", action="store_true")
    action.add_argument("--stop", action="store_true")
    parser.add_argument("--allow-mutation", action="store_true", dest="allowMutation")
    parser.add_argument("--expected-receipt-sha256", default="", dest="expectedReceipt")
    parser.add_argument("--expected-absence-sha256", default="", dest="expectedAbsence")
    parser.add_argument("--expected-generation-nonce", default="", dest="expectedGeneration")
    arguments = parser.parse_args(argv)
    result: dict[str, object] | None = None

    try:
        if os.name != "posix" or os.geteuid() != _ROOT_UID:
            raise GuestError("WireGuard operations require root on the selected Linux guest")

        import fcntl

        stage = Path(__file__).absolute().parent
        request, _, _ = _Request(stage)
        owner = request["owner"]
        root, unit, transaction = _ActivePaths(owner)
        readOnly = arguments.check or arguments.status

        if arguments.expectedGeneration and not (arguments.start or arguments.stop):
            raise GuestError("Generation nonce is valid only for an owned service callback")

        if readOnly and (arguments.allowMutation or arguments.expectedReceipt or arguments.expectedAbsence):
            raise GuestError("WireGuard read-only actions do not accept mutation options")

        if not readOnly and not arguments.allowMutation:
            raise GuestError("WireGuard mutation requires explicit --allow-mutation")

        if arguments.expectedAbsence:
            if not arguments.recover or arguments.expectedReceipt or arguments.expectedAbsence != _AbsenceDigest(owner):
                raise GuestError("WireGuard absence consent requires explicit recovery and the exact namespace proof")

        elif arguments.remove or arguments.recover:
            _RequireDigest(arguments.expectedReceipt)

        elif arguments.expectedReceipt:
            raise GuestError("WireGuard receipt consent requires explicit removal or recovery")

        if arguments.start or arguments.stop:
            # systemd invokes these beneath the controller's lock, or during guest boot/shutdown.
            # Bind them to the installed executable and unit instead of accepting a supplied stage.
            if stage != root or not unit.exists():
                raise GuestError("WireGuard service actions require the exact installed root and unit")

            if arguments.expectedGeneration:
                _GenerationCallback(root, unit, arguments.expectedGeneration, start=arguments.start)

                return 0

            receipt = _Receipt(root, unit, owner, staged=transaction.exists())

            if receipt["schema_version"] != 1 or Path(__file__).absolute() != root / "install.py":
                raise GuestError("Protocol generation service requires its exact nonce-bound lifecycle callback")

            if receipt["status"] == "staged":
                journal, _ = _Transaction(owner)

                if journal["phase"] != "prepared" or journal["receipt"] != receipt:
                    raise GuestError("WireGuard provisional service has no matching installation journal")

            # Service callbacks may follow a reboot that cleared /run; every mutator establishes coordination first.
            os.close(_OpenLock(readOnly=False))

            if arguments.start:
                _Start(root, unit, request)

            else:
                _Stop(root, unit, request, partial=receipt["status"] == "staged")

            return 0

        descriptor: int | None

        try:
            descriptor = _OpenLock(readOnly=readOnly)

        except FileNotFoundError:
            if not readOnly or LOCK.exists() or LOCK.is_symlink():
                raise

            # A crash/reboot can clear /run before the first unit is installed.
            # Read-only status must still obtain recovery consent without creating metadata.
            descriptor = None

        try:
            if descriptor is not None:
                fcntl.flock(descriptor, (fcntl.LOCK_SH if readOnly else fcntl.LOCK_EX) | fcntl.LOCK_NB)

            _ProtocolGate()

            if arguments.remove:
                _Remove(owner, arguments.expectedReceipt)

            elif arguments.recover:
                _Recover(owner, arguments.expectedReceipt, expectedAbsence=arguments.expectedAbsence)

            elif arguments.check:
                if transaction.exists() or transaction.is_symlink():
                    raise GuestError("WireGuard recovery is required before health checks")

                _Check(root, unit, request)

            elif arguments.status:
                result = _Status(stage, request)

            else:
                _Install(stage, request)

            if descriptor is None and (LOCK.exists() or LOCK.is_symlink()):
                # Every mutator creates this file before its first write and never removes it.
                raise GuestError("WireGuard operation started during observation; retry read-only status")

        finally:
            if descriptor is not None:
                os.close(descriptor)

    except GuestError as error:
        print("WireGuard guest operation failed: " + str(error), file=sys.stderr)

        return 1

    except (OSError, ValueError, KeyError, TypeError, RecursionError, tarfile.TarError):
        print("WireGuard guest operation failed; verify owned state, kernel policy and pinned tools.", file=sys.stderr)

        return 1

    print(json.dumps(result, sort_keys=True) if result is not None else
          "WireGuard guest operation completed; client connectivity was not tested.")

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
