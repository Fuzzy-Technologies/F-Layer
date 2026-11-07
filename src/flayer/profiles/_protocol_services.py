"""Measure retained AWG/VLESS services through pinned ownership and existing locks, without executing supplied installers."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import os
import re
import stat
import struct
import tempfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any, cast

AWG_BASE = Path("/etc/flayer")
AWG_LOCKS = Path("/run/lock")
SYSTEMD = Path("/etc/systemd/system")
PROC = Path("/proc")
_AWG_FILES = {"install.sh", "server.conf", "firewall.nft", "network.sh", "service.service"}
_VLESS_FILES = {"install.py", "server.json", "deployment.json"}
_INTERFACE = {"PrivateKey", "ListenPort", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
              "HeaderProtectionKey", "ContentPaddingAddition", "RandomTrailers"}
_OPTIONAL_INTERFACE = {"DisableCookies"}


class ServiceError(ValueError):
    """A fixed service-attestation diagnostic without private configuration, paths or native output."""


def _Stamp(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Keep inode and modification identity while excluding ordinary access times."""

    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def CredentialAccess(mode: int, owner: int, processUid: int, rootUid: int, acl: bytes | None) -> bool:
    """Accept systemd's owner-only fallback or its exact root-owned ACL granting only the selected dynamic UID read access."""

    if any(type(value) is not int for value in (mode, owner, processUid, rootUid)) or any(not 0 <= value < 0xFFFFFFFF for value in (owner, processUid, rootUid)):
        return False

    if mode == 0o400 and owner in {rootUid, processUid} and acl is None:
        return True

    if mode != 0o440 or owner != rootUid or processUid == rootUid or type(acl) is not bytes or len(acl) != 44:
        return False

    if struct.unpack_from("<I", acl)[0] != 2:
        return False

    entries = {(tag, identity): permissions for tag, permissions, identity in struct.iter_unpack("<HHI", acl[4:])}
    expected = {(1, 0xFFFFFFFF): 4, (2, processUid): 4, (4, 0xFFFFFFFF): 0, (16, 0xFFFFFFFF): 4, (32, 0xFFFFFFFF): 0}

    return len(entries) == 5 and entries == expected


def Configuration(guest: Any, content: bytes, *, observed: bool = False) -> dict[str, Any]:
    """Normalize pinned AWG showconf syntax, ignoring only learned peer endpoints and preserving every configuration-affecting value."""

    result = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= 1048576 or type(observed) is not bool:
            raise ValueError

        interface: dict[str, str] = {}
        peers: list[dict[str, str]] = []
        current: dict[str, str] | None = None

        for line in content.decode("ascii").splitlines():
            line = line.strip()

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
                raise ValueError

            name, value = (part.strip() for part in line.split("=", 1))

            if name in current or not value or len(value) > 256:
                raise ValueError

            current[name] = value

        if (set(interface) - _INTERFACE - (_OPTIONAL_INTERFACE if observed else set()) or not _INTERFACE <= set(interface)
                or not 1 <= len(peers) <= 256 or not interface["ListenPort"].isdecimal() or not 1 <= int(interface["ListenPort"]) <= 65535):
            raise ValueError

        for key in ("PrivateKey", "HeaderProtectionKey"):
            guest._Key(interface[key])

        if interface["RandomTrailers"] not in {"on", "off"} or "DisableCookies" in interface and interface["DisableCookies"] not in {"on", "off"}:
            raise ValueError

        for name in set(interface) - {"PrivateKey", "HeaderProtectionKey", "RandomTrailers", "DisableCookies"}:
            value = interface[name]

            if re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", value) is None:
                raise ValueError

            low, _, high = value.partition("-")
            maximum = 4294967295 if name in {"H1", "H2", "H3", "H4"} else 65535

            if not 0 <= int(low) <= int(high or low) <= maximum:
                raise ValueError

            interface[name] = str(int(low)) + ("-" + str(int(high)) if high and int(high) != int(low) else "")

        resultPeers = {}

        for peer in peers:
            if set(peer) - {"PublicKey", "AllowedIPs"} - ({"Endpoint"} if observed else set()) or not {"PublicKey", "AllowedIPs"} <= set(peer):
                raise ValueError

            key = guest._Key(peer["PublicKey"])
            address = ipaddress.IPv4Network(peer["AllowedIPs"], strict=True)

            if address.prefixlen != 32 or key in resultPeers:
                raise ValueError

            if "Endpoint" in peer and re.fullmatch(r"(?:[0-9.]+|\[[0-9a-fA-F:]+\]):[0-9]{1,5}", peer["Endpoint"]) is None:
                raise ValueError

            resultPeers[key] = {name: value for name, value in peer.items() if name != "Endpoint"}

        if interface.get("DisableCookies", "off") != "off":
            raise ValueError

        interface["DisableCookies"] = "off"
        result = {"interface": interface, "peers": {name: resultPeers[name] for name in sorted(resultPeers)}}

    except (ValueError, KeyError, TypeError, UnicodeError):
        pass

    if result is None:
        raise ServiceError("AWG service configuration observation is malformed or unsupported")

    return result


def MatchConfiguration(guest: Any, expected: bytes, observed: bytes) -> dict[str, Any]:
    """Compare retained private roles and public peer policy without including raw values in any diagnostic or public record."""

    desired = Configuration(guest, expected)
    actual = Configuration(guest, observed, observed=True)

    if (any(actual["interface"].get(key) != value for key, value in desired["interface"].items())
            or set(actual["peers"]) != set(desired["peers"])
            or any(any(actual["peers"][key].get(name) != value for name, value in peer.items()) for key, peer in desired["peers"].items())):
        raise ServiceError("AWG live credentials or peer policy differ from the retained source")

    return actual


def _Fingerprint(guest: Any, content: bytes, table: str) -> str:
    """Hash the complete owned nft table while excluding only native handles and metainfo; counters are outside the retained layout."""

    data = guest._Json(content)

    if type(data) is not dict or set(data) != {"nftables"} or type(data["nftables"]) is not list or not data["nftables"]:
        raise ServiceError("AWG forwarding observation is incomplete")

    tables: list[dict[str, Any]] = []
    chains: dict[str, dict[str, Any]] = {}
    rules: dict[str, list[dict[str, Any]]] = {}
    sets: list[dict[str, Any]] = []

    for item in data["nftables"]:
        if type(item) is not dict or len(item) != 1:
            raise ServiceError("AWG forwarding observation is malformed")

        if "metainfo" in item:
            continue

        if "add" in item:
            item = item["add"]

        if type(item) is not dict or len(item) != 1:
            raise ServiceError("AWG forwarding notification is malformed")

        kind, value = next(iter(item.items()))

        if (kind not in {"table", "chain", "rule", "set", "element"} or type(value) is not dict or value.get("family") != "ip"
                or value.get("name" if kind == "table" else "table") != table or b'"counter"' in guest._Encode(value)):
            raise ServiceError("AWG forwarding observation includes unexplained native state")

        value = {key: field for key, field in value.items() if key != "handle"}

        if kind == "table":
            tables.append(value)

        elif kind == "chain":
            if value.get("name") not in {"forward", "postrouting"} or value["name"] in chains:
                raise ServiceError("AWG forwarding has an unexplained or duplicate chain")

            chains[value["name"]] = value

        elif kind == "rule":
            if value.get("chain") not in {"forward", "postrouting"}:
                raise ServiceError("AWG forwarding has an unexplained rule chain")

            rules.setdefault(value["chain"], []).append(value)

        else:
            sets.append({kind: value})

    if len(tables) != 1 or set(chains) != {"forward", "postrouting"} or set(rules) != set(chains):
        raise ServiceError("AWG forwarding observation does not identify its complete retained chains")

    return cast(str, guest._Digest(guest._Encode({"table": tables[0], "chains": chains, "rules": rules, "sets": sets})))


def _Compiled(guest: Any, source: bytes, table: str) -> str:
    """Compile retained forwarding only in a fresh transient network namespace, never in the host's active ruleset."""

    guest._Directory(guest.LOCK.parent)

    with tempfile.TemporaryDirectory(prefix=".flayer-service-", dir=guest.LOCK.parent) as directory:
        path = Path(directory) / "firewall.nft"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)

        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source)

        _, content = guest._Run(["unshare", "--net", "--", "nft", "-j", "-e", "-f", str(path)])

        return _Fingerprint(guest, content, table)


def _UnitNames(path: Path, prefix: str) -> set[str]:
    """Bound complete namespace enumeration while reading no unexpected entry's contents."""

    names = set()

    with os.scandir(path) as entries:
        for count, entry in enumerate(entries):
            if count >= 4096:
                raise ServiceError("Unrelated service unit namespace exceeds its bounded observation capacity")

            if entry.name.startswith(prefix):
                names.add(entry.name)

    return names


class ServiceObserver:
    """Hold existing non-target locks and immutable file descriptors while measuring actual source-bound service facts."""

    def __init__(
        self, guest: Any, authority: Any, completion: Any, runtime: Any, vless: Any,
        identity: dict[str, str], sources: object, bundles: object,
    ) -> None:
        """Bind complete retained server bytes before filesystem access; supplied installers are data and are never executed."""

        self.guest, self.runtime, self.vless = guest, runtime, vless
        self.sources = json.loads(guest._Encode(completion._Sources(guest, authority, identity, sources)))
        self.owner = guest._Digest(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())
        self.vlessOwner = guest._Digest((json.dumps(identity, indent=2, sort_keys=True) + "\n").encode())
        self.bundles: dict[str, dict[str, bytes]] = {}
        self._active = False
        self._files: list[tuple[int, Path, tuple[int, int, int, int, int], str]] = []
        self._directories: list[tuple[int, Path, tuple[int, int, int, int, int]]] = []
        self._links: list[tuple[Path, tuple[int, int, int, int, int], str]] = []
        self._states: dict[str, str] = {}
        self._processes: dict[str, tuple[int, Path, str, bytes, bytes]] = {}
        self._stack: ExitStack | None = None
        selected = [source for source in self.sources if source["pin"]["protocol"] != "wireguard"]

        if type(bundles) is not list or len(bundles) != len(selected):
            raise ServiceError("Service observation requires every exact unrelated server source")

        for source, bundle in zip(selected, bundles):
            protocol = source["pin"]["protocol"]
            expected = _AWG_FILES if protocol == "amneziawg" else _VLESS_FILES

            if (type(bundle) is not dict or set(bundle) != {"protocol", "name", "files"} or bundle["protocol"] != protocol
                    or bundle["name"] != identity["stack"] + "-" + protocol or type(bundle["files"]) is not dict or set(bundle["files"]) != expected
                    or any(type(data) is not bytes or not 1 <= len(data) <= 1048576 for data in bundle["files"].values())
                    or sum(len(data) for data in bundle["files"].values()) > 2 * 1024 * 1024):
                raise ServiceError("Service observation source bundle is incomplete or foreign")

            files = dict(bundle["files"])
            digest = guest._Digest(guest._Encode({"identity": identity, "kind": "server", "name": bundle["name"], "files": [
                {"name": name, "size": len(data), "sha256": guest._Digest(data), "sensitive": True} for name, data in sorted(files.items())]}))

            if digest != source["pin"]["server_digest"]:
                raise ServiceError("Service observation source differs from its complete public bundle pin")

            self.bundles[protocol] = files

        if "amneziawg" in self.bundles:
            Configuration(guest, self.bundles["amneziawg"]["server.conf"])

        if "vless-reality" in self.bundles:
            request = guest._Json(self.bundles["vless-reality"]["deployment.json"])

            if (type(request) is not dict or set(request) != {"schema_version", "owner", "config_sha256", "port", "xray_version"}
                    or type(request["schema_version"]) is not int or request["schema_version"] != 1 or request["owner"] != self.vlessOwner
                    or request["config_sha256"] != guest._Digest(self.bundles["vless-reality"]["server.json"])
                    or type(request["port"]) is not int or not 1 <= request["port"] <= 65535
                    or request["xray_version"] not in {vless.XRAY_VERSION, vless.LEGACY_VERSION}):
                raise ServiceError("VLESS observation descriptor differs from its exact retained owner/configuration")

    def _Directory(self, path: Path, *, private: bool = False) -> None:
        """Pin exact root-owned ancestry and membership without creating a directory or following a link."""

        self.guest._Directory(path, private=private)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        assert self._stack is not None
        self._stack.callback(os.close, descriptor)
        self._directories.append((descriptor, path, _Stamp(os.fstat(descriptor))))

    def _File(self, path: Path, mode: int, *, limit: int = 1048576) -> bytes:
        """Retain bounded private/binary file identity through the whole observation lease."""

        content = self.guest._Read(path, limit=limit, mode=mode)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        assert self._stack is not None
        self._stack.callback(os.close, descriptor)
        info = os.fstat(descriptor)
        linked = path.lstat()

        if (_Stamp(info) != _Stamp(linked) or not stat.S_ISREG(info.st_mode) or info.st_uid != self.guest._ROOT_UID
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != mode or os.pread(descriptor, limit + 1, 0) != content):
            raise ServiceError("Service file changed before its observation lease")

        self._files.append((descriptor, path, _Stamp(info), self.guest._Digest(content)))

        return cast(bytes, content)

    def _Link(self, unit: Path) -> None:
        """Require the original explicit enable link while preserving its identity instead of following it."""

        path = SYSTEMD / "multi-user.target.wants" / unit.name
        info = path.lstat()

        if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.guest._ROOT_UID or os.readlink(path) != str(unit):
            raise ServiceError("Service enable link differs from its owned unit")

        self._links.append((path, _Stamp(info), str(unit)))

    def Verify(self) -> None:
        """Keep the same complete files, directory memberships and enable links throughout protected native completion."""

        if not self._active:
            raise ServiceError("Service observation requires its active pinned lease")

        for descriptor, path, stamp in self._directories:
            if _Stamp(os.fstat(descriptor)) != stamp or _Stamp(path.lstat()) != stamp:
                raise ServiceError("Service directory changed during its observation lease")

        for descriptor, path, stamp, digest in self._files:
            info = os.fstat(descriptor)

            if (_Stamp(info) != stamp or _Stamp(path.lstat()) != stamp or info.st_nlink != 1
                    or self.guest._Digest(os.pread(descriptor, info.st_size + 1, 0)) != digest):
                raise ServiceError("Service file changed during its observation lease")

        for path, stamp, target in self._links:
            if _Stamp(path.lstat()) != stamp or os.readlink(path) != target:
                raise ServiceError("Service enable link changed during its observation lease")

        for descriptor, path, started, arguments, group in self._processes.values():
            pinned, linked = os.fstat(descriptor), path.lstat()

            if ((pinned.st_dev, pinned.st_ino) != (linked.st_dev, linked.st_ino)
                    or self._Start(descriptor) != started or self._Virtual(descriptor, "cmdline", 8192) != arguments
                    or self._Virtual(descriptor, "cgroup", 4096) != group):
                raise ServiceError("Service process identity changed during its observation lease")

    def _Virtual(self, directory: int, name: str, limit: int) -> bytes:
        """Read only fixed PID virtual files without trusting their zero-reported sizes or following a user-controlled leaf."""

        if name not in {"stat", "cmdline", "cgroup"}:
            raise ServiceError("Unsupported process identity file")

        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)

        try:
            info = os.fstat(descriptor)
            content = os.read(descriptor, limit + 1)

            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.fstat(directory).st_uid or info.st_mode & 0o022
                    or not 1 <= len(content) <= limit):
                raise ServiceError("Service process identity file is unsafe or incomplete")

            return content

        finally:
            os.close(descriptor)

    def _Start(self, directory: int) -> str:
        """Bind the kernel start-time token, so recycling the same numeric PID never adopts another daemon."""

        raw = self._Virtual(directory, "stat", 4096).decode("ascii")
        fields = raw.rsplit(")", 1)[-1].split()

        if len(fields) < 20 or not fields[19].isdecimal():
            raise ServiceError("Service process start identity is incomplete")

        return fields[19]

    def _Process(self, state: dict[str, str], arguments: list[str]) -> int:
        """Pin the exact active executable arguments and cgroup before reading any namespace-specific loaded credential."""

        pid = state["MainPID"]
        path = PROC / pid
        self.guest._Directory(PROC)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        assert self._stack is not None
        self._stack.callback(os.close, descriptor)
        started = self._Start(descriptor)
        expected = b"\x00".join(value.encode() for value in arguments) + b"\x00"
        group = ("0::" + state["ControlGroup"] + "\n").encode()

        if self._Virtual(descriptor, "cmdline", 8192) != expected or self._Virtual(descriptor, "cgroup", 4096) != group:
            raise ServiceError("Service process arguments or cgroup differ from its owned unit")

        if pid in self._processes:
            previous = self._processes[pid]
            before, current = os.fstat(previous[0]), os.fstat(descriptor)

            if ((before.st_dev, before.st_ino) != (current.st_dev, current.st_ino) or previous[2:] != (started, expected, group)):
                raise ServiceError("Service PID was recycled during its observation lease")

        self._processes[pid] = (descriptor, path, started, expected, group)

        return descriptor

    def _Credential(self, process: int, pid: str, unit: Path, expected: bytes) -> None:
        """Read the daemon's actual systemd credential in its pinned mount namespace, with only the fixed kernel root magic link allowed."""

        assert self._stack is not None

        if os.readlink("root", dir_fd=process) != "/":
            raise ServiceError("Service process uses an unexplained filesystem root")

        descriptor = os.open("root", os.O_RDONLY | os.O_DIRECTORY, dir_fd=process)
        self._stack.callback(os.close, descriptor)

        for name in ("run", "credentials", unit.name):
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            self._stack.callback(os.close, descriptor)
            info = os.fstat(descriptor)

            if info.st_uid not in {self.guest._ROOT_UID, os.fstat(process).st_uid} or info.st_mode & 0o022:
                raise ServiceError("Loaded service credential directory is unsafe")

        credential = os.open("server.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        self._stack.callback(os.close, credential)
        info = os.fstat(credential)
        content = os.pread(credential, 1048577, 0)
        path = PROC / pid / "root/run/credentials" / unit.name / "server.json"
        acl = None

        try:
            acl = os.getxattr(credential, "system.posix_acl_access")

        except OSError as error:
            if error.errno not in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise ServiceError("Loaded service credential access control cannot be verified") from None

        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in {self.guest._ROOT_UID, os.fstat(process).st_uid}
                or not CredentialAccess(stat.S_IMODE(info.st_mode), info.st_uid, os.fstat(process).st_uid, self.guest._ROOT_UID, acl)
                or not 1 <= len(content) <= 1048576 or content != expected
                or _Stamp(info) != _Stamp(path.lstat())):
            raise ServiceError("VLESS daemon loaded credential differs from its retained source")

        self._files.append((credential, path, _Stamp(info), self.guest._Digest(content)))

    def _Unit(self, unit: Path, binary: Path) -> dict[str, str]:
        """Require the loaded exact active daemon, no queued control work and its actual executable path."""

        state = self.runtime._Service(self.guest, unit)
        _, reload = self.guest._Run(["systemctl", "show", "--all", "--no-pager", "--property=NeedDaemonReload", "--value", unit.name])

        if (state["LoadState"] != "loaded" or state["ActiveState"] != "active" or state["SubState"] != "running"
                or state["Job"] or state["MainPID"] == "0" or state["ControlPID"] != "0" or reload != b"no\n"):
            raise ServiceError("Unrelated daemon has no exact completed active service observation")

        _, executable = self.guest._Run(["readlink", "--", str(PROC / state["MainPID"] / "exe")])

        if executable != (str(binary) + "\n").encode() or self.runtime._Service(self.guest, unit) != state:
            raise ServiceError("Unrelated daemon executable or process identity differs from its owned unit")

        return cast(dict[str, str], state)

    def _Layout(self, protocol: str) -> tuple[Path, Path, Path]:
        """Derive only fixed owner-bound paths; source references never select guest paths."""

        if protocol == "amneziawg":
            service = "flayer-awg-" + self.owner[:12]

            return AWG_BASE / service, SYSTEMD / (service + ".service"), AWG_LOCKS / (service + ".lock")

        return (self.vless.BASE / self.vlessOwner[:24], SYSTEMD / ("flayer-vless-" + self.vlessOwner[:24] + ".service"),
                self.vless.BASE / ("." + self.vlessOwner[:24] + ".lock"))

    def _Units(self, protocol: str, *, active: bool) -> None:
        """Reject on-disk overrides or alternate exact-owner unit entries even before PID1 reloads them."""

        _, unit, _ = self._Layout(protocol)
        entries = _UnitNames(SYSTEMD, unit.stem)
        links = _UnitNames(SYSTEMD / "multi-user.target.wants", unit.stem)
        expected = {unit.name} if active else set()

        if entries != expected or links != expected:
            raise ServiceError("Unrelated service unit namespace contains unexplained owner entries")

    def _Pin(self, protocol: str) -> None:
        """Validate legacy owned files before any binary probe; committed VLESS runtime backups retain their existing helper contract."""

        root, unit, _ = self._Layout(protocol)

        if not root.exists() and not root.is_symlink():
            self._Units(protocol, active=False)
            self._states[protocol] = "absent"

            return

        self._states[protocol] = "active"
        self._Units(protocol, active=True)
        self._Directory(root, private=protocol == "amneziawg")
        files = self.bundles[protocol]

        if protocol == "amneziawg":
            if {path.name for path in root.iterdir()} != {"owner", "payload-hash", "server.conf", "firewall.nft", "network.sh", "bin"}:
                raise ServiceError("AWG root has unexplained or incomplete files")

            service = unit.stem
            payload = "".join(self.guest._Digest(files[name]) + "  " + name + "\n" for name in
                              ("install.sh", "server.conf", "firewall.nft", "network.sh", "service.service"))

            if (self._File(root / "owner", 0o600) != (service + "\n").encode()
                    or self._File(root / "payload-hash", 0o600) != (hashlib.sha256(payload.encode()).hexdigest() + "\n").encode()):
                raise ServiceError("AWG owner or complete payload marker differs from its retained source")

            for name in ("server.conf", "firewall.nft", "network.sh"):
                if self._File(root / name, 0o700 if name == "network.sh" else 0o600) != files[name]:
                    raise ServiceError("AWG installed bytes differ from their exact retained source")

            self._Directory(root / "bin", private=True)

            if {path.name for path in (root / "bin").iterdir()} != {"awg", "amneziawg-go"}:
                raise ServiceError("AWG runtime contains unexplained binaries")

            for name in ("awg", "amneziawg-go"):
                content = self._File(root / "bin" / name, 0o700, limit=96 * 1024 * 1024)

                if not content.startswith(b"\x7fELF"):
                    raise ServiceError("AWG owned runtime is not an installed ELF executable")

            if self._File(unit, 0o644) != files["service.service"]:
                raise ServiceError("AWG installed unit differs from its exact retained source")

        else:
            receipt = self.vless._Existing(root, unit, self.vlessOwner)

            if receipt is None or receipt["files"]["server.json"] != self.guest._Digest(files["server.json"]):
                raise ServiceError("VLESS installed receipt differs from its retained configuration")

            for name, mode in (("owner.json", 0o600), ("server.json", 0o600), ("xray", 0o755)):
                self._File(root / name, mode, limit=96 * 1024 * 1024 if name == "xray" else 1048576)

            if self._File(unit, 0o644) != self.vless._Unit(root):
                raise ServiceError("VLESS installed unit differs from its owned layout")

            upgrade = root / "runtime-upgrade"

            if upgrade.exists() or upgrade.is_symlink():
                self._Directory(upgrade, private=True)

                for name in sorted(self.vless._TRANSACTION_FILES):
                    self._File(upgrade / name, 0o700 if name == "new-xray" else 0o600,
                               limit=96 * 1024 * 1024 if name.endswith("xray") else 1048576)

        self._Link(unit)

    @contextmanager
    def Pinned(self) -> Iterator[ServiceObserver]:
        """Acquire existing AWG then VLESS shared coordination after common/WG locks; never create a missing lock or repair metadata."""

        if self._active:
            raise ServiceError("Nested service observation leases are not supported")

        import fcntl

        with ExitStack() as stack:
            self._stack = stack
            self._files, self._directories, self._links, self._states, self._processes = [], [], [], {}, {}

            try:
                self._Directory(SYSTEMD)
                self._Directory(SYSTEMD / "multi-user.target.wants")

                for protocol in self.bundles:
                    root, _, lock = self._Layout(protocol)
                    self.guest._Directory(lock.parent)
                    descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    stack.callback(os.close, descriptor)
                    info = os.fstat(descriptor)

                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.guest._ROOT_UID or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0 or _Stamp(info) != _Stamp(lock.lstat())):
                        raise ServiceError("Unrelated service coordination has unsafe ownership or contents")

                    fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    self._files.append((descriptor, lock, _Stamp(info), self.guest._Digest(b"")))
                    self._Directory(root.parent)
                    self._Pin(protocol)

                self._active = True
                self.Verify()
                yield self
                self.Verify()

            finally:
                self._active = False
                self._stack = None

    def _Absent(self, protocol: str) -> str:
        """Require complete owned namespace and listener absence, retaining an already existing coordination lock."""

        root, unit, _ = self._Layout(protocol)
        self._Units(protocol, active=False)
        link = SYSTEMD / "multi-user.target.wants" / unit.name

        if any(path.exists() or path.is_symlink() for path in (root, unit, link)):
            raise ServiceError("Unrelated service absence has remaining or foreign owned paths")

        self.runtime._Drained(self.guest, unit)
        port = (int(Configuration(self.guest, self.bundles[protocol]["server.conf"])["interface"]["ListenPort"])
                if protocol == "amneziawg" else self.guest._Json(self.bundles[protocol]["deployment.json"])["port"])
        _, sockets = self.guest._Run(["ss", "-H", "-lun" if protocol == "amneziawg" else "-ltn", "sport = :" + str(port)])

        if sockets.strip():
            raise ServiceError("Unrelated service absence has an occupied retained listener")

        if protocol == "amneziawg":
            interface = "fa" + self.owner[:12]
            _, links = self.guest._Run(["ip", "-j", "link", "show"])
            _, tables = self.guest._Run(["nft", "-j", "list", "tables"])
            observedLinks, observedTables = self.guest._Json(links), self.guest._Json(tables)

            if (type(observedLinks) is not list or any(type(item) is not dict or type(item.get("ifname")) is not str for item in observedLinks)
                    or any(item["ifname"] == interface for item in observedLinks)
                    or type(observedTables) is not dict or type(observedTables.get("nftables")) is not list
                    or any(type(item) is not dict for item in observedTables["nftables"])
                    or any(type(item["table"]) is not dict or type(item["table"].get("name")) is not str
                           for item in observedTables["nftables"] if "table" in item)
                    or any(item["table"]["name"] == interface for item in observedTables["nftables"] if "table" in item)):
                raise ServiceError("AWG absence has remaining or ambiguous native interface/forwarding state")

        return cast(str, self.guest._Digest(self.guest._Encode({"domain": "f-layer/" + protocol + "/absent/v1", "owner": self.owner})))

    def _Awg(self) -> str:
        """Check retained credentials/peers, owned daemon, exact IPv4 address/MTU, forwarding and complete owned nft snapshot."""

        root, unit, _ = self._Layout("amneziawg")
        interface = "fa" + self.owner[:12]
        state = self._Unit(unit, root / "bin/amneziawg-go")
        self._Process(state, [str(root / "bin/amneziawg-go"), "-f", interface])
        _, raw = self.guest._Run([str(root / "bin/awg"), "showconf", interface])
        settings = MatchConfiguration(self.guest, self.bundles["amneziawg"]["server.conf"], raw)
        network = self.bundles["amneziawg"]["network.sh"].decode("ascii")
        addresses = re.findall(r"ip address replace ([0-9./]+) dev " + re.escape(interface) + r"\n", network)
        mtus = re.findall(r"ip link set dev " + re.escape(interface) + r" mtu ([0-9]+) up\n", network)

        if len(addresses) != 1 or len(mtus) != 1:
            raise ServiceError("AWG retained network source has no exact interface address and MTU")

        expectedAddress = ipaddress.IPv4Interface(addresses[0])
        _, raw = self.guest._Run(["ip", "-j", "-4", "address", "show", "dev", interface])
        link = self.guest._Json(raw)

        if (type(link) is not list or len(link) != 1 or type(link[0]) is not dict or link[0].get("ifname") != interface
                or type(link[0].get("mtu")) is not int or link[0]["mtu"] != int(mtus[0])
                or type(link[0].get("flags")) is not list or any(type(flag) is not str for flag in link[0]["flags"]) or "UP" not in link[0]["flags"]
                or type(link[0].get("addr_info")) is not list or len(link[0]["addr_info"]) != 1
                or type(link[0]["addr_info"][0]) is not dict
                or link[0]["addr_info"][0].get("family") != "inet" or link[0]["addr_info"][0].get("local") != str(expectedAddress.ip)
                or type(link[0]["addr_info"][0].get("prefixlen")) is not int or link[0]["addr_info"][0]["prefixlen"] != expectedAddress.network.prefixlen):
            raise ServiceError("AWG actual interface address or MTU differs from its retained source")

        _, forwarding = self.guest._Run(["sysctl", "-n", "net.ipv4.ip_forward"])
        _, nft = self.guest._Run(["nft", "-j", "list", "table", "ip", interface])

        if forwarding != b"1\n":
            raise ServiceError("AWG actual IPv4 forwarding is disabled")

        expectedNft = _Compiled(self.guest, self.bundles["amneziawg"]["firewall.nft"], interface)

        if _Fingerprint(self.guest, nft, interface) != expectedNft:
            raise ServiceError("AWG live forwarding differs from its exact retained source")

        files = {str(path.relative_to(root)) if path.is_relative_to(root) else "service.service": digest
                 for _, path, _, digest in self._files if path == unit or path.is_relative_to(root)}

        return cast(str, self.guest._Digest(self.guest._Encode({"domain": "f-layer/amneziawg/service/v1", "owner": self.owner,
            "files": files, "runtime_config_sha256": self.guest._Digest(self.guest._Encode(settings)),
            "forwarding_sha256": _Fingerprint(self.guest, nft, interface), "address": str(expectedAddress), "mtu": int(mtus[0])})))

    def _Vless(self) -> str:
        """Verify current owned runtime/configuration and its actual daemon/listener without probing external sites or claiming tunnel traffic."""

        root, unit, _ = self._Layout("vless-reality")
        state = self._Unit(unit, root / "xray")
        credential = "/run/credentials/" + unit.name + "/server.json"
        process = self._Process(state, [str(root / "xray"), "run", "-config", credential])
        self._Credential(process, state["MainPID"], unit, self.bundles["vless-reality"]["server.json"])
        receipt = self.vless._Existing(root, unit, self.vlessOwner)
        request = self.guest._Json(self.bundles["vless-reality"]["deployment.json"])

        if receipt is None or receipt["files"]["server.json"] != request["config_sha256"]:
            raise ServiceError("VLESS owned receipt no longer matches its retained source")

        self.guest._Run([str(root / "xray"), "run", "-test", "-config", str(root / "server.json")])
        _, listener = self.guest._Run(["ss", "-H", "-ltnp", "sport = :" + str(request["port"])])
        lines = listener.decode("ascii").splitlines()

        if len(lines) != 1 or set(re.findall(r"pid=([0-9]+),", lines[0])) != {state["MainPID"]}:
            raise ServiceError("VLESS retained TCP listener does not belong exclusively to its exact daemon")

        return cast(str, self.guest._Digest(self.guest._Read(root / "owner.json")))

    def Observe(self, guest: Any, sources: object) -> list[dict[str, str]]:
        """Return only source-bound active receipt or complete absence digests while the trusted observation lease remains held."""

        if guest is not self.guest or self.guest._Encode(sources) != self.guest._Encode(self.sources):
            raise ServiceError("Service observer cannot attest a different receiver or source selection")

        self.Verify()
        result = []

        for source in self.sources:
            protocol = source["pin"]["protocol"]

            if protocol == "wireguard":
                continue

            state = self._states[protocol]
            digest = self._Absent(protocol) if state == "absent" else self._Awg() if protocol == "amneziawg" else self._Vless()
            result.append({"protocol": protocol, "source_sha256": source["pin"]["server_digest"], "state": state,
                           "receipt_sha256": digest if state == "active" else "", "absence_sha256": digest if state == "absent" else ""})

        self.Verify()

        return result
