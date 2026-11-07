"""Observe actual POSIX ownership/leases against fully intercepted process, systemd, nftables and socket facts."""

from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_protocol_services_codec import Sources
from test_vpn_project_v2 import Snapshot

from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _protocol_services as services
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles.amneziawg import AmneziaWgSettings

if os.name == "posix":
    from flayer.profiles import _vless_guest as vless

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Service leases need POSIX metadata/proc semantics; all system/network commands are intercepted")


def Write(path: Path, content: bytes, mode: int = 0o600) -> None:
    """Create only a bounded synthetic fixture file in the test's explicitly owned temporary tree."""

    if path.exists():
        path.chmod(0o600)

    path.write_bytes(content)
    path.chmod(mode)


class Model:
    """Own synthetic native observations independently from the private source bundle and its expected proofs."""

    def __init__(self, observer: services.ServiceObserver, sources: list[dict[str, Any]], base: Path) -> None:
        """Keep every command in an allowlisted readonly model; no daemon or local network tool can run."""

        self.observer, self.sources, self.base = observer, sources, base
        self.active = {protocol: True for protocol in observer.bundles}
        self.commands: list[list[str]] = []
        self.reload = b"no\n"
        self.listenerPid = "315"
        self.forwarding = b"1\n"
        self.configuration = observer.bundles["amneziawg"]["server.conf"] if "amneziawg" in observer.bundles else b""
        interface = "fa" + observer.owner[:12]
        self.address = [{"ifname": interface, "flags": ["UP", "LOWER_UP"], "mtu": AmneziaWgSettings().mtu,
                         "addr_info": [{"family": "inet", "local": "10.66.0.1", "prefixlen": 24}]}]
        self.expectedNft = {"nftables": [
            {"table": {"family": "ip", "name": interface, "handle": 1}},
            {"chain": {"family": "ip", "table": interface, "name": "forward", "type": "filter", "hook": "forward", "prio": -10, "policy": "accept", "handle": 2}},
            {"chain": {"family": "ip", "table": interface, "name": "postrouting", "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept", "handle": 3}},
            {"rule": {"family": "ip", "table": interface, "chain": "forward", "expr": [{"accept": None}], "handle": 4}},
            {"rule": {"family": "ip", "table": interface, "chain": "postrouting", "expr": [{"masquerade": None}], "handle": 5}},
        ]}
        self.liveNft = copy.deepcopy(self.expectedNft)

    def State(self, unit: str) -> dict[str, str]:
        """Return current fake PID1 facts, including exact empty-job and process ownership fields."""

        protocol = "amneziawg" if unit.startswith("flayer-awg-") else "vless-reality"
        active = self.active[protocol]

        return {"Id": unit, "LoadState": "loaded" if active else "not-found", "ActiveState": "active" if active else "inactive",
                "SubState": "running" if active else "dead", "Job": "", "MainPID": ("314" if protocol == "amneziawg" else "315") if active else "0",
                "ControlPID": "0", "ControlGroup": "/system.slice/" + unit if active else "", "FragmentPath": str(services.SYSTEMD / unit) if active else "",
                "DropInPaths": ""}

    def Run(self, command: list[str], **kwargs: Any) -> tuple[int, bytes]:
        """Reject every unrecognized command instead of falling through to the desktop/host subprocess boundary."""

        self.commands.append(list(command))

        if command[:2] == ["systemctl", "show"]:
            if "--property=NeedDaemonReload" in command:
                return 0, self.reload

            return 0, "".join(key + "=" + value + "\n" for key, value in self.State(command[-1]).items()).encode()

        if command[:2] == ["readlink", "--"]:
            return 0, (str(Path(command[-1]).resolve(strict=True)) + "\n").encode()

        if command[1:2] == ["showconf"]:
            return 0, self.configuration

        if command[:3] == ["ip", "-j", "-4"]:
            return 0, guest._Encode(self.address)

        if command == ["sysctl", "-n", "net.ipv4.ip_forward"]:
            return 0, self.forwarding

        if command[:5] == ["nft", "-j", "list", "table", "ip"]:
            return 0, guest._Encode(self.liveNft)

        if command[:3] == ["unshare", "--net", "--"]:
            assert Path(command[-1]).read_bytes() == self.observer.bundles["amneziawg"]["firewall.nft"]

            return 0, guest._Encode({"nftables": [{"add": item} for item in self.expectedNft["nftables"]]})

        if command[:2] == ["ss", "-H"]:
            if command[2] == "-ltnp":
                return 0, ('LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("xray",pid=' + self.listenerPid + ',fd=3))\n').encode()

            return 0, b""

        if command[:4] == ["ip", "-j", "link", "show"]:
            return 0, guest._Encode([])

        if command == ["nft", "-j", "list", "tables"]:
            return 0, guest._Encode({"nftables": []})

        if command[1:4] == ["run", "-test", "-config"]:
            return 0, b""

        raise AssertionError("Unexpected command outside the readonly service-observation model")


def Environment(
    tmpPath: Path, monkeypatch: pytest.MonkeyPatch, protocols: tuple[str, ...] = ("amneziawg", "vless-reality"),
) -> tuple[services.ServiceObserver, Model]:
    """Build both real legacy ownership layouts plus fake /proc and credential mounts under one isolated temporary tree."""

    identity, sources, bundles = Sources(protocols)
    for name in ("awg", "locks", "units", "run", "vless", "proc", "namespaces", "cgroups"):
        (tmpPath / name).mkdir(mode=0o700)

    (tmpPath / "units/multi-user.target.wants").mkdir(mode=0o700)
    monkeypatch.setattr(services, "AWG_BASE", tmpPath / "awg")
    monkeypatch.setattr(services, "AWG_LOCKS", tmpPath / "locks")
    monkeypatch.setattr(services, "SYSTEMD", tmpPath / "units")
    monkeypatch.setattr(services, "PROC", tmpPath / "proc")
    monkeypatch.setattr(runtime, "CGROUPS", tmpPath / "cgroups")
    Write(tmpPath / "cgroups/cgroup.controllers", b"cpu\n", 0o644)
    monkeypatch.setattr(guest, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(guest, "LOCK", tmpPath / "run/wireguard.lock")
    monkeypatch.setattr(vless, "_ROOT_UID", os.getuid())
    monkeypatch.setattr(vless, "BASE", tmpPath / "vless")
    monkeypatch.setattr(vless, "SYSTEMD", tmpPath / "units")
    observer = services.ServiceObserver(guest, authority, completion, runtime, vless, identity, sources, bundles)

    for protocol in protocols:
        root, unit, lock = observer._Layout(protocol)
        root.mkdir(mode=0o700 if protocol == "amneziawg" else 0o755)
        Write(lock, b"")
        files = observer.bundles[protocol]

        if protocol == "amneziawg":
            (root / "bin").mkdir(mode=0o700)
            for name in ("awg", "amneziawg-go"):
                Write(root / "bin" / name, b"\x7fELFsynthetic-retained-runtime-" + name.encode(), 0o700)

            for name in ("server.conf", "firewall.nft", "network.sh"):
                Write(root / name, files[name], 0o700 if name == "network.sh" else 0o600)

            Write(root / "owner", (unit.stem + "\n").encode())
            hashes = "".join(guest._Digest(files[name]) + "  " + name + "\n" for name in
                             ("install.sh", "server.conf", "firewall.nft", "network.sh", "service.service"))
            Write(root / "payload-hash", (guest._Digest(hashes.encode()) + "\n").encode())
            Write(unit, files["service.service"], 0o644)
            pid, binary = "314", root / "bin/amneziawg-go"
            arguments = [str(binary), "-f", "fa" + observer.owner[:12]]

        else:
            Write(root / "server.json", files["server.json"])
            Write(root / "xray", b"\x7fELFsynthetic-retained-xray", 0o755)
            Write(unit, vless._Unit(root), 0o644)
            receipt = {"owner": observer.vlessOwner, "xray_version": vless.XRAY_VERSION, "files": {
                "xray": guest._Digest((root / "xray").read_bytes()), "server.json": guest._Digest(files["server.json"]), "service": guest._Digest(unit.read_bytes())}}
            Write(root / "owner.json", (json.dumps(receipt, sort_keys=True) + "\n").encode())
            pid, binary = "315", root / "xray"
            arguments = [str(binary), "run", "-config", "/run/credentials/" + unit.name + "/server.json"]

        (services.SYSTEMD / "multi-user.target.wants" / unit.name).symlink_to(unit)
        process = services.PROC / pid
        process.mkdir(mode=0o700)
        Write(process / "cmdline", b"\x00".join(value.encode() for value in arguments) + b"\x00", 0o444)
        Write(process / "cgroup", ("0::/system.slice/" + unit.name + "\n").encode(), 0o444)
        Write(process / "stat", (pid + " (daemon) S " + "0 " * 18 + "12345\n").encode(), 0o444)
        (process / "exe").symlink_to(binary)
        namespace = tmpPath / "namespaces" / pid
        namespace.mkdir(mode=0o700)
        (process / "root").symlink_to(namespace, target_is_directory=True)

        if protocol == "vless-reality":
            credential = namespace / "run/credentials" / unit.name
            credential.mkdir(mode=0o700, parents=True)
            Write(credential / "server.json", files["server.json"], 0o400)

    readlink = os.readlink

    def Readlink(path: Any, **kwargs: Any) -> str:
        """Model only the kernel magic-link spelling; the actual fixture descriptor still opens its isolated namespace tree."""

        if path == "root" and kwargs.get("dir_fd") is not None:
            return "/"

        return readlink(path, **kwargs)

    monkeypatch.setattr(os, "readlink", Readlink)
    model = Model(observer, sources, tmpPath)
    monkeypatch.setattr(guest, "_Run", model.Run)

    return observer, model


def test_BothConcreteServiceProofsAreReadOnlyStableAndBoundToCompleteRetainedSources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual POSIX ownership, private source bytes, enable links and process credentials are read while native effects stay intercepted."""

    observer, model = Environment(tmp_path, monkeypatch)
    before = Snapshot(tmp_path)

    with observer.Pinned() as lease:
        proof = lease.Observe(guest, model.sources)
        assert [row["protocol"] for row in proof] == ["amneziawg", "vless-reality"]
        assert all(row["state"] == "active" and len(row["receipt_sha256"]) == 64 and not row["absence_sha256"] for row in proof)
        assert lease.Observe(guest, model.sources) == proof

    assert Snapshot(tmp_path) == before
    assert all(command[:2] != ["systemctl", "start"] and command[0] != "ip-link-mutate" for command in model.commands)
    assert b"PrivateKey" not in guest._Encode(proof) and b"server.json" not in guest._Encode(proof)


@pytest.mark.parametrize("fault", ["config", "payload", "unit", "enable-link", "foreign-file", "live-nft", "live-keys", "live-address", "forwarding", "reload", "loaded-credential", "credential-mode", "listener-pid", "process-args", "process-cgroup"])
def test_DriftedSourcesOrActualRuntimeCannotEmitAnActiveProof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Correct disk hashes cannot hide drifted live forwarding, loaded credentials or a same-port listener owned by another process."""

    observer, model = Environment(tmp_path, monkeypatch)
    awgRoot, awgUnit, _ = observer._Layout("amneziawg")
    _, vlessUnit, _ = observer._Layout("vless-reality")

    if fault == "config":
        Write(awgRoot / "server.conf", b"preserve synthetic changed private config")

    elif fault == "payload":
        Write(awgRoot / "payload-hash", b"0" * 64 + b"\n")

    elif fault == "unit":
        Write(awgUnit, awgUnit.read_bytes() + b"# unknown change\n", 0o644)

    elif fault == "enable-link":
        link = services.SYSTEMD / "multi-user.target.wants" / awgUnit.name
        link.unlink()
        link.symlink_to(services.SYSTEMD / "foreign.service")

    elif fault == "foreign-file":
        Write(awgRoot / "unknown", b"preserve unrelated fixture")

    elif fault == "live-nft":
        model.liveNft["nftables"][-1]["rule"]["expr"] = [{"accept": None}]

    elif fault == "live-keys":
        model.configuration = model.configuration.replace(b"H1 = 1\n", b"H1 = 999\n")

    elif fault == "live-address":
        model.address[0]["addr_info"][0]["local"] = "10.66.0.99"

    elif fault == "forwarding":
        model.forwarding = b"0\n"

    elif fault == "reload":
        model.reload = b"yes\n"

    elif fault in {"loaded-credential", "credential-mode"}:
        credential = tmp_path / "namespaces/315/run/credentials" / vlessUnit.name / "server.json"
        Write(credential, b"preserve stale loaded credential" if fault == "loaded-credential" else credential.read_bytes(), 0o400 if fault == "loaded-credential" else 0o600)

    elif fault == "listener-pid":
        model.listenerPid = "999"

    elif fault == "process-args":
        Write(services.PROC / "315/cmdline", b"wrong-runtime\x00wrong-config\x00", 0o444)

    else:
        Write(services.PROC / "315/cgroup", b"0::/system.slice/foreign.service\n", 0o444)

    before = Snapshot(tmp_path)

    with pytest.raises((ValueError, OSError)):
        with observer.Pinned():
            observer.Observe(guest, model.sources)

    assert Snapshot(tmp_path) == before


@pytest.mark.parametrize("entry", ["file", "directory", "link", "process-start", "late-credential"])
def test_ObservationLeaseRefusesSameByteReplacementOrProcessRecyclingBeforeRelease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str) -> None:
    """Keep the original open descriptors and start tokens; equality of bytes never adopts replacement ownership."""

    observer, model = Environment(tmp_path, monkeypatch)
    root, unit, _ = observer._Layout("amneziawg")

    with pytest.raises((ValueError, OSError)):
        with observer.Pinned():
            observer.Observe(guest, model.sources)

            if entry == "file":
                replacement = tmp_path / "replacement"
                Write(replacement, (root / "server.conf").read_bytes())
                os.replace(replacement, root / "server.conf")

            elif entry == "directory":
                retained = root.with_name("retained-old-root")
                root.rename(retained)
                root.mkdir(mode=0o700)

            elif entry == "link":
                link = services.SYSTEMD / "multi-user.target.wants" / unit.name
                link.unlink()
                link.symlink_to(unit)

            elif entry == "process-start":
                path = services.PROC / "315/stat"
                Write(path, path.read_bytes().replace(b"12345", b"54321"), 0o444)

            else:
                _, vlessUnit, _ = observer._Layout("vless-reality")
                path = tmp_path / "namespaces/315/run/credentials" / vlessUnit.name / "server.json"
                replacement = tmp_path / "replacement"
                Write(replacement, path.read_bytes(), 0o400)
                os.replace(replacement, path)


@pytest.mark.parametrize("protocol", ["amneziawg", "vless-reality"])
def test_AbsenceRetainsExistingCoordinationAndRejectsNotYetReloadedOwnerDropIns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, protocol: str) -> None:
    """An empty cached DropInPaths property cannot explain an on-disk override of an absent owned unit."""

    observer, model = Environment(tmp_path, monkeypatch, (protocol,))
    root, unit, _ = observer._Layout(protocol)
    retained = tmp_path / "retained-private-root"
    root.rename(retained)
    unit.unlink()
    (services.SYSTEMD / "multi-user.target.wants" / unit.name).unlink()
    model.active[protocol] = False

    with observer.Pinned():
        proof = observer.Observe(guest, model.sources)
        assert proof[0]["state"] == "absent" and not proof[0]["receipt_sha256"] and len(proof[0]["absence_sha256"]) == 64

    override = services.SYSTEMD / (unit.name + ".d")
    override.mkdir(mode=0o700)
    before = Snapshot(tmp_path)

    with pytest.raises(ValueError, match="namespace"):
        with observer.Pinned():
            observer.Observe(guest, model.sources)

    assert override.is_dir() and Snapshot(tmp_path) == before


@pytest.mark.skipif(os.environ.get("FLAYER_WG_CONFORMANCE") != "isolated-ci", reason="Real nft conformance runs only in the repository's explicitly isolated Linux CI")
def test_RealNftEchoAndListAgreeForTheRetainedAwgFirewallInOneEphemeralNamespace(tmp_path: Path) -> None:
    """Exercise the actual AWG rules and native set/order rendering without touching any host or desktop interface/rule."""

    identity, _, bundles = Sources(("amneziawg",))
    owner = guest._Digest(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())
    table = "fa" + owner[:12]
    path = tmp_path / "firewall.nft"
    Write(path, bundles[0]["files"]["firewall.nft"])
    script = 'nft -j -e -f "$1"; nft -j list table ip "$2"'
    result = subprocess.run(["sudo", "-n", "unshare", "--net", "--", "/bin/sh", "-ec", script,
                             "flayer-service-conformance", str(path), table], stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, "Isolated AWG nft conformance must compile and read the same complete synthetic policy"
    content = result.stdout.decode("utf-8").lstrip()
    decoder = json.JSONDecoder()
    compiled, index = decoder.raw_decode(content)
    live, end = decoder.raw_decode(content[index:].lstrip())
    assert not content[index:].lstrip()[end:].strip()
    assert services._Fingerprint(guest, guest._Encode(compiled), table) == services._Fingerprint(guest, guest._Encode(live), table)
