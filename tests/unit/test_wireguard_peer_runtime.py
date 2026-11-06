"""Validate sole-peer deltas and safe kernel/firewall prefixes without executing guest or network commands."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from test_wireguard import Profile

from flayer.profiles import _wireguard_guest as guest
from flayer.profiles import _wireguard_peer as peers
from flayer.profiles.vpn import VpnDevice, VpnEndpoint
from flayer.profiles.wireguard import (
    GenerateWireGuardMaterial,
    PrepareWireGuard,
    PrepareWireGuardPeerEnrollment,
    WireGuardSettings,
)


def test_ControllerPacksAnExactHelperPinAndTheStandaloneBodyOnlyDefinesOperations() -> None:
    """Compile and load definitions in memory without invoking Main, a guest helper, native syscalls or any network."""

    program, helper = peers.Programs()
    namespace: dict[str, Any] = {"__name__": "fixture_peer_driver", "__package__": None, "__file__": "fixture/install.py"}
    exec(compile(program, "fixture/install.py", "exec"), namespace)

    assert namespace["HELPER_SHA256"] == hashlib.sha256(helper).hexdigest()
    assert b"__FLAYER_WIREGUARD_HELPER_SHA256__" not in program
    assert callable(namespace["Main"]) and callable(namespace["Recover"])
    assert peers.Programs() == (program, helper), "Program packing must not depend on a guest or generated credentials"


@pytest.mark.parametrize("fault", ["none", "symlink", "owner", "mode", "hardlink", "size", "hash"])
def test_StandaloneHelperExecutesOnlyItsPinnedSourceAfterAnIsolatedMetadataProof(fault: str) -> None:
    """Model the loader's read-only IO boundary entirely in memory; never invoke Main or guest/native operations."""

    import stat

    program, helper = peers.Programs()
    namespace: dict[str, Any] = {"__name__": "fixture_driver", "__package__": None, "__file__": "/fixture/install.py"}
    exec(compile(program, "/fixture/install.py", "exec"), namespace)
    content = b"raise AssertionError('unapproved-helper-executed')" if fault == "hash" else helper
    info = SimpleNamespace(st_mode=stat.S_IFREG | (0o644 if fault == "mode" else 0o600), st_uid=1 if fault == "owner" else 0,
                           st_nlink=2 if fault == "hardlink" else 1, st_size=1048577 if fault == "size" else len(content))
    path = MagicMock()
    path.configure_mock(**{"absolute.return_value": path, "parent": path, "parents": (),
                           "__truediv__.return_value": path, "__str__.return_value": "/fixture/maintenance.py",
                           "is_symlink.return_value": fault == "symlink"})
    closed = []
    namespace["Path"] = MagicMock(return_value=path)
    namespace["os"] = SimpleNamespace(O_RDONLY=0, O_NOFOLLOW=1, open=lambda *args: 42, fstat=lambda descriptor: info,
                                      fdopen=lambda *args, **options: io.BytesIO(content), close=closed.append)

    if fault == "none":
        module = namespace["_Guest"]()
        assert module.TOOLS_VERSION == guest.TOOLS_VERSION and module.__file__ == "/fixture/maintenance.py"

    else:
        with pytest.raises(ValueError):
            namespace["_Guest"]()

    assert closed == ([] if fault == "symlink" else [42])


def Pair(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, bytes]]:
    """Construct real public metadata/server bytes and intercept only private-file reads and wg pubkey derivation."""

    profile, settings = Profile(), WireGuardSettings()
    material = GenerateWireGuardMaterial(profile, settings)
    newDevice = VpnDevice("tablet", "10.67.0.4")
    nextMaterial = GenerateWireGuardMaterial(profile, settings)
    stagedPeer = nextMaterial.peers[0]
    stagedPeer = type(stagedPeer)("tablet", stagedPeer.privateKey, stagedPeer.presharedKey)
    updated, retained = PrepareWireGuardPeerEnrollment(profile, settings, material, newDevice, stagedPeer)
    endpoint = VpnEndpoint("198.51.100.20", 51821)
    oldBundle = PrepareWireGuard(profile, endpoint, settings, material).serverBundle
    newBundle = PrepareWireGuard(updated, endpoint, settings, retained).serverBundle
    oldFiles, newFiles = ({item.name: item.content for item in bundle.files} for bundle in (oldBundle, newBundle))
    before, after = json.loads(oldFiles["deployment.json"]), json.loads(newFiles["deployment.json"])
    contents = {"old": oldFiles["server.conf"], "new": newFiles["server.conf"]}

    def Request(path: Path) -> tuple[dict[str, Any], bytes, bytes]:
        """Model already validated private stages; no filesystem or operating-system ownership is bypassed for live code."""

        request = before if path.name == "old" else after

        return request, contents[path.name], guest._Encode(request)

    def Run(command: list[str], *, payload: bytes, **options: Any) -> tuple[int, bytes]:
        """Independently derive the actual Curve25519 public half instead of invoking a tool or guest."""

        assert command[-1] == "pubkey"
        key = X25519PrivateKey.from_private_bytes(base64.b64decode(payload.strip()))

        return 0, base64.b64encode(key.public_key().public_bytes_raw()) + b"\n"

    monkeypatch.setattr(guest, "_Run", Run)
    boundary = SimpleNamespace(_Request=Request, _Config=guest._Config, _NAME=guest._NAME, GuestError=guest.GuestError)

    return boundary, before, after, contents


def test_SolePeerDeltaPreservesRawServerAndUnrelatedPeerCredentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept exact enrollment and its inverse, using actual server parsing and public-key derivation."""

    boundary, before, after, _ = Pair(monkeypatch)

    assert peers._Delta(boundary, Path("old"), Path("new"), "enroll", "tablet") == (before, after)
    assert peers._Delta(boundary, Path("new"), Path("old"), "revoke", "tablet") == (after, before)


@pytest.mark.parametrize("field", ["owner", "port", "tunnel_cidr", "mtu", "ipv4_routes", "program_sha256", "tools_version", "tools_sha256"])
def test_PeerDeltaCannotBecomeAListenerPolicyOrRuntimeChange(monkeypatch: pytest.MonkeyPatch, field: str) -> None:
    """Changing one device cannot silently authorize another transport/policy/runtime operation."""

    boundary, _, after, _ = Pair(monkeypatch)
    after[field] = "changed"

    with pytest.raises(guest.GuestError, match="cannot modify"):
        peers._Delta(boundary, Path("old"), Path("new"), "enroll", "tablet")


@pytest.mark.parametrize("fault", ["wrong-target", "changed-old-address", "changed-old-psk", "extra-peer"])
def test_PeerDeltaRefusesAnUnrelatedPeerChange(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """Unchanged public identity alone cannot hide a preshared-key replacement for an existing device."""

    boundary, _, after, contents = Pair(monkeypatch)

    if fault == "changed-old-address":
        after["peers"][0]["ipv4_address"] = "10.67.0.9"

    elif fault == "changed-old-psk":
        oldLines = contents["old"].decode().splitlines()
        source = next(line for line in oldLines if line.startswith("PresharedKey = "))
        contents["new"] = contents["new"].replace(source.encode(), ("PresharedKey = " + base64.b64encode(b"z" * 32).decode()).encode())
        after["config_sha256"] = guest._Digest(contents["new"])

    elif fault == "extra-peer":
        after["peers"].append({**copy.deepcopy(after["peers"][-1]), "device_id": "other"})

    with pytest.raises(guest.GuestError):
        peers._Delta(boundary, Path("old"), Path("new"), "enroll", "unknown" if fault == "wrong-target" else "tablet")


@pytest.mark.parametrize("adding,kernel,policy,expected", [
    (True, "old", "old", ["wg", "nft"]), (True, "new", "old", ["nft"]), (True, "new", "new", []), (True, "old", "new", None),
    (False, "old", "old", ["nft", "wg"]), (False, "old", "new", ["wg"]), (False, "new", "new", []), (False, "new", "old", None),
])
def test_OnlyRecordedTransitionPrefixesAreAcceptedAndRevocationDeniesBeforeKernelRemoval(
    monkeypatch: pytest.MonkeyPatch, adding: bool, kernel: str, policy: str, expected: list[str] | None,
) -> None:
    """Exercise the actual convergence ordering with independent state transitions and no OS/network effects."""

    state = {"kernel": kernel, "policy": policy}
    calls = []
    hashes = {"old": "a" * 64, "new": "b" * 64}
    request = {"owner": "c" * 64}
    receipts = {name: {"nonce": "d" * 32, "network_sha256": digest} for name, digest in hashes.items()}

    def WireGuard(directory: Path, request: dict[str, Any]) -> None:
        """Compare the model's actual stored kernel state, never the requested desired state."""

        if state["kernel"] != directory.name:
            raise guest.GuestError("Synthetic peer state differs")

    def Run(command: list[str], *, payload: bytes | None = None) -> None:
        """Apply only one modeled operation and reject accidental service or interface reconstruction."""

        if command[1] == "syncconf":
            calls.append("wg")
            state["kernel"] = Path(command[-1]).parent.name

        else:
            assert command == ["nft", "-f", "-"] and payload is not None
            assert payload.startswith(b"delete table ip owned\n")
            calls.append("nft")
            state["policy"] = payload.split(b"\n", 1)[1].decode()

    boundary = SimpleNamespace(GuestError=guest.GuestError, _Paths=lambda owner: (Path("root"), Path("unit"), Path("txn")),
                               _WireGuardState=WireGuard, _NftState=lambda owner, nonce: hashes[state["policy"]], _Run=Run,
                               _Table=lambda owner: "owned", _Interface=lambda owner: "owned", _Read=lambda path: path.parent.name.encode())
    monkeypatch.setattr(peers, "_Runtime", lambda *args: None)

    if expected is None:
        with pytest.raises(guest.GuestError, match="unrecorded"):
            peers._Converge(boundary, Path("new"), Path("old"), request, request, receipts["new"], receipts["old"], adding=adding)

        assert not calls

    else:
        peers._Converge(boundary, Path("new"), Path("old"), request, request, receipts["new"], receipts["old"], adding=adding)

        assert calls == expected and state == {"kernel": "new", "policy": "new"}


@pytest.mark.parametrize("approved", [True, False])
def test_OriginalInstallerLoaderExecutesOnlyItsExactPinnedPrivateBytes(approved: bool) -> None:
    """Mock only the private read boundary and never execute an installer, subprocess or filesystem operation."""

    source = (b'"""Synthetic pinned module for an in-memory loader check."""\nAPPROVED_SOURCE = True\n' if approved
              else b'raise AssertionError("Unapproved source must never execute")\n')
    boundary = SimpleNamespace(_RequireDigest=guest._RequireDigest, _Read=lambda path: source,
                               _Digest=guest._Digest, GuestError=guest.GuestError)

    if approved:
        loaded = peers._OriginalGuest(boundary, Path("fixture-private-stage"), hashlib.sha256(source).hexdigest())

        assert loaded.APPROVED_SOURCE is True and loaded.__file__.endswith("original.py")

    else:
        with pytest.raises(guest.GuestError, match="program pin"):
            peers._OriginalGuest(boundary, Path("fixture-private-stage"), "a" * 64)
