"""Check pure service-source and AWG observation codecs without guest files, processes, sockets or commands."""

from __future__ import annotations

import copy
import struct
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest
from test_amneziawg_profile import Profile

from flayer._vpn_creation import BundleDigest
from flayer.core.contracts import StackIdentity, _WireDict
from flayer.profiles import _protocol_completion as completion
from flayer.profiles import _protocol_reservation as authority
from flayer.profiles import _protocol_runtime as runtime
from flayer.profiles import _protocol_services as services
from flayer.profiles import _wireguard_guest as guest
from flayer.profiles.amneziawg import AmneziaWgSettings, GenerateAmneziaWgSecrets, PrepareAmneziaWg
from flayer.profiles.vless import (
    LEGACY_XRAY_VERSION,
    XRAY_VERSION,
    GenerateVlessMaterial,
    PrepareVless,
    VlessRealitySettings,
)
from flayer.profiles.vpn import VpnEndpoint, VpnListener


def Sources(protocols: tuple[str, ...] = ("amneziawg", "vless-reality"), *, stackIdentity: StackIdentity | None = None) -> tuple[dict[str, str], list[dict[str, Any]], list[dict[str, Any]]]:
    """Generate only synthetic private in-memory bundles, pinned exactly as real retained source metadata would be."""

    profile = Profile()

    if stackIdentity is not None:
        profile = replace(profile, identity=stackIdentity)

    bundles = []
    records = []
    identity = _WireDict(profile.identity)

    for protocol in protocols:
        if protocol == "amneziawg":
            prepared = PrepareAmneziaWg(profile, VpnEndpoint("198.51.100.10", 51820), AmneziaWgSettings(), GenerateAmneziaWgSecrets(profile))

        else:
            selected = replace(profile, listeners=(VpnListener(protocol, "tcp", 443, ("0.0.0.0/0",)),))
            prepared = PrepareVless(selected, VpnEndpoint("198.51.100.10", 443), VlessRealitySettings("example.org", "example.org"), GenerateVlessMaterial(selected))

        bundle = prepared.serverBundle
        bundles.append({"protocol": protocol, "name": bundle.name, "files": {item.name: item.content for item in bundle.files}})
        records.append({"schema_version": 1, "identity": identity, "pin": {"protocol": protocol, "intent_fingerprint": "a" * 64,
                        "material_digest": "b" * 64, "server_digest": BundleDigest(bundle)}, "kind": "initial", "request_name": "", "request_sha256": ""})

    return identity, records, bundles


def Observer(identity: dict[str, str], sources: list[dict[str, Any]], bundles: list[dict[str, Any]]) -> services.ServiceObserver:
    """Supply version constants as a pure dependency; the POSIX-only VLESS helper is never imported or executed here."""

    vless = SimpleNamespace(XRAY_VERSION=XRAY_VERSION, LEGACY_VERSION=LEGACY_XRAY_VERSION)

    return services.ServiceObserver(guest, authority, completion, runtime, vless, identity, sources, bundles)


def Configuration() -> bytes:
    """Choose one complete generated private AWG configuration without exposing key values in test diagnostics."""

    return Sources(("amneziawg",))[2][0]["files"]["server.conf"]


def test_ActualAwgObservationIgnoresOnlyLearnedEndpointsAndNormalizesPinnedCookieDefault() -> None:
    """The pinned Go UAPI omits unset timing overrides and reports disabled-cookie false; learned endpoints are ordinary mutable traffic facts."""

    expected = Configuration()
    observed = expected.replace(b"RandomTrailers = on", b"RandomTrailers = on\nDisableCookies = off")
    observed = observed.replace(b"AllowedIPs = ", b"Endpoint = 203.0.113.10:45678\nAllowedIPs = ")
    assert services.MatchConfiguration(guest, expected, observed) == services.Configuration(guest, expected)
    assert services.MatchConfiguration(guest, expected, observed.replace(b"203.0.113.10:45678", b"[2001:db8::1]:54321")) == services.Configuration(guest, expected)


@pytest.mark.parametrize("directive", [
    "RekeyAfterTime = 120", "RekeyTimeout = 5", "RejectAfterTime = 180", "KeepaliveTimeout = 10",
    "MaxHandshakeAttempts = 18", "DisableCookies = on", "FwMark = 0x1", "I1 = custom-packet",
])
def test_ExtraConfigurationAffectingAwgOverridesCannotBeAdoptedAsSourceBoundHealth(directive: str) -> None:
    """Even a plausible timing override is not present in the retained source and must not become a new baseline."""

    expected = Configuration()
    observed = expected.replace(b"RandomTrailers = on", ("RandomTrailers = on\n" + directive).encode())

    with pytest.raises(ValueError):
        services.MatchConfiguration(guest, expected, observed)


@pytest.mark.parametrize("directive", ["AdvancedSecurity = on", "AdvancedSecurity = off", "PersistentKeepalive = 25", "PresharedKey = unexpected", "Endpoint = invalid"])
def test_UnconfiguredPeerOverridesRefuseInsteadOfBeingHiddenByEndpointNormalization(directive: str) -> None:
    """Only a syntactically bounded learned endpoint is excluded; protocol, key and keepalive changes remain explicit refusals."""

    expected = Configuration()
    observed = expected.replace(b"AllowedIPs = ", (directive + "\nAllowedIPs = ").encode(), 1)

    with pytest.raises(ValueError):
        services.MatchConfiguration(guest, expected, observed)


@pytest.mark.parametrize("fault", ["private-key", "header-key", "port", "header", "padding", "peer-key", "peer-address", "duplicate", "unknown-section", "empty"])
def test_ChangedOrMalformedLiveAwgConfigurationCannotProduceAProof(fault: str) -> None:
    """Every retained credential and peer role is compared without exposing rejected values in errors."""

    expected = Configuration()
    raw = expected

    if fault in {"private-key", "header-key", "peer-key"}:
        key = {"private-key": b"PrivateKey", "header-key": b"HeaderProtectionKey", "peer-key": b"PublicKey"}[fault]
        line = next(item for item in raw.splitlines() if item.startswith(key + b" = "))
        raw = raw.replace(line, key + b" = " + b"A" * 43 + b"=", 1)

    elif fault == "port":
        raw = raw.replace(b"ListenPort = 51820", b"ListenPort = 51821")

    elif fault == "header":
        raw = raw.replace(b"H1 = 1\n", b"H1 = 999\n")

    elif fault == "padding":
        raw = raw.replace(b"S1 = 32", b"S1 = 33")

    elif fault == "peer-address":
        raw = raw.replace(b"10.66.0.2/32", b"10.66.0.99/32")

    elif fault == "duplicate":
        raw = raw.replace(b"ListenPort = 51820", b"ListenPort = 51820\nListenPort = 51820")

    elif fault == "unknown-section":
        raw += b"[Unknown]\nValue = ignored\n"

    else:
        raw = b""

    with pytest.raises(ValueError):
        services.MatchConfiguration(guest, expected, raw)


@pytest.mark.parametrize("fault", ["missing", "extra", "order", "source-pin", "file", "name", "version", "config", "private-field"])
def test_ServiceSourceBindingRefusesMalformedPrivateBundlesBeforeAnyGuestIo(monkeypatch: pytest.MonkeyPatch, fault: str) -> None:
    """A claimed public source hash cannot substitute for all actual retained server bytes and their complete owner/name identity."""

    identity, sources, bundles = Sources()
    sources, bundles = copy.deepcopy(sources), copy.deepcopy(bundles)

    if fault == "missing":
        bundles.pop()

    elif fault == "extra":
        bundles.append(copy.deepcopy(bundles[0]))

    elif fault == "order":
        bundles.reverse()

    elif fault == "source-pin":
        sources[0]["pin"]["server_digest"] = "0" * 64

    elif fault == "file":
        bundles[0]["files"]["server.conf"] += b"changed"

    elif fault == "name":
        bundles[0]["name"] = "other-owner"

    elif fault == "version":
        sources[0]["schema_version"] = True

    elif fault == "config":
        bundles[1]["files"]["server.json"] += b"changed"

    else:
        sources[0]["private_key"] = "forbidden"

    monkeypatch.setattr(guest, "_Directory", lambda *args, **kwargs: pytest.fail("Invalid source must refuse before guest filesystem access"))
    monkeypatch.setattr(guest, "_Run", lambda *args, **kwargs: pytest.fail("Invalid source must refuse before guest command execution"))

    with pytest.raises(ValueError):
        Observer(identity, sources, bundles)


def test_ObserveCannotImplicitlyAcquireLocksOrRepairTheGuest() -> None:
    """Pure source validation grants no live attestation; the caller must enter the explicit trusted lease."""

    identity, sources, bundles = Sources()
    observer = Observer(identity, sources, bundles)

    with pytest.raises(ValueError, match="active pinned lease"):
        observer.Observe(guest, sources)


def CredentialAcl() -> bytes:
    """Represent systemd's exact root-owner, named dynamic-user read and otherwise inaccessible POSIX access ACL."""

    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", tag, permissions, identity) for tag, permissions, identity in
        ((1, 4, 0xFFFFFFFF), (2, 4, 61234), (4, 0, 0xFFFFFFFF), (16, 4, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF)))


def test_LoadedCredentialAcceptsOnlyTheActualSystemdReadOnlyOwnershipAndAclLayouts() -> None:
    """POSIX ACL masks expose mode 0440 despite an empty owning-group ACL; validate the named process UID rather than granting group access."""

    assert services.CredentialAccess(0o400, 0, 61234, 0, None)
    assert services.CredentialAccess(0o400, 61234, 61234, 0, None)
    assert services.CredentialAccess(0o440, 0, 61234, 0, CredentialAcl())


@pytest.mark.parametrize("fault", ["write", "owner", "process", "group", "other", "mask", "version", "extra", "missing", "no-acl"])
def test_LoadedCredentialAclCannotGrantAnotherIdentityOrPermission(fault: str) -> None:
    """Root ownership and familiar mode bits alone cannot attest a credential that grants an unrelated reader or writer."""

    mode, owner, process = 0o440, 0, 61234
    acl: bytes | None = CredentialAcl()

    if fault == "write":
        mode = 0o640

    elif fault == "owner":
        owner = 12345

    elif fault == "process":
        process = 61235

    elif fault in {"group", "other", "mask"}:
        data = bytearray(acl)
        struct.pack_into("<H", data, {"group": 22, "mask": 30, "other": 38}[fault], 6 if fault == "mask" else 4)
        acl = bytes(data)

    elif fault == "version":
        acl = struct.pack("<I", 3) + acl[4:]

    elif fault == "extra":
        acl += struct.pack("<HHI", 2, 4, 61235)

    elif fault == "missing":
        acl = acl[:-8]

    else:
        acl = None

    assert not services.CredentialAccess(mode, owner, process, 0, acl)
