"""AmneziaWG 3.1 preparation with private keys and a pinned Ubuntu guest installer."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import secrets
from dataclasses import asdict, dataclass, field
from textwrap import dedent

from flayer.profiles.artifacts import Artifact
from flayer.profiles.vpn import (
    BuildVpnDeviceBundle,
    BuildVpnServerBundle,
    PreparedVpnTransport,
    ValidateVpnTransport,
    VpnCapabilities,
    VpnEndpoint,
    VpnError,
    VpnProfile,
)

AMNEZIAWG_CAPABILITIES = VpnCapabilities("amneziawg", "ip-tunnel", ("full", "split"))
AMNEZIAWG_GO_VERSION = "v3.1.20260828"
AMNEZIAWG_GO_REVISION = "b5928efb6ca19f0153958460c3d141f04abc5c2e"
AMNEZIAWG_TOOLS_REVISION = "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"
GO_VERSION = "1.27.2"
GO_LINUX_AMD64_SHA256 = "ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5"
_PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(item) for item in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))


def _Key(value: object) -> str:
    """Validate one canonical, nonzero 32-byte key without echoing rejected secrets."""

    try:
        if not isinstance(value, str):
            raise ValueError

        raw = base64.b64decode(value, validate=True)

        if len(raw) != 32 or raw == bytes(32) or base64.b64encode(raw).decode() != value:
            raise ValueError

    except (ValueError, binascii.Error):
        raise VpnError("AmneziaWG keys must be canonical nonzero 32-byte base64 values") from None

    return value


def _PrivateKey() -> str:
    """Generate a WireGuard-compatible Curve25519 private key using cryptography."""

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    except ImportError:
        raise VpnError("AmneziaWG requires the f-layer[vpn] optional dependency") from None

    return base64.b64encode(X25519PrivateKey.generate().private_bytes_raw()).decode("ascii")


def _PublicKey(private_key: str) -> str:
    """Derive a peer public key without invoking shell tools or logging private material."""

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    except ImportError:
        raise VpnError("AmneziaWG requires the f-layer[vpn] optional dependency") from None

    key = X25519PrivateKey.from_private_bytes(base64.b64decode(_Key(private_key)))

    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


@dataclass(frozen=True, slots=True)
class AmneziaWgDeviceKey:
    """One device credential, excluded from diagnostic object representations."""

    device_id: str
    private_key: str = field(repr=False)

    def __post_init__(self) -> None:
        """Validate credential bytes and the public portable device name."""

        from flayer.core.contracts import ValidateName

        ValidateName(self.device_id, "device_id")
        _Key(self.private_key)


@dataclass(frozen=True, slots=True)
class AmneziaWgSecrets:
    """Private preparation input kept out of generic configuration, state, and repr."""

    server_private_key: str = field(repr=False)
    header_protection_key: str = field(repr=False)
    device_private_keys: tuple[AmneziaWgDeviceKey, ...] = field(repr=False)

    def __post_init__(self) -> None:
        """Require an immutable, bounded set of distinct private credentials."""

        _Key(self.server_private_key)
        _Key(self.header_protection_key)

        if (
            not isinstance(self.device_private_keys, tuple)
            or not 1 <= len(self.device_private_keys) <= 16
            or any(not isinstance(item, AmneziaWgDeviceKey) for item in self.device_private_keys)
            or len({item.device_id for item in self.device_private_keys}) != len(self.device_private_keys)
        ):
            raise VpnError("AmneziaWG secrets require 1..16 unique immutable device keys")

        keys = (self.server_private_key, self.header_protection_key) + tuple(
            item.private_key for item in self.device_private_keys
        )

        if len(set(keys)) != len(keys):
            raise VpnError("AmneziaWG server, header, and device keys must be distinct")


@dataclass(frozen=True, slots=True)
class AmneziaWgSettings:
    """Bounded IPv4 tunnel subnet and conservative client packet size."""

    tunnel_cidr: str = "10.66.0.0/24"
    mtu: int = 1280

    def __post_init__(self) -> None:
        """Reserve the first subnet host for the server and reject unsuitable subnets."""

        try:
            network = ipaddress.IPv4Network(self.tunnel_cidr, strict=True)

            if (
                str(network) != self.tunnel_cidr or not 16 <= network.prefixlen <= 28
                or not any(network.subnet_of(item) for item in _PRIVATE_NETWORKS)
            ):
                raise ValueError

        except (TypeError, ValueError):
            raise VpnError("AmneziaWG tunnel_cidr must be a canonical RFC1918 /16../28") from None

        if type(self.mtu) is not int or not 1280 <= self.mtu <= 1380:
            raise VpnError("AmneziaWG MTU must be an integer within 1280..1380")


def GenerateAmneziaWgSecrets(
    profile: VpnProfile, previous: AmneziaWgSecrets | None = None,
    *, rotate_device_ids: tuple[str, ...] = (),
) -> AmneziaWgSecrets:
    """Keep unchanged credentials while explicitly adding, rotating, or removing devices."""

    ValidateVpnTransport(profile, AMNEZIAWG_CAPABILITIES)
    device_ids = {item.device_id for item in profile.devices}

    if (
        not isinstance(rotate_device_ids, tuple)
        or any(not isinstance(item, str) or item not in device_ids for item in rotate_device_ids)
        or len(set(rotate_device_ids)) != len(rotate_device_ids)
        or (previous is not None and not isinstance(previous, AmneziaWgSecrets))
    ):
        raise VpnError("AmneziaWG rotation requires unique currently declared device IDs")

    old = {} if previous is None else {
        item.device_id: item.private_key for item in previous.device_private_keys
    }
    device_keys = tuple(AmneziaWgDeviceKey(
        item.device_id,
        old[item.device_id] if item.device_id in old and item.device_id not in rotate_device_ids
        else _PrivateKey(),
    ) for item in profile.devices)

    return AmneziaWgSecrets(
        _PrivateKey() if previous is None else previous.server_private_key,
        base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        if previous is None else previous.header_protection_key,
        device_keys,
    )


def EncodeAmneziaWgSecrets(secret_values: AmneziaWgSecrets) -> bytes:
    """Serialize controller-only credentials for an owned private material bundle."""

    if not isinstance(secret_values, AmneziaWgSecrets):
        raise VpnError("AmneziaWG material must be validated private credentials")

    data = {"schema_version": 1, **asdict(secret_values)}

    return (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _UniqueObject(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON fields before they can silently replace credential material."""

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError

        result[key] = value

    return result


def DecodeAmneziaWgSecrets(content: bytes) -> AmneziaWgSecrets:
    """Validate bounded private material without returning rejected bytes in errors."""

    try:
        if not isinstance(content, bytes) or not 1 <= len(content) <= 16384:
            raise ValueError

        data = json.loads(content.decode("utf-8"), object_pairs_hook=_UniqueObject)

        if (
            not isinstance(data, dict)
            or set(data) != {"schema_version", "server_private_key", "header_protection_key", "device_private_keys"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or not isinstance(data["device_private_keys"], list)
        ):
            raise ValueError

        keys = []

        for item in data["device_private_keys"]:
            if not isinstance(item, dict) or set(item) != {"device_id", "private_key"}:
                raise ValueError

            keys.append(AmneziaWgDeviceKey(item["device_id"], item["private_key"]))

        values = AmneziaWgSecrets(data["server_private_key"], data["header_protection_key"], tuple(keys))

    except (ValueError, TypeError, KeyError):
        raise VpnError("AmneziaWG private material is invalid or unsupported") from None

    return values


def AmneziaWgServiceName(profile: VpnProfile) -> str:
    """Derive a stable guest service name from complete stack ownership, not credentials."""

    payload = json.dumps(asdict(profile.identity), sort_keys=True, separators=(",", ":"))

    return "flayer-awg-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _Parameters(secret_values: AmneziaWgSecrets) -> list[str]:
    """Use compatible AWG 3.1 header protection and bounded variable padding on both ends."""

    return [
        "Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 32", "S2 = 32", "S3 = 32", "S4 = 32",
        "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4",
        f"HeaderProtectionKey = {secret_values.header_protection_key}",
        "ContentPaddingAddition = 0-64", "RandomTrailers = on",
    ]


def _Firewall(profile: VpnProfile, interface: str, table: str) -> str:
    """Limit forwarding to declared peer addresses and destinations and provide IPv4 NAT."""

    sources = ", ".join(str(item.ipv4_address) for item in profile.devices)
    destinations = ", ".join(profile.routes.ipv4_cidrs)

    return "\n".join([
        f"table ip {table} {{",
        "  chain forward {",
        "    type filter hook forward priority -10; policy accept;",
        f'    iifname "{interface}" oifname "{interface}" drop',
        f'    iifname "{interface}" ip daddr {{ 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 }} drop',
        f'    iifname "{interface}" ip saddr {{ {sources} }} ip daddr {{ {destinations} }} accept',
        f'    oifname "{interface}" ip daddr {{ {sources} }} ct state established,related accept',
        f'    iifname "{interface}" drop', f'    oifname "{interface}" drop',
        "  }", "  chain postrouting {",
        "    type nat hook postrouting priority srcnat; policy accept;",
        f'    iifname "{interface}" ip saddr {{ {sources} }} ip daddr {{ {destinations} }} masquerade',
        "  }", "}", "",
    ])


def _NetworkScript(base: str, interface: str, table: str, settings: AmneziaWgSettings) -> str:
    """Configure the foreground tunnel and replace only this stack's firewall table."""

    network = ipaddress.IPv4Network(settings.tunnel_cidr)
    server_address = f"{network.network_address + 1}/{network.prefixlen}"

    return dedent(f"""\
        #!/bin/bash
        set -euo pipefail
        export PATH=/usr/sbin:/usr/bin:/sbin:/bin
        case "${{1:-}}" in
          up)
            for attempt in {{1..50}}; do
              if [ -S /run/amneziawg/{interface}.sock ]; then break; fi
              sleep 0.1
            done
            [ -S /run/amneziawg/{interface}.sock ]
            {base}/bin/awg setconf {interface} {base}/server.conf
            ip address replace {server_address} dev {interface}
            ip link set dev {interface} mtu {settings.mtu} up
            sysctl -q -w net.ipv4.ip_forward=1
            if nft list table ip {table} >/dev/null 2>&1; then
              {{ printf 'delete table ip {table}\\n'; cat {base}/firewall.nft; }} | nft -f -
            else
              nft -f {base}/firewall.nft
            fi
            ;;
          down)
            if nft list table ip {table} >/dev/null 2>&1; then nft delete table ip {table}; fi
            ;;
          *) exit 2 ;;
        esac
        """)


def _Service(service: str, base: str, interface: str) -> str:
    """Keep tunnel startup and firewall recovery persistent across guest reboots."""

    return dedent(f"""\
        # Owned by {service}
        [Unit]
        Description=F-Layer AmneziaWG tunnel
        Wants=network-online.target
        After=network-online.target nftables.service
        [Service]
        Type=simple
        UMask=0077
        Environment=LOG_LEVEL=error
        ExecStart={base}/bin/amneziawg-go -f {interface}
        ExecStartPost={base}/network.sh up
        ExecStopPost={base}/network.sh down
        Restart=on-failure
        RestartSec=5
        TimeoutStartSec=30
        [Install]
        WantedBy=multi-user.target
        """)


def _Installer(service: str, base: str, interface: str) -> str:
    """Render the bounded root installer, ownership guard, health probe, and removal path."""

    template = r'''#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
base='@@BASE@@'
service='@@SERVICE@@'
unit="/etc/systemd/system/${service}.service"
[ "$(id -u)" -eq 0 ] || { echo 'Root privileges are required' >&2; exit 1; }
[ "$#" -le 1 ] || exit 2
[ ! -L /etc/flayer ]
exec 9>"/run/lock/${service}.lock"
flock -x 9
if [ -e "$base" ] || [ -L "$base" ]; then
  [ ! -L "$base" ] && [ -d "$base" ]
  [ -f "$base/owner" ] && [ ! -L "$base/owner" ]
  [ "$(cat "$base/owner")" = "$service" ]
  [ -z "$(find "$base" -type l -print -quit)" ]
  [ -z "$(find "$base" ! -user root -print -quit)" ]
  [ -z "$(find "$base" -type f -links +1 -print -quit)" ]
fi
if [ -e "$unit" ] || [ -L "$unit" ]; then
  [ ! -L "$unit" ] && [ -f "$unit" ]
  grep -qxF "# Owned by $service" "$unit"
fi
Check() {
  systemctl is-active --quiet "${service}.service"
  [ "$("$base/bin/awg" show @@INTERFACE@@ listen-port)" -gt 0 ]
  ip -4 address show dev @@INTERFACE@@ | grep -q 'inet '
  [ "$(sysctl -n net.ipv4.ip_forward)" = 1 ]
  nft list table ip @@TABLE@@ >/dev/null
}
case "${1:-}" in
  --check) Check; exit 0 ;;
  --remove)
    [ -d "$base" ] || exit 0
    systemctl disable --now "${service}.service"
    rm -f -- "$unit"
    rm -rf -- "$base"
    systemctl daemon-reload
    exit 0
    ;;
  '') ;;
  *) echo 'Usage: install.sh [--check|--remove]' >&2; exit 2 ;;
esac
. /etc/os-release
[ "$ID" = ubuntu ] && [ "$VERSION_ID" = 24.04 ]
[ "$(uname -m)" = x86_64 ]
[ -c /dev/net/tun ]
source_dir="$(cd -- "$(dirname -- "$0")" && pwd -P)"
for name in install.sh server.conf firewall.nft network.sh service.service; do
  [ -f "$source_dir/$name" ] && [ ! -L "$source_dir/$name" ]
  [ "$(stat -c '%u:%a:%h' "$source_dir/$name")" = '0:600:1' ]
done
payload_hash="$(cd "$source_dir" && sha256sum install.sh server.conf firewall.nft network.sh service.service | sha256sum | cut -d ' ' -f 1)"
if [ -f "$base/payload-hash" ] && [ "$(cat "$base/payload-hash")" = "$payload_hash" ]; then
  if Check; then exit 0; fi
fi
apt-get -q update
apt-get -q install --no-install-recommends -y ca-certificates curl git build-essential nftables iproute2
work="$(mktemp -d /var/tmp/flayer-awg.XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 20 --max-time 300 'https://go.dev/dl/go@@GO_VERSION@@.linux-amd64.tar.gz' \
  --output "$work/go.tar.gz"
printf '%s  %s\n' '@@GO_HASH@@' "$work/go.tar.gz" | sha256sum --check --status
mkdir "$work/toolchain"
tar -xzf "$work/go.tar.gz" -C "$work/toolchain"
export GOTOOLCHAIN=local GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org
export GOCACHE="$work/go-cache" GOPATH="$work/go-path" CGO_ENABLED=0
for component in go tools; do
  git init --quiet "$work/$component"
  git -C "$work/$component" remote add origin "https://github.com/amnezia-vpn/amneziawg-$component.git"
  if [ "$component" = go ]; then revision='@@GO_REV@@'; else revision='@@TOOLS_REV@@'; fi
  git -C "$work/$component" -c advice.detachedHead=false fetch --quiet --depth=1 origin "$revision"
  [ "$(git -C "$work/$component" rev-parse FETCH_HEAD)" = "$revision" ]
  git -C "$work/$component" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
done
printf 'package main\n\nconst Version = "@@GO_RELEASE@@"\n' > "$work/go/version.go"
(cd "$work/go" && "$work/toolchain/go/bin/go" build -mod=readonly -trimpath -buildvcs=false -o "$work/amneziawg-go" .)
make -s -C "$work/tools/src" wg
nft --check --file "$source_dir/firewall.nft"
had_previous=0
if [ -d "$base" ]; then
  cp -a -- "$base" "$work/previous"
  cp -- "$unit" "$work/previous.service"
  had_previous=1
  systemctl stop "${service}.service"
fi
Rollback() {
  trap - ERR
  systemctl stop "${service}.service" >/dev/null 2>&1 || true
  if [ "$had_previous" -eq 1 ]; then
    rm -rf -- "$base"
    cp -a -- "$work/previous" "$base"
    install -m 0644 "$work/previous.service" "$unit"
    systemctl daemon-reload
    systemctl start "${service}.service" >/dev/null 2>&1 || true
  else
    systemctl disable "${service}.service" >/dev/null 2>&1 || true
    rm -f -- "$unit"
    rm -rf -- "$base"
    systemctl daemon-reload
  fi
  echo 'AmneziaWG installation failed; inspect the guest service locally' >&2
  exit 1
}
trap Rollback ERR
install -d -m 0700 "$base" "$base/bin"
printf '%s\n' "$service" > "$base/owner"
printf '%s\n' "$payload_hash" > "$base/payload-hash"
install -m 0700 "$work/amneziawg-go" "$base/bin/amneziawg-go"
install -m 0700 "$work/tools/src/wg" "$base/bin/awg"
install -m 0600 "$source_dir/server.conf" "$base/server.conf"
install -m 0600 "$source_dir/firewall.nft" "$base/firewall.nft"
install -m 0700 "$source_dir/network.sh" "$base/network.sh"
install -m 0644 "$source_dir/service.service" "$unit"
systemctl daemon-reload
systemctl enable --now "${service}.service"
Check
trap - ERR
'''
    replacements = {
        "BASE": base, "SERVICE": service, "INTERFACE": interface,
        "TABLE": interface, "GO_VERSION": GO_VERSION, "GO_HASH": GO_LINUX_AMD64_SHA256,
        "GO_REV": AMNEZIAWG_GO_REVISION, "TOOLS_REV": AMNEZIAWG_TOOLS_REVISION,
        "GO_RELEASE": AMNEZIAWG_GO_VERSION,
    }

    for name, value in replacements.items():
        template = template.replace(f"@@{name}@@", value)

    return template


def PrepareAmneziaWg(
    profile: VpnProfile, endpoint: VpnEndpoint, settings: AmneziaWgSettings,
    secret_values: AmneziaWgSecrets,
) -> PreparedVpnTransport:
    """Produce deterministic private server/client artifacts without any external operation."""

    listener = ValidateVpnTransport(profile, AMNEZIAWG_CAPABILITIES)

    if (
        not isinstance(endpoint, VpnEndpoint) or endpoint.port != listener.port
        or listener.protocol != "udp" or not isinstance(settings, AmneziaWgSettings)
        or not isinstance(secret_values, AmneziaWgSecrets)
    ):
        raise VpnError("AmneziaWG requires matching UDP endpoint, settings, and private keys")

    device_keys = {item.device_id: item.private_key for item in secret_values.device_private_keys}

    if set(device_keys) != {item.device_id for item in profile.devices}:
        raise VpnError("AmneziaWG secrets must match exactly the declared devices")

    network = ipaddress.IPv4Network(settings.tunnel_cidr)

    for device in profile.devices:
        address = ipaddress.IPv4Address(str(device.ipv4_address))

        if address not in network or address in {
            network.network_address, network.network_address + 1, network.broadcast_address,
        }:
            raise VpnError("AmneziaWG device addresses must be usable nonserver tunnel hosts")

    public_keys = {key: _PublicKey(value) for key, value in device_keys.items()}
    server_public_key = _PublicKey(secret_values.server_private_key)

    if len(set(public_keys.values()) | {server_public_key}) != len(public_keys) + 1:
        raise VpnError("AmneziaWG peers must have distinct Curve25519 identities")

    parameters = _Parameters(secret_values)
    server_lines = ["[Interface]", f"PrivateKey = {secret_values.server_private_key}",
                    f"ListenPort = {listener.port}", *parameters]

    for device in profile.devices:
        server_lines.extend(["", "[Peer]", f"PublicKey = {public_keys[device.device_id]}",
                             f"AllowedIPs = {device.ipv4_address}/32"])

    service = AmneziaWgServiceName(profile)
    interface = "fa" + service.removeprefix("flayer-awg-")
    base = "/etc/flayer/" + service
    server_bundle = BuildVpnServerBundle(profile, "amneziawg", (
        Artifact("server.conf", ("\n".join(server_lines) + "\n").encode()),
        Artifact("install.sh", _Installer(service, base, interface).encode()),
        Artifact("firewall.nft", _Firewall(profile, interface, interface).encode()),
        Artifact("network.sh", _NetworkScript(base, interface, interface, settings).encode()),
        Artifact("service.service", _Service(service, base, interface).encode()),
    ))
    device_bundles = []

    for device in profile.devices:
        client_lines = [
            "[Interface]", f"PrivateKey = {device_keys[device.device_id]}",
            f"Address = {device.ipv4_address}/32", f"MTU = {settings.mtu}",
            "DNS = " + ", ".join(profile.routes.dns_servers), *parameters, "", "[Peer]",
            f"PublicKey = {server_public_key}", f"Endpoint = {endpoint.host}:{endpoint.port}",
            "AllowedIPs = " + ", ".join(profile.routes.ipv4_cidrs), "PersistentKeepalive = 25", "",
        ]
        device_bundles.append(BuildVpnDeviceBundle(profile, "amneziawg", device.device_id, (
            Artifact("amneziawg.conf", "\n".join(client_lines).encode()),
        )))

    return PreparedVpnTransport(profile, AMNEZIAWG_CAPABILITIES, server_bundle, tuple(device_bundles))
