# AmneziaWG deployment profile

F-Layer prepares an AmneziaWG 3.1 server and a separate importable `.conf` file
for each device. The server runs on Ubuntu 24.04, x86-64, with systemd and a
working `/dev/net/tun`. It uses the official userspace implementation, so it does
not require a third-party kernel module.

The public example is [`examples/vpn/amneziawg.toml`](../../examples/vpn/amneziawg.toml).
Its device addresses belong to `10.66.0.0/24`; `10.66.0.1` is reserved for the
server. Choose a different private subnet if this overlaps a network you use.

## Traffic and client support

In full mode, all **IPv4** destinations use the tunnel. In split mode, only the
listed destinations use it. The DNS addresses must be covered by those routes.
Server forwarding follows the same destination list and applies IPv4 NAT.
Clients cannot forward traffic to other VPN clients or the cloud metadata
address range.

IPv6 is not supported by this profile. Disable IPv6 on the client connection
before using it as a full tunnel; `ipv6_policy = "disabled"` records that
prerequisite, but does not change the client's operating system. F-Layer does
not add `::/0` to an IPv4-only server. Enabling a client kill switch or disabling
IPv6 is a separate client-side action and must be verified on the actual device.

Use a native AmneziaWG client that supports protocol 3.1:

- [AmneziaWG for Windows 3.1.0](https://github.com/amnezia-vpn/amneziawg-windows-client/releases/tag/3.1.0).
- [AmneziaWG for Android v3.1.20260814](https://github.com/amnezia-vpn/amneziawg-android/releases/tag/v3.1.20260814).

Import the device's `amneziawg.conf` using the client's **Import from file**
action, then activate the tunnel. Keep one configuration per device. A plain
WireGuard client and older AmneziaWG clients cannot read all the generated 3.1
settings. See the [official import instructions](https://docs.amnezia.org/documentation/instructions/awg-app/).

## Preparation and credential handling

`GenerateAmneziaWgSecrets()` creates Curve25519 keys with the `cryptography`
optional dependency, plus an independent 32-byte header-protection key.
`PrepareAmneziaWg()` renders the validated public profile, endpoint, settings,
and those keys into owned server and device bundles. Rendering performs no
filesystem, network, or cloud operations. The same inputs produce the same bytes.

The server bundle has five files:

| File              | Purpose                                                         |
| ----------------- | --------------------------------------------------------------- |
| `server.conf`     | Server private key, obfuscation settings, and peer public keys. |
| `install.sh`      | Pinned installation, health checks, replacement, and removal.   |
| `firewall.nft`    | Per-interface IPv4 forwarding restrictions and NAT.             |
| `network.sh`      | Tunnel address, MTU, forwarding, and owned firewall activation. |
| `service.service` | Persistent systemd service for the userspace tunnel.            |

All bundle files are classified as sensitive. Client private keys appear only
in their respective client bundles and the controller's private credential
store. They are absent from `server.conf`. Never copy the controller's encoded
credential material to the guest, cloud-init metadata, generic resource state,
logs, or a Git repository.

`EncodeAmneziaWgSecrets()` and `DecodeAmneziaWgSecrets()` support bounded private
controller storage. This allows preparation before the cloud assigns an IP
address, followed by client rendering with the real endpoint and the same keys.
Store those bytes using the existing private owned-artifact contract.

To add or remove a device, change public intent and call
`GenerateAmneziaWgSecrets(profile, previous)` with the retained credentials.
Unchanged devices and the server retain their keys. To replace one compromised
device key, explicitly supply `rotate_device_ids=("phone",)`.
Preparation alone does not revoke a device: deploy the replacement server
configuration first, verify it, and only then remove obsolete local artifacts.

## Guest installation contract

The provisioning adapter must verify the SSH host key and transfer the five
server files into a private staging directory on the intended guest. Files must
be regular, root-owned, mode `0600`, and have exactly one hard link. Execute:

```bash
sudo bash ./install.sh
sudo bash ./install.sh --check
```

The installer verifies Ubuntu 24.04 and x86-64, installs standard build/network
dependencies through the distribution's authenticated APT repositories, and
builds the pinned official upstream source. It verifies the Go archive's SHA-256
before extraction, verifies both Git revisions before building, and requires
Go's module checksum database with a read-only dependency graph. HTTPS access to
GitHub, `go.dev`, and the Go module proxy/checksum service is required during
initial installation.

| Component       | Pin                                                                |
| --------------- | ------------------------------------------------------------------ |
| AmneziaWG Go    | `v3.1.20260828`, commit `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| AmneziaWG tools | `v3.1.20260812`, commit `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` |
| Go compiler     | `1.27.2`, official Linux amd64 archive with a pinned SHA-256.      |

The service and interface names derive from the complete stack ownership
identity. Installation refuses foreign or symlinked managed paths. Repeating an
unchanged healthy installation returns without reinstalling dependencies. A
changed configuration is backed up before replacement; a failed service start
restores the previous files and attempts to restart the previous service.
The systemd unit starts the tunnel and its owned firewall rules after a reboot.

The guest bootstrap must explicitly allow the declared UDP ingress and permit
the forwarding path used by this profile. The original SSH application gateway
has a forwarding policy of `drop` and cannot be reused unchanged: an `accept`
rule in another nftables base chain does not override that drop. This installer
never flushes unrelated firewall rules. `network.sh` enables IPv4 forwarding
when the service starts.

`--check` verifies the systemd unit, tunnel listen port, assigned IPv4 address,
IPv4 forwarding, and owned nftables table. It does not claim a client handshake,
internet reachability, DNS success, or protection against a particular network's
traffic filtering. Test those from a real client after deployment.

`sudo bash ./install.sh --remove` removes only the ownership-verified service
and its private guest files. It leaves distribution packages and global
forwarding settings alone because other profiles may use them. Destroying the
owned cloud instance remains the lifecycle adapter's responsibility.

## Evidence and upstream references

Targeted tests cover distinct device keys, exact secret redaction, native client
INI parsing, deterministic bundles, full/split routes, peer replacement,
malformed inputs, encoded private material, ownership-derived names, and shell
syntax. The official pinned AmneziaWG tools parser also accepted a generated
server configuration in a local parser-only probe. Both pinned upstream tools
and the Go daemon compiled locally with the selected dependencies. This does
not constitute a live cloud or device tunnel test.

- [Official AmneziaWG 3.1 configuration](https://docs.amnezia.org/documentation/amnezia-wg/).
- [Official userspace installation guide](https://docs.amnezia.org/documentation/instructions/install-amneziawg-go/).
- [Pinned userspace source](https://github.com/amnezia-vpn/amneziawg-go/tree/b5928efb6ca19f0153958460c3d141f04abc5c2e).
- [Pinned tools source](https://github.com/amnezia-vpn/amneziawg-tools/tree/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843).
- [Official Go downloads and checksums](https://go.dev/dl/).
