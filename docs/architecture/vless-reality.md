# VLESS Reality gateway

F-Layer prepares an Xray server and a separate import profile for each device.
VLESS authenticates each device with its own UUID. Reality encrypts the connection
using the server's X25519 key, the selected TLS server name, and a short ID. The
profile uses TCP and the `xtls-rprx-vision` flow.

This is an **application proxy**. The generated Xray client listens on
`127.0.0.1:10808`; applications must use that SOCKS5 proxy. Importing a VLESS link
into a graphical client does not, by itself, route the operating system's traffic.
For device-wide routing, enable that client's documented VPN/TUN mode and verify
its routing and DNS settings.

## Server requirements

Use Ubuntu 24.04 on amd64 or arm64. The VM must have Python 3, systemd, outbound
HTTPS access to GitHub release assets, and access to the selected Reality target.
F-Layer installs the official **Xray 26.3.27 stable release**, with a separate
pinned SHA-256 digest for each architecture. It does not run a downloaded shell
installer, use an unpinned container, or select a moving `latest` release.

The deployment's cloud security group and guest firewall must allow the selected
TCP port from the configured client networks. The VLESS installer does not flush
firewalls, widen SSH ingress, or change other transports.

Choose `target_host`, `target_port`, and `server_name` explicitly. The target must
be a reachable TLS 1.3 server with a certificate valid for `server_name`; follow
[Project X's Reality target guidance](https://github.com/XTLS/REALITY#readme).
F-Layer validates these settings' syntax. Before changing the guest service, the
installer checks the target from that VM: a certificate-valid TLS 1.3 handshake
must negotiate HTTP/2. A failed handshake stops installation with a target
preflight error. Repeat this check when the target or network conditions change.

## Private artifacts

`GenerateVlessMaterial()` creates one X25519 key pair and one UUID per device.
`EncodeVlessMaterial()` and `DecodeVlessMaterial()` let the controller retain these
credentials in its own sensitive artifact bundle before the cloud assigns an IP
address. Reuse that material when rendering clients for the actual endpoint.
Generating fresh material locally neither changes the deployed server nor revokes
its current clients. The installer rejects different input for an existing
deployment; this workflow does not yet support server-side credential rotation
or revocation through configuration replacement.

`PrepareVless()` produces these files:

| Bundle | File              | Purpose                                             |
| ------ | ----------------- | --------------------------------------------------- |
| Server | `server.json`     | Private Reality key and permitted device UUIDs      |
| Server | `deployment.json` | Ownership, configuration hash, port, pinned version |
| Server | `install.py`      | Bounded install, local health check, owned removal  |
| Device | `client.json`     | One device's loopback SOCKS client configuration    |
| Device | `import.txt`      | One device's VLESS Reality import URI               |

Every file is marked sensitive and exported through the existing private artifact
writer. Device bundles exclude the server private key and other devices' UUIDs.
The controller credential snapshot stays on the controller. Configuration intent,
cloud-init, provider resource state, diagnostics, and logs do not carry these
credentials.

The installer runs over a separately authenticated SSH connection. Its commands
are `sudo python3 install.py`, `sudo python3 install.py --check`, and
`sudo python3 install.py --remove`, using the private files beside the script.
The CLI is responsible for verifying the guest's host key before transfer.

## Routing and client import

The generated client JSON supports two IPv4 policies:

- `full`: proxy all IPv4 destinations requested by applications using this client;
- `split`: proxy the configured IPv4 destination networks and refuse unmatched
  destinations. It does not silently connect directly outside that list.

DNS servers are explicit IPv4 addresses. Both server and generated client use
these resolvers with `queryStrategy: UseIPv4`, including DNS lookup for routing.
A dual-stack hostname therefore does not match the IPv6 deny rule merely because
it also has an AAAA record. Split intent must include the DNS servers in its
allowed networks.
The server blocks private, loopback, link-local, multicast, and IPv6 destinations,
including the cloud metadata network. This transport therefore targets Internet
access, not access to a cloud VM's internal network.

The first version does not provide IPv6 routing. Disable IPv6 in the selected
client's VPN/TUN profile or at the device level when testing device-wide privacy.
A SOCKS configuration cannot block traffic from applications that bypass it.

The import URI includes the device UUID, server address and port, Reality public
key, short ID, server name, fingerprint, transport, and flow. Standard VLESS links
do **not** carry this project's full route and DNS policy. After import into
[v2rayN](https://github.com/2dust/v2rayN) or
[v2rayNG](https://github.com/2dust/v2rayNG), explicitly configure those settings and
the desired system proxy or VPN mode. The generated `client.json` preserves the
complete F-Layer application-proxy policy for Xray itself.

To inspect the raw Xray client locally, run the pinned executable with
`xray run -test -config client.json`, then `xray run -config client.json`.
An application can use `socks5h://127.0.0.1:10808`; the `h` requests remote hostname
resolution. Verify an HTTPS request through that proxy and compare its visible
source address with the deployed gateway's address.

## Installation, updates, and removal

The guest installer manages only `/opt/flayer/vless/<ownership-hash>` and its
corresponding `flayer-vless-<ownership-hash>.service`. It:

1. validates the private input's exact hash and ownership descriptor, then checks
   the target's TLS certificate, TLS 1.3, and HTTP/2 support;
2. verifies the pinned archive digest before inspecting the archive;
3. extracts only the regular `xray` executable, without extracting archive paths;
4. tests the generated configuration with that actual executable;
5. installs a hardened systemd service under a dynamic unprivileged user, with
   `LoadCredential` delivering the root-readable configuration;
6. confirms configuration syntax, systemd activity, and the local TCP listener.

A per-deployment lock rejects concurrent operations. Reapplying unchanged input
checks the running service without replacing credentials. Different configuration
bytes for an existing owned deployment are rejected before managed files or
services change. Credential rotation and revocation need a future explicit
expected-old authorization contract; silently replacing a working configuration
is not supported. Failed first installation removes the files created by that
attempt.

A forced process kill or power loss during initial installation can leave an incomplete
receipt. Subsequent operations then stop instead of guessing which files to
remove or overwrite. Inspect the owned deployment and restore its known private
bundle before retrying; automatic recovery from this interrupted state is not
implemented. Removal refuses unknown files, symlinks, changed credentials, and
foreign ownership. Empty ownership lock files remain to prevent lock-inode races.

## Validation and release evidence

Unit tests cover credential separation, import fields, split routing, malformed
settings, hash verification, malicious archive entries, unauthorized replacement rejection,
failed-install cleanup, private-file link rejection, and installer entry points.
`FLAYER_XRAY_BINARY` enables a targeted test that passes generated server and
client configurations to the actual checksum-verified Xray 26.3.27 executable.
CI also exercises its real router with static DNS and loopback-only sinks: public
dual-stack names and IPv4 pass, while private, metadata and IPv6 targets remain
blocked. These routing tests do not exercise a Reality handshake or external DNS.

These checks establish configuration and installer behavior. They are not proof
of an external VPN connection. Release acceptance still requires an authorized
cloud deployment, a real client connection, DNS and routing checks, and cleanup
of that deployment.

## Upstream references

- [Pinned Xray release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
- [Versioned Reality configuration parser](https://github.com/XTLS/Xray-core/blob/v26.3.27/infra/conf/transport_internet.go)
- [VLESS inbound configuration](https://xtls.github.io/en/config/inbounds/vless.html)
- [VLESS outbound configuration](https://xtls.github.io/en/config/outbounds/vless.html)
