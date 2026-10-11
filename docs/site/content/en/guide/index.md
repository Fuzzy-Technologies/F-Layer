# Quick Start

Create a private VPN project, deploy one Yandex Cloud server, and connect a device
using **AmneziaWG** or **VLESS Reality**. F-Layer creates the cloud resources,
installs both services and exports separate client settings for each device.

## 1. Install F-Layer

To delegate these steps to an assistant with terminal access, copy the task from
[AI Quick Start](ai-operator.md). It covers installation, the questions the
assistant should ask, paid-resource approval and evidence of a working connection.
The commands below are the manual route.

Use Linux or WSL, Python 3.11+, OpenSSH (`ssh` and `ssh-keygen`), and the
[official Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart).
Download the F-Layer 2.0.0 wheel and verify its hash as described in
[Install](installation.md). Create and activate a virtual environment, then
install the wheel with its `vpn` extra. Replace the path with your downloaded file:

```bash
FLAYER_WHEEL=/absolute/path/to/f_layer-2.0.0-py3-none-any.whl
python -m pip install "${FLAYER_WHEEL}[vpn]"
flayer project --help
flayer vpn --help
```

The extra supplies cryptography for local keys and Segno for offline QR export.
Git and Docker are not needed.

## 2. Set up the project

Initialize `yc` using its official instructions, then inspect your profiles:

```bash
yc config profile list
flayer project init ~/flayer-vpn
```

Open `~/flayer-vpn/project.toml`. Replace these values before preparation:

| Setting                                  | What to enter                                                                                                        |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `identity.project`, `stack`, `owner_id`  | Names identifying your project, deployment and owner.                                                                |
| `identity.scope_id`                      | The Yandex Cloud folder ID in which to create resources.                                                             |
| `cloud.yc_profile`                       | The configured `yc` profile with permission to create and remove compute and network resources in that folder.       |
| `cloud.zone_id`, `cloud.image_id`        | Your availability zone and an Ubuntu 24.04 **amd64** image ID.                                                       |
| `cloud.management_cidrs`                 | Your current public administrator IPv4 address with `/32`; replace the example address.                              |
| `devices`                                | Device names and unique tunnel addresses, starting with the example `laptop` / `10.66.0.2`.                          |
| `vless.target_host`, `vless.server_name` | A reachable TLS 1.3 / HTTP/2 site with a valid certificate for the server name. The supplied hostname is an example. |

Keep the initial route settings to try full IPv4 routing. Before connecting,
disable IPv6 in the VPN client's settings or on the device: this version does
not route IPv6. Changing `ipv6_policy` in TOML does not change the device's OS.

The project directory contains private SSH and VPN keys. Keep it outside Git and
shared directories, retain its access permissions, and keep a private backup.
Decide which devices and routes you need before the next step.

## 3. Prepare and deploy

```bash
flayer vpn prepare --project ~/flayer-vpn
flayer vpn deploy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
flayer vpn status --project ~/flayer-vpn
```

Replace `YOUR_FOLDER_ID` with the exact `identity.scope_id` value. `prepare`
creates local files without contacting the cloud. `deploy` creates a network,
subnet, security group, public address, boot disk and VM, then installs both VPN
services. Yandex Cloud bills for those resources while they exist.

F-Layer verifies the VM's SSH host key against the key obtained through the
Yandex API for that owned VM before transferring private files. A deployment
report showing `services-active` confirms running server processes; the client
connection still needs the check below.

Before `deploy`, `status`, `recover` or `destroy`, F-Layer checks that the
configured `cloud.yc_profile` can read `identity.scope_id`. Failed preflight
stops before cloud lifecycle operations and preserves existing state and journals.
For `authentication`, renew the profile through the official local sign-in flow;
for `permission_denied`, verify folder access. A `timeout` alone proves neither
expired credentials nor an API outage. Keep credentials private and follow the
[AI operator troubleshooting steps](ai-operator.md#5-deploy-and-observe).
The probe does not verify write permissions or guarantee access for the whole run.

## 4. Connect a device

Use **AmneziaVPN 5.0.3.0 for Android** as the reference client. Use the files for
your device; the paths below use the default `laptop` device name.

1. In AmneziaVPN, add a connection from a file and select
   `artifacts/device-laptop-amneziawg/amneziawg.conf` for AmneziaWG. Ordinary
   WireGuard clients do not understand the additional AmneziaWG 3.1 fields.
2. For VLESS, open `artifacts/device-laptop-vless-reality/amnezia-qr-01.svg`
   locally on another screen and scan it with **AmneziaVPN's own scanner**.
   If there are several numbered QR files, scan all of them in the same import
   session. Alternatively, import `amnezia.vpn` as a connection file or paste
   its `vpn://` connection key. Do not use a QR of `import.txt` with this scanner.
3. Enable the Android VPN connection and accept Android's VPN permission.
   Check full-device VPN/TUN mode, the intended DNS servers and any app or
   destination exclusions. The native profile contains the generated Xray DNS
   and routing policy, but application settings can override it. Disable IPv6
   in the client/device as described above; IPv4 success does not prove IPv6
   cannot bypass the connection.
4. Test the protocols **one at a time**, disconnecting the other profile first.
   Open an HTTPS site by hostname, check that the visible public IPv4 matches
   the server, and verify actual traffic plus DNS, routes and IPv6 behavior.
   `services-active`, `connectivity=not-verified`, successful import or a client
   showing “Connected” are not confirmation of Internet access.

Keep the profile, QR files and connection keys private; each grants access for
that device. Files retain mode `0600` inside private `0700` bundle directories.
Do not upload them to online QR converters or issue trackers.

For either protocol, use [local device export](cli.md#export-an-existing-vpn-device)
to obtain a native AmneziaVPN connection file and optional QR frames from existing
device files. For application-specific failures, follow the
[Shorts/Telegram diagnostic comparison](cli.md#investigate-shorts-and-telegram-media).

The separate standard VLESS URI remains in `import.txt` for clients such as
v2rayNG; it does not carry the full DNS/routing policy. `client.json` preserves
the complete Xray application-proxy policy and listens on `127.0.0.1:10808`.
Run it with the pinned Xray version, then compare these two HTTPS checks:

```bash
curl --fail --show-error --max-time 20 --proxy socks5h://127.0.0.1:10808 https://example.com/
curl --fail --show-error --max-time 20 --ipv4 --proxy socks5://127.0.0.1:10808 https://example.com/
```

Both must succeed. The first resolves the hostname through the proxy; the second
resolves IPv4 locally. Test an operator-selected exit-IP endpoint as well.
SOCKS checks cover only applications using that proxy, not Android VPN/TUN mode.
TLS 1.3/HTTP2 target preflight also does not prove Reality authentication: repeat
actual client traffic checks after changing the target or Xray version.
See the [AmneziaWG](../../../../architecture/amneziawg.md) and
[VLESS Reality](../../../../architecture/vless-reality.md) guides for details.

## 5. Recover or remove the deployment

If cloud creation was interrupted, keep the same project files and use:

```bash
flayer vpn recover --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

Read the report before retrying. A guest installation interrupted partway through
may require inspection and restoration of its known private files; cloud recovery
does not authorize overwriting an unknown server configuration.

To remove the cloud resources belonging to this project:

```bash
flayer vpn destroy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

Check the result and the cloud folder. Local keys, client files and state remain
in the project directory. Keep them until cleanup is confirmed.

Prepared project settings are immutable in this version. To add a device or
change routes, first destroy the old deployment using its unchanged project,
then initialize a **new private project directory** with the desired settings.
The CLI does not yet offer in-place device addition, revocation or key rotation.

## Next steps

Yandex Cloud is the implemented cloud provider. Other clouds require an adapter.
For existing services, use [CLI diagnostics](cli.md); for Python integrations,
see [Configuration](configuration.md) and the [API reference](../api/index.md).
Release maintainers record real cloud and client checks in the
[VPN release acceptance procedure](../../../../development/vpn-release-acceptance.md).

In command help, braces such as `{prepare,deploy,status,destroy,recover}` mean
**choose one command**. Do not type the braces.
