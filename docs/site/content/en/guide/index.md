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

The extra supplies the cryptography library used to generate keys locally.
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

## 4. Connect a device

Use the files for your own device. For the default `laptop` device:

| Protocol      | Import                                                                     | Client setup                                                                                                                                    |
| ------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| AmneziaWG     | `~/flayer-vpn/artifacts/device-laptop-amneziawg/amneziawg.conf`            | Import into an AmneziaWG 3.1-compatible client and activate the tunnel. Ordinary WireGuard clients do not understand the added protocol fields. |
| VLESS Reality | The URI in `~/flayer-vpn/artifacts/device-laptop-vless-reality/import.txt` | Import into a compatible client such as v2rayN or v2rayNG. Set DNS, routing and VPN/TUN mode explicitly for device-wide traffic.                |

A VLESS import link does not carry the complete DNS and route policy. For the
raw Xray client, the same directory contains `client.json`, which preserves the
application-proxy policy and listens on `127.0.0.1:10808`. Applications must use
`socks5h://127.0.0.1:10808`; this does not automatically route other applications.
See the [AmneziaWG](../../../../architecture/amneziawg.md) and
[VLESS Reality](../../../../architecture/vless-reality.md) guides for compatible
clients, split routing and protocol details.

Test the protocols **one at a time**. Open an HTTPS site through each client,
check that the visible public IPv4 address is the server's address, and verify
DNS and IPv6 behavior. A successful import or active server service alone does
not prove that traffic is using the tunnel.

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
