# F-Layer

![F-Layer with AIna in the Fuzzy Technologies engineering laboratory](https://raw.githubusercontent.com/Fuzzy-Technologies/F-Layer/master/docs/site/content/en/assets/brand/FTech-card-F-Layer.png)

**Your cloud infrastructure, managed from one configuration.**

F-Layer is an open-source infrastructure automation platform for engineers,
small teams and applications that need repeatable deployments. Describe your
environment, create its resources, check their state and remove the resources
belonging to that deployment through the same CLI or Python API.

The main workflow in **F-Layer 2.0** is a self-hosted VPN on **Yandex Cloud**:
one server running **AmneziaWG 3.1** and **VLESS Reality**, with separate
connection files for each device. You own the cloud account, server and keys;
you pay the cloud provider for resources and traffic.

[Documentation](https://fuzzy-technologies.github.io/F-Layer/) ·
[English](https://fuzzy-technologies.github.io/F-Layer/en/) ·
[Русский](https://fuzzy-technologies.github.io/F-Layer/ru/) ·
[简体中文](https://fuzzy-technologies.github.io/F-Layer/zh-CN/) ·
[Releases](https://github.com/Fuzzy-Technologies/F-Layer/releases)

## What you get

- **A VPN you control:** provision the VM, network, firewall, public IP and disk,
  install both services, and export private client profiles and native AmneziaVPN QR codes for both protocols.
- **Configurable resources:** choose CPU, RAM, platform, CPU performance level,
  disk size and HDD/SSD type in `project.toml`.
- **One deployment lifecycle:** inspect status, recover interrupted cloud
  operations and remove your stack using its retained local state.
- **More than VPN:** prepare restricted SSH gateways, run HTTP availability
  and timing checks, or integrate the infrastructure APIs into your application.

## Quick Start

### Deploy with an AI assistant

Give an assistant with terminal access this task:

> Deploy my self-hosted VPN using F-Layer: https://github.com/Fuzzy-Technologies/F-Layer.
> Read its AI operator guide and use documentation matching the installed package.
> Ask for my cloud, region and devices. Install a verified package, prepare a
> private project and show the resources, access rules, costs and cleanup plan.
> Obtain my approval before creating paid resources. Deploy through F-Layer's
> public CLI, help import the client profiles, and verify actual traffic.
> Keep secrets local and report what passed, what remains untested and how to
> remove the deployment.

The [AI operator guide](https://fuzzy-technologies.github.io/F-Layer/en/guide/ai-operator/)
covers the full workflow. The assistant supplies your choices and runs F-Layer;
F-Layer supplies the configuration, deployment lifecycle and client artifacts.

### Deploy manually

**Outcome:** a server in your Yandex Cloud folder and private connection files
you can import on your devices. Finish by checking real traffic through each protocol.

**You need:** Linux or a user-managed WSL Linux distribution, Python 3.11+,
OpenSSH (`ssh` and `ssh-keygen`), and an authenticated
[Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart) profile with
permissions in your chosen folder. Use an Ubuntu 24.04 **amd64** server image.
Git and Docker are not required to run the package. Windows can run local
package diagnostics; VPN deployment runs inside Linux/WSL.

#### 1. Install and check

Create and activate a virtual environment in Linux/WSL:

```bash
python3 -m venv ~/.venvs/flayer
source ~/.venvs/flayer/bin/activate
```

Download the wheel and `build-evidence.json` from the
[v2.0.1 release](https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v2.0.1).
Check the wheel SHA-256 against the build evidence, then install from the
download directory:

```bash
python -m pip install "./f_layer-2.0.1-py3-none-any.whl[vpn]"
```

After the separate PyPI publication, you can also install with
`python -m pip install "f-layer[vpn]==2.0.1"`. The `vpn` extra installs the
cryptography dependency needed for local key generation.

```bash
flayer --help
flayer check --format json
```

Expected: `"status": "ok"` and exit code `0`. This checks the local installation;
it does not contact the cloud or test VPN connectivity.

#### 2. Create your project

```bash
flayer project init ~/flayer-vpn
```

Edit `~/flayer-vpn/project.toml` before preparing it:

- Set `identity.scope_id` to your cloud folder ID and choose your project, stack and owner names.
- Set `cloud.yc_profile`, `zone_id` and `image_id` to your actual profile, zone
  and image. Choose a subnet that does not overlap your other networks.
- Set `cloud.management_cidrs` to your administrator public IPv4 with `/32`.
- List your `devices` with unique tunnel addresses; the template includes
  `laptop`. Choose full or split IPv4 routing in `[routes]`.
- Set `vless.target_host` and `server_name` to a reachable TLS 1.3 / HTTP/2
  target with a matching certificate; replace the example hostname.

For explicit server sizing, uncomment the complete `[resources]` block in the template:

```toml
[resources]
platform_id = "standard-v3"
cores = 2
core_fraction = 50
memory_gib = 2
disk_size_gib = 10
disk_type = "network-hdd"
```

Check regional availability and the image's minimum disk size. Omitting this
block retains the default 2 vCPU, 2 GiB RAM and 20 GiB SSD configuration.
See [configuration](https://fuzzy-technologies.github.io/F-Layer/en/guide/configuration/)
for supported combinations. Keep the project outside Git and shared folders;
in WSL, use its Linux filesystem rather than `/mnt/c`.

#### 3. Prepare and deploy

`prepare` generates local keys and artifacts without cloud calls. After this
step, keep the configuration unchanged and retain the project directory.

```bash
flayer vpn prepare --project ~/flayer-vpn
```

Review the selected resources and their cost. **The next command creates paid
cloud resources.** Replace `YOUR_FOLDER_ID` with the same `identity.scope_id`:

```bash
flayer vpn deploy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
flayer vpn status --project ~/flayer-vpn
```

Expected: owned cloud resources, both server services reported as
`services-active`, and per-device files under `~/flayer-vpn/artifacts/`.
Server status alone does not prove that a client can access the Internet.

#### 4. Connect a device

The client guide uses **AmneziaVPN 5.0.3.0 on Android**. For the template's
`laptop` device, find these files inside your project:

- **AmneziaWG:** import `artifacts/device-laptop-amneziawg/amneziawg.conf`.
- **VLESS Reality:** import `artifacts/device-laptop-vless-reality/amnezia.vpn`,
  or open `amnezia-qr-01.svg` from that directory on another screen and scan it
  with AmneziaVPN's scanner. If several numbered QR files exist, scan all of
  them in the same import session.

Connect one protocol at a time. Open an HTTPS site by hostname, verify the
server's public IPv4 as your exit address, and check DNS, routing and VPN/TUN settings.
This version routes **IPv4**; disable IPv6 on the client/device to prevent bypass.
The project's IPv6 setting does not change your device settings.
Keep client files and QR codes private: they grant access to your VPN.

See the [client walkthrough](https://fuzzy-technologies.github.io/F-Layer/en/guide/#4-connect-a-device)
for protocol-specific checks and import details.

## Manage your deployment

Use `flayer vpn status --project ~/flayer-vpn` to inspect your server.
For an interrupted cloud operation, retain the project and follow the
[recovery guide](https://fuzzy-technologies.github.io/F-Layer/en/guide/#5-recover-or-remove-the-deployment).
When you want to remove this project's cloud resources:

```bash
flayer vpn destroy --project ~/flayer-vpn --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

Verify removal in the report and cloud folder. Local keys, artifacts and state
remain on disk. Disconnecting a client does not remove billable cloud resources.

**Current boundaries:** Yandex Cloud is the implemented provider. Prepared
projects are immutable; in-place resizing, device addition/revocation and key
rotation are not available through the VPN CLI. Changing these settings requires
a new project and the documented lifecycle for the old deployment.

## Explore further

[SSH gateway](https://fuzzy-technologies.github.io/F-Layer/en/guide/first-deployment/) ·
[CLI diagnostics](https://fuzzy-technologies.github.io/F-Layer/en/guide/cli/) ·
[Python API](https://fuzzy-technologies.github.io/F-Layer/en/api/) ·
[Changelog](https://github.com/Fuzzy-Technologies/F-Layer/blob/master/CHANGELOG.md)

Built by **Fuzzy Technologies**. Licensed under
[Apache 2.0](https://github.com/Fuzzy-Technologies/F-Layer/blob/master/LICENSE).
To contribute, start with [CONTRIBUTING.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/CONTRIBUTING.md).
