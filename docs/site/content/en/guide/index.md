# Quick Start

Deploy a small server in Yandex Cloud, connect through it and remove the
resources when you finish. The stable **v1.2.1** walkthrough uses an SSH gateway:
it forwards selected connections through the server. The two-protocol VPN
workflow is being prepared for 2.0 and is not part of that stable package.

## 1. Check the installation

[Install the release package](installation.md), then run:

```bash
flayer check --format json
```

Expected result: `"status": "ok"`, exit code `0`. This confirms the local
installation. Cloud access is configured in the next step.

## 2. Connect your Yandex Cloud account

Use Linux or macOS for this walkthrough. Install and initialize the
[official Yandex Cloud CLI](https://yandex.cloud/en/docs/cli/quickstart), then
check the available profiles:

```bash
yc --version
yc config profile list
```

Keep the profile name and the ID of the cloud folder where you want the server.
In the commands below, replace `example` with that profile name and
`example-folder` with that folder ID. Your account needs permission to create
and remove compute and network resources there. Yandex Cloud charges for the
resources while they exist.

## 3. Prepare the server settings

Copy the `gateway.toml` example from [First deployment](first-deployment.md#prepare-a-secure-gateway-locally)
into a new working directory. Fill in the cloud folder ID, availability zone,
Ubuntu 24.04 image ID, management IP range and your SSH public keys. The example
creates a network, subnet, firewall, public address, boot disk and virtual machine.

Run the local preparation snippet in that guide. It creates the server's
cloud-init file and `generated-artifacts/plan.toml`. Inspect these files before
creating resources. Keep the configuration and generated files in the same
working directory for the remaining commands.

## 4. Create and inspect the deployment

```bash
flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
```

The first command creates cloud resources and records their IDs in `stack.json`.
The second reads their current state. Keep that state file: recovery and cleanup
use it to identify your resources. If creation is interrupted, use the
[recovery procedure](first-deployment.md#recovery-and-cleanup).

Once cloud-init has finished, follow [Connect one authorized device](first-deployment.md#connect-one-authorized-device)
to create the client configuration and open the SSH connection. With the example
settings, traffic to `127.0.0.1:8443` reaches `example.org:443` through the server.
A running virtual machine alone does not prove that this connection works.

## 5. Remove the resources

When you finish, review the folder and project names, then run:

```bash
flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

Check the command result and cloud state before discarding the state file.
The deployment guide also explains how to remove the generated local files.

## Other ways to use F-Layer

To check an existing HTTP service, replace the example URL with your endpoint:

```bash
flayer health --endpoint https://example.com/ --timeout 3 --format json
```

The [CLI guide](cli.md) explains diagnostics and exit codes. To integrate
F-Layer into Python, see [Configuration](configuration.md) and the
[API reference](../api/index.md). Yandex Cloud is the implemented cloud provider;
other providers need their own adapter before they can be used.

In command help, braces such as `{create,status,destroy,recover}` mean
**choose one command**. Do not type the braces.
