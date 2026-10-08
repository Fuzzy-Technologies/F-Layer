# First deployment

This walkthrough deploys the secure SSH gateway included in the stable release.
You need a Yandex Cloud account and an authenticated `yc` profile. Start with
`python -m flayer lifecycle --help` to inspect the available commands.

A deployment consists of explicit stack identity, a compiled resource plan,
owned local state, and bounded provider operations. A secure gateway adds a
reviewed server profile and separately owned device artifacts. Credentials
and private keys stay outside plans and documentation.

The secure artifact store currently requires POSIX ownership/mode checks and
descriptor-relative filesystem operations. Use Linux/macOS for this artifact
walkthrough; Windows persistence remains unsupported until an equivalent ACL
contract exists. Installation and offline diagnostics are separate capabilities.

## Operator sequence

1. Install from the desired source revision and configure the existing `yc` profile.
2. Prepare and validate the secure gateway profile locally.
3. Build the server artifacts and inspect the generated lifecycle plan/cloud-init.
4. Check that identity, folder, SSH key, management ranges and service ports match your intent.
5. Create with explicit mutation consent and exact folder confirmation.
6. Inspect provider observations, then run endpoint diagnostics separately.
7. Destroy only through the matching owned plan/state after reviewing the target scope.

Gateway profile compilation is local and does not contact the cloud, generate
private keys, or establish guest readiness. The first transport is a restricted
SSH local forward, with explicit target and per-device authorization. The profile does not assume an
A-VPN product, private NAS, fixed country, or implicit account.

## Prepare a secure gateway locally

Save this as `gateway.toml` in an operator-controlled working directory.
The folder, zone, image, management address, and public keys below are synthetic.
Replace them before deployment. Choose an Ubuntu 24.04 image compatible with
the explicit guest contract and the smallest appropriate management CIDRs.

```toml
schema_version = 1
profile = "secure-gateway"
guest_contract = "ubuntu-24.04-cloud-init"

[identity]
project = "example"
stack = "gateway"
provider = "yandex-cloud"
scope_id = "example-folder"
owner_id = "example-owner"

[gateway]
zone_id = "example-zone"
image_id = "example-ubuntu-image"
subnet_cidr = "10.42.0.0/24"
ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
management_cidrs = ["198.51.100.42/32"]
ssh_username = "gateway-admin"
ssh_port = 22
cores = 2
memory_gib = 2
boot_disk_gib = 20

[transport]
kind = "ssh-local-forward"
username = "gateway-tunnel"

[[transport.targets]]
name = "web"
host = "example.org"
port = 443

[[transport.devices]]
device_id = "laptop"
public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5"
source_cidrs = ["198.51.100.42/32"]
```

An allowed UDP port does not install a VPN. The SSH local forward uses the
configured SSH port; remove unused service entries and narrow their ranges
when possible. The generated
guest configuration disables password/root SSH login and IPv4 forwarding,
limits inbound access, and disables IPv6 for this initial profile. It does
not establish packet routing or readiness evidence. The separate non-sudo
transport account permits only the declared local-forward destinations and
per-device source CIDRs; administrative forwarding remains disabled.

Generate and inspect the owned server bundle and lifecycle plan locally
from a POSIX console:

```bash
python - <<'PY'
"""Prepare an owned gateway bundle without accessing a cloud account."""

import os
from pathlib import Path

from flayer.profiles import (
    BuildServerBundle, CompileGateway, LoadGatewayProfile, RenderPlan, WriteArtifactBundle,
)

os.umask(0o077)
profile = LoadGatewayProfile("gateway.toml")
directory = WriteArtifactBundle("generated-artifacts", BuildServerBundle(profile))
plan_text = RenderPlan(
    CompileGateway(profile), user_data_file=directory / "server-cloud-init.json",
)
plan_path = Path("generated-artifacts/plan.toml")

with plan_path.open("x", encoding="utf-8") as stream:
    stream.write(plan_text)

print(plan_path)
PY
```

The store publishes a new bundle exclusively with restrictive permissions and
an ownership/hash manifest. Existing bundles are never overwritten. `RenderPlan`
verifies the cloud-init bytes against the profile before binding their file
path. The resulting local path is machine-specific; keep the generated plan
and bundle outside Git and do not move the cloud-init file after compilation.

## Lifecycle command contract

Commands use the same explicit plan/state/profile:

```bash
python -m flayer lifecycle status --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --format json
python -m flayer lifecycle create --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
python -m flayer lifecycle recover --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

`status` reads provider observations. `create`, `recover`, and `destroy` require
both `--allow-mutation` and `--scope-confirm` equal to the plan's exact scope ID.
They must use the same ownership identity and operator-controlled state path.
Top-level diagnostic `status` remains separate from lifecycle `status`.

Successful creation establishes provider resources; it does not prove that
cloud-init finished or a client can connect. Test an
explicit endpoint with `health` only after selecting the appropriate guest
readiness checks for your deployment.

## Recovery and cleanup

Interrupted operations preserve a journal next to the state file.
A timed-out create may have succeeded remotely: recovery must identify the
exact owned logical resource rather than create a duplicate. An uncertain
missing resource keeps recovery blocked for operator investigation.

A hard process crash can leave a cooperative operation lock. Verify the old
process is dead and inspect the journal/state before manual lock removal;
F-Layer does not automatically erase a potentially active lock.

Rollback applies to resources created by that operation; exact owned resources
adopted from before the operation remain intact. Explicit cleanup uses:

```bash
python -m flayer lifecycle destroy --config generated-artifacts/plan.toml --state generated-artifacts/stack.json --yc-profile example --allow-mutation --scope-confirm example-folder --format json
```

Review the real folder and resource identity before substituting production
values. Provider ownership must match before deletion. Keep journal/state
until cleanup succeeds and interrupted outcomes are resolved.

After cloud cleanup is confirmed, remove the exact server bundle through its
ownership manifest rather than deleting an arbitrary directory:

```python
from flayer.profiles import LoadGatewayProfile, RemoveArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="server", name=profile.identity.stack,
)
```

## Connect one authorized device

Prepare the device private key yourself, corresponding to its public key in
`transport.devices`. Obtain and verify the server host key through a trusted
channel and place it in an explicit `known_hosts` file. The generator neither
reads private-key material nor accepts the first observed server key as trust.

Generate the device's usable SSH client configuration after the actual server
endpoint and trust paths are known:

```python
from flayer.profiles import BuildSshDeviceBundle, LoadGatewayProfile, WriteArtifactBundle

profile = LoadGatewayProfile("gateway.toml")
bundle = BuildSshDeviceBundle(
    profile, "laptop", endpoint="203.0.113.42",
    identity_file="/path/to/laptop-key",
    known_hosts_file="/path/to/trusted-known-hosts",
    local_ports=(8443,),
)
directory = WriteArtifactBundle("generated-artifacts", bundle)
print(directory / "ssh-client.conf")
```

`203.0.113.42` is a documentation address. Substitute the observed endpoint
and your explicit local key/trust paths; those generated paths are not portable.
Then keep the local forward running with:

```bash
ssh -F generated-artifacts/device-laptop/ssh-client.conf -N laptop
```

The example binds `127.0.0.1:8443` to the declared `example.org:443` destination.
Strict host-key checking is enabled, and the server limits which keys, source
ranges and destinations are permitted. A local forward carries the selected
connection; it is not a full-device VPN, packet router, or automatic client
installation. Inspect actual SSH/endpoint evidence before treating connectivity
as successful.

Device bundles have independent ownership manifests. Once no longer needed,
remove only the matching bundle with `RemoveArtifactBundle(..., kind="device",
name="laptop")`. Private keys and trusted host-key files remain separately
managed operator inputs.
