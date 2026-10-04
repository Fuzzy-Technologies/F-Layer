# Secure gateway profile

The first `secure-gateway` profile prepares a restricted SSH application gateway
for an explicitly selected Ubuntu 24.04 cloud-init image. Its encrypted TCP
forwards have exact destination allowlists. It does not configure a full IP VPN.

The versioned example is [secure-gateway.toml](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/examples/secure-gateway.toml).
Every identifier, source CIDR, and synthetic public key must be replaced before
deployment. The example uses documentation addresses and no real infrastructure.

## Contracts and limits

| Boundary              | Required behavior                                                      |
| --------------------- | ---------------------------------------------------------------------- |
| Profile schema        | Version 1; unknown fields and inline private credentials rejected.     |
| Placement             | Explicit provider identity, scope, owner, zone, and image.             |
| Subnet                | Canonical RFC1918 IPv4 subnet with prefix `/16` through `/28`.         |
| Management access     | Explicit administrator public key; 1–16 source CIDRs of `/24`–`/32`.   |
| SSH transport         | Separate non-sudo account; 1–8 exact TCP destinations.                 |
| Device authorization  | 1–16 devices with unique public keys; at most 32 source CIDRs.         |
| Firewall expansion    | At most 63 ingress rules plus one explicit IPv4 egress rule.           |
| Resource sizing       | 2–32 cores, 1–64 GiB RAM, and a separately owned 10–256 GiB boot disk. |
| Exported bundle       | 1–8 files, at most 1 MiB per file and 2 MiB total.                     |
| Local storage         | Caller-owned POSIX directories `0700`, regular files `0600`.           |
| Replacement / cleanup | Exclusive publication; complete ownership and digest verification.     |

Public keys must be canonical Ed25519 public wire keys without comments. Keys
are separate for administration and every device. Private key values are never
accepted in this schema. CIDRs must be canonical; duplicate and overlapping
entries within an individual source set are rejected.

The resource graph orders network creation before subnet and security group.
The instance depends on subnet, security group, reserved address, and boot disk.
The disk uses `auto-delete=false` in the provider contract so the lifecycle owns
its cleanup explicitly.

## Preparation

Profile preparation performs local filesystem operations only:

```python
from flayer.profiles import (
    BuildServerBundle,
    CompileGateway,
    LoadGatewayProfile,
    RenderPlan,
    WriteArtifactBundle,
)

profile = LoadGatewayProfile("gateway.toml")
server_directory = WriteArtifactBundle("generated-artifacts", BuildServerBundle(profile))
plan_text = RenderPlan(
    CompileGateway(profile),
    user_data_file=server_directory / "server-cloud-init.json",
)
```

Persist `plan_text` only in explicit private local storage. Its absolute artifact
path is a local execution reference and is not portable repository configuration.
The lifecycle parser consumes its versioned TOML; orchestration and provider
mutation require their own explicit commands. No cloud resources are created by
the preparation calls above.

The exported `server-cloud-init.json` uses the `#cloud-config` marker followed by
JSON, which is also valid YAML. It creates locked key-authenticated accounts,
installs nftables and unattended upgrades, writes the full SSH server configuration,
denies packet forwarding, and checks SSH/firewall syntax before enabling services.
Replacing the full SSH configuration belongs to this fresh guest profile and is
not an in-place management command for an arbitrary existing server.

The tunnel account must be absent before bootstrap; an existing account, failed
account lookup, or failed creation stops before service activation. Root-owned
exact administrator/device key files are selected explicitly, so unrelated image
or home-directory authorized keys are not merged into gateway authorization.
The dedicated tunnel account receives its own primary group and no sudo membership.
Bootstrap explicitly enables `ssh.service` for subsequent boots after disabling
socket activation. This bootstrap is a one-time fresh guest operation; manually
rerunning it after account creation fails its fresh-account precondition.

`RenderPlan()` rejects foreign, changed, unowned, or incomplete bundles and binds
the exact initialization digest to the instance intent. The provider validates
the digest again when dispatching initialization. A file path alone is insufficient
to authorize changed server content.

## Device configuration

After independently obtaining the actual server host key, put it in an explicit
trusted known-hosts file. Provide the private key corresponding to the declared
device public key as a file reference. Generation does not read or validate either
file and does not accept a host key automatically.

```python
from flayer.profiles import BuildSshDeviceBundle, WriteArtifactBundle

device_directory = WriteArtifactBundle(
    "generated-artifacts",
    BuildSshDeviceBundle(
        profile,
        "laptop",
        endpoint="203.0.113.42",
        identity_file="/path/to/laptop-key",
        known_hosts_file="/path/to/trusted-known-hosts",
        local_ports=(8443,),
    ),
)
```

The local port tuple corresponds to declared targets in order. Ports must be
unique and within `1024..65535`; forwards always bind to IPv4 loopback. Windows
client file references use absolute paths such as `C:/Keys/laptop-key`.

Run the generated configuration with OpenSSH:

```bash
ssh -F generated-artifacts/device-laptop/ssh-client.conf -N laptop
```

The example forwards `127.0.0.1:8443` to `example.org:443` through the gateway.
The remote destination string must match the server's exact `PermitOpen` entry.
This provides TCP reachability and does not change HTTP host names, TLS names,
application routing, or the operating system's default route.

Client configuration enforces strict host key checking, public key authentication,
one connection attempt, a bounded connection timeout, and failure on forward bind
errors. It disables agent, X11, shell, proxy command, and local command behavior.
`ExitOnForwardFailure` does not prove that the destination accepts connections.
The descriptor records `prepared-unverified`, never deployed or healthy.

`BuildDeviceBundle()` separately accepts externally issued sensitive transport
files. Their bytes stay out of repr, manifests, state, and tracked configuration.
That helper does not issue credentials or verify another transport implementation.

## Ownership and cleanup

```python
from flayer.profiles import RemoveArtifactBundle

RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="device", name="laptop"
)
RemoveArtifactBundle(
    "generated-artifacts", profile.identity, kind="server", name=profile.identity.stack
)
```

Cleanup first validates the full manifest, exact stack identity, every digest,
private file mode, and complete directory membership. It preserves foreign or
changed files and never follows symlinks, accepts hardlinks, or recursively removes
directories. Removing local files never destroys cloud resources.

Cleanup retains pinned inode and content receipts and checks them again before
each destructive step, including rollback and lock release. Reads return the
verified immutable snapshot rather than rereading an unbound filename. Detected
same-user substitutions or in-place edits are preserved and require recovery.

Private directories and exclusive locks define a cooperative writer boundary.
POSIX provides no atomic conditional unlink by inode and content; a process with
the same operating system identity can race the final check or bypass the lock.
This store is not a security boundary against an actively hostile same-user
process or a privileged administrator.

Existing bundles are never overwritten. An existing operation lock is preserved
for explicit operator recovery. A failed write rolls back only its own files;
filesystem failures can leave a published or partial bundle that requires local
recovery. Interrupted removal can leave its manifest and remaining files; subsequent
automatic cleanup refuses the incomplete manifest. Keep the server artifact until
any active deployment or recovery that references it has finished.

## Validation and remaining limits

Deterministic tests cover strict schema and size bounds, resource graph serialization,
artifact ownership, public/private key boundaries, collisions, symlinks, hardlinks,
FIFO rejection, permission changes, complete pre-deletion verification, and partial
publication/removal failures. Available OpenSSH tools validate client/server syntax
without network access. Effective `Match User` checks use `sshd -T` only when its
existing development environment can run them.

Cloud-init execution, real SSH authentication, host key acquisition, destination
reachability, and live guest readiness are not proven by these offline checks.
The cloud-init and nftables tools are not runtime dependencies of F-Layer.
Provider status remains a cloud observation. Artifact storage has no Windows ACL
implementation, and DNS destination resolution happens on the gateway at connection
time. An allowlisted DNS name is not an immutable destination-IP ownership claim.

See [ADR 0007](../adr/0007-secure-gateway-profile.md) for the design decision.
