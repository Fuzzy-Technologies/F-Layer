# Static site profile

The second concrete deployment profile, `static-site`, prepares nginx to serve
one HTML page on HTTP port 80. It accepts bounded plain text and escapes it into
fixed markup. It composes the same owned resource and artifact contracts as the
[secure gateway](secure-gateway.md), while producing a distinct web-serving
outcome without device accounts or SSH transport.

The profile explicitly selects Yandex Cloud placement and the
`ubuntu-24.04-cloud-init` fresh guest contract. No provider, folder, owner, zone,
or image is inferred from the host environment. The selected image must actually
support that guest contract; local validation does not verify image contents.
The [synthetic example](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/examples/static-site.toml)
contains no real placement or usable private credential. Replace its ownership,
placement, sources, and synthetic Ed25519 public key before deployment.

## Contract and limits

| Boundary              | Required behavior                                                         |
| --------------------- | ------------------------------------------------------------------------- |
| Schema                | Version 1; `static-site`; unknown fields and commands rejected.           |
| Placement             | Explicit Yandex identity, folder, owner, zone, image, and subnet.         |
| Subnet                | Canonical RFC1918 IPv4 subnet with prefix `/16` through `/28`.            |
| Administrator         | Explicit non-root username and one canonical Ed25519 public wire key.     |
| Administrator sources | 1–16 canonical IPv4 CIDRs with prefix `/24` through `/32`.                |
| HTTP sources          | 1–16 explicit canonical IPv4 CIDRs; `/0` is allowed for HTTP only.        |
| Source uniqueness     | Duplicate and overlapping CIDRs rejected within each source set.          |
| Page                  | Nonempty plain title up to 160 UTF-8 bytes; body up to 8192 UTF-8 bytes.  |
| Text controls         | Controls and invalid Unicode scalars rejected; body permits line feeds.   |
| Resource sizing       | 2–32 cores, 1–64 GiB RAM, separately owned 10–256 GiB boot disk.          |
| Firewall expansion    | At most 32 ingress rules plus one explicit IPv4 egress rule.              |
| Input                 | Regular UTF-8 TOML file up to 32768 bytes; no traversal or symlink paths. |
| Generated storage     | Existing POSIX caller-owned `0700` directories and `0600` artifact files. |

All title and body characters are escaped with HTML quote escaping. HTML,
template syntax, and shell-looking text become page text. The schema provides
no arbitrary file path, HTML template, shell command, nginx directive, package
list, credential value, device account, or routed VPN setting. Use publishable
text only: the resulting page is content for the declared HTTP clients.

Public keys require only the canonical `ssh-ed25519` type and complete public
wire blob, without comments or key options. The profile never resolves a private
key or emits a secret artifact. HTTP and administrator source sets may overlap,
but HTTP source allowance never grants access to SSH port 22.
Administrator names cannot be `root`, `www-data`, or `nginx`; web worker accounts
must remain separate from the privileged administrator.

## Local preparation

With an installed F-Layer package, prepare both owned local bundles:

```bash
python -m flayer.profiles.static_site site.toml --artifact-root generated-artifacts
```

The command prints JSON with `status: prepared-unverified` and the absolute
`plan_file` path. It performs local file operations only and does not instantiate
a provider. For the example stack name `site`, the result is:

| Bundle             | Owned payload                 | Purpose                               |
| ------------------ | ----------------------------- | ------------------------------------- |
| `server-site`      | `static-site-cloud-init.json` | Exact nonsecret guest initialization. |
| `server-site-plan` | `deployment-plan.toml`        | Existing lifecycle plan TOML.         |

Each directory also contains the existing ownership and digest `manifest.json`.
New bundles are published exclusively: repeated preparation fails instead of
overwriting existing files. Paths cannot traverse or follow symlinks. The plan
stays inside the caller-selected artifact root and references the absolute
cloud-init path. That local reference is not portable repository configuration.

The same preparation is available as a Python API:

```python
from flayer.core.lifecycle import LoadDeploymentPlan
from flayer.profiles.static_site import LoadStaticSiteProfile, PrepareStaticSite

profile = LoadStaticSiteProfile("site.toml")
prepared = PrepareStaticSite(profile, artifact_root="generated-artifacts")
plan = LoadDeploymentPlan(prepared.PlanFile)
```

`ParseStaticSiteProfile()`, `CompileStaticSite()`, `BuildStaticSiteBundle()`, and
`RenderStaticSitePlan()` expose the separate parsing, validation, generation,
and rendering steps. Rendering requires the exact filename and verifies the
complete existing ownership manifest, all file digests, and semantic byte equality
with the compiled profile before binding the SHA-256 digest to instance intent.

## Existing lifecycle composition

The plan contains six existing resource kinds: network, subnet, security group,
reserved address, boot disk, and instance. The subnet and security group depend
on the network. The instance depends on the subnet, security group, address,
and boot disk. The disk remains separately owned and uses the existing provider
`auto-delete=false` behavior. The new profile does not modify lifecycle recovery,
provider semantics, cloud defaults, or persisted state.

The existing explicit lifecycle CLI consumes the prepared plan. For example,
after selecting real placement and a preauthenticated CLI profile, an operator
can run the following commands; preparation itself runs none of them:

```bash
python -m flayer lifecycle create \
  --config generated-artifacts/server-site-plan/deployment-plan.toml \
  --state site-state.json --yc-profile YOUR_PROFILE \
  --allow-mutation --scope-confirm YOUR_FOLDER_ID

python -m flayer lifecycle status \
  --config generated-artifacts/server-site-plan/deployment-plan.toml \
  --state site-state.json --yc-profile YOUR_PROFILE

python -m flayer lifecycle destroy \
  --config generated-artifacts/server-site-plan/deployment-plan.toml \
  --state site-state.json --yc-profile YOUR_PROFILE \
  --allow-mutation --scope-confirm YOUR_FOLDER_ID
```

Keep both bundles until deployment, destruction, and any required recovery that
uses the plan have finished. The Yandex adapter rechecks initialization bytes
against the recorded digest before dispatching a private temporary metadata
copy. Provider `RUNNING` status describes cloud existence; it does not prove
cloud-init success, SSH authentication, HTTP content, or guest readiness.

## Fresh guest behavior

Cloud initialization uses `#cloud-config` followed by JSON, which is valid YAML.
It creates one locked administrator with sudo authority, installs nginx,
nftables, and unattended upgrades, and writes fixed root-owned configuration.
It replaces the full SSH server and nginx configuration for a fresh guest.
This is not an in-place update operation for an arbitrary existing server.

SSH selects only `/etc/ssh/f-layer-static-admin-keys`, an exact root-owned key
file. Home authorized keys, image-provided keys, key commands, and SSH CAs do
not become additional authorization sources. `AllowUsers` constrains the single
administrator to its own source CIDRs. Root/password login, SSH forwarding,
agent forwarding, Unix socket forwarding, and tunnel interfaces are disabled.
HTTP ingress is separately restricted by both the cloud security group and
guest input firewall. Guest packet forwarding is denied and IPv6 is disabled.

Nginx serves only `/` and `/index.html` from the fixed document root. Other URLs
return 404; directory indexing and dynamic execution are absent. The page and
directory are root owned. HTTP is unencrypted; this bounded profile provides no
TLS certificate issuance, HTTPS, domain management, uploads, or dynamic backend.

The fixed bootstrap runs with `set -eu`, checks `sshd -t`,
`nft --check --file`, and `nginx -t` before its explicit service activation,
then enables persistent `ssh.service` after disabling socket activation and
enables nginx. Package installation may start distribution services through
the package manager; bootstrap checks do not claim otherwise. The profile does
not emit a readiness marker or report successful guest execution locally.

## Cleanup and failure behavior

Remove the plan bundle and server bundle only after their active use is complete:

```python
from flayer.profiles.artifacts import RemoveArtifactBundle

RemoveArtifactBundle(
    "generated-artifacts", profile.identity,
    kind="server", name=profile.identity.stack + "-plan",
)
RemoveArtifactBundle(
    "generated-artifacts", profile.identity,
    kind="server", name=profile.identity.stack,
)
```

Cleanup uses the existing complete manifest, identity, private mode, file
membership, digest, and pinned receipt checks. It preserves changed or foreign
files and rejects symlinks, hardlinks, special files, and collisions. It never
recursively removes directories or destroys cloud resources.

If plan preparation fails, cleanup is bound to the original generated server
bundle when no exact verified published plan references it. The existing store
checks the caller-held expected files, exact bytes, and manifest metadata inside
the cleanup operation lock before any removal. A valid same-identity replacement
with different content is preserved rather than reauthorized by ownership alone.
A late failure after plan publication preserves that verified pair for explicit
recovery. Detected server replacements are preserved, and cleanup refusal is
reported. The underlying store can leave partial output or a lock after filesystem
failure; existing locks are never removed automatically. It remains a cooperative same-user writer
contract, not isolation from a hostile process using the same UID or root.
Byte-identical replacements with identical manifest metadata are equivalent
expected content; the optional content binding is not a historical inode receipt.

## Evidence and remaining limits

Deterministic tests run the actual lifecycle parser, engine, and Yandex adapter
through an in-memory CLI runner. They cover six-resource create, cloud status,
idempotency, reverse dependency destroy, digest rejection before instance
mutation, rollback, and cleanup of both prepared bundles. Other tests cover
strict schema, UTF-8 bounds, escaped page text, public key structure, source
separation, private paths, publication collisions, and preserved replacements.

Shell syntax and bootstrap ordering use isolated command fakes without touching
host users, guest files, or services. OpenSSH configuration parsing runs offline
when available. Cloud-init schema and nginx test-mode checks are optional
development validators; an unavailable validator is skipped and is not a pass.
The nginx fixture redirects writable paths and its listen endpoint to owned
scratch storage and a Unix socket because test mode can bind sockets. It preserves
the server/location rules and `default_server`; a separate assertion checks the
production HTTP port 80 listener. It opens no privileged or public TCP listener.
No real cloud resource, guest installation, nginx deployment, service restart,
credential issuance, HTTP connection, or live guest readiness is validated here.

See [ADR 0013](../adr/0013-static-site-profile.md) for the extensibility decision.
