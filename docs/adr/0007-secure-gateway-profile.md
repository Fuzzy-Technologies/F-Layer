# ADR 0007: Explicit secure gateway profile and owned artifacts

## Status

Accepted for the first secure gateway profile implementation.

## Context

The working baseline combined cloud resource creation, operating system hardening,
transport installation, credential issuance, and client configuration export. Those
concerns need separate ownership contracts before they become reusable F-Layer
capabilities. A hardened virtual machine alone does not provide a gateway outcome.

The first profile must perform useful traffic transport while avoiding a dependency
on a VPN product, private infrastructure, implicit placement, or generated private
keys in cloud metadata. Cloud observations cannot prove guest initialization or
transport readiness.

## Decision

Implement a versioned `secure-gateway` profile with an explicit
`ubuntu-24.04-cloud-init` guest contract and an `ssh-local-forward` transport.
It composes six separately owned resources: network, subnet, security group,
reserved address, boot disk, and instance. The boot disk is explicit so interrupted
instance creation cannot leave an unlabeled compound-created disk outside the
resource lifecycle.

`CompileGateway()` returns immutable validated profile intent. `RenderPlan()`
serializes the lifecycle TOML boundary after verifying the exact exported server
artifact and its complete ownership manifest. The profile package does not import
provider mutation or lifecycle implementations. Composition is checked at the
integration boundary.

The server separates administration from transport:

- The administrator uses an explicit Ed25519 public key and bounded source CIDRs.
- Each declared device has a unique public key and bounded source CIDRs.
- A separate locked non-sudo account permits local TCP forwarding only to the
  declared destination allowlist. Shell, subsystem, TTY, remote forwarding,
  agent forwarding, Unix socket forwarding, and SSH tunnel interfaces are denied.
- Device authorization keys also constrain their source CIDRs and destinations.
- Exact root-owned authorized key files replace home-key fallback for both roles.
  Bootstrap proves the tunnel account is absent before creating it with its own
  group and locked password; lookup or creation failures stop service activation.
- Device configurations bind forwards to `127.0.0.1`, require an explicit private
  key reference and independently trusted known-hosts file, and enforce strict
  host key checking. Generation never reads either file or accepts host keys
  automatically.

Cloud initialization contains public keys and declared hardening configuration,
never private keys or resolved credentials. The lifecycle plan includes an explicit
`user_data_file` and the SHA-256 digest of its expected bytes. The provider verifies
and copies the file before dispatch; the provider owns upload mechanics.

Generated artifacts are separate from cloud state. New bundles use exclusive
creation, private permissions, a manifest written last, and exact content hashes.
Cleanup validates complete identity and every declared file before removing any
file. Unknown files, changed payloads, malformed manifests, symlinks, hardlinks,
foreign ownership, and collisions fail closed. Cleanup never recursively deletes
a directory or touches provider resources.

Pinned inode, modification, and digest receipts are rechecked before cleanup,
rollback, and lock release. Artifact reads return the verified immutable snapshot.
These checks detect concrete same-user substitutions, while private directories
and exclusive locks remain a cooperative writer contract. POSIX has no atomic
conditional unlink by identity and digest; an actively hostile same-user process
or privileged administrator is outside this store's isolation boundary.

## Consequences

The first profile is a usable application TCP gateway rather than a full IP VPN.
IPv4 packet routing remains disabled, and IPv6 is outside this guest contract.
Optional service port allowances install no additional listener.

Profile preparation and offline syntax checks do not prove successful cloud-init
execution, destination reachability, SSH authentication, or guest readiness.
The local device descriptor therefore records `prepared-unverified`. An operator
must obtain the server host key through an independently trusted channel before
connecting. `ExitOnForwardFailure` checks forward setup, not destination health.

Artifact storage currently requires a POSIX host with caller-owned `0700`
directories and `0600` files. Client configurations can reference POSIX paths or
Windows absolute paths using forward slashes. Windows ACL-aware artifact storage
is not implemented. Exported private transport profiles from other systems remain
sensitive memory inputs to `BuildDeviceBundle()`; their transport validity is not
claimed.

An interrupted write normally rolls back only its own new files. Failed cleanup
or lock release can require explicit local recovery; an existing lock is never
automatically removed. A published bundle may remain visible if the final lock
release fails. Local cleanup is distinct from infrastructure destruction and must
not race an active deployment.

## Alternatives

Reusing VPN containers would preserve product coupling and require implementing
secret issuance, revocation, version pinning, and transport-specific health in the
same change. A server foundation without transport would not meet the gateway
outcome. Broad SSH forwarding or trust-on-first-use would weaken the explicit
scope and verification contracts.

## Compatibility and migration

The existing desired configuration schema and provider discovery interfaces remain
unchanged. This profile introduces its own explicit TOML schema. There is no
implicit migration of previous private configurations, state, device credentials,
or endpoint values.

## References

- [Secure gateway contract](../architecture/secure-gateway.md)
- [OpenSSH server configuration](https://man.openbsd.org/sshd_config.5)
- [OpenSSH client configuration](https://man.openbsd.org/ssh_config.5)
- [Cloud-init module reference](https://docs.cloud-init.io/en/latest/reference/modules.html)
- [nftables server rules](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server)
