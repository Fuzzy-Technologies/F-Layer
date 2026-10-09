# ADR 0019: Private VPN projects and authenticated guest provisioning

- Status: Proposed
- Date: 2026-10-09
- Related: [Task #71](https://github.com/Fuzzy-Technologies/F-Layer/issues/71), [Feature #55](https://github.com/Fuzzy-Technologies/F-Layer/issues/55)

## Context

An installed F-Layer package needs a complete user workflow: create a local
project, set cloud placement and devices, prepare credentials, create cloud
resources, install both transports, and export usable client files. The workflow
must retain the existing separation between public intent, minimal cloud state,
private artifacts, and actual health observations.

The first connection to a fresh server also needs an authenticated SSH host key.
Automatically accepting whichever key answers at the public address would leave
the private server bundle exposed to interception. Copying keys manually is
possible but makes the first deployment unnecessarily difficult.

## Decision

Add `flayer project init DIRECTORY` and the following project commands:

```bash
flayer vpn prepare --project DIRECTORY
flayer vpn deploy --project DIRECTORY --allow-mutation --scope-confirm FOLDER_ID
flayer vpn status --project DIRECTORY
flayer vpn destroy --project DIRECTORY --allow-mutation --scope-confirm FOLDER_ID
flayer vpn recover --project DIRECTORY --allow-mutation --scope-confirm FOLDER_ID
```

`recover --rollback` explicitly requests rollback through the existing lifecycle
engine. It does not guess the result of an uncertain cloud operation.

### Local project and credentials

The controller supports a POSIX host, including Linux and WSL. Initialization
requires a new directory and OpenSSH `ssh-keygen`. It creates the directory with
mode `0700`, generates an Ed25519 administration key with mode `0600`, and writes
an editable `project.toml` and a local Git exclusion. Existing directories are
never overwritten. A partial failed initialization is retained for inspection.

The public project schema contains exact stack ownership, an existing authorized
`yc` profile, Yandex folder, zone and Ubuntu 24.04 amd64 image, a private cloud
subnet, bounded administration CIDRs, device addresses, routing, and explicit
AmneziaWG/VLESS settings. Unknown fields and inline credentials fail validation.
Cloud and tunnel subnets must not overlap. TCP port 22 remains administration-only.

Preparation generates protocol material once. Controller credentials live in a
separate sensitive owned artifact bundle. AmneziaWG client private keys are not
transferred to the server. Server artifacts contain only the credentials their
protocol requires. The public project fingerprint prevents accidental reuse of
credentials after configuration changes; changed material and manifests fail
closed rather than triggering implicit rotation.

The local preparation step validates both protocol renderers. It persists server
artifacts and the public bootstrap, but no client files with a placeholder server
address. Client files are generated only after the exact reserved IPv4 address is
observed on the exact owned instance.

### Cloud resource lifecycle

A VPN-specific bootstrap and six typed resources compose with the existing
`LifecycleEngine`: network, subnet, security group, reserved address, boot disk,
and instance. Generic cloud state still stores only owned provider locators.
Cloud metadata contains the administration public key and nonsecret initialization;
private transport bytes never enter the lifecycle parameters or cloud-init.

The bootstrap configures key-only non-root administration, bounded input filtering,
and disabled guest IPv6. Its firewall does not install the SSH gateway profile's
forward-drop chain. AmneziaWG owns its own interface-specific forwarding and NAT
rules and enables IPv4 forwarding when its service starts.

The CLI requires both `--allow-mutation` and the exact `--scope-confirm` folder ID
before preparation or provider construction for deploy, destroy, or recovery.
Lifecycle journals preserve uncertain operations and partial cleanup. Retrying an
ordinary deployment cannot silently recreate an unresolved pending resource.

### Independent host trust

After successful public bootstrap, the guest writes a public Ed25519 host key
to its serial console with the exact public project fingerprint. The controller
first obtains the persisted instance and reserved address by their exact IDs,
verifies their complete ownership labels and scope, and requires their public
IPv4 addresses to match.

It then calls the authenticated Yandex Cloud serial-output API for that exact
instance through the selected `yc` profile. Parsing is bounded, unrelated console
output is discarded, and conflicting matching keys fail closed. Missing bootstrap
output allows a bounded wait and then a clear retry message. Serial-console
contents are never printed or stored wholesale.

The key is saved as an owned private known-hosts artifact. A changed key or
address cannot overwrite an existing pin. OpenSSH uses strict host-key checking,
an exact private key, no agent, no user SSH configuration, no proxy command,
no connection sharing, and only Ed25519 host keys. This trust derives from the
already authorized cloud account and exact owned instance, not from the first
unauthenticated network connection.

### Guest installation and observations

Private server bundles travel over SSH standard input, not command-line arguments.
The guest receiver validates the complete bounded envelope before creating files.
It stages each installer in a root-owned temporary directory with `0700` mode and
regular files with `0600` mode, uses an explicit working directory, and invokes
only the selected protocol installer. Each installer owns its separate service,
pinned dependencies, validation, rollback, and guest-side cleanup behavior.

Installer output is suppressed at the controller boundary to avoid printing
credentials. The receiver returns only a fixed completion marker. Temporary
staging files are removed after success or failure. A failure after one transport
was installed leaves the cloud resources and controller material intact; retry
uses the same credentials and the protocol installers' idempotency checks.

`status` separately reports cloud resource existence and exact guest service
activity. A successful installation or active service is not represented as
client connectivity. The report explicitly asks for client import and end-to-end
traffic verification. VLESS output remains an application proxy until the user
configures a compatible client's TUN or system-routing mode. The initial IPv4
contract still requires client IPv6 precautions from ADR 0016.

### Replacement and destruction

This initial CLI supports new deployment and identical retries. It does not offer
a credential rotation or device revocation command. Changing a prepared project
or its material requires a separate explicit replacement workflow; deletion of
local client files is not server-side revocation. A future replacement command
must bind the expected previous remote deployment receipt before changing it.

`destroy` removes only cloud resources in the verified owned lifecycle state.
Private local artifacts are retained intentionally, and the CLI says so. It does
not recursively delete a project directory, remove foreign files, or claim that
local exported credentials were erased. A changed address or host-key pin on a
later deployment requires explicit artifact recovery or a new private project.

## Validation

Deterministic tests run the real compiler, lifecycle journals, owned artifact
store, and both protocol renderers against a fake cloud and guest. They cover
create/status/destroy, identical retries, consent failure before mutation,
known cloud rejection and rollback, uncertain creation and explicit recovery,
guest failure with retained credentials, inactive services, foreign ownership,
address mismatch, host-key changes, private filesystem rules, and secret-free
bootstrap/state/error output.

A distribution test installs the actual wheel and its VPN extra outside the
source checkout, invokes `flayer project init`, and prepares both server bundles.
SSH tests inspect exact options and verify that private payloads occur only in
standard input. Guest staging tests exercise actual temporary file permissions
with fake installer processes. No tests in this change mutate a real cloud.

## Consequences and limits

A package installation now has an executable path from editable project settings
to both server services and private client exports. Every external operation has
an explicit boundary that deterministic tests can replace.

The deployment still requires an authorized Yandex Cloud account, cloud quotas,
correct administrator source CIDRs, outbound package access from the guest,
and an accessible Reality target supporting TLS 1.3 and HTTP/2. Actual cloud
bootstrap, operating-system package installation, VPN client compatibility,
traffic forwarding, DNS behavior, and IPv6 leak precautions require a separately
authorized deployment acceptance run. Offline evidence must not be presented as
that live result.

Windows-native artifact ACL handling, turnkey client TUN setup for every platform,
remote credential replacement/revocation, and migration of an arbitrary existing
server are outside this initial project workflow.

## Alternatives

Embedding secrets in cloud-init would violate ADR 0007. Trust-on-first-use or
`ssh-keyscan` alone would not authenticate the first guest connection. Reusing the
restricted SSH-forwarding profile would block VPN packet routing. A new generic
provider resource kind for each protocol would couple cloud state to guest secrets.

## References

- [ADR 0016: VPN provisioning contracts](0016-vpn-provisioning-contracts.md)
- [Yandex Cloud serial-output command](https://yandex.cloud/en/docs/cli/cli-ref/compute/cli-ref/v0/instance/get-serial-port-output)
- [Yandex Cloud serial-output access](https://yandex.cloud/en/docs/compute/operations/vm-info/get-serial-port-output)
