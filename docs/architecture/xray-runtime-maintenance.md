# Xray runtime maintenance

Use an installed, verified F-Layer candidate to maintain an existing owned
VLESS runtime. A public release is not required: retain the exact candidate
commit, wheel SHA-256 and CI/build evidence. Do not install an arbitrary
working tree or replace a binary manually.

## Scope and prerequisites

The supported transition is **Xray 26.9.30 to 26.10.31**, on Ubuntu 24.04
amd64 or arm64. The existing private project, complete owned cloud state,
administrator key and authenticated SSH host pin are required. The controller
retains its POSIX filesystem contract. These commands do not start WSL, launch
a VPN client, or alter the controller's networking.

Only the owned Xray executable and its receipt change. Server configuration,
Reality keys, device UUIDs, short IDs, endpoint, DNS/routes, AWG, existing device
exports and cloud resource identities stay unchanged. Existing projects keep
their original prepared runtime descriptor and artifact manifests.

Runtime operations make read-only cloud ownership/trust checks; they never
create, update or delete cloud resources. Use a stable management connection
independent of the VLESS service being maintained. Reserve a brief VLESS outage
and keep the rollback instructions before applying an update.

## Observe the current runtime

```bash
flayer vpn runtime-status --project ~/flayer-vpn --format json
```

The report includes `version`, `receipt_sha256`, `binary_sha256`,
`previous_receipt_sha256`, `upgrade_status`, `kernel_release`,
`kernel_package_version` and `kernel_patch_status`. The version describes the
verified on-disk receipt, not proof of the running process or client traffic.
`kernel_patch_status` remains `not-assessed`; a distribution may backport fixes
without changing the upstream kernel version.

`upgrade_status` is `none`, `rollback-available` or `interrupted`. An interrupted
transaction returns an incomplete report, a nonzero exit and
`recovery_required: true`. Save the complete old `receipt_sha256` before upgrading.
Status also reports it as `previous_receipt_sha256` while a transaction exists.
Never paste private server configuration or connection profiles into diagnostics.

## Apply the explicit upgrade

Review the exact candidate, scope, old version, receipt digest, access and
rollback procedure. Replace both placeholders with your own recorded values:

```bash
flayer vpn upgrade --project ~/flayer-vpn \
  --allow-mutation --scope-confirm YOUR_FOLDER_ID \
  --expected-version 26.9.30 --expected-receipt-sha256 OLD_RECEIPT_SHA256 \
  --format json
```

The controller verifies retained artifact ownership and project settings before
contacting the guest. The guest rejects mismatched consent, version, receipt,
private configuration, service layout, foreign files and incomplete installations
before switching the runtime. It verifies the pinned download and syntax-checks
the candidate against the unchanged configuration first.

A complete private transaction is published atomically before stopping VLESS.
It holds the exact old and new binaries/receipts. After replacing the executable
and receipt, the operation starts only that VLESS service and checks its Reality
target, syntax, activity and local listener. The prior runtime is retained for
explicit rollback. Repeating the successful command with the original expected
receipt verifies the completed transaction without restarting the service.

Ordinary `deploy` does not upgrade an old runtime or downgrade an upgraded one.
Recognized legacy projects remain usable without rewriting their private bundles.
An arbitrary or modified historical installer is not accepted.

## Roll back or recover

For an intentionally requested rollback after a completed upgrade, use the
**current new receipt**, obtained from `runtime-status`:

```bash
flayer vpn rollback-upgrade --project ~/flayer-vpn \
  --allow-mutation --scope-confirm YOUR_FOLDER_ID \
  --expected-version 26.10.31 --expected-receipt-sha256 NEW_RECEIPT_SHA256 \
  --format json
```

A failed upgrade attempts automatic restoration. If the process is killed,
the SSH session is lost, or restoration fails, inspect `runtime-status`. For
an **interrupted** transaction use the **original old receipt**:

```bash
flayer vpn recover-upgrade --project ~/flayer-vpn \
  --allow-mutation --scope-confirm YOUR_FOLDER_ID \
  --expected-version 26.9.30 --expected-receipt-sha256 OLD_RECEIPT_SHA256 \
  --format json
```

Recovery restores the exact saved old executable and receipt; it does not guess
that the new version is healthy. Both operations verify current configuration,
service, binary and every saved journal file before writing. Unexpected state
blocks recovery rather than overwriting it. Restore management access and
inspect the known private deployment before retrying; never edit a receipt to
bypass drift checks.

Ordinary installation and removal refuse an interrupted transaction. A verified
committed backup is included in scoped service removal. A forced kill before
journal publication or during detached cleanup can leave an inert private
staging directory; no unknown directory is removed by guessing its ownership.

## Kernel maintenance and acceptance

Xray 26.10.31 disables default MPTCP to reduce exposure to CVE-2026-98432. It
**does not patch the Linux kernel**. Identify the actual running kernel flavor
and installed package, then consult the current
[Ubuntu advisory](https://ubuntu.com/security/CVE-2026-98432) and
[Xray security release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31).
Do not infer patch status from a version string or apply an unconditional
distribution upgrade, copied firewall rule, or reboot. If a fixed vendor package
is available, prepare an explicitly authorized maintenance window with rollback
and reboot verification. A kernel reboot interrupts both VPN protocols.

After runtime maintenance, manually check both protocols with the existing
device profiles: hostname/IPv4 HTTPS, DNS, exit address, Telegram, reconnect and
actual media playback. Record the exact client/candidate and network used.
AmneziaVPN 5.1.0.6 native import schema checks and CI's pinned-binary syntax/
transaction tests are not evidence of actual Android or desktop traffic.
YouTube/Shorts acceptance remains separate from basic connectivity.
