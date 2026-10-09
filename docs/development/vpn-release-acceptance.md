# Verify the installed VPN workflow before release

Release 2.0 is ready only after an operator has installed its candidate package,
deployed a project in Yandex Cloud and connected real clients using both
AmneziaWG and VLESS Reality. Record the results in
[Task 73](https://github.com/Fuzzy-Technologies/F-Layer/issues/73).
Configuration tests and active systemd services do not replace this check.

## Choose the candidate and cloud scope

Use the wheel and build evidence from the successful release-artifact CI run for
the exact reviewed commit. Record the commit, workflow run, wheel filename,
SHA-256 and Python version. A development wheel retains the current source
version until release preparation; identify it by its hash and commit, not by
renaming it to 2.0.0.

Use a dedicated Yandex Cloud catalogue with an explicit resource budget and
permission to create and remove the test resources. The operator selects the
account, named `yc` profile, catalogue, zone and compatible Ubuntu 24.04 amd64
image. This runbook does not grant access to an account or authorize an automated
agent to create billable resources. Keep cloud identifiers and client credentials
in private local records; the public issue needs outcomes, versions and evidence
references, not secrets.

Run the controller on Linux or a compatible POSIX environment with Python 3.11
or newer and OpenSSH. Install the selected wheel with its `vpn` extra into a
fresh virtual environment outside any source checkout. Replace the example
filename with the artifact actually downloaded:

```bash
python3 -m venv flayer-acceptance-env
. flayer-acceptance-env/bin/activate
python -m pip install './f_layer-1.2.1-py3-none-any.whl[vpn]'
python -m pip check
flayer --help
flayer check --format json
```

Verify that Python imports `flayer` from this environment's installed package.
Do not set `PYTHONPATH`, use an editable installation or run from the repository.

## Create and deploy one project

Follow the [Quick Start](../site/content/en/guide/index.md), recording any step
that needs undocumented knowledge or a manual correction. Create a new private
project:

```bash
flayer project init acceptance-vpn
```

Edit `acceptance-vpn/project.toml`: set the selected catalogue, `yc` profile,
image, zone, current administrator public IPv4 range and reachable Reality
target. Use a separate named device for each client. Avoid overlap between
the tunnel subnet, cloud subnet and the clients' local networks. Follow the
documented client IPv6 prerequisite before treating the connection as a full
IPv4 tunnel.

Local preparation must succeed without contacting the cloud, and a repeat
must reuse the existing keys:

```bash
flayer vpn prepare --project acceptance-vpn --format json
flayer vpn prepare --project acceptance-vpn --format json
```

The operator then explicitly authorizes creation in the selected catalogue.
Replace `example-folder` with the same catalogue ID used in the project:

```bash
flayer vpn deploy --project acceptance-vpn --allow-mutation --scope-confirm example-folder --format json
flayer vpn status --project acceptance-vpn --format json
```

Verify that the project owns the expected network, subnet, security group,
reserved public address, boot disk and VM. The SSH host key must be obtained
through the authenticated cloud channel and pinned before private files are
transferred. Do not bypass a host-key mismatch or enable trust on first use.
Use the client artifact paths reported by the successful deployment.

## Connect both protocols

Test the protocols separately so a working first tunnel cannot hide a failed
second one. Record the operating system, client version, import method and
results for each device. Use an HTTPS endpoint under the operator's control,
or one the operator has chosen, to observe the connection's source address.

For [AmneziaWG](../architecture/amneziawg.md):

1. Import that device's `amneziawg.conf` into a compatible AmneziaWG 3.1 client.
2. Activate the tunnel and verify an actual client/server handshake.
3. Resolve a hostname and load HTTPS content through the tunnel. Verify that
   the observed IPv4 source matches the project's reserved public address.
4. Check the configured route policy and client IPv6 setting. An IPv4 success
   does not establish that IPv6 or other traffic cannot bypass the tunnel.
5. Disconnect the tunnel before testing VLESS.

For [VLESS Reality](../architecture/vless-reality.md):

1. Import that device's `import.txt` URI into a compatible graphical client, or
   run the generated `client.json` with the documented Xray version.
2. For graphical clients, explicitly select their proxy or VPN/TUN mode and
   apply the documented DNS and route settings. The import URI does not carry
   the complete routing policy. Record which traffic the selected mode covers.
3. Verify an actual authenticated connection, hostname resolution and HTTPS
   transfer through it. The observed IPv4 source must match the gateway.
4. For the generated Xray configuration, test an application through
   `socks5h://127.0.0.1:10808`. This checks the application proxy, not OS-wide
   routing. Check any claimed VPN/TUN behavior separately in the chosen client.
5. Disconnect and reconnect. Confirm that the retained import still works.

Verify any split-routing mode that the release intends to advertise with a
separate project. Test both a permitted destination and an excluded destination;
record whether the documented behavior is blocking or direct routing. Do not
change an already prepared project's settings to bypass replacement safeguards.

## Verify repeat deployment and failure handling

Run the same deployment command again. It must retain the cloud resource IDs
and client credentials; both previously imported profiles must still connect.
Record the result without copying private configuration contents into the issue.

Exercise a controlled interruption within the authorized test scope. Record
whether it occurred during cloud creation or guest installation, preserve the
private project and state, and follow the relevant documented recovery path.
For an interrupted cloud operation, the explicit commands are:

```bash
flayer vpn recover --project acceptance-vpn --allow-mutation --scope-confirm example-folder --format json
flayer vpn deploy --project acceptance-vpn --allow-mutation --scope-confirm example-folder --format json
```

Guest installation failure after cloud creation normally permits another
`deploy` with the retained project. A forced kill during a guest replacement
may require the documented manual inspection and repair; do not report
automatic recovery unless that path was actually exercised successfully.
Any failed or unexplained outcome stays open as a release blocker.

## Remove resources and record the outcome

Disconnect the clients, then remove the exact owned deployment:

```bash
flayer vpn destroy --project acceptance-vpn --allow-mutation --scope-confirm example-folder --format json
```

Verify in Yandex Cloud that every resource recorded for this deployment,
including the reserved address and boot disk, has been removed and that
unrelated resources remain intact. Keep the private state until this check is
complete. Remove local credentials separately according to the operator's
retention policy; `destroy` retains local files for inspection.

Task 73's evidence must include the candidate identity, controller/client
versions, both protocols' connection/DNS/routing results, repeat-deployment
result, interruption/recovery result, cleanup confirmation and any limitations.
Use `passed`, `failed` or `not run` for each check. Missing evidence is not a pass.

Close Task 73 only after the operator accepts the actual results. Complete the
remaining native milestone items before closing `release-2.0`; only then
prepare the versioned changelog, stable master release and annotated `v2.0.0`
tag. PyPI publication, if configured, also requires verification of an
installation from the published package index.
