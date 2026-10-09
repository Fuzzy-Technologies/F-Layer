# F-Layer

![F-Layer with AIna in the Fuzzy Technologies engineering laboratory](https://raw.githubusercontent.com/Fuzzy-Technologies/F-Layer/master/docs/site/content/en/assets/brand/FTech-card-F-Layer.png)

**Deploy cloud servers, manage their resources and check availability from Python or the command line.**

F-Layer turns a deployment configuration into cloud resources and keeps a local
record of what it created. That record lets you inspect the deployment, recover
an interrupted operation, and remove the resources belonging to your stack.
Use it to automate a service environment or give your application a reusable
infrastructure backend instead of maintaining separate provisioning scripts.

The **2.0 development candidate** can deploy a Yandex Cloud server with
**AmneziaWG 3.1** and **VLESS Reality**, then export separate connection settings
for each device. Install the candidate wheel, initialize a private project,
fill in the cloud settings and deploy from the CLI. The published **v1.2.1**
release supports the secure SSH gateway and HTTP checks; it does not include the
new VPN commands. Version 2.0 is not yet published as a stable release.
Other cloud providers need an adapter. Cloud resources are billed by your
provider; F-Layer is open source under Apache 2.0.

[Documentation](https://fuzzy-technologies.github.io/F-Layer/) ·
[Quick Start](https://fuzzy-technologies.github.io/F-Layer/en/guide/) ·
[First deployment](https://fuzzy-technologies.github.io/F-Layer/en/guide/first-deployment/) ·
[API reference](https://fuzzy-technologies.github.io/F-Layer/en/api/) ·
[Changelog](https://github.com/Fuzzy-Technologies/F-Layer/blob/master/CHANGELOG.md) ·
[Releases](https://github.com/Fuzzy-Technologies/F-Layer/releases)

## Install

Use Python 3.11 or newer. Install the release wheel in a virtual environment;
Git and Docker are not required:

```bash
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on Linux/macOS,
`.venv\Scripts\Activate.ps1` in PowerShell, or
`.venv\Scripts\activate.bat` in Windows Command Prompt. Then run:

```bash
python -m pip install https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v1.2.1/f_layer-1.2.1-py3-none-any.whl
python -m flayer --help
python -m flayer check --format json
```

Expected result: the local check reports `"status": "ok"` and exits with `0`.
It checks Python and package availability without cloud credentials or network
access. This is a working first check, not a server deployment.

## Quick Start

Follow the [2.0 candidate Quick Start](https://fuzzy-technologies.github.io/F-Layer/en/guide/)
to install the candidate with its `vpn` extra, create a private project, deploy
in Yandex Cloud and import the generated client settings. The guide covers both
protocols, DNS and route checks, and removal of the cloud resources.
For the published v1.2.1 package installed above, use the
[SSH gateway walkthrough](https://fuzzy-technologies.github.io/F-Layer/en/guide/first-deployment/).

## What you can build

- **A managed cloud environment:** create, inspect, recover and destroy an owned
  stack through the same configuration and state file.
- **A private VPN server in the 2.0 candidate:** deploy AmneziaWG and VLESS Reality
  together, with per-device client files and explicit cloud cleanup.
- **A controlled SSH gateway:** prepare server configuration and per-device
  SSH local forwards to explicitly allowed destinations.
- **Operational checks:** test an HTTP endpoint and measure bounded response
  and transfer timings, with JSON reports for automation.
- **Application integrations:** reuse the Python configuration, provider and
  lifecycle APIs in your own tools.

See the [architecture](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/architecture/README.md) for how these parts fit
together. Stable releases are tagged on `master`; the changelog records their
scope. `develop` also contains accepted work for later releases.

## Contributing

Read [AGENTS.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/AGENTS.md) and [DEVELOPMENT_PROTOCOL.md](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/DEVELOPMENT_PROTOCOL.md).
Build the installed-wheel API documentation with
`python tools/build_api_reference.py`; see [documentation setup](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/site/README.md).

[Release workflow](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/RELEASE_WORKFLOW.md) · [Apache License 2.0](https://github.com/Fuzzy-Technologies/F-Layer/blob/master/LICENSE)
