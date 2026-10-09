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

## Deploy with an AI assistant

Have an assistant with terminal access? Give it the task below. It prepares the
environment and configuration, asks for missing choices and gets your approval
before creating paid resources. Sign-in and client setup may need your help.
Read the [AI operator guide](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/site/content/en/guide/ai-operator.md) for the
complete workflow and the distinction between a stable release and a candidate.

> Help me deploy a personal VPN with F-Layer: https://github.com/Fuzzy-Technologies/F-Layer.
> Read the AI operator guide linked from its README and use documentation matching
> the selected release or explicitly approved candidate. Ask which cloud, region
> and client devices I use, then select a supported adapter. Install the verified
> package and prepare a private project. Show the resources, access rules, cost
> estimate and cleanup plan; wait for my approval before creating paid resources.
> Deploy through F-Layer, help connect my devices and verify traffic. Keep secrets
> local. Finish with the actual results, ongoing costs and removal instructions.

The current VPN workflow requires the reviewed **2.0 candidate**, not the stable
v1.2.1 wheel below. Use PyPI only once the official release announces a verified
published version. The [manual Quick Start](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/site/content/en/guide/index.md)
remains available if you prefer to execute the commands yourself.

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
