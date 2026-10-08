# F-Layer

![F-Layer with AIna in the Fuzzy Technologies engineering laboratory](docs/site/content/en/assets/brand/FTech-card-F-Layer.png)

**Deploy cloud servers, manage their resources and check availability from Python or the command line.**

F-Layer turns a deployment configuration into cloud resources and keeps a local
record of what it created. That record lets you inspect the deployment, recover
an interrupted operation, and remove the resources belonging to your stack.
Use it to automate a service environment or give your application a reusable
infrastructure backend instead of maintaining separate provisioning scripts.

The current release supports **Yandex Cloud**, a **secure SSH gateway** with
per-device connection settings, and HTTP availability and timing checks.
Other clouds and VPN profiles are roadmap work. Cloud resources are billed by
your provider; F-Layer is open source under Apache 2.0.

[Documentation](https://fuzzy-technologies.github.io/F-Layer/) ·
[Quick Start](docs/site/content/en/guide/index.md) ·
[First deployment](docs/site/content/en/guide/first-deployment.md) ·
[API reference](https://fuzzy-technologies.github.io/F-Layer/en/api/) ·
[Changelog](CHANGELOG.md) ·
[Releases](https://github.com/Fuzzy-Technologies/F-Layer/releases)

## Quick Start

Use Python 3.11 or newer. Install the stable release in a virtual environment:

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git checkout v1.1.0
python -m venv .venv
```

Activate it with `source .venv/bin/activate` on Linux/macOS,
`.venv\Scripts\Activate.ps1` in PowerShell, or
`.venv\Scripts\activate.bat` in Windows Command Prompt. Then run:

```bash
python -m pip install .
python -m flayer --help
python -m flayer check --format json
```

Expected result: the local check reports `"status": "ok"` and exits with `0`.
It checks Python and package availability without cloud credentials or network
access. This is a working first check, not a server deployment.

Next, follow the [Quick Start](docs/site/content/en/guide/index.md) to try an
endpoint check, or the [gateway walkthrough](docs/site/content/en/guide/first-deployment.md)
to prepare a server plan and deploy it with explicit provider access.

## What you can build

- **A managed cloud environment:** create, inspect, recover and destroy an owned
  stack through the same configuration and state file.
- **A controlled SSH gateway:** prepare server configuration and per-device
  SSH local forwards to explicitly allowed destinations.
- **Operational checks:** test an HTTP endpoint and measure bounded response
  and transfer timings, with JSON reports for automation.
- **Application integrations:** reuse the Python configuration, provider and
  lifecycle APIs in your own tools.

See the [architecture](docs/architecture/README.md) for how these parts fit
together. Stable releases are tagged on `master`; the changelog records their
scope. `develop` also contains accepted work for later releases.

## Contributing

Read [AGENTS.md](AGENTS.md) and [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md).
Build the installed-wheel API documentation with
`python tools/build_api_reference.py`; see [documentation setup](docs/site/README.md).

[Release workflow](docs/RELEASE_WORKFLOW.md) · [Apache License 2.0](LICENSE)
