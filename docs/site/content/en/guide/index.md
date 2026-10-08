# Quick Start

Try F-Layer locally first, then choose a service check or a cloud deployment.
You need **Python 3.11+ and Git**. The first check needs no cloud account.

## 1. Install the stable release

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git checkout v1.2.0
python -m venv .venv
```

Activate the environment for your console:

| Console                 | Command                      |
| ----------------------- | ---------------------------- |
| Linux/macOS bash or zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

```bash
python -m pip install .
```

See [installation](installation.md) for environment troubleshooting.

## 2. Run your first check

```bash
python -m flayer --help
python -m flayer check --format json
```

Expected result: `"command": "check"`, `"status": "ok"`, exit code **0**.
The checks confirm that Python and F-Layer are available. They do not access
an endpoint, authenticate a cloud account or create a server.

In help, `{status,check,health,benchmark,lifecycle}` means **choose one command**.
Do not type the braces. For example, `python -m flayer check --help` shows the
options for `check`.

## 3. Choose a real scenario

**Check an HTTP service.** Supply an endpoint you are authorized to access:

```bash
python -m flayer health --endpoint https://example.com/ --timeout 3 --format json
```

Replace the example address with your service. This sends an HTTP request;
`"status": "ok"` and exit code `0` mean the requested check passed. Failures
produce a nonzero exit code and a structured result. The
[CLI guide](cli.md) explains statuses, limits and timing measurements.

**Deploy an SSH gateway in Yandex Cloud.** Follow the
[first deployment](first-deployment.md) to prepare a configuration and owned
resource plan, then explicitly authorize cloud changes. You need an existing
cloud account and an authenticated `yc` profile; cloud resources can incur
charges. The gateway forwards traffic to configured destinations through SSH.
It is not a ready-made VPN profile.

**Use Python in your own application.** Start with the
[API reference](../api/index.md) and the [configuration guide](configuration.md).

Top-level `status` currently returns `unsupported` (exit code `4`) for cloud
observation. Use `lifecycle status` with the plan/state and provider profile to
inspect an actual deployment; do not treat the local check as cloud readiness.
