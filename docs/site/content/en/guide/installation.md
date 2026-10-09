# Install

F-Layer is a Python package. You need **Python 3.11 or newer**; Git and Docker
are not required to use a release. The distribution is named `f-layer`; its
Python module and command are named `flayer`.

## Install the release package

Create an isolated Python environment:

```bash
python -m venv .venv
```

| Console                 | Activation                   |
| ----------------------- | ---------------------------- |
| Linux/macOS bash or zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

Download `f_layer-2.0.0-py3-none-any.whl` and `build-evidence.json` from the
[release assets](https://github.com/Fuzzy-Technologies/F-Layer/releases).
Verify the wheel SHA-256 against the build evidence. From the download directory,
install F-Layer 2.0 with the `vpn` extra:

```bash
python -m pip install "./f_layer-2.0.0-py3-none-any.whl[vpn]"
flayer --help
flayer check --format json
flayer project --help
flayer vpn --help
```

Expected result: `"status": "ok"` and exit code `0`. `flayer` and
`python -m flayer` accept the same arguments. Continue with the
[VPN Quick Start](index.md), or the [SSH gateway walkthrough](first-deployment.md)
for restricted SSH forwarding.

The `vpn` extra supplies the cryptography library for local key generation.
The release assets also include a source archive and build evidence with the
source revision and artifact hashes. Keep that evidence with your installation.

Run the VPN deployment controller on Linux or a user-managed WSL Linux
distribution with OpenSSH and the Yandex Cloud CLI. Private project files use
POSIX ownership and permissions. Windows can run package diagnostics; use the
WSL environment for deployment.

## Development checkout

Only contributors need Git. To work on the integration branch:

```bash
git clone --branch develop https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
python -m pip install -e ".[dev]"
```

Run the tests relevant to your change during development. CI runs the complete
validation gate when the pull request opens. See the
[development workflow](../development.md) for tests and documentation builds.

## Installation issues

| Symptom                       | Next step                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `No module named flayer`      | Activate the environment used for installation and reinstall the wheel there. |
| `python` is unavailable       | Use a Python 3.11+ launcher such as `python3` or `py -3.11` consistently.     |
| `flayer` is unavailable       | Activate the installation environment or use `python -m flayer`.              |
| Windows activation is blocked | Use `.venv\Scripts\python.exe` directly for installation and commands.        |

Keep credentials, generated client configurations and deployment state outside
the source repository.
