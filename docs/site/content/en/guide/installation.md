# Install from source

F-Layer requires **Python 3.11 or newer** and Git. The `f-layer` distribution
contains the `flayer` Python package. A published PyPI release is not assumed:
install the checked-out source so its documentation and behavior match.

## Clone and install

```bash
git clone https://github.com/Fuzzy-Technologies/F-Layer.git
cd F-Layer
git switch develop
python -m venv .venv
```

Activate the environment for your console:

| Console                 | Activation                   |
| ----------------------- | ---------------------------- |
| Linux/macOS bash or zsh | `source .venv/bin/activate`  |
| Windows PowerShell      | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt  | `.venv\Scripts\activate.bat` |

Install and check the current package:

```bash
python -m pip install .
python -m flayer --help
python -m flayer check --format json
```

`check` examines local runtime/package availability. It does not authenticate a
cloud account, infer a folder, create infrastructure, or prove guest readiness.
A successful diagnostic exits with `0`.

The module command `python -m flayer` works with the foundation package. The
`flayer` console entry point is introduced by the distribution task #25; once
that change is included, it accepts the same command arguments.

## Development checkout

For contributors, install editable source and the pinned validation tools:

```bash
python -m pip install -e ".[dev]"
python tools/validate.py
```

The canonical runner compiles, lints, type-checks, runs all test stages, verifies
separate line/branch coverage floors, and installs a wheel in isolation. Tests
use synthetic resources and deny unrequested network access. See the
[development workflow](../development.md) for the documentation build.

## Installation issues

| Symptom                                              | Next step                                                                                      |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `No module named flayer`                             | Activate the same environment used for `python -m pip install .`; reinstall from the checkout. |
| `python` is unavailable                              | Use the platform's Python 3.11+ launcher consistently, for example `python3` or `py -3.11`.    |
| `flayer` is unavailable but the module command works | Use `python -m flayer`; the console entry point requires task #25 in the installed revision.   |
| Windows activation is blocked                        | Use `.venv\Scripts\python.exe` directly for installation and commands.                         |

Reinstall after changing branches so the installed package matches the source
revision. Keep generated environments, credentials, and runtime state outside
tracked source.
