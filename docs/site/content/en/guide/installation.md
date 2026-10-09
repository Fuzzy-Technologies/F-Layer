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

Install the wheel from the [v1.2.1 release](https://github.com/Fuzzy-Technologies/F-Layer/releases/tag/v1.2.1):

```bash
python -m pip install https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v1.2.1/f_layer-1.2.1-py3-none-any.whl
flayer --help
flayer check --format json
```

Expected result: `"status": "ok"` and exit code `0`. `flayer` and
`python -m flayer` accept the same arguments. Continue with the
[Quick Start](index.md) to prepare your Yandex Cloud deployment.

You can also download `f_layer-1.2.1-py3-none-any.whl` from the release assets
and pass its local path to `python -m pip install`. The same release provides
a source archive and build evidence with artifact hashes. PyPI publication
is a separate release step; use the linked wheel until a PyPI release is
announced. The upcoming 2.0 features are not included in the stable 1.2.1 package.

The cloud deployment walkthrough requires Linux or macOS because generated
configuration files use POSIX owner and permission checks. Windows users can
install the package and run local diagnostics; use a Linux environment for
the deployment walkthrough.

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
