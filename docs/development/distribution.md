# Python distribution and installation

F-Layer is distributed as the `f-layer` Python package. It installs the `flayer`
command and the import package of the same name. Users install a wheel; cloning
this repository is only necessary when contributing code. A Docker controller
image is not required for the release-2.0 installation path.

## Install a release package

Use Python 3.11 or newer. Run the cloud deployment controller on Linux or in WSL:
private project files require POSIX permissions. The provider CLI and VPN client
are separate applications described in the user guide.

Download `f_layer-2.0.0-py3-none-any.whl` and `build-evidence.json` from the
[release assets](https://github.com/Fuzzy-Technologies/F-Layer/releases).
Verify the wheel hash, then install the core CLI from the download directory:

```bash
pipx install ./f_layer-2.0.0-py3-none-any.whl
flayer --help
flayer check
```

Install [pipx](https://pipx.pypa.io/latest/how-to/install-pipx.html) first if needed.
Run `pipx ensurepath` and reopen the terminal if `flayer` is not found. pipx creates
an isolated environment for the command. To use pip instead:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./f_layer-2.0.0-py3-none-any.whl
python -m flayer check
```

## Install the VPN extra

The `vpn` extra supplies `cryptography==50.0.2` for local key generation. The core
package has no required third-party runtime dependencies. The development extra
includes the same dependency for VPN tests. For VPN deployment, install with pipx:

```bash
pipx install './f_layer-2.0.0-py3-none-any.whl[vpn]'
flayer check
```

Or use pip inside a virtual environment:

```bash
python -m pip install './f_layer-2.0.0-py3-none-any.whl[vpn]'
```

The dependency resolver obtains the extra's libraries from the configured Python
index. The F-Layer wheel comes from the explicit local file. Wheels contain no
SSH keys, VPN credentials or project configuration. PyPI publication and its
post-upload installation check are described below.

## Version ownership

`src/flayer/__init__.py` owns the literal `__version__`. Hatchling's regex source
reads it without importing the package. Wheel metadata, sdist metadata and the
installed runtime share that version. The VPN dependency is loaded by VPN code;
installing or importing the core does not implicitly enable that extra.

Stable releases use `X.Y.Z` and an immutable annotated `vX.Y.Z` tag, as described
in the [release workflow](../RELEASE_WORKFLOW.md). Version bumps belong to a
reviewed release branch. A development merge does not publish a package.

## Build and test installation

From a development environment installed with `python -m pip install -e '.[dev]'`:

```bash
python -m hatchling build --directory _build/distribution
python -m pytest tests/integration/test_distribution.py --no-cov
```

The wheel contains the typed `flayer` package, Apache-2.0 license metadata and the
console entry point. The sdist includes source, tests, tools, documentation,
changelog and examples needed to rebuild the package. Local environments, private
state and generated reports are excluded. Build output remains untracked.

Installation tests build both formats, rebuild the wheel from the sdist and compare
bytes. They install the wheel into a fresh virtual environment, run the command
outside the source checkout, compare module and console behavior, execute local
runtime diagnostics and check installed dependencies. Core installation also
checks that the optional cryptography package was not pulled in.

Release CI applies these tests to the **exact audited artifacts** before uploading
them. It resolves the VPN dependency wheels first, then installs the F-Layer wheel
with its `vpn` extra offline in a second clean environment. The VPN smoke generates
X25519 and RSA keys in memory and checks dependency consistency. It never calls a
cloud provider. Reproduce that focused check with:

```bash
python -m pip download --only-binary=:all: --dest _build/vpn-wheels './_build/distribution/f_layer-2.0.0-py3-none-any.whl[vpn]'
FLAYER_DISTRIBUTION_DIRECTORY=_build/distribution \
FLAYER_DISTRIBUTION_WHEELHOUSE=_build/vpn-wheels \
python -m pytest tests/integration/test_distribution.py --no-cov
```

Use the actual version of your locally built wheel. Full regression, documentation
and artifact gates run in CI. Without an explicitly supplied wheel directory, the
tests build fresh distributions. Without a dependency wheelhouse, the VPN extra
installation test reports a skip; it does not claim to have checked that path.

## Configure and perform PyPI publication

The tracked workflow is `.github/workflows/release-publish.yml`. It uses PyPI
Trusted Publishing and GitHub OIDC, with no long-lived upload token. Creating
that workflow alone does not grant PyPI project ownership.

The owner completes the following setup before the first production upload:

1. Sign in to the intended PyPI account and verify its ownership of `f-layer`.
   If the project does not yet exist, configure a pending Trusted Publisher for
   that name. A pending publisher does not reserve the name.
2. Set the publisher's GitHub owner to `Fuzzy-Technologies`, repository to
   `F-Layer`, and workflow filename to `release-publish.yml`. The current upload
   job uses no GitHub environment, so leave that optional publisher field empty.
3. Set repository variable `FLAYER_RELEASE_OWNER` to the exact authorized GitHub
   login, and set `FLAYER_PYPI_ENABLED=true` only after verifying the publisher.
4. Finish and close the native release milestone with no open items. Review and
   merge the release into `master`, then create its annotated version tag.
5. Run **Publish an owner-approved PyPI release** from `master` with that tag,
   the native milestone number and publication confirmation enabled.
6. Inspect the upload result and verify PyPI's project URLs and version identify
   this repository. Install the published version in a fresh environment and run
   `flayer check` before describing installation by package name as available.

Validation requires the configured owner, explicit confirmation, exact tag/master
identity and the completed matching milestone. The upload job receives only the
artifacts that passed validation and isolated installation. Only this job receives
OIDC permission. Neither a normal PR nor a tag push publishes to PyPI.

Actual account ownership, publisher configuration, first upload and post-upload
installation are operational release acceptance steps. They remain unverified
until their results have been inspected.

## References

- [ADR 0017: Package installation and the optional VPN dependency](../adr/0017-package-installation.md)
- [Hatch regex source](https://hatch.pypa.io/latest/plugins/version-source/regex/)
- [PyPA project metadata](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
- [PyPI pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [Cryptography changelog](https://cryptography.io/en/latest/changelog/)
