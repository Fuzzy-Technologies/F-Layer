# Python distribution and installation

F-Layer is distributed as the `f-layer` Python package. It installs the `flayer`
command and the import package of the same name. Users install a wheel; cloning
this repository is only necessary when contributing code. A Docker controller
image is not required for the release-2.0 installation path.

## Install a published release

Use Python 3.11 or newer. For the cloud gateway workflow, run the controller on
Linux or in WSL: generated private files require POSIX permissions. The provider's
CLI and a VPN client are separate applications, installed as described in the
user guide. Installing the Python package does not configure a cloud account.

The existing [GitHub releases](https://github.com/Fuzzy-Technologies/F-Layer/releases)
include wheels. For example, this installs the published **1.2.1** CLI with pipx:

```bash
pipx install https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v1.2.1/f_layer-1.2.1-py3-none-any.whl
flayer --help
flayer check
```

Install [pipx](https://pipx.pypa.io/latest/how-to/install-pipx.html) first if it is
not available. Run `pipx ensurepath`, then reopen the terminal if `flayer` is not
found. pipx creates an isolated environment for the command.

For an application or an environment managed without pipx, install the same wheel
with pip inside a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v1.2.1/f_layer-1.2.1-py3-none-any.whl
python -m flayer check
```

Version 1.2.1 does not include the release-2.0 VPN workflow. Download the wheel for
the version you intend to use; do not rename a preview wheel to a release version.

## Install the VPN extra in release 2.0

The release-2.0 package adds the `vpn` extra for local key generation. It installs
`cryptography==50.0.2`; the core package still has no required third-party runtime
dependencies. The same dependency is included in the development extra so tests
exercise VPN code in the normal development environment.

After the official 2.0.0 wheel is published, the normal gateway installation is:

```bash
pipx install 'f-layer[vpn] @ https://github.com/Fuzzy-Technologies/F-Layer/releases/download/v2.0.0/f_layer-2.0.0-py3-none-any.whl'
flayer check
```

For a downloaded release or CI preview wheel, use its actual filename:

```bash
python -m pip install './f_layer-2.0.0-py3-none-any.whl[vpn]'
```

Run the latter command in a virtual environment. The dependency resolver downloads
the extra's dependencies from the configured Python index; the F-Layer wheel itself
comes from the explicit local file or GitHub URL. No SSH key, VPN credential or
project configuration is included in a wheel.

The same package can be installed by name after ownership and publication on PyPI
have been verified:

```bash
pipx install 'f-layer[vpn]==2.0.0'
```

This command describes the publication target. It is not evidence that the name
has been reserved or that 2.0.0 is already available on PyPI. Until publication,
use the exact wheel attached to the official GitHub release.

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
python -m pip download --only-binary=:all: --dest _build/vpn-wheels './_build/distribution/f_layer-1.2.1-py3-none-any.whl[vpn]'
FLAYER_DISTRIBUTION_DIRECTORY=_build/distribution \
FLAYER_DISTRIBUTION_WHEELHOUSE=_build/vpn-wheels \
python -m pytest tests/integration/test_distribution.py --no-cov
```

Use the actual version of your locally built wheel. A branch preview keeps the
current source version until release stabilization. Full regression, documentation
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
