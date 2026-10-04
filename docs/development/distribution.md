# Python distribution contract

The distribution is `f-layer`; the import package and console command are
`flayer`. F-Layer currently supports Python 3.11 and newer and has no runtime
dependencies. Install from the reviewed repository until an official package
has actually been published.

## Version ownership

`src/flayer/__init__.py` owns the literal `__version__`. Hatchling's regex
version source reads that file without importing the package. Wheel metadata,
sdist metadata and the installed runtime therefore share one version source.
The 1.1.0 release uses this single source for package and runtime identity.

Stable releases use `X.Y.Z` with an immutable annotated `vX.Y.Z` tag, as described
in the [release workflow](../RELEASE_WORKFLOW.md). Version bumps belong to a
reviewed release branch; never derive the version from a machine-local Git
state or silently create a new release on a development merge.

## Build and inspect

From a development environment installed with `python -m pip install -e '.[dev]'`:

```bash
python -m hatchling build --directory _build/distribution
python tools/validate.py
```

The wheel contains the typed `flayer` package, Apache-2.0 license metadata and
the `flayer` console entry point. The sdist includes the sources, tests, tools,
documentation, changelog and repository examples needed to rebuild the same package.
It excludes local environments, caches, state and generated reports. Generated
distribution files remain untracked.

Installation tests build both formats offline, rebuild a wheel from the sdist,
compare package metadata and bytes, and execute the installed entry point
outside the source tree with Python's isolated mode.

## Publication

Package metadata and local builds are ready for release preparation. They do
not establish PyPI name ownership or Trusted Publisher configuration, and no
package upload occurs during ordinary validation. Publication is a separate
owner-controlled action after the stable release passes its release gates.

The version-source contract follows the official
[Hatch regex source](https://hatch.pypa.io/latest/plugins/version-source/regex/)
and [PyPA project metadata](https://packaging.python.org/en/latest/specifications/pyproject-toml/).
