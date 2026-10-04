# Validation gates

Install the pinned development tools once, then use the same command locally and
in the Python quality workflow:

```bash
python -m pip install -e ".[dev]"
python tools/validate.py
```

The wrapper locates the checkout containing the script, so it also works when
invoked by an absolute path from another directory. Every tool receives
`PYTHONPATH=src:.` resolved against that checkout. An editable installation of a
different worktree cannot silently supply the package under test.
Ambient pytest options, plugin injection, and mypy source overrides are cleared;
only the required pytest coverage plugin is loaded by the full wrapper.

## Required checks

The full gate runs sequentially and stops on the first error:

1. Force-compile `src`, `tests`, and `tools` with `compileall`.
2. Run Ruff lint checks and strict mypy checks.
3. Discover and run every test stage with pytest and branch measurement.
4. Require at least 80% overall statement-plus-branch coverage and independently
   at least 80% branch coverage for `flayer`. A package with no branches has no
   branch obligations; empty or invalid measurement is a failure.
5. Import the package from this checkout with an isolated interpreter.
6. Build and install the package into a temporary directory, with dependency
   downloads and build isolation disabled, then import that installed package.
7. Run `python -m flayer --help` when the checkout provides `flayer/__main__.py`.
   A checkout without a CLI reports that fact explicitly.

The offline install check requires the pinned Hatchling build backend included
in the development extra. Missing tools, nonzero exits, and stage timeouts fail
the gate. Each subprocess has a ten-minute bound. Coverage reports and the
temporary installed package are removed on success and failure.

The package coverage floor measures production package code. Repository tools
are checked by compileall and mypy and have behavior tests; the percentage does
not claim coverage of workflows or documentation. The shared
`tools/locale_documentation.py` blueprint validator retains its upstream typing
and has a narrow mypy exception when present.

## Test stages

Pytest discovers `tests/` rather than only unit tests. Place each test in its
stage directory; collection automatically adds the corresponding strict marker.
An unclassified path causes collection to fail.

| Directory / marker | Scope |
| --- | --- |
| `unit` | Isolated module behavior and failure branches |
| `contract` | Shared interfaces and persisted data compatibility |
| `functional` | Complete local workflows |
| `integration` | Adapter composition with fakes or mocks |
| `e2e` | Complete local scenarios without cloud mutation |

Run a focused stage during development, followed by the full gate before review:

```bash
PYTHONPATH=src:. python -m pytest -m contract --no-cov
python tools/validate.py
```

Every test has a socket guard that blocks Python socket connections, outbound
datagrams, and DNS. Inject fake provider clients and transports. This guard is
an accident-prevention fixture, not an operating-system sandbox: subprocesses
and native libraries still require deterministic fakes and careful review.
Tests do not authorize real provider operations or provision cloud resources.

CI invokes the same full wrapper as local development. A later tracked edit
invalidates earlier evidence and requires the full gate again.
