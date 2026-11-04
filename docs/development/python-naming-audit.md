# Python naming audit and migration

Task: [#116](https://github.com/Fuzzy-Technologies/F-Layer/issues/116).

The owner confirmed camelCase variables, parameters and fields on 2026-11-04.
PascalCase functions, methods and classes and UPPER_SNAKE_CASE constants remain
the established callable/type and constant conventions.

## Audit scope and origin

The audit starts from `develop` at `e8561f5`. It inventories all 92 tracked
Python modules and stubs in `src`, `tools` and every test stage. The initial
binding inventory finds 1,374 snake_case binding occurrences across 78 files,
with 503 distinct candidate names. These raw candidate counts include valid
pytest and external-interface names; they are not a violation total.

The conflicting snake_case variable instruction was introduced in foundation
commit `57c9260` on 2026-10-04, in both the development protocol and style guide.
Ruff's configured checks covered syntax, imports and selected correctness
rules, but did not enforce this custom naming convention. The dedicated
`tools.python_naming` stage closes that enforcement gap.

The refactor includes bindings, fields, parameters, keyword calls, import
aliases, fixture registration and relevant embedded Python examples. Functions
overriding argparse, configparser, importlib, HTMLParser, Griffe, SSL and other
external interfaces retain the externally required spelling. The validator
records those exceptions by exact file and qualified definition.

## Python caller migration

Python callers now use names such as `CloudPlacement.ycProfile`,
`project.cloud.zoneId`, `settings.commandTimeout` and `expectedIdentity=`.
Existing snake_case Python field and keyword spellings must be updated.
Methods such as `LoadVpnProject()` retain PascalCase. Test functions keep their
`test_` prefix and built-in pytest fixture arguments retain their injection names.

CLI flags, project TOML keys, Yandex/API field names, integration envelopes,
persisted state, ownership manifests and protocol JSON retain their existing
external spelling. For example, `project.toml` still contains `yc_profile`,
and `subprocess.run` still receives `capture_output`.

Dataclass serialization at wire and fingerprint boundaries explicitly converts
owned camelCase fields back to their established snake_case names while
preserving raw dictionary keys. Renaming Python fields therefore does not
silently change existing project fingerprints or durable state schemas.
Direct `dataclasses.asdict()` reflects the new Python field names; use the
existing public codecs when producing persisted or integration data.

## Verification

The dedicated PR runs the canonical gate, including naming enforcement, on
its exact revision. Naming tests cover rejection, framework exceptions and
whole-repository discovery. Wire regression tests freeze pre-refactor
serialization and hashes. Full distribution and documentation validation
remain required; a native Windows subset cannot substitute for Linux results.

This change does not alter deployed resources, credentials, networking or VPN
profiles. Experimental VPN work remains separate from this refactor.
