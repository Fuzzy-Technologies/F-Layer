# Documentation completeness contract

Documentation completeness means every tracked file has an explicit disposition,
not that every file becomes a consumer API page. The generated
[repository inventory](https://fuzzy-technologies.github.io/F-Layer/en/coverage/) records each file, its rendered
route or source link, and its reason. The machine-readable counterpart is
`_build/api-reference/repository-coverage.json`.

Repository documentation contains maintained user guides, architecture contracts,
ADRs, release notes and engineering instructions. Keep one-off investigations,
session notes, audit reports, review summaries, raw logs and test-run receipts
in GitHub issues, PRs, CI artifacts or private records, outside tracked release
inputs and published pages. Reusable performance measurements and explicit
ADR-compliance reports are the permitted report categories. Translation review
metadata remains a build input; narrative review snapshots are not documentation.

## File accountability

`docs/site/repository-coverage.toml` defines repository-relative `fnmatch` rules.
Each Git-tracked file must match exactly one rule with a nonempty rationale.
Unknown file types, overlapping rules, absent tracked files, and malformed rules
fail the gate. Untracked package or canonical site files cannot enter build artifacts. Patterns intentionally cover future files in established
categories without pinning module or file counts. A new category requires an
explicit manifest decision rather than silent exclusion.

| File category                     | Documentation disposition                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Public package Python             | Installed-wheel API page and exact public definition anchors.                                               |
| `flayer.__main__`                 | Explicit public executable entry point, despite its underscored name.                                       |
| Private package Python            | Source-only implementation; listed with an explicit reason.                                                 |
| Canonical Markdown                | Rendered and navigable, including ADR templates, policies, release guides, and GitHub PR template.          |
| Locale Markdown                   | Rendered by the locale wrapper with explicit draft/stale/missing/approved state; never implicitly approved. |
| Tests and engineering tools       | Source-only executable evidence and commands; not consumer APIs.                                            |
| Examples                          | Source inputs linked from user guidance; not Python APIs.                                                   |
| Workflows and issue forms         | Source-only automation and governance configuration.                                                        |
| Assets and locale metadata        | Site resources or validator inputs; not API pages.                                                          |
| Packaging, typing marker, license | Source and distribution contracts; not API pages.                                                           |

Canonical authored routes remain unchanged. Other repository Markdown receives
an `en/repository/<repository-path>/` route. The hidden `.github/` source
directory is rendered as `repository/github/` so MkDocs includes its PR template. Generated copies resolve Markdown
links to rendered pages and nonpage references to their exact `develop` sources.
The builder never rewrites owner-controlled policy files.

## Installed package and API boundary

The wheel is installed into a fresh owned target rather than the documentation-tool
environment; ambient F-Layer installations are irrelevant. Discovery reads installed
files through Python syntax and never imports F-Layer.
Every package file, including private Python, `__main__.py`, `py.typed`, and future
package resources, must match the source file inventory and bytes. Interpreter
bytecode caches are excluded. Missing or extra wheel files fail before rendering.

Each nonprivate module and the explicit CLI module gets an API page. Defined
public classes, functions, and methods require docstrings and exact rendered
anchors. Callable protocol methods (`__call__`) are included. Definitions inside conditional/control-flow blocks retain their module or class
scope and are inventoried without execution. Private helpers,
other special methods, and nested function definitions appear in the definition inventory
as source-only. Constructors remain represented by their class signature and
source; their docstrings are included in translation review when the renderer merges
them into class documentation. Dataclass hooks are implementation methods. Imported aliases, constants,
fields, and inherited methods are represented by their defining module or class;
the gate does not require duplicate anchors or pretend that tests are a public API.

A future public module is discovered automatically. A future private module is
accounted for and checked for wheel parity. Introducing a supported underscored
module other than the established CLI requires an explicit boundary decision.

## Site gates and evidence

Table padding measures raw Markdown cell text with a bounded Unicode display-width
approximation: wide/fullwidth characters count as two, combining marks as zero,
and other characters as one. It preserves cell bytes and Markdown escaping; it
does not claim full grapheme or emoji terminal-width equivalence.

The source gate checks every tracked Markdown link, table alignment, repository
classification, and generated-output policy. The strict installed-wheel build
checks every rendered local URL and exact fragment, required API anchors and
source links, and a graph walk from the English entry page. Every classified
Markdown/API page and the inventory must exist and be reachable. An existing
but orphaned page therefore fails.

```bash
python -m tools.documentation_coverage
python -m tools.documentation_gates
python -m tools.build_api_reference
python tools/validate.py
```

These gates check structural completeness and provenance. They cannot prove that
prose explains every behavior, that docstrings are semantically correct, or that
a translation has received a human review. No such approval is generated.

## Translation completeness

Repository pages, module introductions, public API descriptions, rendered
constructor descriptions, and inventory prose each have discovered translation
units under [ADR 0018](../adr/0018-generated-documentation-translations.md).
TOML catalogs in `docs/i18n/generated/` are localization inputs, not additional
canonical Markdown pages. Their reviews bind both source and translated bytes.
API source listings, commands, filenames, and symbol identities remain unchanged.

The locale renderer preserves routes and canonical heading anchors, records every
actual missing or stale unit, and never treats English fallback as a translation.
For package versions 2.0 and later, any incomplete rendered narrative prevents a
successful documentation build. The optional `--require-complete-translations`
flag applies that same gate to earlier stabilization versions. Existing tracked-file,
API-anchor, import-guard, link, reachability, and wheel-parity gates remain in force.
