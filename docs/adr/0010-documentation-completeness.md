# ADR 0010: Explicit repository documentation completeness

- Status: Accepted
- Date: 2026-10-04
- Task: [#28](https://github.com/Fuzzy-Technologies/F-Layer/issues/28)
- Builds on: [ADR 0004](0004-documentation-platform.md)

## Context

The initial builder discovers nonprivate installed Python modules. Its path
filter also excludes `flayer.__main__`, although that module provides the
supported CLI entry point. Comparing only discovered public modules cannot
detect a private module omitted from the wheel or source/wheel drift outside
that subset. Copying selected documentation folders leaves other Markdown,
including policy and project guides, outside the rendered navigation.

"Documentation for all files" needs an explicit scope. Autodocumenting tests,
engineering tools, and private implementation helpers would falsely imply a
supported consumer API. Excluding them silently would make the claim unverifiable.

## Decision

Maintain an explicit coverage-rule manifest. Every tracked file must match one
rule with an accountable category and reason. Generate file and definition
inventories as disposable JSON and navigable Markdown. Established categories
accept future files dynamically; missing, ambiguous, and unsupported categories
fail closed. Do not hardcode module counts.

Require exact source/installed-wheel package inventory and byte parity, excluding
interpreter bytecode. Include the executable CLI module explicitly. Render
nonprivate modules, public definitions, public methods, and callable protocols;
record private, nested, and other special-method definitions as source-only.
Keep constructors represented through class signatures and source.

Render every canonical tracked Markdown file, including ADR templates, policy,
release and development guides, repository entry points, and PR template.
Preserve existing authored routes and generate repository routes for the rest.
Resolve copied Markdown links to rendered routes; preserve source references for
nonpage files. Never modify owner-controlled policies during generation.

Gate rendered existence and reachability from the English entry, exact API
anchors, links, table alignment, coverage rules, and generated-output policy.
Keep locale review authority unchanged and never infer human approval from
structural coverage. Add an implemented architecture reference and ADR index.

## Consequences

The build can support an honest file-completeness claim while distinguishing
supported API documentation from source-only engineering material. New files
in established categories are visible automatically; new categories need a
reviewable rule. Private wheel omissions and orphaned pages become failures.
Machine-readable evidence records exact dispositions alongside wheel provenance.

Structural completeness does not establish semantic completeness of prose or
translation quality. Imported aliases, fields, constants, and inherited members
remain represented by their defining module/class rather than duplicate anchor
requirements. A supported underscored module needs an explicit boundary decision.

## Alternatives

Blind autodoc of every Python file exposes internals as consumer contracts.
Hand-maintained file/module counts become stale as independent branches merge.
Directory-only copying or checking merely that target files exist misses orphaned
pages. Runtime imports retain unacceptable execution and credential risks.

## Compatibility and migration

Public Python behavior and authored documentation routes are unchanged. The CLI
API page, repository routes, and coverage inventory are additive. Build evidence
adds completeness fields. Locale hashes must be refreshed when canonical English
content changes, with translations remaining missing or stale until reviewed.
