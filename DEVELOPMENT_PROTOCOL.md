# F-Layer Development Protocol

## Status and authority

Protocol version: `0.1`  
Project: **F-Layer by Fuzzy Technologies**

This document is the persistent development contract for the repository. Human contributors, AI agents, scripts, and CI jobs are expected to follow it.

## 1. Core principle

Development follows this order:

```text
architecture / contract
→ implementation
→ tests
→ evidence
→ documentation
→ review
```

A change is not complete because the code looks correct. Completion requires the applicable tests and evidence.

## 2. Project identity

F-Layer is a modular infrastructure automation platform for deploying, managing, and integrating secure cloud environments.

The core must remain independent from one cloud provider, one transport or network protocol, one deployment profile, one consumer application, and private/local Fuzzy Technologies infrastructure.

Provider-, deployment-, and integration-specific behavior belongs behind explicit contracts rather than being embedded into the core.

## 3. Repository language

Canonical repository language is English for source code, comments, docstrings, documentation, ADRs, commits, workflows, schemas, CLI/API names, issues, and pull requests. Localization assets are the normal exception.

## 4. GitHub planning model

Use native GitHub metadata as the source of truth.

```text
Milestone
└── Feature
    ├── Task
    └── Task
```

Every planned Feature and Task must have native Type, Priority, Effort, Milestone, native parent/sub-issue relationship, and an Assignee when work is active.

Titles describe work. Do not repeat planning metadata in titles.

## 5. Branching and release flow

Canonical branches:

- `master` — stable/released state;
- `develop` — integration branch for the next release;
- `feature/<name>` — feature/task implementation from `develop`;
- `fix/<name>` — non-release correction from `develop`;
- `release/<version>` — release stabilization;
- `hotfix/<name-or-version>` — urgent correction from `master`.

Normal flow:

```text
feature/* or fix/* → develop → release/X.Y.Z → master → tag vX.Y.Z
                                           └──────────→ develop
```

Normal implementation work must not be pushed directly to `master` or `develop`. Squash merge is the default for ordinary PRs into `develop`.

Detailed release rules are documented in [docs/RELEASE_WORKFLOW.md](docs/RELEASE_WORKFLOW.md).

## 6. Pull requests

Every implementation PR must have:

- base `develop` unless it is an explicit release/hotfix/publication flow;
- assignee;
- native Milestone matching the primary implementation issue;
- appropriate PR label when available;
- explicit closing reference to each completed Task;
- summary and validation evidence;
- security/compatibility notes when applicable.

Accepted Task-closing keywords are `Closes`, `Fixes`, `Resolves`, and `Implements`.

Human review remains the default merge gate. Automated agents must not merge their own PRs unless the owner explicitly requests that merge.

## 7. Python house style

The canonical Python style is [docs/development/PYTHON_CODE_STYLE.md](docs/development/PYTHON_CODE_STYLE.md).

Important invariants:

- functions and methods use `PascalCase`;
- classes/protocols/enums use `PascalCase`;
- variables, parameters, and fields use `snake_case`;
- constants use `UPPER_SNAKE_CASE`;
- source code, comments, docstrings, tests, and assertion messages are English-only;
- `ruff format` is not the canonical formatter and must not be used as a project-wide formatting gate.

External naming contracts take precedence over cosmetic normalization.

## 8. Architecture and ADRs

Architecture-impacting work requires an explicit design decision before or together with implementation.

Use [docs/adr/](docs/adr/) for ADRs. ADRs document context, decision, consequences, alternatives, and compatibility/migration impact when relevant.

Do not introduce speculative abstractions. Add an abstraction when it represents a real stable contract or has at least two credible consumers.

## 9. Configuration and state

Configuration, desired state, observed provider state, and generated artifacts are separate concepts.

- credentials never belong in tracked configuration;
- persisted state stores only the minimum identifiers required to manage resources;
- generated artifacts have clear ownership and lifecycle;
- cleanup and rollback behavior are explicit;
- partial deployment and interrupted operations must fail safely and remain diagnosable.

## 10. Provider and deployment boundaries

Provider-specific code owns cloud API details, authentication adapters, capability discovery, and provider resource translation.

Deployment profiles compose provider capabilities into user-facing infrastructure outcomes.

The core owns generic contracts and orchestration semantics and must not assume a specific provider, region, network protocol, or local environment.

## 11. Tests

`pytest` is the canonical Python test runner.

```text
tests/
├── unit/
├── contract/
├── functional/
├── integration/
└── e2e/
```

Bootstrap may start with `tests/unit/`. Infrastructure, cleanup, rollback, resource-management, and error branches require deterministic tests without calls to real production infrastructure.

## 12. Canonical validation gate

```bash
python -m compileall -q src tests tools
python -m ruff check .
python -m mypy
python -m pytest
```

A later tracked-file edit invalidates the previous full gate and requires it again before the change is reported ready.

## 13. Security and secrets

Never commit credentials, tokens, private keys, cookies, session material, private infrastructure identifiers, or machine-local secrets.

Real cloud mutation requires explicit owner authorization for the specific task. Destructive provider operations require bounded scope, cleanup behavior, and failure-path tests.

## 14. Local/private state

Do not commit virtual environments, IDE metadata, caches, coverage output, local databases/state, generated reports, logs, credentials, build artifacts, local absolute paths, or NAS references.

## 15. Documentation

Use:

- `README.md` for the concise project entry point;
- `docs/architecture/` for architecture;
- `docs/adr/` for decisions;
- `docs/development/` for engineering guidance;
- future localized documentation for EN/RU/ZH user documentation.

Documentation must distinguish implemented behavior from roadmap direction.

## 16. Post-merge automation

After a PR is actually merged, automation may parse explicit closing references, verify native `Task` type, add a completion comment, close the Task as completed, and safely delete the merged same-repository branch when it is not protected.

Features are not automatically closed merely because a child Task merged.

## 17. Definition of done

A change is done only when scope/contracts are understood, implementation and relevant tests are complete, failure behavior is considered, no secret/private/local artifact entered the diff, documentation is updated when required, and required gates pass.

If a required check was not run or failed, report that fact.

## 18. Owner escalation

Stop and ask before destructive or ambiguous actions, expansion to another system, real cloud mutation not already authorized, security-policy changes, public compatibility breaks, license/trademark/product decisions, or changes to `AGENTS.md` / this protocol.
