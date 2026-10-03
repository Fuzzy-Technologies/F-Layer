# AGENTS.md

## Purpose

This file is the mandatory entry point for AI agents, Codex sessions, IDE assistants, automation, and other software agents working in F-Layer.

Before changing code or documentation, read and follow [DEVELOPMENT_PROTOCOL.md](DEVELOPMENT_PROTOCOL.md). It is the canonical repository development contract.

## Repository boundary

- Work only inside this repository unless the owner explicitly authorizes another repository or external system for the current task.
- Do not inspect or modify parent directories, sibling repositories, user home data, mounted shares, or unrelated local storage.
- Do not infer permission to access infrastructure merely because credentials or tooling are available.
- Read only the files required for the task; prefer targeted search and narrow excerpts over unrestricted context dumps.

## Infrastructure safety

F-Layer manages infrastructure. Tests and development must not mutate real cloud resources unless the owner explicitly authorizes that exact operation.

By default:

- provider tests use mocks, fakes, fixtures, or repository-defined isolated resources;
- destructive create/update/delete operations against real accounts are prohibited;
- credentials and secrets are never model context and are never committed;
- cleanup, rollback, idempotency, and failure behavior are first-class contracts.

## Language

- Source code, comments, docstrings, commit messages, ADRs, canonical documentation, schemas, CLI commands, and repository metadata are English-only.
- Localization assets may contain their target language.
- User-facing discussion may follow the user's language.

## Mandatory development rules

- Follow `DEVELOPMENT_PROTOCOL.md`.
- Architecture-impacting changes require an ADR or explicit design decision.
- Prefer deterministic tools and tests when they can answer the question.
- Keep changes small, reviewable, and scoped to one objective.
- Do not mix behavior changes with unrelated formatting or cleanup.
- Never claim completion without applicable tests and evidence.
- Never add private infrastructure identifiers, local paths, credentials, tokens, or secrets to tracked files.

## Git workflow

- `master` is the stable/released branch.
- `develop` is the integration branch.
- Normal work uses `feature/*`, `fix/*`, `release/*`, or `hotfix/*` branches.
- Do not push normal implementation work directly to `master` or `develop`.
- Automated agents may prepare branches, commits, and pull requests when authorized, but must not merge their own PRs unless the owner explicitly requests that merge.
- Do not force-push protected branches or rewrite published history.

## Protected policy files

`AGENTS.md` and `DEVELOPMENT_PROTOCOL.md` are owner-controlled policy files. Agents may read and cite them, but must not modify, replace, delete, or weaken them without explicit owner authorization.

## Completion

Before reporting completion:

1. inspect the exact diff;
2. run targeted tests;
3. run the canonical full gate when available;
4. verify no secret, private identifier, or unrelated file entered the change;
5. update documentation when required;
6. report actual evidence, failures, and remaining uncertainty.

If a required check cannot be run, report it as not run. Never convert an unexecuted check into PASS.
