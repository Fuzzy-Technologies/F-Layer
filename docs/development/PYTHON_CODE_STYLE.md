# Python Code Style

These rules apply to every Python file in Fuzzy Technologies engineering repositories, including production code, tests, scripts, and embedded Python fixtures.

## Language

- Python code, identifiers, docstrings, comments, assertion messages, and embedded Python source are English-only.
- Localized website content is outside this Python contract.
- Comments explain a reason, invariant, limitation, or architectural decision; they do not narrate obvious statements.

## Naming

Project-owned identifiers use:

- functions and methods: `PascalCase`, including `Main()`;
- classes, protocols, and enums: `PascalCase`;
- variables, parameters, and fields: `camelCase`; leading underscores are allowed for internal and name-mangled implementation details;
- constants: `UPPER_SNAKE_CASE`, with underscores between words;
- test files: `test_*.py`;
- test functions: the required `test_` prefix followed by `PascalCase`.

Preserve names imposed by Python, frameworks, SDKs, schemas, protocols, and third-party APIs. This includes dunder methods, pytest fixtures and hooks, callbacks, CLI options, configuration keys, and compatibility contracts.

Examples: `ycProfile`, `projectRoot`, `_statePath`, `LoadVpnProject()` and
`SCHEMA_VERSION`. Keep `subprocess.run(capture_output=True)` and
`Path.unlink(missing_ok=True)` exactly as their external APIs define them.
The same applies to standard-library overrides and test doubles implementing
those interfaces. Computed properties may retain their callable PascalCase
names; protocol properties describing stored data fields use those fields' camelCase names.

The owner reconfirmed these rules on 2026-11-04. The foundation's former
snake_case variable instruction is superseded. See
[the naming audit and migration](python-naming-audit.md) for scope and compatibility.

## Docstrings

- Every production and test module, class, function, and method has a concise English docstring.
- A docstring is the first statement in its scope.
- Leave one blank line after a function or method docstring before the implementation.

## Vertical Spacing

Use one blank line to expose transitions between logical phases inside a function or method.

Insert one blank line before a new control-flow phase, before a later `return`/`raise`/`yield`, after completed nested control flow, before `elif`/`else`/`except`/`finally`, between class methods, and before the module guard.

Do not insert a blank line immediately after a `def`, `class`, `try`, `if`, `elif`, `else`, `except`, `finally`, `for`, `while`, `with`, `match`, or `case` header.

Keep tightly related assignments and calls together. Use two blank lines between module-level functions and classes.

## Formatting and Linting

`ruff format` is not the canonical formatter and must not be run as an automatic project-wide rewrite or CI gate.

Use Ruff for lint and static checks:

```bash
python -m ruff check .
```

The canonical gate also runs `python -m tools.python_naming`. This checks all
tracked and newly authored Python modules and stubs without importing them.
External overrides are identified by exact file and qualified definition in
the validator; unrelated names receive no exemption. Built-in pytest fixture
parameters retain their registered injection names.

Formatting-only changes must not rename protected interfaces, modify behavior, or collapse logical blocks.

## Validation

Typical repository gates:

```bash
python -m compileall -q src tests
python -m ruff check .
python -m mypy
python -m pytest
```

Infrastructure, cleanup, rollback, authorization, resource-management, and error branches require deterministic tests without calls to real production infrastructure.

## Assertions and Tests

- Assertion messages identify the violated invariant and likely cause.
- Use branch coverage for control-flow-heavy code.
- Do not hide flaky tests with automatic retries.
- Tests must not depend on execution order or shared mutable state unless explicitly isolated.

## Git

Commit messages are concise, English, and imperative.

## Final Principle

Code must be consistent, readable, reproducible, and verifiable: explicit behavior over magic, evidence over assumptions, tests over manual confidence, and stability over cosmetic refactoring.
