# Python Code Style

## Naming

- Functions and methods: `PascalCase`.
- Classes: `PascalCase`.
- Variables, parameters and fields: `lowerCamelCase`.
- Constants: `UPPERCASE` without underscores.
- Do not use snake_case in project-owned identifiers.

Exceptions:
- Python protocol names.
- External API names.
- Test discovery names.

## Documentation

Production code:
- Module, class and function documentation in Russian.

Tests:
- Documentation and comments in English.

## Formatting

- Use `ruff check`.
- Do not use `ruff format` because intentional formatting may be removed.

## Testing

Required validation:
- tests;
- ruff check;
- compileall;
- CLI help checks when applicable.

## Principles

Readable, reproducible and testable code is preferred over clever solutions.
