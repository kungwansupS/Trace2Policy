# Contributing

Thanks for your interest in Trace2Policy.

Trace2Policy v0.1 accepts focused contributions: bug fixes, tests, docs, and
small improvements that match the current scope (offline trace-to-policy
synthesis and replay testing).

## Development Setup

```bash
uv sync --all-extras
uv run trace2policy --help
```

Fallback:

```bash
pip install -e ".[dev,test]"
```

## Quality Checks

Before opening a pull request, run:

```bash
uv run ruff check
uv run ruff format --check
uv run mypy src tests
uv run pytest
uv build
```

OPA is optional locally. CI installs OPA and runs the Rego parity test.

## Guidelines

- Keep changes focused and include tests for behavior changes.
- Avoid unrelated formatting or generated-file churn.
- Match existing code style and module boundaries.

## License Notice

Unless explicitly stated otherwise, contributions intentionally submitted for
inclusion in this repository are licensed under the Apache License, Version 2.0.
