# Policy DSL v0.1

Trace2Policy emits a YAML policy before compiling to Rego.

Top-level fields:

- `schema_version`: currently `0.1`.
- `task`: policy boundary.
- `defaults`: default decision is deny.
- `allow`: least-privilege rules inferred from observed behavior.
- `require_human_approval`: rules for high-impact actions.
- `deny`: global and data-flow deny rules.
- `egress`: allowed network domains.
- `audit`: receipt settings.

Rules match a subject, action, optional resource, and optional constraints. YAML
is always parsed with safe loading.
