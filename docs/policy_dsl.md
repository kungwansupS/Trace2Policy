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

`require_human_approval` rules are allow rules gated by approval. If a matching
decision input has `human_approved: false`, the decision is `requires_approval`.
If the same input has `human_approved: true`, the decision is allowed unless a
deny rule also matches.

Built-in deny rules block untrusted shell execution, sensitive external HTTP
exfiltration, private-network HTTP egress, secret file reads, and execution from
untrusted tool metadata.
