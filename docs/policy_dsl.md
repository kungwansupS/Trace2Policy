# Policy DSL

TracePolicyKit emits a YAML policy before compiling to Rego.

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

Supported rule constraint keys are `labels_in` and `query`. Unsupported
constraint keys fail validation.

Supported deny condition keys are `action`, `sink`, `input.trust_level`,
`input.sensitivity`, `input.sensitivity_in`, `input.labels_contains`,
`resource.matches`, `resource.private_network`, `resource.domain_in`, and
`resource.scheme_in`. Unsupported condition keys fail validation before policy
evaluation or Rego emission.

`require_human_approval` rules are allow rules gated by approval. If a matching
decision input has `human_approved: false`, the decision is `requires_approval`.
If the same input has `human_approved: true`, the decision is allowed unless a
deny rule also matches.

Built-in deny rules block untrusted shell execution, sensitive external HTTP
exfiltration, private-network HTTP egress, secret file reads, and execution from
untrusted tool metadata.

`egress.allowed_domains` is enforced for `external_http` decisions. Exact
domains match only themselves. Wildcards support only `*.example.com`, which
matches subdomains such as `api.example.com` but not `example.com`. Evaluation
does not perform DNS lookups or live network calls.
