# Roadmap

TracePolicyKit v0.2 is an offline policy synthesis and replay-testing CLI. The
next work should strengthen correctness, input coverage, and enforcement
readiness without adding empty modules or premature public plugin APIs.

## Near Term

- Add golden fixtures for OpenInference-like and Langfuse-like exports gathered
  from broader real anonymized traces.
- Expand Rego parity tests with larger policy fixtures and generated decision
  input tables.
- Add policy diff output so users can review what changed between two trace
  captures or policy revisions.
- Add structured error codes for validation, ingest mapping, policy evaluation,
  and OPA execution failures.

## Security

- Add egress checks for domain allowlists, wildcard domains, redirects, and DNS
  rebinding risk beyond offline URL analysis.
- Add stricter secret detection tests for common credential formats while
  keeping redaction deterministic and local-only.
- Add MCP tool-list provenance fields so tool metadata can be pinned or treated
  as untrusted by default.
- Add attack mutators for tool result spoofing, URL rewriting, path traversal,
  and approval bypass attempts.

## Integration

- Add a non-interactive GitHub issue exporter example that produces canonical
  trace JSONL without calling live tools during tests.
- Add optional SARIF or JUnit report emitters for CI systems.
- Add installation docs for OPA on Linux, macOS, and Windows.
- Add a small public sample dataset with sanitized traces and expected policies.

## Later

- Define a provisional plugin boundary only after two or more external ingestors
  need it.
- Explore runtime enforcement adapters after offline policy evaluation is stable.
  The v0.2 CLI should not become a live firewall.
