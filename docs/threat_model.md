# Threat Model

Trace2Policy focuses on offline policy synthesis and replay testing for
tool-using AI agents.

Security defaults:

- Deny by default.
- Infer least privilege from observed behavior.
- Require human approval for irreversible or public-impact actions.
- Treat unknown or external content as untrusted.
- Never allow untrusted content to trigger code execution.
- Block external HTTP egress to loopback, link-local, private, or otherwise
  non-global IP literal destinations.
- Enforce external HTTP domain allowlists without live DNS resolution.
- Do not store raw secrets in traces.
- Redact content by default and use content hashes when possible.
- Treat tool metadata as untrusted unless pinned.
- Emit auditable decisions.

Out of scope for v0.2:

- Live runtime firewall enforcement.
- SaaS dashboard.
- Calling real external tools during red-team replay.
- Complete support for every agent framework trace format.
