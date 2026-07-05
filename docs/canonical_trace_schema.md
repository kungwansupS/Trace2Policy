# Canonical Trace Schema v0.1

TracePolicyKit normalizes trace inputs into JSONL. Each line is one event with
`schema_version` set to `0.1`.

Required fields:

- `trace_id`: execution identifier.
- `span_id`: event identifier inside the trace.
- `task_id`: policy synthesis boundary.
- `event_type`: one of `agent`, `user_input`, `system_instruction`,
  `llm_call`, `tool_call`, `tool_result`, `retrieval`, `file_read`,
  `file_write`, `network_request`, `mcp_tool_list`, `mcp_tool_call`,
  `mcp_resource_read`, `guardrail`, `human_approval`, `policy_decision`, or
  `error`.
- `operation.action`: normalized action such as `github.issue.read`.

Important nested fields:

- `actor`: subject performing the operation.
- `operation`: system, tool name, action, resource, and parameters.
- `input` and `output`: content reference, labels, sensitivity, trust, and sink.
- `auth`, `runtime`, `decision`, `metadata`: optional provenance fields.

Raw prompt, output, tool arguments, and tool results are not stored by default.
Use `content_ref` hashes and labels for policy synthesis.

Policy tests convert events into decision inputs with `subject`, `action`,
`resource`, `input`, `sink`, `params`, and `human_approved`. URL resources also
derive optional `resource.scheme`, `resource.host`, `resource.port`,
`resource.domain`, and `resource.private_network` fields for offline egress
checks. The package version can advance without changing the canonical trace
`schema_version`.
