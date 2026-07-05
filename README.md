# TracePolicyKit

Convert AI agent traces into enforceable least-privilege policies.

TracePolicyKit ingests AI agent traces, normalizes them to a canonical trace IR,
builds a capability graph, synthesizes policy, emits YAML/Rego, generates
offline red-team mutations, and reports whether the policy blocks those
mutations.

## ภาษาไทย

TracePolicyKit เป็น CLI สำหรับแปลง trace ของ AI agent ให้เป็น policy แบบ
least privilege ที่ตรวจสอบซ้ำได้ เหมาะกับงานทดลอง, security review, และการ
เตรียม policy ก่อนนำ agent ไปใช้กับเครื่องมือจริง

ลำดับงานหลัก:

- รับ trace จาก canonical JSONL, OpenInference-like JSON, หรือ Langfuse-like JSON
- normalize เป็น canonical trace schema v0.1
- สร้าง capability graph จากพฤติกรรมที่เห็นจริง
- infer policy แบบ default deny
- emit เป็น YAML หรือ Rego สำหรับ OPA
- สร้าง offline red-team mutations โดยไม่เรียกใช้ tool จริง
- ทดสอบ policy และสร้างรายงาน

เริ่มใช้งาน:

```bash
uv sync --all-extras
uv run tracepolicykit validate examples/github_issue_triage/traces.normal.jsonl
uv run tracepolicykit infer examples/github_issue_triage/traces.normal.jsonl --out policy.yaml
```

ค่าเริ่มต้นด้านความปลอดภัย:

- ไม่เก็บ raw prompt/output โดย default
- trust ที่ไม่รู้จักถือเป็น untrusted
- sensitivity ที่ไม่รู้จักถือเป็น internal
- deny เป็นค่าเริ่มต้นของ policy
- red-team replay ทำงาน offline เท่านั้น
- secret-looking values ถูก redact ในรายงาน

## Status

TracePolicyKit is alpha software. The v0.2 CLI is usable for local experiments,
examples, and policy synthesis research. Public APIs may still change.

## Install

Recommended development workflow:

```bash
uv sync --all-extras
uv run tracepolicykit --help
```

Fallback:

```bash
pip install -e ".[dev,test]"
tracepolicykit --help
```

## Quickstart

```bash
tracepolicykit validate examples/github_issue_triage/traces.normal.jsonl

tracepolicykit decision-input examples/github_issue_triage/traces.normal.jsonl \
  --out decisions.jsonl

tracepolicykit graph examples/github_issue_triage/traces.normal.jsonl \
  --format mermaid \
  --out graph.md

tracepolicykit infer examples/github_issue_triage/traces.normal.jsonl \
  --out policy.yaml

tracepolicykit emit policy.yaml \
  --target rego \
  --out policy.rego

tracepolicykit validate-policy policy.yaml

tracepolicykit redteam generate examples/github_issue_triage/traces.normal.jsonl \
  --out attacks.jsonl

tracepolicykit test \
  --policy policy.yaml \
  --positive examples/github_issue_triage/traces.normal.jsonl \
  --negative attacks.jsonl \
  --out results.json

tracepolicykit test \
  --policy policy.rego \
  --positive examples/github_issue_triage/traces.normal.jsonl \
  --negative attacks.jsonl \
  --out results-rego.json

tracepolicykit report results.json \
  --format markdown \
  --out report.md
```

## Inputs

Supported v0.2 inputs:

- canonical TracePolicyKit JSONL
- OpenInference-like JSON spans
- Langfuse-like JSON exports

The canonical schema is documented in
[docs/canonical_trace_schema.md](docs/canonical_trace_schema.md).

## Security Defaults

- Default decision is deny.
- Unknown trust is treated as untrusted.
- Unknown sensitivity is treated as internal.
- Raw prompt/output content is not persisted by default.
- Red-team replay is offline and does not call live tools.
- YAML policies are parsed with safe loading.
- Secret-looking values are redacted from reports.
- External HTTP egress to private network destinations is denied.
- External HTTP egress is limited to policy allowlisted domains.

## Development

```bash
uv run ruff check
uv run ruff format --check
uv run mypy src tests
uv run pytest
uv build
```

OPA is optional for local development. If `opa` is installed, the Rego parity
test also runs.

## License

This repository is licensed under the Apache License, Version 2.0. See
[LICENSE](LICENSE).

Unless a more specific license file is added later for a subdirectory or file,
the Apache-2.0 license applies to the whole repository, including source code,
documentation, examples, and configuration.
