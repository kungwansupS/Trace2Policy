from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from tracepolicykit import models as trace_models
from tracepolicykit.graph import build_capability_graph, graph_to_mermaid
from tracepolicykit.ingest import normalize_trace
from tracepolicykit.io import load_events, load_policy, write_jsonl, write_policy
from tracepolicykit.policy import (
    evaluate_policy,
    event_to_decision_input,
    run_policy_tests,
    synthesize_policy_from_events,
)
from tracepolicykit.redteam import generate_attacks
from tracepolicykit.rego import emit_rego, evaluate_rego
from tracepolicykit.report import render_markdown

ROOT = Path(__file__).resolve().parents[1]
GITHUB_TRACE = ROOT / "examples" / "github_issue_triage" / "traces.normal.jsonl"
OPENINFERENCE_FIXTURE = ROOT / "tests" / "fixtures" / "openinference_export.json"
LANGFUSE_FIXTURE = ROOT / "tests" / "fixtures" / "langfuse_export.json"
EXAMPLES = [
    ROOT / "examples" / "github_issue_triage" / "traces.normal.jsonl",
    ROOT / "examples" / "email_summarizer" / "traces.normal.jsonl",
    ROOT / "examples" / "filesystem_agent" / "traces.normal.jsonl",
]


def test_jsonl_ingest_preserves_canonical_events(tmp_path: Path) -> None:
    out = tmp_path / "normalized.jsonl"
    events = normalize_trace(GITHUB_TRACE, "jsonl")
    write_jsonl(out, events)

    loaded = load_events(out)
    assert len(loaded) == 3
    assert loaded[0].input.trust_level == "trusted_user_instruction"
    assert loaded[1].input.trust_level == "untrusted"
    assert loaded[2].operation.params["label"] == "bug"


def test_openinference_and_langfuse_like_ingest(tmp_path: Path) -> None:
    openinference = tmp_path / "openinference.json"
    openinference.write_text(
        """
        {"spans":[{"trace_id":"tr","span_id":"sp","attributes":{
          "openinference.span.kind":"TOOL",
          "tool.name":"github.issue.read",
          "resource.type":"github.issue",
          "resource.id":"owner/project#123"
        }}]}
        """,
        encoding="utf-8",
    )
    langfuse = tmp_path / "langfuse.json"
    langfuse.write_text(
        """
        {"observations":[{"traceId":"tr","id":"obs","type":"generation","name":"classify"}]}
        """,
        encoding="utf-8",
    )

    assert (
        normalize_trace(openinference, "openinference")[0].operation.action == "github.issue.read"
    )
    assert normalize_trace(langfuse, "langfuse")[0].event_type.value == "llm_call"


def test_real_shape_ingest_fixtures_cover_supported_span_kinds() -> None:
    openinference = normalize_trace(OPENINFERENCE_FIXTURE, "openinference")
    langfuse = normalize_trace(LANGFUSE_FIXTURE, "langfuse")

    assert [event.event_type.value for event in openinference] == [
        "agent",
        "llm_call",
        "tool_call",
        "retrieval",
        "guardrail",
    ]
    assert openinference[0].operation.action == "agent.run"
    assert openinference[-1].operation.action == "guardrail.check"
    assert langfuse[0].event_type.value == "llm_call"
    assert langfuse[1].operation.action == "github.issue.comment.create"


def test_graph_policy_redteam_and_report_pipeline(tmp_path: Path) -> None:
    events = load_events(GITHUB_TRACE)
    graph = build_capability_graph(events)
    mermaid = graph_to_mermaid(graph)
    policy = synthesize_policy_from_events(events)
    attacks = generate_attacks(events)
    results = run_policy_tests(policy, events, attacks)
    report = render_markdown(results)

    write_policy(tmp_path / "policy.yaml", policy)
    loaded_policy = load_policy(tmp_path / "policy.yaml")

    assert "flowchart TD" in mermaid
    assert loaded_policy.defaults.decision == "deny"
    assert any(
        rule.action == "github.issue.comment.create" for rule in policy.require_human_approval
    )
    assert results.passed
    assert "TracePolicyKit Report" in report


@pytest.mark.parametrize("trace_path", EXAMPLES)
def test_examples_generate_passing_policy_tests(trace_path: Path) -> None:
    events = load_events(trace_path)
    policy = synthesize_policy_from_events(events)
    attacks = generate_attacks(events)
    results = run_policy_tests(policy, events, attacks)

    assert results.passed


def test_policy_blocks_scope_creep_and_secret_reads() -> None:
    events = load_events(GITHUB_TRACE)
    policy = synthesize_policy_from_events(events)
    attacks = {event.expected.attack: event for event in generate_attacks(events) if event.expected}

    scope = evaluate_policy(policy, event_to_decision_input(attacks["scope_creep"]))
    secret = evaluate_policy(policy, event_to_decision_input(attacks["secret_read_attempt"]))
    public_write = evaluate_policy(policy, event_to_decision_input(attacks["unsafe_public_write"]))

    assert scope.decision == "deny"
    assert secret.decision == "deny"
    assert public_write.decision == "requires_approval"


def test_human_approved_high_impact_action_is_allowed() -> None:
    events = load_events(GITHUB_TRACE)
    policy = synthesize_policy_from_events(events)
    attack = next(
        event
        for event in generate_attacks(events)
        if event.expected and event.expected.attack == "unsafe_public_write"
    )
    attack.decision.human_approved = True

    decision = evaluate_policy(policy, event_to_decision_input(attack))

    assert decision.decision == "allow"


def test_private_network_egress_is_denied() -> None:
    events = load_events(GITHUB_TRACE)
    policy = synthesize_policy_from_events(events)
    event = events[0].model_copy(deep=True)
    event.operation.system = "http"
    event.operation.action = "http.post"
    event.operation.tool_name = "http.post"
    event.operation.resource_id = "http://127.0.0.1/admin"
    event.output.sink = "external_http"
    event.input.sensitivity = "internal"
    event.input.labels = []

    decision = evaluate_policy(policy, event_to_decision_input(event))

    assert decision.decision == "deny"
    assert "Private network egress" in "; ".join(decision.deny_reasons)


def test_egress_allowlist_and_url_scheme_policy() -> None:
    policy = trace_models.Policy(
        task="egress",
        allow=[
            trace_models.Rule(
                id="allow_http_post",
                subject="agent:egress",
                action="http.post",
            )
        ],
        egress={"allowed_domains": ["api.example.com", "*.trusted.example"]},
    )
    base = load_events(GITHUB_TRACE)[0].model_copy(deep=True)
    base.actor.id = "agent:egress"
    base.operation.system = "http"
    base.operation.action = "http.post"
    base.operation.tool_name = "http.post"
    base.operation.resource_type = "url"
    base.output.sink = "external_http"
    base.input.sensitivity = "internal"
    base.input.labels = []

    exact = base.model_copy(deep=True)
    exact.operation.resource_id = "https://api.example.com/upload"
    wildcard = base.model_copy(deep=True)
    wildcard.operation.resource_id = "https://sub.trusted.example/upload"
    unknown = base.model_copy(deep=True)
    unknown.operation.resource_id = "https://evil.example/upload"
    bad_scheme = base.model_copy(deep=True)
    bad_scheme.operation.resource_id = "javascript:alert(1)"
    metadata = base.model_copy(deep=True)
    metadata.operation.resource_id = "http://169.254.169.254/latest/meta-data/"

    assert evaluate_policy(policy, event_to_decision_input(exact)).decision == "allow"
    assert evaluate_policy(policy, event_to_decision_input(wildcard)).decision == "allow"
    assert evaluate_policy(policy, event_to_decision_input(unknown)).decision == "deny"
    assert "URL scheme" in "; ".join(
        evaluate_policy(policy, event_to_decision_input(bad_scheme)).deny_reasons
    )
    assert "Private network" in "; ".join(
        evaluate_policy(policy, event_to_decision_input(metadata)).deny_reasons
    )


def test_policy_contract_rejects_unsupported_condition_and_constraint(tmp_path: Path) -> None:
    invalid_condition = tmp_path / "invalid-condition.yaml"
    invalid_condition.write_text(
        """
schema_version: "0.1"
task: invalid
deny:
  - id: bad
    when:
      actor.role: admin
    reason: bad
""",
        encoding="utf-8",
    )
    invalid_constraint = trace_models.Policy(
        task="invalid",
        allow=[
            trace_models.Rule(
                id="bad_constraint",
                action="file.read",
                constraints={"unsupported": True},
            )
        ],
    )

    with pytest.raises(ValueError, match="unsupported condition key"):
        load_policy(invalid_condition)
    with pytest.raises(ValueError, match="unsupported key"):
        emit_rego(invalid_constraint)


def test_redteam_generates_all_default_attacks() -> None:
    from tracepolicykit.redteam import DEFAULT_ATTACKS

    attacks = generate_attacks(load_events(GITHUB_TRACE))

    assert {event.expected.attack for event in attacks if event.expected} == set(DEFAULT_ATTACKS)
    assert all(event.expected is not None for event in attacks)


def test_rego_emitter_contains_v1_policy() -> None:
    policy = synthesize_policy_from_events(load_events(GITHUB_TRACE))
    rego = emit_rego(policy)

    assert "import rego.v1" in rego
    assert "default allow := false" in rego
    assert "github.issue.add_label" in rego


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa CLI is not installed")
def test_rego_decision_matches_native_evaluator() -> None:
    events = load_events(GITHUB_TRACE)
    policy = synthesize_policy_from_events(events)
    rego = emit_rego(policy)
    attacks = generate_attacks(events)
    approved = next(
        event.model_copy(deep=True)
        for event in attacks
        if event.expected and event.expected.attack == "unsafe_public_write"
    )
    approved.decision.human_approved = True
    label_only_exfil = events[0].model_copy(deep=True)
    label_only_exfil.operation.system = "http"
    label_only_exfil.operation.action = "http.post"
    label_only_exfil.operation.tool_name = "http.post"
    label_only_exfil.operation.resource_id = "https://unknown.example/upload"
    label_only_exfil.output.sink = "external_http"
    label_only_exfil.input.sensitivity = "internal"
    label_only_exfil.input.labels = ["customer_data"]
    private_egress = label_only_exfil.model_copy(deep=True)
    private_egress.operation.resource_id = "http://127.0.0.1/admin"
    private_egress.input.labels = []
    exact_resource_type = events[0].model_copy(deep=True)
    exact_resource_type.operation.resource_id = None
    exact_resource_type.operation.resource_type = "github.issue"

    for event in [
        *events,
        *attacks,
        approved,
        label_only_exfil,
        private_egress,
        exact_resource_type,
    ]:
        decision_input = event_to_decision_input(event)
        native = evaluate_policy(policy, decision_input)
        from_rego = evaluate_rego(rego, decision_input)

        assert from_rego.decision == native.decision


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa CLI is not installed")
def test_rego_condition_domain_and_scheme_match_native_evaluator() -> None:
    policy = trace_models.Policy(
        task="condition_parity",
        allow=[trace_models.Rule(id="allow_http", subject="agent:egress", action="http.post")],
        deny=[
            trace_models.DenyRule(
                id="deny_bad_domain",
                when={
                    "resource.domain_in": ["*.evil.example"],
                    "resource.scheme_in": ["https"],
                },
                reason="Blocked egress domain",
            )
        ],
        egress={"allowed_domains": ["*.evil.example"]},
    )
    event = load_events(GITHUB_TRACE)[0].model_copy(deep=True)
    event.actor.id = "agent:egress"
    event.operation.system = "http"
    event.operation.action = "http.post"
    event.operation.tool_name = "http.post"
    event.operation.resource_id = "https://sub.evil.example/upload"
    event.output.sink = "external_http"

    decision_input = event_to_decision_input(event)
    native = evaluate_policy(policy, decision_input)
    from_rego = evaluate_rego(emit_rego(policy), decision_input)

    assert native.decision == "deny"
    assert from_rego.decision == native.decision


def test_yaml_loader_rejects_unsafe_constructors(tmp_path: Path) -> None:
    malicious = tmp_path / "policy.yaml"
    malicious.write_text("!!python/object/new:os.system ['echo unsafe']\n", encoding="utf-8")

    with pytest.raises(yaml.YAMLError):
        load_policy(malicious)


def test_raw_content_is_not_persisted_in_normalized_events(tmp_path: Path) -> None:
    source = tmp_path / "trace.json"
    source.write_text(
        """
        {"observations":[{"traceId":"tr","id":"obs","type":"generation",
        "name":"summarize","input":"customer secret text","output":"summary"}]}
        """,
        encoding="utf-8",
    )

    event = normalize_trace(source, "langfuse")[0]

    assert event.input.content_ref is not None
    assert event.input.content_preview is None


def test_ingest_validation_errors_include_line_context(tmp_path: Path) -> None:
    source = tmp_path / "trace.jsonl"
    source.write_text(
        '{"trace_id":"tr","span_id":"sp","task_id":"t","event_type":"tool_call",'
        '"operation":{"action":" "}}\n',
        encoding="utf-8",
    )

    with pytest.raises(trace_models.TraceValidationError) as exc_info:
        normalize_trace(source, "jsonl")

    assert str(source) in str(exc_info.value)
    assert ":1:" in str(exc_info.value)


def test_report_redacts_secret_like_values() -> None:
    results = trace_models.TestResults(
        policy_id="demo",
        policy_hash="sha256:test",
        negative=[
            trace_models.TestCaseResult(
                name="token=abc123",
                expected="deny",
                actual="allow",
                passed=False,
                reasons=[
                    "api_key=secret-value should not appear",
                    "Bearer abcdefghijklmnopqrstuvwxyz",
                    "AKIA1234567890ABCDEF",
                    "ghp_abcdefghijklmnopqrstuvwxyz123456",
                ],
            )
        ],
        positive=[
            trace_models.TestCaseResult(
                name="positive",
                expected="allow",
                actual="deny",
                passed=False,
                reasons=["password=hunter2"],
            )
        ],
    )

    report = render_markdown(results)

    assert "abc123" not in report
    assert "secret-value" not in report
    assert "hunter2" not in report
    assert "AKIA1234567890ABCDEF" not in report
    assert "ghp_" not in report
    assert "[REDACTED_SECRET]" in report
    assert "Failed Positive Cases" in report


def test_policy_test_receipts_are_redacted() -> None:
    event = load_events(GITHUB_TRACE)[0].model_copy(deep=True)
    policy = trace_models.Policy(
        task="receipt_redaction",
        deny=[
            trace_models.DenyRule(
                id="redacted_reason",
                when={"action": event.operation.action},
                reason="token=abc123",
            )
        ],
    )

    results = run_policy_tests(policy, [], [event])

    assert "abc123" not in str(results.receipts)
    assert "[REDACTED_SECRET]" in str(results.receipts)
