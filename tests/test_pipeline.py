from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import yaml

from trace2policy.graph import build_capability_graph, graph_to_mermaid
from trace2policy.ingest import normalize_trace
from trace2policy.io import load_events, load_policy, write_jsonl, write_policy
from trace2policy.policy import (
    evaluate_policy,
    event_to_decision_input,
    run_policy_tests,
    synthesize_policy_from_events,
)
from trace2policy.redteam import generate_attacks
from trace2policy.rego import emit_rego, evaluate_rego
from trace2policy.report import render_markdown

ROOT = Path(__file__).resolve().parents[1]
GITHUB_TRACE = ROOT / "examples" / "github_issue_triage" / "traces.normal.jsonl"
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
    assert "Trace2Policy Report" in report


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
    decision_input = event_to_decision_input(events[-1])

    native = evaluate_policy(policy, decision_input)
    from_rego = evaluate_rego(rego, decision_input)

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
