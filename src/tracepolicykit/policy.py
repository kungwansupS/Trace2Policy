from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from ipaddress import ip_address
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from tracepolicykit.conditions import condition_matches, egress_decision, validate_policy_contract
from tracepolicykit.graph import Capability, CapabilityGraph, build_capability_graph
from tracepolicykit.labels import is_high_impact_action, is_secret_path
from tracepolicykit.models import (
    DecisionInput,
    DecisionResource,
    DecisionResult,
    DecisionSink,
    DenyRule,
    Event,
    Policy,
    Rule,
    TestCaseResult,
    TestResults,
    utc_now,
)
from tracepolicykit.redact import redact_json_value

SENSITIVE_LABELS = {"credential", "secret", "pii", "customer_data", "financial", "health", "legal"}


def synthesize_policy_from_events(events: list[Event], task: str | None = None) -> Policy:
    return synthesize_policy(build_capability_graph(events, task))


def synthesize_policy(graph: CapabilityGraph) -> Policy:
    task = graph.task
    subject_ids = sorted({capability.subject for capability in graph.capabilities})
    policy = Policy(
        task=task,
        subjects=[{"id": subject, "type": "agent"} for subject in subject_ids],
        egress={"allowed_domains": _allowed_domains(graph.capabilities)},
    )
    for capability in graph.capabilities:
        rule = _rule_from_capability(capability)
        if is_high_impact_action(capability.action):
            policy.require_human_approval.append(rule)
        else:
            policy.allow.append(rule)
    policy.require_human_approval.extend(_inferred_approval_rules(graph.capabilities))
    policy.deny.extend(default_deny_rules())
    return policy


def default_deny_rules() -> list[DenyRule]:
    return [
        DenyRule(
            id="no_shell_from_untrusted_content",
            when={"action": "shell.exec", "input.trust_level": "untrusted"},
            reason="Untrusted content cannot trigger shell execution",
        ),
        DenyRule(
            id="no_sensitive_data_to_external_http",
            when={"sink": "external_http", "input.sensitivity_in": sorted(SENSITIVE_LABELS)},
            reason="Sensitive content cannot be sent to external HTTP sinks",
        ),
        DenyRule(
            id="no_private_network_egress",
            when={"sink": "external_http", "resource.private_network": True},
            reason="Private network egress is outside task scope",
        ),
        DenyRule(
            id="no_secret_file_read",
            when={"action": "file.read", "resource.matches": ["**/.env", "**/.env.*", "~/.ssh/**"]},
            reason="Secret files are outside task scope",
        ),
        DenyRule(
            id="no_untrusted_tool_metadata_execution",
            when={"action": "mcp.tool.call", "input.labels_contains": "untrusted_tool_metadata"},
            reason="Untrusted tool metadata cannot trigger MCP tool execution",
        ),
    ]


def event_to_decision_input(event: Event) -> DecisionInput:
    resource = _decision_resource(event.operation.resource_type, event.operation.resource_id)
    sink = DecisionSink(
        type=event.output.sink, domain=_domain_from_resource(event.operation.resource_id)
    )
    return DecisionInput(
        subject=event.actor.id,
        action=event.operation.action,
        resource=resource,
        input=event.input,
        sink=sink,
        params={**event.operation.params, **event.input.params},
        human_approved=event.decision.human_approved,
        metadata={"trace_id": event.trace_id, "span_id": event.span_id, "task_id": event.task_id},
    )


def evaluate_policy(policy: Policy, decision_input: DecisionInput) -> DecisionResult:
    validate_policy_contract(policy)
    deny_reasons: list[str] = []
    matched: list[str] = []
    for deny_rule in policy.deny:
        if condition_matches(deny_rule.when, decision_input):
            deny_reasons.append(deny_rule.reason)
            matched.append(deny_rule.id)
    egress = egress_decision(policy, decision_input)
    if not egress.allowed and egress.reason:
        deny_reasons.append(egress.reason)
        matched.append("egress")
    if deny_reasons:
        return DecisionResult(allow=False, deny_reasons=deny_reasons, matched_rules=matched)

    approval_reasons: list[str] = []
    approval_matched = False
    for approval_rule in policy.require_human_approval:
        if _matches_rule(approval_rule, decision_input):
            matched.append(approval_rule.id)
            approval_matched = True
            approval_reasons.append(approval_rule.reason or "Action requires human approval")
    if approval_reasons and not decision_input.human_approved:
        return DecisionResult(
            allow=False,
            requires_approval=True,
            deny_reasons=approval_reasons,
            matched_rules=matched,
        )
    if approval_matched and decision_input.human_approved:
        return DecisionResult(allow=True, matched_rules=matched)

    for allow_rule in policy.allow:
        if _matches_rule(allow_rule, decision_input):
            matched.append(allow_rule.id)
            return DecisionResult(allow=True, matched_rules=matched)

    return DecisionResult(
        allow=False,
        deny_reasons=["No allow rule matched; default decision is deny"],
        matched_rules=matched,
    )


def run_policy_tests(policy: Policy, positive: list[Event], negative: list[Event]) -> TestResults:
    return run_evaluator_tests(
        policy.task,
        hash_policy(policy),
        positive,
        negative,
        lambda value: evaluate_policy(policy, value),
    )


def run_evaluator_tests(
    policy_id: str,
    policy_hash: str,
    positive: list[Event],
    negative: list[Event],
    evaluator: Callable[[DecisionInput], DecisionResult],
) -> TestResults:
    positive_results = [_run_case(event, "allow", evaluator) for event in positive]
    negative_results = [
        _run_case(event, _expected_decision(event), evaluator) for event in negative
    ]
    cases = [
        *zip(positive, positive_results, strict=True),
        *zip(negative, negative_results, strict=True),
    ]
    receipts = [_receipt(policy_id, policy_hash, event, result) for event, result in cases]
    return TestResults(
        policy_id=policy_id,
        policy_hash=policy_hash,
        positive=positive_results,
        negative=negative_results,
        receipts=receipts,
    )


def hash_policy(policy: Policy) -> str:
    payload = json.dumps(policy.model_dump(mode="json", exclude_none=True), sort_keys=True).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _rule_from_capability(capability: Capability) -> Rule:
    constraints: dict[str, Any] = {}
    if label_values := capability.params.get("label"):
        constraints["labels_in"] = label_values
    if (query_values := capability.params.get("query")) and len(query_values) == 1:
        constraints["query"] = query_values[0]
    resource = _minimize_resource(capability)
    return Rule(
        id=_safe_rule_id(f"{capability.action}_{resource or 'global'}"),
        subject=capability.subject,
        action=capability.action,
        resource=resource,
        constraints=constraints,
        reason="Observed high-impact action" if is_high_impact_action(capability.action) else None,
    )


def _inferred_approval_rules(capabilities: list[Capability]) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[tuple[str, str, str | None]] = set()
    for capability in capabilities:
        resource = _minimize_resource(capability)
        candidates: list[tuple[str, str]] = []
        if capability.system == "github" and resource and resource.startswith("github.repo:"):
            candidates.extend(
                [
                    (
                        "github.issue.comment.create",
                        "Public GitHub comments require human approval",
                    ),
                    ("github.issue.close", "Closing GitHub issues requires human approval"),
                ]
            )
        if capability.system == "gmail":
            candidates.extend(
                [
                    ("gmail.message.send", "Sending email requires human approval"),
                    ("gmail.message.forward", "Forwarding email requires human approval"),
                ]
            )
        for action, reason in candidates:
            key = (capability.subject, action, resource)
            if key in seen:
                continue
            seen.add(key)
            rules.append(
                Rule(
                    id=_safe_rule_id(f"{action}_{resource or 'global'}"),
                    subject=capability.subject,
                    action=action,
                    resource=resource,
                    reason=reason,
                )
            )
    return rules


def _minimize_resource(capability: Capability) -> str | None:
    resource_id = capability.resource_id
    action = capability.action
    if not resource_id:
        return capability.resource_type
    if action.startswith("github.") and "#" in resource_id:
        return "github.repo:" + resource_id.split("#", 1)[0]
    if action.startswith("github.") and "/" in resource_id:
        return "github.repo:" + resource_id.strip("/")
    if action.startswith("file."):
        normalized = _normalize_path(resource_id)
        if is_secret_path(normalized):
            return normalized
        parent = str(PurePosixPath(normalized).parent)
        if parent in {"", "."}:
            return normalized
        return f"{parent}/**"
    if action.startswith("http.") or action.startswith("network."):
        domain = _domain_from_resource(resource_id)
        return f"domain:{domain}" if domain else resource_id
    return resource_id


def _allowed_domains(capabilities: list[Capability]) -> list[str]:
    domains = {
        domain
        for capability in capabilities
        if (domain := _domain_from_resource(capability.resource_id))
        and capability.action.startswith(("http.", "network."))
    }
    return sorted(domains)


def _decision_resource(resource_type: str | None, resource_id: str | None) -> DecisionResource:
    parsed = urlparse(resource_id or "")
    if resource_id and parsed.scheme:
        return DecisionResource(
            type=resource_type,
            id=resource_id,
            scheme=parsed.scheme.lower(),
            host=(parsed.hostname or "").lower() or None,
            port=_safe_port(parsed),
            domain=_domain_from_resource(resource_id),
            private_network=_private_network_from_resource(resource_id),
        )
    if resource_id and "#" in resource_id and "/" in resource_id:
        repo = resource_id.split("#", 1)[0]
        return DecisionResource(type=resource_type or "github.issue", id=resource_id, repo=repo)
    if resource_id and (resource_id.startswith(".") or "/" in resource_id or "\\" in resource_id):
        return DecisionResource(type=resource_type or "file", id=resource_id, path=resource_id)
    return DecisionResource(type=resource_type, id=resource_id)


def _matches_rule(rule: Rule, value: DecisionInput) -> bool:
    if rule.subject and rule.subject != value.subject:
        return False
    if rule.action != value.action:
        return False
    if rule.resource and not _resource_matches(rule.resource, value.resource):
        return False
    return _constraints_match(rule.constraints, value)


def _resource_matches(rule_resource: str, resource: DecisionResource) -> bool:
    if rule_resource.startswith("github.repo:"):
        return resource.repo == rule_resource.removeprefix("github.repo:")
    if rule_resource.startswith("domain:"):
        return resource.domain == rule_resource.removeprefix("domain:")
    if rule_resource.endswith("/**"):
        path = _normalize_path(resource.path or resource.id or "")
        return path.startswith(rule_resource[:-3])
    return rule_resource in {resource.id, resource.type}


def _constraints_match(constraints: dict[str, Any], value: DecisionInput) -> bool:
    if labels := constraints.get("labels_in"):
        label = value.params.get("label")
        if label not in labels:
            return False
    query = constraints.get("query")
    return not (query and value.params.get("query") != query)


def _run_case(
    event: Event, expected: str, evaluator: Callable[[DecisionInput], DecisionResult]
) -> TestCaseResult:
    decision = evaluator(event_to_decision_input(event))
    actual = decision.decision
    return TestCaseResult(
        name=event.expected.attack if event.expected and event.expected.attack else event.span_id,
        expected=expected,  # type: ignore[arg-type]
        actual=actual,
        passed=actual == expected,
        reasons=decision.deny_reasons,
        trace_id=event.trace_id,
        span_id=event.span_id,
    )


def _expected_decision(event: Event) -> str:
    if event.expected:
        return event.expected.decision
    return "deny"


def _receipt(
    policy_id: str, policy_hash: str, event: Event, result: TestCaseResult
) -> dict[str, Any]:
    receipt = {
        "receipt_version": "0.1",
        "decision_id": hashlib.sha256(f"{policy_hash}:{event.span_id}".encode()).hexdigest()[:16],
        "timestamp": utc_now(),
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "decision": "allowed" if result.actual == "allow" else "blocked",
        "policy_id": policy_id,
        "policy_hash": policy_hash,
        "subject": event.actor.id,
        "action": event.operation.action,
        "reason": "; ".join(result.reasons) if result.reasons else "",
        "lineage": [
            {
                "event": event.operation.action,
                "labels": event.input.labels,
            }
        ],
    }
    redacted = redact_json_value(receipt)
    if not isinstance(redacted, dict):
        raise TypeError("receipt redaction produced an invalid receipt")
    return redacted


def _domain_from_resource(resource: str | None) -> str | None:
    if not resource:
        return None
    parsed = urlparse(resource)
    return parsed.hostname.lower() if parsed.hostname else None


def _safe_port(parsed: Any) -> int | None:
    try:
        port = parsed.port
    except ValueError:
        return None
    return port if isinstance(port, int) else None


def _private_network_from_resource(resource: str | None) -> bool:
    domain = _domain_from_resource(resource)
    if not domain:
        return False
    host = domain.strip("[]").lower()
    if host in {"localhost", "0"} or host.endswith((".localhost", ".local")):
        return True
    try:
        return not ip_address(host).is_global
    except ValueError:
        return False


def _normalize_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _safe_rule_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_").lower()[:80]
