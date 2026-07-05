from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from trace2policy.conditions import (
    allowed_domains,
    rego_condition_snippets,
    validate_policy_contract,
)
from trace2policy.models import DecisionInput, DecisionResult, Policy


def emit_rego(policy: Policy) -> str:
    validate_policy_contract(policy)
    package = re.sub(r"[^a-zA-Z0-9_]", "_", policy.task).strip("_").lower() or "policy"
    lines = [
        f"package trace2policy.{package}",
        "",
        "import rego.v1",
        "",
        "default allow := false",
        "default egress_domain_allowed := false",
        "",
        *_empty_set_guards(),
        *_sensitive_input_helpers(),
        *_resource_match_helpers(),
        *_domain_match_helpers(),
        *_egress_helpers(policy),
    ]
    for deny_rule in policy.deny:
        lines.extend(_deny_rule(deny_rule.id, deny_rule.when, deny_rule.reason))
    for approval_rule in policy.require_human_approval:
        payload = approval_rule.model_dump(mode="json", exclude_none=True)
        lines.extend(
            _approval_rule(payload, approval_rule.reason or "Action requires human approval")
        )
        lines.extend(_approved_allow_rule(payload))
    for allow_rule in policy.allow:
        lines.extend(_allow_rule(allow_rule.model_dump(mode="json", exclude_none=True)))
    return "\n".join(lines).rstrip() + "\n"


def evaluate_rego(rego_source: str, decision_input: DecisionInput) -> DecisionResult:
    if shutil.which("opa") is None:
        raise RuntimeError("opa CLI is not installed")
    query = "data.trace2policy"
    with tempfile.TemporaryDirectory() as temp_dir:
        policy_path = Path(temp_dir) / "policy.rego"
        input_path = Path(temp_dir) / "input.json"
        policy_path.write_text(rego_source, encoding="utf-8")
        input_path.write_text(
            json.dumps(decision_input.model_dump(mode="json", exclude_none=True)),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                "opa",
                "eval",
                "--format",
                "json",
                "--data",
                "policy.rego",
                "--input",
                "input.json",
                query,
            ],
            check=False,
            text=True,
            capture_output=True,
            cwd=temp_dir,
        )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    payload = json.loads(completed.stdout)
    values = payload["result"][0]["expressions"][0]["value"]
    package_values = next(iter(values.values()))
    deny = sorted(package_values.get("deny", []))
    approvals = sorted(package_values.get("requires_approval", []))
    allow = bool(package_values.get("allow")) and not deny and not approvals
    return DecisionResult(
        allow=allow, requires_approval=bool(approvals), deny_reasons=[*deny, *approvals]
    )


def _deny_rule(rule_id: str, when: dict[str, Any], reason: str) -> list[str]:
    conditions = rego_condition_snippets(when)
    return [
        f"deny contains {json.dumps(reason)} if {{",
        *[f"  {condition}" for condition in conditions],
        "}",
        "",
    ]


def _empty_set_guards() -> list[str]:
    return [
        'deny contains "" if {',
        "  false",
        "}",
        "",
        'requires_approval contains "" if {',
        "  false",
        "}",
        "",
    ]


def _approval_rule(rule: dict[str, Any], reason: str) -> list[str]:
    conditions = ["count(deny) == 0", *_rule_match_conditions(rule), "not input.human_approved"]
    return [
        f"requires_approval contains {json.dumps(reason)} if {{",
        *[f"  {condition}" for condition in conditions],
        "}",
        "",
    ]


def _approved_allow_rule(rule: dict[str, Any]) -> list[str]:
    conditions = ["count(deny) == 0", *_rule_match_conditions(rule), "input.human_approved"]
    return ["allow if {", *[f"  {condition}" for condition in conditions], "}", ""]


def _allow_rule(rule: dict[str, Any]) -> list[str]:
    conditions = ["count(deny) == 0", "count(requires_approval) == 0"]
    conditions.extend(_rule_match_conditions(rule))
    return ["allow if {", *[f"  {condition}" for condition in conditions], "}", ""]


def _rule_match_conditions(rule: dict[str, Any]) -> list[str]:
    conditions: list[str] = []
    if subject := rule.get("subject"):
        conditions.append(f"input.subject == {json.dumps(subject)}")
    conditions.append(f"input.action == {json.dumps(rule['action'])}")
    if resource := rule.get("resource"):
        conditions.extend(_resource_conditions(resource))
    constraints = rule.get("constraints") or {}
    if labels := constraints.get("labels_in"):
        labels_set = "{" + ", ".join(json.dumps(label) for label in labels) + "}"
        conditions.append(f"input.params.label in {labels_set}")
    if query := constraints.get("query"):
        conditions.append(f"input.params.query == {json.dumps(query)}")
    return conditions


def _sensitive_input_helpers() -> list[str]:
    return [
        "sensitive_input(values) if {",
        "  input.input.sensitivity in values",
        "}",
        "",
        "sensitive_input(values) if {",
        "  some label in input.input.labels",
        "  label in values",
        "}",
        "",
    ]


def _resource_match_helpers() -> list[str]:
    return [
        "resource_matches(value) if {",
        "  input.resource.id == value",
        "}",
        "",
        "resource_matches(value) if {",
        "  input.resource.type == value",
        "}",
        "",
    ]


def _domain_match_helpers() -> list[str]:
    return [
        "domain_allowed(domain, pattern) if {",
        "  domain == pattern",
        "}",
        "",
        "domain_allowed(domain, pattern) if {",
        '  startswith(pattern, "*.")',
        '  suffix := trim_prefix(pattern, "*")',
        "  endswith(domain, suffix)",
        '  base := trim_prefix(pattern, "*.")',
        "  domain != base",
        "}",
        "",
    ]


def _egress_helpers(policy: Policy) -> list[str]:
    lines = [
        "valid_external_http_scheme if {",
        '  input.resource.scheme == "http"',
        "}",
        "",
        "valid_external_http_scheme if {",
        '  input.resource.scheme == "https"',
        "}",
        "",
    ]
    for domain in allowed_domains(policy):
        if domain.startswith("*."):
            lines.extend(
                [
                    "egress_domain_allowed if {",
                    f"  endswith(input.resource.domain, {json.dumps(domain[1:])})",
                    f"  input.resource.domain != {json.dumps(domain[2:])}",
                    "}",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "egress_domain_allowed if {",
                    f"  input.resource.domain == {json.dumps(domain)}",
                    "}",
                    "",
                ]
            )
    lines.extend(
        [
            'deny contains "External HTTP URL scheme is not allowed" if {',
            '  input.sink.type == "external_http"',
            "  not valid_external_http_scheme",
            "}",
            "",
            'deny contains "Private network egress is outside task scope" if {',
            '  input.sink.type == "external_http"',
            "  valid_external_http_scheme",
            "  input.resource.private_network == true",
            "}",
            "",
            'deny contains "External HTTP domain is outside policy egress allowlist" if {',
            '  input.sink.type == "external_http"',
            "  valid_external_http_scheme",
            "  input.resource.private_network != true",
            "  not egress_domain_allowed",
            "}",
            "",
        ]
    )
    return lines


def _resource_conditions(resource: str) -> list[str]:
    if resource.startswith("github.repo:"):
        return [f"input.resource.repo == {json.dumps(resource.removeprefix('github.repo:'))}"]
    if resource.startswith("domain:"):
        return [f"input.resource.domain == {json.dumps(resource.removeprefix('domain:'))}"]
    if resource.endswith("/**"):
        return [f"startswith(input.resource.path, {json.dumps(resource[:-3])})"]
    return [f"resource_matches({json.dumps(resource)})"]
