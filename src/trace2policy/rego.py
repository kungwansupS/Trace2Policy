from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from trace2policy.models import DecisionInput, DecisionResult, Policy


def emit_rego(policy: Policy) -> str:
    package = re.sub(r"[^a-zA-Z0-9_]", "_", policy.task).strip("_").lower() or "policy"
    lines = [
        f"package trace2policy.{package}",
        "",
        "import rego.v1",
        "",
        "default allow := false",
        "",
        *_sensitive_input_helpers(),
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
    conditions = _when_conditions(when)
    return [
        f"deny contains {json.dumps(reason)} if {{",
        *[f"  {condition}" for condition in conditions],
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


def _when_conditions(when: dict[str, Any]) -> list[str]:
    conditions: list[str] = []
    for key, expected in when.items():
        if key == "action":
            conditions.append(f"input.action == {json.dumps(expected)}")
        elif key == "input.trust_level":
            conditions.append(f"input.input.trust_level == {json.dumps(expected)}")
        elif key == "input.sensitivity":
            conditions.append(f"input.input.sensitivity == {json.dumps(expected)}")
        elif key == "input.sensitivity_in":
            values = "{" + ", ".join(json.dumps(item) for item in expected) + "}"
            conditions.append(f"sensitive_input({values})")
        elif key == "input.labels_contains":
            conditions.append(f"{json.dumps(expected)} in input.input.labels")
        elif key == "sink":
            conditions.append(f"input.sink.type == {json.dumps(expected)}")
        elif key == "resource.matches":
            regexes = [_glob_to_regex(pattern) for pattern in expected]
            conditions.append(
                "some pattern in [" + ", ".join(json.dumps(regex) for regex in regexes) + "]"
            )
            conditions.append("regex.match(pattern, input.resource.path)")
        elif key == "resource.private_network":
            conditions.append(f"input.resource.private_network == {json.dumps(expected)}")
    return conditions or ["false"]


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


def _resource_conditions(resource: str) -> list[str]:
    if resource.startswith("github.repo:"):
        return [f"input.resource.repo == {json.dumps(resource.removeprefix('github.repo:'))}"]
    if resource.startswith("domain:"):
        return [f"input.resource.domain == {json.dumps(resource.removeprefix('domain:'))}"]
    if resource.endswith("/**"):
        return [f"startswith(input.resource.path, {json.dumps(resource[:-3])})"]
    return [f"input.resource.id == {json.dumps(resource)}"]


def _glob_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern).replace("\\*\\*", ".*").replace("\\*", "[^/]*")
    return f"^{escaped}$"
