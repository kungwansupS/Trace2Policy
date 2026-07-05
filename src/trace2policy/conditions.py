from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from trace2policy.models import DecisionInput, Policy, Rule

SUPPORTED_CONDITION_KEYS = frozenset(
    {
        "action",
        "sink",
        "input.trust_level",
        "input.sensitivity",
        "input.sensitivity_in",
        "input.labels_contains",
        "resource.matches",
        "resource.private_network",
        "resource.domain_in",
        "resource.scheme_in",
    }
)
SUPPORTED_CONSTRAINT_KEYS = frozenset({"labels_in", "query"})


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str | None = None


def validate_policy_contract(policy: Policy) -> None:
    errors: list[str] = []
    for rule in [*policy.allow, *policy.require_human_approval]:
        errors.extend(_rule_errors(rule))
    for deny in policy.deny:
        for key in deny.when:
            if key not in SUPPORTED_CONDITION_KEYS:
                errors.append(f"deny.{deny.id}.when uses unsupported condition key: {key}")
    raw_domains = policy.egress.get("allowed_domains", [])
    if not isinstance(raw_domains, list):
        errors.append("egress.allowed_domains must be a list")
        raw_domains = []
    for domain in allowed_domains(policy):
        if not _valid_domain_pattern(domain):
            errors.append(f"egress.allowed_domains has unsupported pattern: {domain}")
    if errors:
        raise ValueError("; ".join(errors))


def allowed_domains(policy: Policy) -> list[str]:
    raw = policy.egress.get("allowed_domains", [])
    if not isinstance(raw, list):
        return []
    return sorted({str(item).lower() for item in raw if str(item).strip()})


def condition_matches(when: dict[str, Any], value: DecisionInput) -> bool:
    _validate_when_keys(when)
    for key, expected in when.items():
        if key == "action":
            if value.action != expected:
                return False
        elif key == "input.trust_level":
            if value.input.trust_level != expected:
                return False
        elif key == "input.sensitivity":
            if value.input.sensitivity != expected:
                return False
        elif key == "input.sensitivity_in":
            expected_values = _string_set(expected)
            has_label = bool(set(value.input.labels).intersection(expected_values))
            if value.input.sensitivity not in expected_values and not has_label:
                return False
        elif key == "input.labels_contains":
            if str(expected) not in value.input.labels:
                return False
        elif key == "sink":
            if value.sink.type != expected:
                return False
        elif key == "resource.matches":
            path = (value.resource.path or value.resource.id or "").replace("\\", "/")
            if not any(fnmatch.fnmatch(path, pattern) for pattern in _string_list(expected)):
                return False
        elif key == "resource.private_network":
            if value.resource.private_network != bool(expected):
                return False
        elif key == "resource.domain_in":
            if not domain_allowed(value.resource.domain, _string_list(expected)):
                return False
        elif key == "resource.scheme_in" and (value.resource.scheme or "") not in _string_set(
            expected
        ):
            return False
    return True


def egress_decision(policy: Policy, value: DecisionInput) -> EgressDecision:
    if value.sink.type != "external_http":
        return EgressDecision(allowed=True)
    if value.resource.scheme not in {"http", "https"}:
        return EgressDecision(allowed=False, reason="External HTTP URL scheme is not allowed")
    if value.resource.private_network:
        return EgressDecision(allowed=False, reason="Private network egress is outside task scope")
    if not domain_allowed(value.resource.domain, allowed_domains(policy)):
        return EgressDecision(
            allowed=False, reason="External HTTP domain is outside policy egress allowlist"
        )
    return EgressDecision(allowed=True)


def domain_allowed(domain: str | None, patterns: Iterable[str]) -> bool:
    if not domain:
        return False
    normalized = domain.lower()
    for pattern in patterns:
        value = str(pattern).lower()
        if value.startswith("*."):
            base = value[2:]
            if normalized.endswith(f".{base}") and normalized != base:
                return True
        elif normalized == value:
            return True
    return False


def rego_condition_snippets(when: dict[str, Any]) -> list[str]:
    _validate_when_keys(when)
    conditions: list[str] = []
    for key, expected in when.items():
        if key == "action":
            conditions.append(f"input.action == {_json_string(expected)}")
        elif key == "input.trust_level":
            conditions.append(f"input.input.trust_level == {_json_string(expected)}")
        elif key == "input.sensitivity":
            conditions.append(f"input.input.sensitivity == {_json_string(expected)}")
        elif key == "input.sensitivity_in":
            conditions.append(f"sensitive_input({_rego_set(_string_list(expected))})")
        elif key == "input.labels_contains":
            conditions.append(f"{_json_string(expected)} in input.input.labels")
        elif key == "sink":
            conditions.append(f"input.sink.type == {_json_string(expected)}")
        elif key == "resource.matches":
            regexes = [_glob_to_regex(pattern) for pattern in _string_list(expected)]
            conditions.append(
                "some pattern in [" + ", ".join(_json_string(regex) for regex in regexes) + "]"
            )
            conditions.append("regex.match(pattern, input.resource.path)")
        elif key == "resource.private_network":
            conditions.append(f"input.resource.private_network == {_rego_bool(expected)}")
        elif key == "resource.domain_in":
            patterns = _string_list(expected)
            conditions.append(
                "some domain_pattern in ["
                + ", ".join(_json_string(pattern) for pattern in patterns)
                + "]"
            )
            conditions.append("domain_allowed(input.resource.domain, domain_pattern)")
        elif key == "resource.scheme_in":
            conditions.append(f"input.resource.scheme in {_rego_set(_string_list(expected))}")
    return conditions or ["false"]


def _rule_errors(rule: Rule) -> list[str]:
    return [
        f"rule.{rule.id}.constraints uses unsupported key: {key}"
        for key in rule.constraints
        if key not in SUPPORTED_CONSTRAINT_KEYS
    ]


def _validate_when_keys(when: dict[str, Any]) -> None:
    unsupported = [key for key in when if key not in SUPPORTED_CONDITION_KEYS]
    if unsupported:
        raise ValueError(f"unsupported condition key: {unsupported[0]}")


def _valid_domain_pattern(pattern: str) -> bool:
    value = pattern[2:] if pattern.startswith("*.") else pattern
    return bool(value) and "/" not in value and ":" not in value and "*" not in value


def _string_set(value: Any) -> set[str]:
    return set(_string_list(value))


def _string_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _rego_set(values: list[str]) -> str:
    return "{" + ", ".join(_json_string(item) for item in values) + "}"


def _rego_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def _json_string(value: Any) -> str:
    import json

    return json.dumps(str(value))


def _glob_to_regex(pattern: str) -> str:
    escaped = re.escape(pattern).replace("\\*\\*", ".*").replace("\\*", "[^/]*")
    return f"^{escaped}$"
