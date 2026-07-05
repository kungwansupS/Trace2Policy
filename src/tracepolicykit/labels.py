from __future__ import annotations

import re
from pathlib import PurePosixPath

from tracepolicykit.models import Event, EventType

SECRET_PATH_PATTERNS = ("**/.env", "**/.env.*", "~/.ssh/**", "**/id_rsa", "**/id_ed25519")
SECRET_VALUE_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|credential|private[_-]?key)")


def classify_event(event: Event) -> Event:
    labels = set(event.input.labels)
    output_labels = set(event.output.labels)
    sensitivity = event.input.sensitivity or "internal"
    output_sensitivity = event.output.sensitivity or sensitivity
    trust_level = event.input.trust_level or "untrusted"
    action = event.operation.action

    if not labels:
        labels.add(_default_input_label(event))
    if not output_labels:
        output_labels.add(_default_output_label(event))
    if sensitivity == "internal":
        sensitivity = _infer_sensitivity(event)
    if output_sensitivity == "internal":
        output_sensitivity = sensitivity
    if trust_level == "untrusted":
        trust_level = _infer_trust(event)

    sink = event.output.sink or _infer_sink(event)
    params = {**event.operation.params, **event.input.params}

    updated = event.model_copy(deep=True)
    updated.input.labels = sorted(labels)
    updated.input.sensitivity = sensitivity
    updated.input.trust_level = trust_level
    updated.input.params = params
    updated.output.labels = sorted(output_labels)
    updated.output.sensitivity = output_sensitivity
    updated.output.sink = sink
    if _is_secret_read(action, event.operation.resource_id):
        updated.input.sensitivity = "secret"
        if "secret" not in updated.input.labels:
            updated.input.labels.append("secret")
    return updated


def is_high_impact_action(action: str) -> bool:
    high_impact_fragments = (
        ".delete",
        ".close",
        ".send",
        ".forward",
        ".push",
        "shell.exec",
        "calendar.event.create",
        "github.issue.comment.create",
        "github.repo.push",
        "branch.delete",
    )
    return any(fragment in action for fragment in high_impact_fragments)


def contains_secret_value(value: object) -> bool:
    return bool(SECRET_VALUE_RE.search(repr(value)))


def is_secret_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.replace("\\", "/")
    posix = PurePosixPath(normalized)
    return any(posix.match(pattern) for pattern in SECRET_PATH_PATTERNS) or "/.ssh/" in normalized


def _default_input_label(event: Event) -> str:
    if event.event_type == EventType.USER_INPUT:
        return "untrusted_user_content"
    if event.event_type == EventType.SYSTEM_INSTRUCTION:
        return "trusted_system_instruction"
    if event.event_type == EventType.MCP_TOOL_LIST:
        return "untrusted_tool_metadata"
    if event.event_type in {EventType.FILE_READ, EventType.RETRIEVAL}:
        return "tool_generated_content"
    return (
        "model_generated_content"
        if event.event_type == EventType.TOOL_CALL
        else "internal_metadata"
    )


def _default_output_label(event: Event) -> str:
    if event.event_type == EventType.LLM_CALL:
        return "model_generated_content"
    if event.event_type in {EventType.TOOL_CALL, EventType.TOOL_RESULT}:
        return "tool_generated_content"
    if event.event_type == EventType.FILE_READ:
        return "file_content"
    return "internal_metadata"


def _infer_sensitivity(event: Event) -> str:
    text = (
        f"{event.operation.action} {event.operation.resource_id or ''} {event.operation.params!r}"
    )
    if contains_secret_value(text) or is_secret_path(event.operation.resource_id):
        return "secret"
    if "customer" in text.lower() or "email" in text.lower():
        return "customer_data"
    if "github.issue" in event.operation.action:
        return "public"
    return "internal"


def _infer_trust(event: Event) -> str:
    if event.event_type == EventType.SYSTEM_INSTRUCTION:
        return "trusted_system_instruction"
    if event.event_type == EventType.USER_INPUT:
        return "trusted_user_instruction"
    if any(label.startswith("untrusted_") for label in event.input.labels):
        return "untrusted"
    if event.event_type == EventType.LLM_CALL:
        return "untrusted"
    return event.input.trust_level or "untrusted"


def _infer_sink(event: Event) -> str | None:
    action = event.operation.action
    if action.startswith("http.") or action.startswith("network."):
        return "external_http"
    if action.startswith("file.write"):
        return "local_file"
    if action == "shell.exec":
        return "shell_exec"
    if "comment.create" in action:
        return "github_public_comment"
    if action.startswith("gmail.message.send") or action.startswith("gmail.message.forward"):
        return "email_send"
    if action.startswith("mcp."):
        return "mcp_tool_call"
    return event.output.sink


def _is_secret_read(action: str, resource_id: str | None) -> bool:
    return action.startswith("file.read") and is_secret_path(resource_id)
