from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from tracepolicykit.io import read_json_file, read_jsonl
from tracepolicykit.labels import classify_event
from tracepolicykit.models import (
    SCHEMA_VERSION,
    Actor,
    DataRef,
    Event,
    EventType,
    Operation,
    RuntimeMeta,
    TraceValidationError,
)

TraceFormat = Literal["jsonl", "openinference", "langfuse"]


def normalize_trace(path: Path, trace_format: TraceFormat) -> list[Event]:
    if trace_format == "jsonl":
        raw_events = read_jsonl(path)
        events = []
        for index, row in enumerate(raw_events, 1):
            try:
                events.append(_canonicalize_event(row, index))
            except ValidationError as exc:
                raise TraceValidationError(str(path), index, str(exc)) from exc
    elif trace_format == "openinference":
        events = list(_from_openinference(read_json_file(path)))
    elif trace_format == "langfuse":
        events = list(_from_langfuse(read_json_file(path)))
    else:
        raise ValueError(f"unsupported trace format: {trace_format}")
    return [classify_event(event) for event in events]


def _canonicalize_event(row: dict[str, Any], index: int) -> Event:
    operation = row.get("operation") or {}
    if "action" not in operation and "action" in row:
        operation = {**operation, "action": row["action"]}
    if "action" not in operation:
        operation = {
            **operation,
            "action": operation.get("tool_name") or row.get("event_type", "unknown"),
        }
    trace_id = str(row.get("trace_id") or row.get("task_id") or "trace")
    span_id = str(row.get("span_id") or _stable_id(row, f"span-{index}"))
    task_id = str(row.get("task_id") or trace_id)
    event = {
        "schema_version": row.get("schema_version", SCHEMA_VERSION),
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": row.get("parent_span_id"),
        "session_id": row.get("session_id"),
        "task_id": task_id,
        "timestamp": row.get("timestamp"),
        "event_type": row.get("event_type", _infer_event_type(operation)),
        "actor": row.get("actor") or {"type": "agent", "id": f"agent:{task_id}"},
        "operation": operation,
        "input": row.get("input") or {},
        "output": row.get("output") or {},
        "auth": row.get("auth") or {},
        "runtime": row.get("runtime") or {},
        "decision": row.get("decision") or {},
        "metadata": row.get("metadata") or {},
        "expected": row.get("expected"),
    }
    return Event.model_validate(event)


def _from_openinference(data: Any) -> Iterable[Event]:
    spans = _extract_items(data, ("spans", "data", "observations"))
    for index, span in enumerate(spans, 1):
        attrs = span.get("attributes") or span
        span_kind = str(
            attrs.get("openinference.span.kind") or attrs.get("span_kind") or ""
        ).upper()
        action = _first(
            attrs,
            "tool.name",
            "tool_call.function.name",
            "llm.invocation_parameters.tool_name",
            "name",
        )
        event_type = _openinference_event_type(span_kind, action)
        trace_id = str(span.get("trace_id") or attrs.get("trace_id") or "openinference")
        span_id = str(
            span.get("span_id") or attrs.get("span_id") or _stable_id(span, f"span-{index}")
        )
        task_id = str(attrs.get("session.id") or attrs.get("conversation.id") or trace_id)
        tool_name = str(action or span.get("name") or event_type.value)
        operation = Operation(
            system=_system_from_action(tool_name),
            tool_name=tool_name,
            action=_normalize_action(tool_name, event_type),
            resource_type=str(
                attrs.get("resource.type") or attrs.get("tool.resource_type") or "unknown"
            ),
            resource_id=_optional_str(attrs.get("resource.id") or attrs.get("tool.resource_id")),
            params=_extract_params(attrs),
        )
        yield Event(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=_optional_str(span.get("parent_span_id")),
            task_id=task_id,
            timestamp=_optional_str(span.get("start_time") or span.get("timestamp")),
            event_type=event_type,
            actor=Actor(id=f"agent:{task_id}"),
            operation=operation,
            input=_data_ref(attrs, "input"),
            output=_data_ref(attrs, "output"),
            runtime=RuntimeMeta(
                framework="openinference",
                model=_optional_str(attrs.get("llm.model_name")),
            ),
            metadata={"source_format": "openinference", "raw_span_ref": span_id},
        )


def _from_langfuse(data: Any) -> Iterable[Event]:
    observations = _extract_items(data, ("observations", "data", "traces"))
    for index, item in enumerate(observations, 1):
        trace_id = str(item.get("traceId") or item.get("trace_id") or item.get("id") or "langfuse")
        span_id = str(item.get("id") or item.get("span_id") or _stable_id(item, f"span-{index}"))
        task_id = str(
            item.get("name") or item.get("sessionId") or item.get("session_id") or trace_id
        )
        item_type = str(item.get("type") or item.get("observationType") or "").lower()
        name = str(item.get("name") or item.get("tool") or item_type or "langfuse.event")
        event_type = _langfuse_event_type(item_type, name)
        operation = Operation(
            system=_system_from_action(name),
            tool_name=name,
            action=_normalize_action(name, event_type),
            resource_type=_optional_str(item.get("resourceType") or item.get("resource_type")),
            resource_id=_optional_str(item.get("resourceId") or item.get("resource_id")),
            params=_dict_or_empty(item.get("metadata")),
        )
        yield Event(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=_optional_str(
                item.get("parentObservationId") or item.get("parent_span_id")
            ),
            task_id=task_id,
            timestamp=_optional_str(item.get("startTime") or item.get("timestamp")),
            event_type=event_type,
            actor=Actor(id=f"agent:{task_id}"),
            operation=operation,
            input=_content_data_ref(item.get("input")),
            output=_content_data_ref(item.get("output")),
            runtime=RuntimeMeta(framework="langfuse", model=_optional_str(item.get("model"))),
            metadata={"source_format": "langfuse", "raw_span_ref": span_id},
        )


def _extract_items(data: Any, keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [data]
    raise ValueError("trace input must be a JSON object or array")


def _infer_event_type(operation: dict[str, Any]) -> str:
    action = str(operation.get("action") or operation.get("tool_name") or "")
    if action.startswith("file.read"):
        return EventType.FILE_READ.value
    if action.startswith("file.write"):
        return EventType.FILE_WRITE.value
    if action.startswith("http.") or action.startswith("network."):
        return EventType.NETWORK_REQUEST.value
    if action.startswith("mcp."):
        return EventType.MCP_TOOL_CALL.value
    if action.startswith("llm."):
        return EventType.LLM_CALL.value
    return EventType.TOOL_CALL.value


def _openinference_event_type(span_kind: str, action: str | None) -> EventType:
    if span_kind == "AGENT":
        return EventType.AGENT
    if span_kind == "LLM":
        return EventType.LLM_CALL
    if span_kind == "RETRIEVER":
        return EventType.RETRIEVAL
    if span_kind == "TOOL":
        return EventType.TOOL_CALL
    if span_kind == "GUARDRAIL":
        return EventType.GUARDRAIL
    if action:
        return EventType(_infer_event_type({"action": action}))
    return EventType.TOOL_CALL


def _langfuse_event_type(item_type: str, name: str) -> EventType:
    if item_type in {"generation", "llm"}:
        return EventType.LLM_CALL
    if item_type in {"span", "tool"}:
        return EventType(_infer_event_type({"action": name}))
    return EventType.TOOL_CALL


def _normalize_action(name: str, event_type: EventType) -> str:
    if "." in name:
        return name
    if event_type == EventType.AGENT:
        return "agent.run"
    if event_type == EventType.LLM_CALL:
        return "llm.generate"
    if event_type == EventType.RETRIEVAL:
        return "retrieval.query"
    if event_type == EventType.GUARDRAIL:
        return "guardrail.check"
    return name


def _system_from_action(action: str) -> str:
    return action.split(".", 1)[0] if "." in action else "unknown"


def _data_ref(attrs: dict[str, Any], prefix: str) -> DataRef:
    labels = attrs.get(f"{prefix}.labels") or attrs.get("labels") or []
    content = attrs.get(f"{prefix}.value") or attrs.get(f"{prefix}.messages")
    return _content_data_ref(
        content,
        labels=labels if isinstance(labels, list) else [str(labels)],
        sensitivity=_optional_str(attrs.get(f"{prefix}.sensitivity")),
        trust_level=_optional_str(attrs.get(f"{prefix}.trust_level")),
    )


def _content_data_ref(
    content: Any,
    *,
    labels: list[str] | None = None,
    sensitivity: str | None = None,
    trust_level: str | None = None,
) -> DataRef:
    return DataRef(
        content_ref=_content_ref(content),
        content_preview=None,
        redaction="full",
        labels=labels or [],
        sensitivity=sensitivity or "internal",
        trust_level=trust_level or "untrusted",
    )


def _content_ref(content: Any) -> str | None:
    if content is None:
        return None
    encoded = repr(content).encode("utf-8", errors="replace")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _extract_params(attrs: dict[str, Any]) -> dict[str, Any]:
    for key in ("tool.parameters", "tool_call.function.arguments", "input.params", "params"):
        value = attrs.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first(values: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = values.get(key)
        if value:
            return str(value)
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _stable_id(value: Any, fallback: str) -> str:
    digest = hashlib.sha256(repr(value).encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"{fallback}-{digest}"
