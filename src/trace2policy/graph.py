from __future__ import annotations

from collections import defaultdict
from typing import Any

import networkx as nx
from pydantic import BaseModel, Field

from trace2policy.models import Event


class Capability(BaseModel):
    task: str
    subject: str
    action: str
    system: str
    resource_type: str | None = None
    resource_id: str | None = None
    resource: str | None = None
    params: dict[str, list[Any]] = Field(default_factory=dict)
    input_labels: list[str] = Field(default_factory=list)
    sensitivity: str = "internal"
    trust_level: str = "untrusted"
    sink: str | None = None


class CapabilityGraph(BaseModel):
    task: str
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    capabilities: list[Capability]


def build_capability_graph(events: list[Event], task: str | None = None) -> CapabilityGraph:
    selected = [event for event in events if task is None or event.task_id == task]
    if not selected:
        raise ValueError("no events matched the requested task")
    task_id = task or selected[0].task_id
    graph = nx.MultiDiGraph()
    capabilities = _extract_capabilities(selected)

    for event in selected:
        event_node = f"event:{event.span_id}"
        action_node = f"action:{event.operation.action}"
        resource_node = (
            f"resource:{event.operation.resource_id or event.operation.resource_type or 'unknown'}"
        )
        graph.add_node(
            event_node,
            type=event.event_type.value,
            label=event.operation.tool_name or event.event_type,
        )
        graph.add_node(action_node, type="ToolCall", label=event.operation.action)
        graph.add_node(
            resource_node, type="Resource", label=event.operation.resource_id or "unknown"
        )
        graph.add_edge(event_node, action_node, type="calls")
        graph.add_edge(
            action_node,
            resource_node,
            type="writes_to" if _is_write(event.operation.action) else "reads_from",
        )
        if event.output.sink:
            sink_node = f"sink:{event.output.sink}"
            graph.add_node(sink_node, type="Sink", label=event.output.sink)
            graph.add_edge(action_node, sink_node, type="writes_to")
        if event.parent_span_id:
            parent = f"event:{event.parent_span_id}"
            graph.add_edge(parent, event_node, type="transforms")

    nodes = [{"id": node, **attrs} for node, attrs in graph.nodes(data=True)]
    edges = [
        {"source": source, "target": target, **attrs}
        for source, target, attrs in graph.edges(data=True)
    ]
    return CapabilityGraph(task=task_id, nodes=nodes, edges=edges, capabilities=capabilities)


def graph_to_mermaid(graph: CapabilityGraph) -> str:
    lines = ["```mermaid", "flowchart TD"]
    node_ids: dict[str, str] = {}
    for index, node in enumerate(graph.nodes, 1):
        node_id = f"N{index}"
        node_ids[node["id"]] = node_id
        label = str(node.get("label") or node["id"]).replace('"', "'")
        lines.append(f'  {node_id}["{label}"]')
    for edge in graph.edges:
        source = node_ids.get(edge["source"])
        target = node_ids.get(edge["target"])
        if source and target:
            label = str(edge.get("type") or "").replace('"', "'")
            lines.append(f'  {source} -- "{label}" --> {target}')
    lines.append("```")
    return "\n".join(lines) + "\n"


def _extract_capabilities(events: list[Event]) -> list[Capability]:
    grouped: dict[tuple[str, str, str, str | None], list[Event]] = defaultdict(list)
    for event in events:
        subject = event.actor.id
        key = (event.task_id, subject, event.operation.action, event.operation.resource_id)
        grouped[key].append(event)

    capabilities: list[Capability] = []
    for (task, subject, action, resource_id), items in sorted(grouped.items()):
        first = items[0]
        params: dict[str, set[Any]] = defaultdict(set)
        for item in items:
            for param_key, value in {**item.operation.params, **item.input.params}.items():
                if isinstance(value, (str, int, float, bool)):
                    params[param_key].add(value)
        capabilities.append(
            Capability(
                task=task,
                subject=subject,
                action=action,
                system=first.operation.system,
                resource_type=first.operation.resource_type,
                resource_id=resource_id,
                resource=first.operation.resource_id,
                params={key: sorted(values) for key, values in params.items()},
                input_labels=sorted({label for item in items for label in item.input.labels}),
                sensitivity=_max_sensitivity(item.input.sensitivity for item in items),
                trust_level=_min_trust(item.input.trust_level for item in items),
                sink=first.output.sink,
            )
        )
    return capabilities


def _is_write(action: str) -> bool:
    fragments = (".add_", ".create", ".write", ".send", ".forward", ".close", ".delete", ".push")
    return action.startswith("file.write") or any(fragment in action for fragment in fragments)


def _max_sensitivity(values: Any) -> str:
    order = [
        "public",
        "low",
        "internal",
        "confidential",
        "customer_data",
        "pii",
        "credential",
        "secret",
    ]
    best = "internal"
    for value in values:
        score = order.index(value) if value in order else order.index("internal")
        if score > order.index(best):
            best = value
    return best


def _min_trust(values: Any) -> str:
    if any(value == "untrusted" or str(value).startswith("untrusted_") for value in values):
        return "untrusted"
    return next(iter(values), "untrusted")
