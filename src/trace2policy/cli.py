from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from trace2policy.graph import CapabilityGraph, build_capability_graph, graph_to_mermaid
from trace2policy.ingest import TraceFormat, normalize_trace
from trace2policy.io import (
    load_events,
    load_policy,
    read_json_file,
    write_json_file,
    write_jsonl,
    write_policy,
)
from trace2policy.models import TestResults
from trace2policy.policy import (
    run_evaluator_tests,
    run_policy_tests,
    synthesize_policy,
    synthesize_policy_from_events,
)
from trace2policy.redteam import generate_attacks
from trace2policy.rego import emit_rego, evaluate_rego
from trace2policy.report import render_html, render_markdown

app = typer.Typer(no_args_is_help=True, help="Convert AI agent traces into enforceable policies.")
redteam_app = typer.Typer(no_args_is_help=True, help="Generate offline red-team traces.")
app.add_typer(redteam_app, name="redteam")
console = Console()


@app.command()
def validate(trace: Annotated[Path, typer.Argument(help="Canonical trace JSONL file.")]) -> None:
    events = load_events(trace)
    console.print(f"Validated {len(events)} events")


@app.command()
def ingest(
    trace_format: Annotated[TraceFormat, typer.Option("--format", help="Input trace format.")],
    input_path: Annotated[Path, typer.Option("--input", exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    events = normalize_trace(input_path, trace_format)
    write_jsonl(out, events)
    console.print(f"Wrote {len(events)} normalized events to {out}")


@app.command()
def graph(
    trace: Annotated[Path, typer.Argument(exists=True, readable=True)],
    task: Annotated[str | None, typer.Option("--task")] = None,
    out: Annotated[Path | None, typer.Option("--out")] = None,
    output_format: Annotated[str, typer.Option("--format")] = "json",
) -> None:
    events = load_events(trace)
    capability_graph = build_capability_graph(events, task)
    if output_format == "json":
        payload = capability_graph.model_dump(mode="json")
        if out:
            write_json_file(out, payload)
        else:
            console.print_json(json.dumps(payload))
    elif output_format == "mermaid":
        rendered = graph_to_mermaid(capability_graph)
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(rendered, encoding="utf-8", newline="\n")
        else:
            console.print(rendered)
    else:
        raise typer.BadParameter("format must be json or mermaid")
    if out:
        console.print(f"Wrote capability graph to {out}")


@app.command()
def infer(
    source: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out")],
    task: Annotated[str | None, typer.Option("--task")] = None,
) -> None:
    if source.suffix == ".json":
        data = read_json_file(source)
        policy = synthesize_policy(CapabilityGraph.model_validate(data))
    else:
        policy = synthesize_policy_from_events(load_events(source), task)
    write_policy(out, policy)
    console.print(f"Policy generated: {out}")


@app.command()
def emit(
    policy_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    target: Annotated[str, typer.Option("--target")] = "rego",
    out: Annotated[Path | None, typer.Option("--out")] = None,
) -> None:
    if target != "rego":
        raise typer.BadParameter("target must be rego")
    rendered = emit_rego(load_policy(policy_path))
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8", newline="\n")
        console.print(f"Wrote Rego policy to {out}")
    else:
        console.print(rendered)


@redteam_app.command("generate")
def redteam_generate(
    trace: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out")],
    attacks: Annotated[str | None, typer.Option("--attacks")] = None,
) -> None:
    selected = attacks.split(",") if attacks else None
    generated = generate_attacks(load_events(trace), selected)
    write_jsonl(out, generated)
    console.print(f"Red-team attacks generated: {len(generated)}")


@app.command("test")
def test_policy(
    policy_path: Annotated[Path, typer.Option("--policy", exists=True, readable=True)],
    positive: Annotated[Path, typer.Option("--positive", exists=True, readable=True)],
    negative: Annotated[Path, typer.Option("--negative", exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out")],
) -> None:
    positive_events = load_events(positive)
    negative_events = load_events(negative)
    if policy_path.suffix == ".rego":
        rego_source = policy_path.read_text(encoding="utf-8")
        policy_hash = "sha256:" + hashlib.sha256(rego_source.encode()).hexdigest()
        results = run_evaluator_tests(
            policy_path.stem,
            policy_hash,
            positive_events,
            negative_events,
            lambda value: evaluate_rego(rego_source, value),
        )
    else:
        results = run_policy_tests(load_policy(policy_path), positive_events, negative_events)
    write_json_file(out, results.model_dump(mode="json"))
    console.print(f"Policy tests: {'passed' if results.passed else 'failed'}")
    raise typer.Exit(0 if results.passed else 1)


@app.command()
def report(
    results_path: Annotated[Path, typer.Argument(exists=True, readable=True)],
    out: Annotated[Path, typer.Option("--out")],
    output_format: Annotated[str, typer.Option("--format")] = "markdown",
) -> None:
    results = TestResults.model_validate(read_json_file(results_path))
    if output_format == "markdown":
        rendered = render_markdown(results)
    elif output_format == "html":
        rendered = render_html(results)
    else:
        raise typer.BadParameter("format must be markdown or html")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(rendered, encoding="utf-8", newline="\n")
    console.print(f"Report written: {out}")
