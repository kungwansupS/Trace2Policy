from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from trace2policy.cli import app

ROOT = Path(__file__).resolve().parents[1]
GITHUB_TRACE = ROOT / "examples" / "github_issue_triage" / "traces.normal.jsonl"


def test_cli_full_pipeline(tmp_path: Path) -> None:
    runner = CliRunner()
    normalized = tmp_path / "normalized.jsonl"
    graph = tmp_path / "graph.json"
    policy = tmp_path / "policy.yaml"
    rego = tmp_path / "policy.rego"
    attacks = tmp_path / "attacks.jsonl"
    results = tmp_path / "results.json"
    report = tmp_path / "report.md"

    assert (
        runner.invoke(
            app,
            ["ingest", "--format", "jsonl", "--input", str(GITHUB_TRACE), "--out", str(normalized)],
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["validate", str(normalized)]).exit_code == 0
    assert runner.invoke(app, ["graph", str(normalized), "--out", str(graph)]).exit_code == 0
    assert runner.invoke(app, ["infer", str(graph), "--out", str(policy)]).exit_code == 0
    assert (
        runner.invoke(app, ["emit", str(policy), "--target", "rego", "--out", str(rego)]).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["redteam", "generate", str(normalized), "--out", str(attacks)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app,
            [
                "test",
                "--policy",
                str(policy),
                "--positive",
                str(normalized),
                "--negative",
                str(attacks),
                "--out",
                str(results),
            ],
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["report", str(results), "--format", "markdown", "--out", str(report)]
        ).exit_code
        == 0
    )
    assert report.read_text(encoding="utf-8").startswith("# Trace2Policy Report")
