from __future__ import annotations

import html

from trace2policy.models import TestResults


def render_markdown(results: TestResults) -> str:
    positive_passed = sum(case.passed for case in results.positive)
    negative_passed = sum(case.passed for case in results.negative)
    missed = [case for case in results.negative if not case.passed]
    lines = [
        "# Trace2Policy Report",
        "",
        f"Policy: `{results.policy_id}`",
        f"Policy hash: `{results.policy_hash}`",
        "",
        "## Summary",
        "",
        f"- Positive tests: {positive_passed}/{len(results.positive)} passed",
        (
            f"- Negative tests: {negative_passed}/{len(results.negative)} "
            "blocked or approved as expected"
        ),
        f"- Overall: {'passed' if results.passed else 'failed'}",
        "",
    ]
    if missed:
        lines.extend(["## Missed Cases", ""])
        for case in missed:
            reason = "; ".join(case.reasons) if case.reasons else "no reason"
            lines.append(
                f"- `{case.name}` expected `{case.expected}` but got `{case.actual}`: {reason}"
            )
        lines.append("")
    return "\n".join(lines)


def render_html(results: TestResults) -> str:
    body = html.escape(render_markdown(results))
    return (
        "<!doctype html>\n"
        '<html><head><meta charset="utf-8"><title>Trace2Policy Report</title></head>'
        f"<body><pre>{body}</pre></body></html>\n"
    )
