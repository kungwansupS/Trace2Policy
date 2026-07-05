from __future__ import annotations

import html
from collections import Counter

from trace2policy.models import TestResults
from trace2policy.redact import redact_secret_text


def render_markdown(results: TestResults) -> str:
    positive_passed = sum(case.passed for case in results.positive)
    negative_passed = sum(case.passed for case in results.negative)
    failed_positive = [case for case in results.positive if not case.passed]
    missed = [case for case in results.negative if not case.passed]
    decisions = Counter(case.actual for case in [*results.positive, *results.negative])
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
        (
            "- Decisions: "
            f"allow={decisions['allow']}, deny={decisions['deny']}, "
            f"requires_approval={decisions['requires_approval']}"
        ),
        f"- Failed positives: {len(failed_positive)}",
        f"- Missed negatives: {len(missed)}",
        f"- Overall: {'passed' if results.passed else 'failed'}",
        "",
    ]
    if failed_positive:
        lines.extend(["## Failed Positive Cases", ""])
        for case in failed_positive:
            reason = "; ".join(case.reasons) if case.reasons else "no reason"
            lines.append(
                "- "
                f"`{redact_secret_text(case.name)}` expected `{case.expected}` "
                f"but got `{case.actual}`: {redact_secret_text(reason)}"
            )
        lines.append("")
    if missed:
        lines.extend(["## Missed Cases", ""])
        for case in missed:
            reason = "; ".join(case.reasons) if case.reasons else "no reason"
            lines.append(
                "- "
                f"`{redact_secret_text(case.name)}` expected `{case.expected}` "
                f"but got `{case.actual}`: {redact_secret_text(reason)}"
            )
        lines.append("")
    return redact_secret_text("\n".join(lines))


def render_html(results: TestResults) -> str:
    body = html.escape(render_markdown(results))
    return (
        "<!doctype html>\n"
        '<html><head><meta charset="utf-8"><title>Trace2Policy Report</title></head>'
        f"<body><pre>{body}</pre></body></html>\n"
    )
