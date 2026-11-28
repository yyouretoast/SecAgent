"""GitHub PR Markdown security triage formatter."""

from __future__ import annotations

import json
from typing import Any

MAX_GITHUB_COMMENT_LENGTH = 65000
COMMENT_MARKER = "<!-- secagent-security-gate -->"
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _field(obj: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dict or an object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def escape_cell(value: Any) -> str:
    """Escape pipe characters, backticks, HTML angle brackets, and newlines inside a Markdown cell."""
    return (
        str(value)
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .strip()
    )


def format_markdown_report(
    result: Any,
    agent_name: str = "",
    scenarios_evaluated: int = 0,
) -> str:
    """Format an evaluation result (dict or object) as a GitHub PR Markdown triage comment."""
    status = escape_cell(_field(result, "status", "PASS") or "PASS")
    raw_violations = _field(result, "violations", [])
    violations = list(raw_violations) if isinstance(raw_violations, (list, tuple)) else []
    effective_agent = escape_cell(
        agent_name or _field(result, "agent", "default_fixture") or "default_fixture"
    )
    effective_scenarios = scenarios_evaluated or int(_field(result, "scenarios_evaluated", 0) or 0)

    if status == "NOT_EVALUATED":
        return (
            f"{COMMENT_MARKER}\n"
            "### SecAgent Security Gate: NOT_EVALUATED\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Prepared**: {effective_scenarios}\n"
            "- **Status**: No executable agent traces were produced; "
            "no policies were evaluated in this run.\n"
        )

    def _coverage_lines(cov: Any) -> str:
        if not isinstance(cov, dict):
            return ""
        lines: list[str] = []
        util_rate = cov.get("utility_pass_rate")
        if util_rate is not None:
            lines.append(f"- **Utility Pass Rate**: {int(round(float(util_rate) * 100))}%\n")
        if cov.get("low_coverage_warning"):
            rate = int(round(float(cov.get("tool_invocation_rate", 0.0)) * 100))
            lines.append(
                f"- **Coverage Warning**: Only {cov.get('scenarios_with_tool_calls', 0)}/"
                f"{cov.get('total_traces', 0)} scenarios invoked tools ({rate}%). "
                "Verify agent prompts/tools are being exercised.\n"
            )
        return "".join(lines)

    cov_block = _coverage_lines(_field(result, "coverage", None))

    if status == "PASS" and not violations:
        return (
            f"{COMMENT_MARKER}\n"
            "### SecAgent Security Gate: PASS\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Evaluated**: {effective_scenarios}\n"
            "- **Violations Detected**: 0\n"
            f"{cov_block}"
            "- **Status**: All invariant security policies satisfied.\n"
        )

    sorted_violations = sorted(
        violations,
        key=lambda v: (
            _SEVERITY_ORDER.get(str(_field(v, "severity", "")), 99),
            int(_field(v, "offending_step_index", 0) or 0),
        ),
    )

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in sorted_violations:
        sev = str(_field(v, "severity", "HIGH")).upper()
        if sev in counts:
            counts[sev] += 1
    severity_summary = (
        f"CRITICAL: {counts['CRITICAL']} · HIGH: {counts['HIGH']} · "
        f"MEDIUM: {counts['MEDIUM']} · LOW: {counts['LOW']}"
    )

    header = (
        f"{COMMENT_MARKER}\n"
        f"### SecAgent Security Gate: {status}\n\n"
        f"- **Target Agent**: `{effective_agent}`\n"
        f"- **Scenarios Evaluated**: {effective_scenarios}\n"
        f"- **Violations Detected**: {len(sorted_violations)}\n"
        f"- **Severity Breakdown**: {severity_summary}\n"
        f"{cov_block}\n"
    )

    if not sorted_violations:
        return header

    table_header = (
        "| Rule ID | Severity | OWASP Category | Offending Span | Remediation |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
    )

    rows: list[str] = []
    base_len = len(header) + len(table_header) + 120
    running_len = base_len

    for v in sorted_violations:
        rule_id = escape_cell(_field(v, "rule_id", "UNKNOWN"))
        severity = escape_cell(_field(v, "severity", "HIGH"))
        owasp = escape_cell(_field(v, "owasp_category", "UNKNOWN"))
        tool_name = escape_cell(_field(v, "offending_tool_name", ""))
        span_id = escape_cell(_field(v, "offending_span_id", "unknown"))
        span_cell = f"`{tool_name}` (`{span_id}`)" if tool_name else f"`{span_id}`"
        remediation = escape_cell(_field(v, "remediation", ""))

        row = f"| `{rule_id}` | {severity} | {owasp} | {span_cell} | {remediation} |"
        if running_len + len(row) + 1 > MAX_GITHUB_COMMENT_LENGTH:
            break
        rows.append(row)
        running_len += len(row) + 1

    body = header + table_header + "\n".join(rows) + "\n"
    if len(rows) < len(sorted_violations):
        body += (
            f"\n*Truncated: showing {len(rows)} of {len(sorted_violations)} violations "
            "(see report.json for full details).*\n"
        )

    evidence_lines: list[str] = []
    for v in sorted_violations[:5]:
        ev = _field(v, "evidence", None)
        if isinstance(ev, dict) and ev:
            rule_id = escape_cell(_field(v, "rule_id", "UNKNOWN"))
            tool_name = escape_cell(_field(v, "offending_tool_name", "unknown"))
            span_id = escape_cell(_field(v, "offending_span_id", "unknown"))
            ev_json = (
                json.dumps(ev, default=str)
                .replace("`", "'")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            if len(ev_json) > 220:
                ev_json = ev_json[:217] + "..."
            evidence_lines.append(f"- **`{rule_id}`** (`{tool_name}` · `{span_id}`): `{ev_json}`")

    if evidence_lines:
        details_block = (
            "\n<details>\n"
            "<summary><b>Detailed Evidence (Top Findings)</b></summary>\n\n"
            + "\n".join(evidence_lines)
            + "\n\n</details>\n"
        )
        if len(body) + len(details_block) <= MAX_GITHUB_COMMENT_LENGTH:
            body += details_block

    footer = "\n*Inspect trace waterfall locally: `secagent serve --report report.json`*\n"
    if len(body) + len(footer) <= MAX_GITHUB_COMMENT_LENGTH:
        body += footer

    return body
