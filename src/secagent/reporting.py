"""Markdown report generation for pull request comments and CLI triage tables."""

import json

from secagent.engine import EvaluationResult

MAX_GITHUB_COMMENT_LENGTH = 65000

SEVERITY_BADGES = {
    "CRITICAL": "🔴 **CRITICAL**",
    "HIGH": "🟠 **HIGH**",
    "MEDIUM": "🟡 **MEDIUM**",
    "LOW": "⚪ **LOW**",
}

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def _escape_table_cell(text: str) -> str:
    """Escape vertical pipe characters and clean newlines for Markdown tables."""
    return str(text).replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").strip()


def format_markdown_report(
    result: EvaluationResult,
    agent_name: str = "default_fixture",
    scenarios_evaluated: int = 0,
) -> str:
    """Format an EvaluationResult into a GitHub-Flavored Markdown PR triage report.

    Conforms to US-5.3 acceptance criteria:
    - Renders summary table with columns:
      | Severity | Rule ID | OWASP Category | Offending Tool / Span | Remediation |
    - Contains collapsible diagnostic evidence.
    - Guards against GitHub's 65,536 character comment length limit.
    """
    effective_agent = agent_name or "default_fixture"

    if result.status == "PASS" and not result.violations:
        return (
            "### 🛡️ SecAgent Security Gate: PASS\n\n"
            "All declarative security invariants verified with **0 violations**.\n\n"
            "| Metric | Value |\n"
            "| :--- | :--- |\n"
            "| **Status** | ✅ **PASSED** |\n"
            f"| **Target Agent** | `{effective_agent}` |\n"
            f"| **Scenarios Evaluated** | {scenarios_evaluated} |\n"
            f"| **Spans Audited** | {result.total_spans_evaluated} |\n"
            f"| **Verification Time** | {result.execution_time_ms:.1f}ms |\n\n"
            "*No policy violations detected. This pull request complies with configured OWASP invariant policies.*\n"
        )

    # Sort violations: highest severity first, then by step index
    sorted_violations = sorted(
        result.violations,
        key=lambda v: (SEVERITY_ORDER.get(v.severity, 99), v.offending_step_index),
    )

    critical_high_count = sum(1 for v in sorted_violations if v.severity in ("CRITICAL", "HIGH"))

    header = (
        "### 🚨 SecAgent Security Gate: FAILED (Violations Detected)\n\n"
        f"SecAgent evaluated **{scenarios_evaluated}** scenarios across **{result.total_spans_evaluated}** execution spans. "
        f"**{len(sorted_violations)} security invariant violations** were detected.\n\n"
        "| Metric | Value |\n"
        "| :--- | :--- |\n"
        "| **Status** | ❌ **FAIL (PR BLOCKED)** |\n"
        f"| **Target Agent** | `{effective_agent}` |\n"
        f"| **Total Violations** | {len(sorted_violations)} |\n"
        f"| **Critical / High** | {critical_high_count} |\n"
        f"| **Verification Time** | {result.execution_time_ms:.1f}ms |\n\n"
        "#### Violation Summary Table\n\n"
        "| Severity | Rule ID | OWASP Category | Offending Tool / Span | Remediation |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
    )

    table_rows: list[str] = []
    evidence_items: list[str] = []

    for idx, v in enumerate(sorted_violations, start=1):
        severity_badge = SEVERITY_BADGES.get(v.severity, f"**{v.severity}**")
        rule_cell = f"`{_escape_table_cell(v.rule_id)}`"
        owasp_cell = _escape_table_cell(v.owasp_category)
        tool_span_cell = f"`{_escape_table_cell(v.offending_tool_name)}` (`{_escape_table_cell(v.offending_span_id)}`)"
        remediation_cell = _escape_table_cell(v.remediation)

        table_rows.append(
            f"| {severity_badge} | {rule_cell} | {owasp_cell} | {tool_span_cell} | {remediation_cell} |"
        )

        try:
            evidence_json = json.dumps(v.evidence, indent=2)
        except Exception:
            evidence_json = str(v.evidence)

        evidence_items.append(
            f"##### {idx}. `{v.rule_id}`: {v.rule_name}\n"
            f"- **Tool / Span**: `{v.offending_tool_name}` (`{v.offending_span_id}`, step index {v.offending_step_index})\n"
            f"- **OWASP Category**: {v.owasp_category}\n"
            f"- **Severity**: {v.severity} (`{v.failure_action}`)\n"
            "- **Offending Evidence**:\n"
            f"```json\n{evidence_json}\n```\n"
            f"- **Remediation**: {v.remediation}\n"
        )

    table_content = "\n".join(table_rows) + "\n\n"

    evidence_header = (
        "#### Technical Evidence & Context\n\n"
        f"<details>\n<summary>🔍 View Diagnostic Evidence ({len(sorted_violations)} items)</summary>\n\n"
    )
    evidence_footer = "\n</details>\n\n"
    footer = (
        "---\n"
        "> **Action Required**: Pull request merge is blocked until all `BLOCK_PR` invariant violations are resolved.\n"
    )

    evidence_body = "\n".join(evidence_items)
    full_report = (
        header + table_content + evidence_header + evidence_body + evidence_footer + footer
    )

    # Guard against GitHub PR comment size limits (65,536 characters)
    if len(full_report) > MAX_GITHUB_COMMENT_LENGTH:
        # Keep table, truncate evidence items until length is safe
        truncated_evidence: list[str] = []
        current_len = (
            len(header)
            + len(table_content)
            + len(evidence_header)
            + len(evidence_footer)
            + len(footer)
            + 200
        )
        included_count = 0
        for item in evidence_items:
            if current_len + len(item) > MAX_GITHUB_COMMENT_LENGTH:
                break
            truncated_evidence.append(item)
            current_len += len(item)
            included_count += 1

        truncation_notice = (
            f"\n> ⚠️ *Diagnostic evidence truncated ({included_count} of {len(sorted_violations)} items shown) "
            "to respect GitHub comment length limits. Download report.json artifact for complete trace data.*\n\n"
        )
        full_report = (
            header
            + table_content
            + evidence_header
            + "\n".join(truncated_evidence)
            + truncation_notice
            + evidence_footer
            + footer
        )

    return full_report


# Alias for US-5.3 target interface compliance
_format_markdown_report = format_markdown_report

__all__ = ["MAX_GITHUB_COMMENT_LENGTH", "_format_markdown_report", "format_markdown_report"]
