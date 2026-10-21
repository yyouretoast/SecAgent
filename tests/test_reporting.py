"""Unit tests for PR triage comment Markdown formatter (US-5.3)."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secagent.cli import MAX_GITHUB_COMMENT_LENGTH, _format_markdown_report, app


@dataclass
class _MockViolation:
    rule_id: str
    rule_name: str
    owasp_category: str
    severity: str
    offending_span_id: str
    offending_step_index: int
    offending_tool_name: str
    failure_action: str
    evidence: dict[str, Any]
    remediation: str


@dataclass
class _MockResult:
    status: str
    total_spans_evaluated: int
    violations: list[_MockViolation]
    execution_time_ms: float


def test_format_markdown_report_pass():
    """Verify formatting of a compliant evaluation result with zero violations."""
    result = {
        "status": "PASS",
        "total_spans_evaluated": 14,
        "violations": [],
        "execution_time_ms": 3.2,
    }
    md = _format_markdown_report(result, agent_name="finance_agent", scenarios_evaluated=7)

    assert "### SecAgent Security Gate: PASS" in md
    assert "`finance_agent`" in md
    assert "- **Scenarios Evaluated**: 7" in md
    assert "- **Violations Detected**: 0" in md
    assert "| Rule ID |" not in md


def test_format_markdown_report_with_critical_and_high_violations():
    """Verify US-5.3 Gherkin scenario with 1 CRITICAL and 1 HIGH violation."""
    v_critical = _MockViolation(
        rule_id="POL-ASI03-001",
        rule_name="Predecessor HITL Gate Enforcement",
        owasp_category="ASI03: Identity & Privilege Abuse",
        severity="CRITICAL",
        offending_span_id="span-003",
        offending_step_index=2,
        offending_tool_name="issue_refund",
        failure_action="BLOCK_PR",
        evidence={"required_gate": "approval_gate", "approval_granted": False},
        remediation="Ensure the agent redirects high-risk operations (pay/admin) to approval_gate.",
    )
    v_high = _MockViolation(
        rule_id="POL-ASI06-001",
        rule_name="Need-to-Know Field Scope Allowlist",
        owasp_category="ASI06: Context Poisoning / Scope Abuse",
        severity="HIGH",
        offending_span_id="span-001",
        offending_step_index=0,
        offending_tool_name="query_db",
        failure_action="BLOCK_PR",
        evidence={"forbidden_fields_detected": ["password_hash", "ssn"]},
        remediation="Configure query_db tool schema to exclude sensitive profile fields.",
    )
    result = _MockResult(
        status="FAIL",
        total_spans_evaluated=8,
        violations=[v_high, v_critical],
        execution_time_ms=5.4,
    )

    md = _format_markdown_report(result, agent_name="support_agent", scenarios_evaluated=4)

    assert "### SecAgent Security Gate: FAIL" in md
    assert "`support_agent`" in md
    assert "- **Violations Detected**: 2" in md
    assert "| Rule ID | Severity | OWASP Category | Offending Span | Remediation |" in md
    assert "`issue_refund` (`span-003`)" in md
    assert "`query_db` (`span-001`)" in md
    assert md.index("`POL-ASI03-001`") < md.index("`POL-ASI06-001`")
    assert len(md) <= MAX_GITHUB_COMMENT_LENGTH


def test_format_markdown_report_escapes_pipes_and_backticks():
    """Verify unescaped pipes and backticks in fields do not corrupt Markdown table columns."""
    result = {
        "status": "FAIL",
        "violations": [
            {
                "rule_id": "POL-ASI02-001",
                "severity": "CRITICAL",
                "owasp_category": "ASI02: Tool Misuse",
                "offending_tool_name": "tool|with|`pipes`",
                "offending_span_id": "span|002",
                "offending_step_index": 1,
                "remediation": "Use parameterized queries | Avoid raw concat",
            }
        ],
    }
    md = _format_markdown_report(result)

    data_rows = [line for line in md.splitlines() if line.startswith("| `POL-")]
    assert len(data_rows) == 1
    cells = re.split(r"(?<!\\)\|", data_rows[0].strip().strip("|"))
    assert len(cells) == 5


def test_format_markdown_report_enforces_character_limit():
    """Verify table rows truncate under MAX_GITHUB_COMMENT_LENGTH even on large violation counts."""
    violations = [
        {
            "rule_id": f"POL-ASI08-{i:03d}",
            "severity": "HIGH",
            "owasp_category": "ASI08: Cascading Failures",
            "offending_tool_name": f"repetitive_tool_{i}",
            "offending_span_id": f"span-{i:04d}",
            "offending_step_index": i,
            "remediation": "Add termination conditions and retry limits to the planning loop. " * 2,
        }
        for i in range(600)
    ]
    result = {"status": "FAIL", "violations": violations}

    md = _format_markdown_report(result, agent_name="looping_agent", scenarios_evaluated=10)

    assert len(md) <= MAX_GITHUB_COMMENT_LENGTH
    assert "Truncated: showing" in md


def test_cli_scan_generates_markdown_comment(tmp_path: Path):
    """Verify secagent scan writes comment.md via _format_markdown_report."""
    from typer.testing import CliRunner

    runner = CliRunner()
    comment_path = tmp_path / "comment.md"
    report_path = tmp_path / "report.json"

    res = runner.invoke(
        app,
        [
            "scan",
            "--agent",
            "examples.finance_agent.agent",
            "--output-report",
            str(report_path),
            "--output-markdown",
            str(comment_path),
        ],
    )
    assert res.exit_code == 0
    content = comment_path.read_text(encoding="utf-8")
    assert "### SecAgent Security Gate: PASS" in content
    assert "`examples.finance_agent.agent`" in content
