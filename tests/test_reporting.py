"""Unit tests for Pull Request triage reporting and Markdown formatting (US-5.3)."""

from pathlib import Path

from secagent.cli import _format_markdown_report, format_markdown_report
from secagent.engine import EvaluationResult, PolicyViolation
from secagent.reporting import MAX_GITHUB_COMMENT_LENGTH


def test_format_markdown_report_pass():
    """Verify formatting of a compliant evaluation result with zero violations."""
    result = EvaluationResult(
        status="PASS",
        total_spans_evaluated=14,
        violations=[],
        execution_time_ms=3.2,
    )
    md = _format_markdown_report(result, agent_name="finance_agent", scenarios_evaluated=7)

    assert "### 🛡️ SecAgent Security Gate: PASS" in md
    assert "✅ **PASSED**" in md
    assert "`finance_agent`" in md
    assert "7" in md  # scenarios evaluated
    assert "14" in md  # spans audited
    assert "3.2ms" in md
    assert "Violation Summary Table" not in md
    assert "No policy violations detected." in md


def test_format_markdown_report_with_critical_and_high_violations():
    """Verify US-5.3 Gherkin scenario:

    Given an evaluation with 1 CRITICAL and 1 HIGH violation
    When comment.md is written
    Then it contains a Markdown table with columns:
      | Severity | Rule ID | OWASP Category | Offending Tool / Span | Remediation |
    And does not exceed GitHub PR comment length limits
    """
    v_critical = PolicyViolation(
        rule_id="POL-ASI03-001",
        rule_name="Predecessor HITL Gate Enforcement",
        owasp_category="ASI03: Identity & Privilege Abuse",
        severity="CRITICAL",
        offending_span_id="span-003",
        offending_step_index=2,
        offending_tool_name="issue_refund",
        failure_action="BLOCK_PR",
        evidence={
            "required_gate": "approval_gate",
            "approval_granted": False,
            "lookback_operational_steps": 1,
        },
        remediation="Ensure the agent redirects high-risk operations (pay/admin) to approval_gate before invoking execution tools.",
    )

    v_high = PolicyViolation(
        rule_id="POL-ASI06-001",
        rule_name="Need-to-Know Field Scope Allowlist",
        owasp_category="ASI06: Context Poisoning / Scope Abuse",
        severity="HIGH",
        offending_span_id="span-001",
        offending_step_index=0,
        offending_tool_name="query_db",
        failure_action="BLOCK_PR",
        evidence={
            "task_context": "address_update",
            "forbidden_fields_detected": ["password_hash", "ssn"],
        },
        remediation="Configure query_db tool schema and output projection to exclude sensitive profile fields.",
    )

    result = EvaluationResult(
        status="FAIL",
        total_spans_evaluated=8,
        violations=[v_high, v_critical],  # Deliberately out of order to verify sorting
        execution_time_ms=5.4,
    )

    md = _format_markdown_report(result, agent_name="support_agent", scenarios_evaluated=4)

    # 1. Header & Verdict checks
    assert "### 🚨 SecAgent Security Gate: FAILED (Violations Detected)" in md
    assert "❌ **FAIL (PR BLOCKED)**" in md
    assert "`support_agent`" in md
    assert "2 security invariant violations" in md

    # 2. Table Column Header check
    required_header = (
        "| Severity | Rule ID | OWASP Category | Offending Tool / Span | Remediation |"
    )
    assert required_header in md

    # 3. CRITICAL row must precede HIGH row due to severity ordering
    crit_badge = "🔴 **CRITICAL**"
    high_badge = "🟠 **HIGH**"
    assert crit_badge in md
    assert high_badge in md
    assert md.index(crit_badge) < md.index(high_badge)

    # 4. Offending tool and span representation
    assert "`issue_refund` (`span-003`)" in md
    assert "`query_db` (`span-001`)" in md

    # 5. Rule IDs and OWASP categories present
    assert "`POL-ASI03-001`" in md
    assert "ASI03: Identity & Privilege Abuse" in md
    assert "`POL-ASI06-001`" in md
    assert "ASI06: Context Poisoning / Scope Abuse" in md

    # 6. Remediations present
    assert "Ensure the agent redirects high-risk operations" in md
    assert "Configure query_db tool schema" in md

    # 7. Collapsible Diagnostic Evidence block
    assert "<details>" in md
    assert "<summary>🔍 View Diagnostic Evidence (2 items)</summary>" in md
    assert "</details>" in md
    assert '"required_gate": "approval_gate"' in md
    assert '"password_hash"' in md

    # 8. Length safety constraint
    assert len(md) < MAX_GITHUB_COMMENT_LENGTH


def test_format_markdown_report_escapes_pipes():
    """Verify pipe characters in tool names, evidence, or remediations do not break Markdown table structure."""
    v = PolicyViolation(
        rule_id="POL-ASI02-001",
        rule_name="Tool Parameter SQL Injection Blocklist",
        owasp_category="ASI02: Tool Misuse & Exploitation",
        severity="CRITICAL",
        offending_span_id="span-002",
        offending_step_index=1,
        offending_tool_name="tool|with|pipes",
        failure_action="BLOCK_PR",
        evidence={"input": "' OR '1'='1 | DROP TABLE users; --"},
        remediation="Use parameterized queries | Avoid raw string concat",
    )
    result = EvaluationResult(
        status="FAIL",
        total_spans_evaluated=3,
        violations=[v],
        execution_time_ms=1.1,
    )
    md = _format_markdown_report(result)

    # All row cells should have escaped pipes so the table has exactly 6 pipe delimiters per line
    for line in md.splitlines():
        if line.startswith("| 🔴 **CRITICAL**"):
            # Split by unescaped pipe:
            parts = line.split(" | ")
            assert len(parts) == 5


def test_format_markdown_report_enforces_character_limit():
    """Verify report truncates safely when hundreds of violations would exceed GitHub comment limits."""
    violations = []
    for i in range(200):
        violations.append(
            PolicyViolation(
                rule_id=f"POL-RUNAWAY-{i:03d}",
                rule_name="Runaway Step Loop",
                owasp_category="ASI08: Cascading Failures",
                severity="HIGH",
                offending_span_id=f"span-{i:04d}",
                offending_step_index=i,
                offending_tool_name=f"repetitive_tool_{i}",
                failure_action="BLOCK_PR",
                evidence={"trace_dump": "A" * 500, "iteration": i},
                remediation="Add termination conditions and retry limits to the planning loop.",
            )
        )

    result = EvaluationResult(
        status="FAIL",
        total_spans_evaluated=200,
        violations=violations,
        execution_time_ms=120.0,
    )

    md = format_markdown_report(result, agent_name="looping_agent", scenarios_evaluated=10)

    assert len(md) <= MAX_GITHUB_COMMENT_LENGTH
    assert "Diagnostic evidence truncated" in md
    assert "to respect GitHub comment length limits" in md


def test_cli_scan_generates_markdown_comment(tmp_path: Path):
    """Verify running secagent scan generates comment.md matching reporting formatter format."""
    from typer.testing import CliRunner

    from secagent.cli import app

    runner = CliRunner()
    comment_path = tmp_path / "comment.md"
    report_path = tmp_path / "report.json"

    result = runner.invoke(
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
    assert result.exit_code == 0
    assert comment_path.exists()

    content = comment_path.read_text(encoding="utf-8")
    assert "### 🛡️ SecAgent Security Gate: PASS" in content
    assert "`examples.finance_agent.agent`" in content
    assert "All declarative security invariants verified with **0 violations**." in content
