"""Unit tests for SecAgent Rich terminal UI components."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

from rich.console import Console

from secagent.ui import (
    make_progress,
    render_discovered_tools,
    render_summary_card,
    render_violations,
    render_welcome_banner,
)


def _buffer_console(*, is_terminal: bool = False) -> tuple[Console, StringIO]:
    buf = StringIO()
    con = Console(file=buf, force_terminal=is_terminal, no_color=True, width=120)
    return con, buf


def test_render_welcome_banner_detects_workspace_policies_and_report(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Missing policies & report
    con1, buf1 = _buffer_console()
    render_welcome_banner(con1, "0.1.0")
    out1 = buf1.getvalue()
    assert "packaged defaults" in out1
    assert "Last Scan" not in out1

    # Present policies & PASS report
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "security_rules.yaml").write_text("version: '1'\n", encoding="utf-8")
    (tmp_path / "report.json").write_text(
        json.dumps({"status": "PASS", "violations_detected": 0}),
        encoding="utf-8",
    )
    con2, buf2 = _buffer_console()
    render_welcome_banner(con2, "0.1.0")
    out2 = buf2.getvalue()
    assert "security_rules.yaml" in out2
    assert "PASS" in out2
    assert "0 violations" in out2

    # Corrupt report.json fallback does not crash
    (tmp_path / "report.json").write_text("{not-json", encoding="utf-8")
    con3, buf3 = _buffer_console()
    render_welcome_banner(con3, "0.1.0")
    assert "SecAgent v0.1.0" in buf3.getvalue()


def test_render_discovered_tools_marks_mocked_and_live_and_escapes_brackets():
    con, buf = _buffer_console()
    tools = [
        SimpleNamespace(name="execute_trade", permission_tier="pay"),
        SimpleNamespace(name="restart_server", permission_tier="admin"),
        SimpleNamespace(name="modify_user", permission_tier="write"),
        SimpleNamespace(name="post_data", permission_tier="net"),
        SimpleNamespace(name="query_db[0]", permission_tier="read"),
        SimpleNamespace(name="calc_tax", permission_tier="pure"),
    ]
    render_discovered_tools(con, tools)
    out = buf.getvalue()
    assert "Discovered Tools (6)" in out
    assert "MOCKED" in out
    assert "LIVE" in out
    assert "query_db[0]" in out


def test_render_violations_truncates_list_and_long_evidence():
    con, buf = _buffer_console()
    violations = [
        {
            "rule_id": f"POL-ASI03-{i:03d}",
            "severity": "CRITICAL",
            "rule_name": "Gate Check",
            "owasp_category": "ASI03: Identity & Privilege Abuse",
            "offending_tool_name": "execute_trade",
            "offending_span_id": f"span-{i}",
            "offending_step_index": i,
            "evidence": {"payload": "x" * 200},
            "remediation": "Add gate",
        }
        for i in range(7)
    ]
    render_violations(con, violations, max_display=3, report_path=Path("vuln_report.json"))
    out = buf.getvalue()
    assert "showing 3 of 7 violation groups" in out
    assert "vuln_report.json" in out
    assert "..." in out

    con_grouped, buf_grouped = _buffer_console()
    repeated = [
        {
            "rule_id": "POL-ASI03-001",
            "severity": "CRITICAL",
            "rule_name": "Gate Check",
            "owasp_category": "ASI03: Identity & Privilege Abuse",
            "offending_tool_name": "execute_trade",
            "offending_span_id": f"s-{i}",
            "offending_step_index": 1,
            "remediation": "Add gate",
        }
        for i in range(5)
    ] + [
        {
            "rule_id": "POL-ASI03-001",
            "severity": "CRITICAL",
            "rule_name": "Gate Check",
            "owasp_category": "ASI03: Identity & Privilege Abuse",
            "offending_tool_name": "transfer_funds",
            "offending_span_id": "s-tf",
            "offending_step_index": 1,
            "remediation": "Add gate",
        }
    ]
    render_violations(con_grouped, repeated, max_display=5)
    grouped_out = buf_grouped.getvalue()
    assert "execute_trade" in grouped_out
    assert "transfer_funds" in grouped_out
    assert "(×5)" in grouped_out


def test_render_summary_card_includes_sarif_and_omits_owasp_when_not_evaluated():
    con1, buf1 = _buffer_console()
    render_summary_card(
        con1,
        status="FAIL",
        scenarios=4,
        spans=10,
        violations=1,
        report_path=Path("report.json"),
        markdown_path=Path("comment.md"),
        sarif_path=Path("report.sarif"),
        elapsed_ms=12.5,
        violation_list=[{"owasp_category": "ASI03: Identity & Privilege Abuse"}],
    )
    out1 = buf1.getvalue()
    assert "report.sarif" in out1
    assert "12.5 ms" in out1
    assert "ASI03 ✗(1)" in out1

    con2, buf2 = _buffer_console()
    render_summary_card(
        con2,
        status="NOT_EVALUATED",
        scenarios=4,
        spans=0,
        violations=0,
        report_path=Path("report.json"),
        markdown_path=Path("comment.md"),
        violation_list=[],
    )
    assert "OWASP" not in buf2.getvalue()


def test_make_progress_disables_in_quiet_and_non_tty():
    non_tty, _ = _buffer_console(is_terminal=False)
    assert make_progress(non_tty, quiet=False).disable is True

    tty, _ = _buffer_console(is_terminal=True)
    assert make_progress(tty, quiet=True).disable is True
