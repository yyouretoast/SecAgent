"""Unit and Streamlit AppTest suite for US-5.5 audit dashboard and `secagent serve`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from streamlit.testing.v1 import AppTest
from typer.testing import CliRunner

from secagent.app import (
    _total_trace_duration_ms,
    build_timeline_rows,
    build_waterfall_chart_spec,
    extract_traces,
    parse_app_args,
)
from secagent.cli import app as cli_app

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"
APP_PATH = ROOT_DIR / "src" / "secagent" / "app.py"


def test_build_timeline_rows_computes_nanosecond_offsets_and_durations():
    trace = json.loads((FIXTURES_DIR / "sample_trace.json").read_text(encoding="utf-8"))
    rows = build_timeline_rows(trace["spans"], violations=[])

    assert [r["step_index"] for r in rows] == [0, 1, 2]
    assert rows[0]["offset_ns"] == 0
    assert rows[0]["duration_ns"] == 1_000_000
    assert rows[1]["span_type"] == "gate.hitl"
    assert rows[1]["category"] == "gate.hitl"
    assert all(not r["violated"] for r in rows)


def test_build_timeline_rows_highlights_violating_spans():
    trace = json.loads(
        (FIXTURES_DIR / "trace_privilege_violation.json").read_text(encoding="utf-8")
    )
    violations = [
        {
            "rule_id": "POL-ASI03-001",
            "rule_name": "Predecessor HITL Gate Enforcement",
            "owasp_category": "ASI03: Identity & Privilege Abuse",
            "severity": "CRITICAL",
            "offending_span_id": "span-002",
            "offending_step_index": 1,
            "offending_tool_name": "issue_refund",
            "failure_action": "BLOCK_PR",
            "evidence": {"required_gate": "approval_gate"},
            "remediation": "Route pay tools through approval_gate.",
        }
    ]

    rows = build_timeline_rows(trace["spans"], violations)
    spec = build_waterfall_chart_spec(rows)

    assert rows[0]["violated"] is False
    assert rows[1]["violated"] is True
    assert rows[1]["category"] == "VIOLATION"
    assert rows[1]["rule_ids"] == "POL-ASI03-001"

    color_scale = spec["encoding"]["color"]["scale"]
    assert color_scale["range"][color_scale["domain"].index("VIOLATION")] == "#d93025"
    tooltip_fields = {item["field"] for item in spec["encoding"]["tooltip"]}
    assert {"duration_ns", "offset_ns", "violated", "rule_ids"}.issubset(tooltip_fields)


def test_extract_traces_supports_embedded_and_relative_trace_paths(tmp_path: Path):
    sample = json.loads((FIXTURES_DIR / "sample_trace.json").read_text(encoding="utf-8"))
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(json.dumps(sample), encoding="utf-8")

    assert len(extract_traces({"traces": [sample]})) == 1
    assert len(extract_traces({"trace": sample})) == 1
    assert len(extract_traces({"trace_path": "trace.json"}, base_dir=tmp_path)) == 1
    assert len(extract_traces(sample)) == 1


def test_parse_app_args_ignores_streamlit_flags():
    args = parse_app_args(
        ["--server.port", "8501", "--report", "out/report.json", "--trace", "out/trace.json"]
    )
    assert args.report == Path("out/report.json")
    assert args.trace == Path("out/trace.json")


def test_streamlit_apptest_renders_pass_report_and_trace(tmp_path: Path, monkeypatch):
    sample = json.loads((FIXTURES_DIR / "sample_trace.json").read_text(encoding="utf-8"))
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "status": "PASS",
                "agent": "examples.finance_agent.agent",
                "scenarios_evaluated": 1,
                "violations": [],
                "execution_time_ms": 4.2,
                "traces": [sample],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(sys, "argv", ["app.py", "--report", str(report_path)])
    at = AppTest.from_file(str(APP_PATH)).run()

    assert not at.exception
    assert len(at.success) == 1
    assert "PASS" in at.success[0].value
    assert len(at.expander) == 3


def test_streamlit_apptest_renders_fail_report_with_red_violations(tmp_path: Path, monkeypatch):
    trace = json.loads(
        (FIXTURES_DIR / "trace_privilege_violation.json").read_text(encoding="utf-8")
    )
    trace_path = tmp_path / "trace.json"
    trace_path.write_text(json.dumps(trace), encoding="utf-8")

    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "status": "FAIL",
                "agent": "examples.support_agent.agent",
                "scenarios_evaluated": 1,
                "violations": [
                    {
                        "rule_id": "POL-ASI03-001",
                        "rule_name": "Predecessor HITL Gate Enforcement",
                        "owasp_category": "ASI03: Identity & Privilege Abuse",
                        "severity": "CRITICAL",
                        "offending_span_id": "span-002",
                        "offending_step_index": 1,
                        "offending_tool_name": "issue_refund",
                        "failure_action": "BLOCK_PR",
                        "evidence": {"approval_granted": False},
                        "remediation": "Require approval_gate before issue_refund.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys, "argv", ["app.py", "--report", str(report_path), "--trace", str(trace_path)]
    )
    at = AppTest.from_file(str(APP_PATH)).run()

    assert not at.exception
    assert any("FAIL" in err.value for err in at.error)
    assert any("POL-ASI03-001" in err.value for err in at.error)
    assert len(at.dataframe) == 1


def test_streamlit_apptest_handles_missing_report_gracefully(tmp_path: Path, monkeypatch):
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(sys, "argv", ["app.py", "--report", str(missing)])
    at = AppTest.from_file(str(APP_PATH)).run()

    assert not at.exception
    assert len(at.error) == 1
    assert "Could not load report" in at.error[0].value


def test_cli_serve_rejects_missing_report_or_trace(tmp_path: Path):
    runner = CliRunner()
    missing_report = tmp_path / "missing_report.json"

    res1 = runner.invoke(cli_app, ["serve", "--report", str(missing_report)])
    assert res1.exit_code == 1
    assert "Report file not found" in res1.stdout

    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    missing_trace = tmp_path / "missing_trace.json"

    res2 = runner.invoke(cli_app, ["serve", "--report", str(report), "--trace", str(missing_trace)])
    assert res2.exit_code == 1
    assert "Trace file not found" in res2.stdout


def test_cli_serve_launches_streamlit_on_configured_port(tmp_path: Path, monkeypatch):
    report = tmp_path / "report.json"
    trace = tmp_path / "trace.json"
    report.write_text('{"status": "PASS", "violations": []}', encoding="utf-8")
    trace.write_text('{"spans": []}', encoding="utf-8")

    recorded: list[list[str]] = []

    def fake_run(cmd: list[str], check: bool = False) -> SimpleNamespace:
        recorded.append(cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    runner = CliRunner()
    result = runner.invoke(
        cli_app,
        ["serve", "--report", str(report), "--trace", str(trace), "--port", "8501"],
    )

    assert result.exit_code == 0
    assert len(recorded) == 1
    cmd = recorded[0]
    assert cmd[:4] == [sys.executable, "-m", "streamlit", "run"]
    assert str(APP_PATH) == cmd[4]
    assert "--server.port" in cmd and "8501" in cmd
    assert "--report" in cmd and str(report) in cmd
    assert "--trace" in cmd and str(trace) in cmd


def test_zero_duration_span_scales_visibly_and_deduplicates_labels():
    spans = [
        {
            "span_id": "span-a",
            "step_index": 0,
            "span_type": "gate.hitl",
            "name": "approval_gate",
            "permission_tier": "gate",
            "start_time_ns": 1_000_000_000,
            "end_time_ns": 1_000_000_000,
        },
        {
            "span_id": "span-b",
            "step_index": 0,
            "span_type": "gate.hitl",
            "name": "approval_gate",
            "permission_tier": "gate",
            "start_time_ns": 1_000_000_000,
            "end_time_ns": 1_500_000_000,
        },
    ]
    rows = build_timeline_rows(spans, violations=[])
    assert _total_trace_duration_ms(rows) == 500.0
    assert rows[0]["duration_ms"] == 0.0
    assert rows[0]["end_ms"] - rows[0]["offset_ms"] == 7.5
    assert rows[0]["label"] != rows[1]["label"]


def test_streamlit_apptest_supports_raw_trace_filters_and_nullable_metadata(
    tmp_path: Path, monkeypatch
):
    raw_trace = {
        "scenario_id": "RAW-001",
        "metadata": None,
        "spans": [
            {
                "span_id": "span-1",
                "step_index": None,
                "span_type": "tool.call",
                "name": "read_kb",
                "permission_tier": "read",
                "start_time_ns": None,
                "end_time_ns": 2_000_000,
            },
            {
                "span_id": "span-2",
                "step_index": 1,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "permission_tier": "gate",
                "start_time_ns": 2_000_000,
                "end_time_ns": 2_000_000,
            },
        ],
    }
    trace_path = tmp_path / "raw_trace.json"
    trace_path.write_text(json.dumps(raw_trace), encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["app.py", "--report", str(trace_path)])
    at = AppTest.from_file(str(APP_PATH)).run()

    assert not at.exception
    assert any("RAW-001" in info.value for info in at.info)
    assert len(at.expander) == 2

    at.sidebar.multiselect[0].select("gate.hitl").run()
    assert not at.exception
    assert len(at.expander) == 1


def test_streamlit_apptest_multi_trace_selector_handles_duplicate_scenario_ids(
    tmp_path: Path, monkeypatch
):
    trace1 = {
        "scenario_id": "FUZZ-001",
        "task_context": "mutated",
        "execution_id": "exec-1",
        "spans": [
            {
                "span_id": "s1",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "tool_alpha",
                "permission_tier": "read",
                "start_time_ns": 100,
                "end_time_ns": 200,
            }
        ],
    }
    trace2 = {
        "scenario_id": "FUZZ-001",
        "task_context": "mutated",
        "execution_id": "exec-2",
        "spans": [
            {
                "span_id": "s2",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "tool_beta",
                "permission_tier": "write",
                "start_time_ns": 100,
                "end_time_ns": 300,
            }
        ],
    }
    report_path = tmp_path / "fuzz_report.json"
    report_path.write_text(
        json.dumps({"status": "PASS", "traces": [trace1, trace2]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(sys, "argv", ["app.py", "--report", str(report_path)])
    at = AppTest.from_file(str(APP_PATH)).run()
    assert not at.exception
    assert any("tool_alpha" in exp.label for exp in at.expander)

    at.selectbox[0].select_index(1).run()
    assert not at.exception
    assert any("tool_beta" in exp.label for exp in at.expander)


def test_cli_serve_rejects_out_of_range_port(tmp_path: Path):
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    runner = CliRunner()

    res_low = runner.invoke(cli_app, ["serve", "--report", str(report), "--port", "0"])
    assert res_low.exit_code != 0

    res_high = runner.invoke(cli_app, ["serve", "--report", str(report), "--port", "70000"])
    assert res_high.exit_code != 0
