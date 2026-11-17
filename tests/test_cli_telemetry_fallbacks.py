"""Regression tests for CLI telemetry fallback, interrupt capture, and fail-closed guards."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import ValidationError
from typer.testing import CliRunner

from secagent.cli import _execute_scenarios_with_telemetry, app
from secagent.harness.sandbox import ToolCallRecord
from secagent.sdk import permission
from secagent.telemetry.exporter import TraceExporter


def test_fallback_handles_sandbox_tool_call_record_without_extra_attributes():
    @permission(tier="pay")
    def wire_funds(amount: float) -> dict[str, float]:
        return {"amount": amount}

    class GenericAgent:
        tools = [wire_funds]

        def invoke(self, state, config=None):
            self.tools[0](100.0)
            return {"ok": True}

    from secagent.generator import ScenarioGenerator

    gen = ScenarioGenerator()
    agent = GenericAgent()
    tools = gen.introspect_tools(agent.tools)
    traces = _execute_scenarios_with_telemetry(
        agent,
        None,
        tools,
        [{"id": "SCN-GENERIC", "target_tool": "wire_funds", "user_prompt": "Pay 100"}],
        {},
    )

    assert len(traces) == 1
    TraceExporter().validate(traces[0])
    assert traces[0]["spans"][0]["name"] == "wire_funds"
    assert traces[0]["spans"][0]["permission_tier"] == "pay"
    assert traces[0]["spans"][0]["output_result"] is None


def test_tool_call_record_fallback_serializes_list_output_from_custom_record(monkeypatch):
    class FakeHarness:
        def __init__(self, **kwargs):
            pass

        def run_scenario(self, target, scn, mod, callbacks=None):
            rec = ToolCallRecord(
                tool_name="query_db",
                tier="read",
                arguments={"table": "users"},
                mocked=False,
            )
            rec.output = ["row1", "row2"]  # type: ignore[attr-defined]
            return SimpleNamespace(
                output=None,
                tool_calls=[rec],
                error_span=lambda step_index=0: None,
            )

    monkeypatch.setattr("secagent.harness.runner.ExecutionHarness", FakeHarness)

    class DummyTarget:
        def invoke(self, state, config=None):
            return None

    traces = _execute_scenarios_with_telemetry(
        DummyTarget(),
        None,
        [],
        [{"id": "SCN-LIST-OUT", "target_tool": "query_db"}],
        {},
    )

    assert len(traces) == 1
    assert traces[0]["spans"][0]["output_result"] == '["row1", "row2"]'


def test_scan_rejects_broken_explicit_agent_entrypoint(tmp_path: Path):
    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "scan",
            "--agent",
            "nonexistent.module.path:app",
            "--output-report",
            str(tmp_path / "report.json"),
            "--output-markdown",
            str(tmp_path / "comment.md"),
        ],
    )

    assert res.exit_code == 1
    assert "Error loading agent entrypoint" in res.stdout


def test_scan_rejects_valid_module_with_no_tools(monkeypatch, tmp_path: Path):
    mod = types.ModuleType("empty_dummy_agent_mod")
    monkeypatch.setitem(sys.modules, "empty_dummy_agent_mod", mod)

    runner = CliRunner()
    res = runner.invoke(
        app,
        [
            "scan",
            "--agent",
            "empty_dummy_agent_mod",
            "--output-report",
            str(tmp_path / "report.json"),
            "--output-markdown",
            str(tmp_path / "comment.md"),
        ],
    )

    assert res.exit_code == 1
    assert "No tools discovered" in res.stdout


def test_telemetry_surfaces_schema_validation_errors(monkeypatch):
    class InvalidOutputHarness:
        def __init__(self, **kwargs):
            pass

        def run_scenario(self, target, scn, mod, callbacks=None):
            rec = ToolCallRecord(
                tool_name="bad_tool",
                tier="invalid_tier",
                arguments={},
                mocked=False,
            )
            rec.permission_tier = "invalid_tier"  # type: ignore[attr-defined]
            return SimpleNamespace(
                output=None,
                tool_calls=[rec],
                error_span=lambda step_index=0: None,
            )

    monkeypatch.setattr("secagent.harness.runner.ExecutionHarness", InvalidOutputHarness)

    class DummyTarget:
        def invoke(self, state, config=None):
            return None

    # Also corrupt TraceExporter to simulate schema violation not being swallowed
    def fail_validate(self, trace):
        raise ValidationError("invalid trace")

    monkeypatch.setattr("secagent.telemetry.exporter.TraceExporter.validate", fail_validate)

    with pytest.raises(ValidationError, match="invalid trace"):
        _execute_scenarios_with_telemetry(
            DummyTarget(),
            None,
            [],
            [{"id": "SCN-BAD-SCHEMA", "target_tool": "bad_tool"}],
            {},
        )


def test_interrupt_payloads_are_normalized_to_gate_hitl_spans():
    @permission(tier="pay")
    def execute_trade(symbol: str) -> dict[str, str]:
        return {"symbol": symbol}

    class InterruptAgent:
        tools = [execute_trade]

        def invoke(self, state, config=None):
            return {
                "__interrupt__": [
                    SimpleNamespace(value={"approved": True, "operation": "execute_trade"}),
                    SimpleNamespace(value={"question": "Confirm transfer?"}),
                ]
            }

    from secagent.generator import ScenarioGenerator

    gen = ScenarioGenerator()
    agent = InterruptAgent()
    tools = gen.introspect_tools(agent.tools)
    traces = _execute_scenarios_with_telemetry(
        agent,
        None,
        tools,
        [{"id": "SCN-INT", "target_tool": "execute_trade", "user_prompt": "Buy AAPL"}],
        {},
    )

    assert len(traces) == 1
    TraceExporter().validate(traces[0])
    gate_spans = [s for s in traces[0]["spans"] if s["span_type"] == "gate.hitl"]
    assert len(gate_spans) == 2
    assert gate_spans[0]["approval_granted"] is True
    assert gate_spans[0]["input_parameters"]["operation"] == "execute_trade"
    assert gate_spans[1]["approval_granted"] is False
    assert json.loads(json.dumps(traces[0]))  # JSON-serializable


def test_generate_and_fuzz_reject_broken_explicit_agent_entrypoint(tmp_path: Path):
    runner = CliRunner()

    gen_res = runner.invoke(
        app,
        [
            "generate",
            "--agent",
            "nonexistent.module.path:app",
            "--output-dir",
            str(tmp_path / "gen"),
        ],
    )
    assert gen_res.exit_code == 1
    assert "Error loading agent entrypoint" in gen_res.stdout

    fuzz_res = runner.invoke(
        app,
        [
            "fuzz",
            "--agent",
            "nonexistent.module.path:app",
            "--output-dir",
            str(tmp_path / "fuzz"),
        ],
    )
    assert fuzz_res.exit_code == 1
    assert "Error loading agent entrypoint" in fuzz_res.stdout
