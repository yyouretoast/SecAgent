"""Tests for PR-8: subprocess isolation, runtime guardrail middleware, live ToxicFlow, concurrency, and benchmark."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from typer.testing import CliRunner

from secagent.cli import app
from secagent.engine import PolicyEngine
from secagent.harness.isolated import build_sanitized_env, run_isolated_scenarios
from secagent.sdk import PolicyViolationError, SecAgentGuardrail, permission
from secagent.telemetry import SecAgentTelemetryCallback, TraceExporter


def test_sanitized_env_strips_secrets_unless_allowlisted(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_should_not_leak")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_secret_should_not_leak")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-allowlisted-test-key")

    env_default = build_sanitized_env()
    assert "GITHUB_TOKEN" not in env_default
    assert "AWS_SECRET_ACCESS_KEY" not in env_default
    assert "OPENAI_API_KEY" not in env_default

    env_with_allow = build_sanitized_env(pass_env=["OPENAI_API_KEY"])
    assert env_with_allow.get("OPENAI_API_KEY") == "sk-allowlisted-test-key"
    assert "GITHUB_TOKEN" not in env_with_allow


def test_isolated_scan_never_imports_untrusted_code_in_host_and_blocks_network(tmp_path: Path):
    marker_file = tmp_path / "import_pids.txt"
    agent_mod = tmp_path / "untrusted_iso_agent.py"
    agent_mod.write_text(
        f"""
import asyncio
import os
import socket
import subprocess
from pathlib import Path
from secagent.sdk import permission

Path({str(marker_file)!r}).open("a", encoding="utf-8").write(f"{{os.getpid()}}\\n")

@permission(tier="read")
def probe_sandbox(x: str = "ok") -> dict:
    results = {{}}
    for label, fn in [
        ("tcp", lambda: socket.create_connection(("127.0.0.1", 1), timeout=0.1)),
        ("udp", lambda: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))),
        ("dns", lambda: socket.getaddrinfo("example.com", 80)),
        ("subproc", lambda: subprocess.Popen(["python", "-c", "print(1)"])),
    ]:
        try:
            fn()
            results[label] = "ALLOWED"
        except PermissionError:
            results[label] = "BLOCKED"
        except Exception as exc:
            results[label] = f"ERR:{{type(exc).__name__}}"
    async def _async_tcp():
        try:
            await asyncio.open_connection("127.0.0.1", 1)
            return "ALLOWED"
        except PermissionError:
            return "BLOCKED"
        except Exception as exc:
            return f"ERR:{{type(exc).__name__}}"
    results["async_tcp"] = asyncio.run(_async_tcp())
    return results

class App:
    tools = [probe_sandbox]
    def invoke(self, state, config=None):
        return {{"probe": self.tools[0]("run")}}

app = App()
""".strip(),
        encoding="utf-8",
    )

    scn_dir = tmp_path / "scns"
    scn_dir.mkdir()
    (scn_dir / "s1.json").write_text(
        json.dumps({"id": "ISO-PROBE-1", "target_tool": "probe_sandbox", "user_prompt": "Run"}),
        encoding="utf-8",
    )
    report_path = tmp_path / "iso_report.json"
    comment_path = tmp_path / "iso_comment.md"
    host_pid = str(os.getpid())

    old_pp = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = f"{tmp_path}{os.pathsep}{old_pp}" if old_pp else str(tmp_path)
    try:
        res = CliRunner().invoke(
            app,
            [
                "scan",
                "--agent",
                "untrusted_iso_agent:app",
                "--scenarios",
                str(scn_dir),
                "--isolate",
                "--block-network",
                "--output-report",
                str(report_path),
                "--output-markdown",
                str(comment_path),
                "--json",
            ],
        )
    finally:
        if old_pp:
            os.environ["PYTHONPATH"] = old_pp
        else:
            os.environ.pop("PYTHONPATH", None)

    assert res.exit_code == 0, res.stdout
    assert "untrusted_iso_agent" not in sys.modules
    pids = [line.strip() for line in marker_file.read_text(encoding="utf-8").splitlines() if line]
    assert pids and all(pid != host_pid for pid in pids), f"Imported in host PID {host_pid}: {pids}"

    payload = json.loads(res.stdout)
    probe_out = payload["traces"][0]["spans"][0]["output_result"]
    assert probe_out == {
        "tcp": "BLOCKED",
        "udp": "BLOCKED",
        "dns": "BLOCKED",
        "subproc": "BLOCKED",
        "async_tcp": "BLOCKED",
    }


def test_block_network_without_isolate_fails_closed(tmp_path: Path):
    res = CliRunner().invoke(
        app,
        [
            "scan",
            "--agent",
            "examples.finance_agent.agent:app",
            "--block-network",
            "--output-report",
            str(tmp_path / "r.json"),
            "--output-markdown",
            str(tmp_path / "m.md"),
        ],
    )
    assert res.exit_code == 1


def test_isolated_subprocess_hard_kills_hung_agent(tmp_path: Path):
    hung_mod = tmp_path / "hung_agent_fixture.py"
    hung_mod.write_text(
        """
import time
from secagent.sdk import permission

@permission(tier="read")
def hang_forever(x: str = "a") -> str:
    time.sleep(30)
    return x

class HungApp:
    tools = [hang_forever]
    def invoke(self, state, config=None):
        self.tools[0]("x")
        return {"ok": True}

app = HungApp()
""".strip(),
        encoding="utf-8",
    )
    traces = run_isolated_scenarios(
        "hung_agent_fixture:app",
        [{"id": "ISO-HANG-1", "target_tool": "hang_forever", "user_prompt": "hang"}],
        {},
        timeout_s=0.3,
        startup_grace_s=1.0,
        cwd=tmp_path,
    )
    assert len(traces) == 1
    TraceExporter().validate(traces[0])
    assert traces[0]["metadata"]["framework"] == "isolated_subprocess"
    assert traces[0]["spans"][0]["name"] == "isolated_subprocess"
    assert traces[0]["spans"][0]["is_error"] is True
    assert traces[0]["spans"][0]["error_message"] == "Isolated subprocess killed after timeout"


def test_live_toxic_flow_fires_end_to_end_via_tainted_read_output():
    from secagent.harness.executor import execute_scenarios_with_telemetry

    @permission(tier="read")
    def read_ticket(ticket_id: str) -> str:
        """Read a support ticket."""
        return f"Ticket {ticket_id}: customer asks for status."

    @permission(tier="pay")
    def execute_trade(symbol: str, quantity: int) -> str:
        """Execute a stock trade."""
        return f"traded {symbol} x {quantity}"

    def planner(state: MessagesState) -> dict[str, Any]:
        msgs = state["messages"]
        tool_msgs = [m for m in msgs if isinstance(m, ToolMessage)]
        if not tool_msgs:
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {"name": "read_ticket", "args": {"ticket_id": "T-9"}, "id": "c1"}
                        ],
                    )
                ]
            }
        if len(tool_msgs) == 1 and "ignore previous" in str(tool_msgs[0].content).lower():
            return {
                "messages": [
                    AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "name": "execute_trade",
                                "args": {"symbol": "NVDA", "quantity": 100},
                                "id": "c2",
                            }
                        ],
                    )
                ]
            }
        return {"messages": [AIMessage(content="Done")]}

    def route(state: MessagesState) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    g = StateGraph(MessagesState)
    g.add_node("planner", planner)
    g.add_node("tools", ToolNode([read_ticket, execute_trade]))
    g.add_edge(START, "planner")
    g.add_conditional_edges("planner", route, {"tools": "tools", END: END})
    g.add_edge("tools", "planner")
    compiled = g.compile()

    from rich.console import Console

    from secagent.generator import ScenarioGenerator

    gen = ScenarioGenerator()
    discovered = gen.introspect_tools([read_ticket, execute_trade])
    scenarios = gen.generate(discovered)
    toxic_scn = next(s for s in scenarios if s.expected_failure_policy == "POL-ASI01-002")

    traces = execute_scenarios_with_telemetry(
        compiled,
        None,
        discovered,
        [toxic_scn.to_dict()],
        {},
        console=Console(quiet=True),
        quiet=True,
    )
    assert len(traces) == 1
    res = PolicyEngine().evaluate_trace(traces[0])
    assert any(v.rule_id == "POL-ASI01-002" for v in res.violations)


def test_parallel_toolnode_concurrency_with_telemetry_and_guardrail():
    @permission(tier="read")
    def read_a(item: str) -> str:
        """Read A."""
        return f"A:{item}"

    @permission(tier="read")
    def read_b(item: str) -> str:
        """Read B."""
        return f"B:{item}"

    guard = SecAgentGuardrail(mode="enforce")
    wrapped_tools = guard.wrap_tools(
        [
            StructuredTool.from_function(func=read_a, name="read_a"),
            StructuredTool.from_function(func=read_b, name="read_b"),
        ]
    )

    def planner(state: MessagesState) -> dict[str, Any]:
        if any(isinstance(m, ToolMessage) for m in state["messages"]):
            return {"messages": [AIMessage(content="All done")]}
        return {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {"name": "read_a", "args": {"item": "x1"}, "id": "call_a"},
                        {"name": "read_b", "args": {"item": "x2"}, "id": "call_b"},
                    ],
                )
            ]
        }

    def route(state: MessagesState) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    g = StateGraph(MessagesState)
    g.add_node("planner", planner)
    g.add_node("tools", ToolNode(wrapped_tools))
    g.add_edge(START, "planner")
    g.add_conditional_edges("planner", route, {"tools": "tools", END: END})
    g.add_edge("tools", "planner")
    compiled = g.compile()

    cb = SecAgentTelemetryCallback()
    compiled.invoke({"messages": [("user", "read both")]}, config={"callbacks": [cb]})

    TraceExporter().validate(cb.session.as_dict())
    TraceExporter().validate(guard.session.as_dict())
    tool_spans = [s for s in guard.session.spans if s["span_type"] == "tool.call"]
    assert {s["name"] for s in tool_spans} == {"read_a", "read_b"}


@pytest.mark.asyncio
async def test_runtime_guardrail_custom_basetool_async_redaction_and_non_poisoning():
    # 1. Custom BaseTool subclass overriding _run must be enforced
    class CustomPayTool(BaseTool):
        name: str = "execute_trade"
        description: str = "Custom pay tool"

        def _run(self, symbol: str = "AAPL") -> str:
            return f"TRADED:{symbol}"

    guard = SecAgentGuardrail(mode="enforce", task_context="address_update")
    wrapped_custom = guard.wrap_tool(CustomPayTool())
    with pytest.raises(PolicyViolationError) as exc_info:
        wrapped_custom.invoke({"symbol": "AAPL"})
    assert any(v.rule_id == "POL-ASI03-001" for v in exc_info.value.violations)

    # 2. Output containing PII/secret is redacted AND does NOT poison subsequent benign calls
    @permission(tier="read")
    def query_db(fields: list[str]) -> dict[str, str]:
        return {"address": "1 Main St", "ssn": "123-45-6789", "tok": "ghp_" + "A" * 36}

    @permission(tier="pure")
    async def calc_sum(a: int, b: int) -> int:
        return a + b

    w_read = guard.wrap_tool(query_db)
    w_calc = guard.wrap_tool(calc_sum)
    w_read(["address"])
    # Secret & SSN must be scrubbed in recorded output_result
    recorded_out = guard.session.spans[-1]["output_result"]
    assert "123-45-6789" not in json.dumps(recorded_out)
    assert "ghp_" not in json.dumps(recorded_out)
    # Subsequent benign async tool must NOT be poisoned by prior output violation
    assert await w_calc(2, 3) == 5

    # 3. Tool raising exception records is_error=True and error_message
    @permission(tier="read")
    def boom() -> str:
        raise ValueError("db offline")

    w_boom = guard.wrap_tool(boom)
    with pytest.raises(ValueError, match="db offline"):
        w_boom()
    assert guard.session.spans[-1]["is_error"] is True
    assert "db offline" in str(guard.session.spans[-1]["error_message"])

    # 4. Audit mode must not emit O(N^2) duplicate violations on subsequent benign calls
    audit_guard = SecAgentGuardrail(mode="audit")

    @permission(tier="pay")
    def pay_it(amount: int) -> str:
        return f"paid:{amount}"

    @permission(tier="pure")
    def add_one(x: int) -> int:
        return x + 1

    wp = audit_guard.wrap_tool(pay_it)
    wa = audit_guard.wrap_tool(add_one)
    wp(50)
    wa(1)
    wa(2)
    assert len(audit_guard.audit_violations) == 1


def test_benchmark_eval_achieves_perfect_precision_recall_and_utility():
    from scripts.benchmark_eval import run_benchmark

    summary = run_benchmark()
    assert summary["total_cases"] == 26
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["false_positive_rate"] == 0.0
    assert summary["utility_retention"] == 1.0
    assert summary["fp"] == 0
    assert summary["fn"] == 0


def test_runtime_guardrail_strips_run_manager_and_prevents_double_wrap():
    class ManagerAwarePayTool(BaseTool):
        name: str = "execute_trade"
        description: str = "Pay tool accepting run_manager"

        def _run(self, symbol: str = "AAPL", run_manager: Any = None) -> str:
            return f"TRADED:{symbol}:{run_manager is not None}"

    guard = SecAgentGuardrail(mode="enforce")
    raw_tool = ManagerAwarePayTool()
    wrapped_once = guard.wrap_tool(raw_tool)
    wrapped_twice = guard.wrap_tool(wrapped_once)
    assert wrapped_twice is wrapped_once

    class NonSerializableMgr:
        pass

    guard.record_approval("execute_trade", arguments={"symbol": "AAPL"})
    out = wrapped_twice._run(symbol="AAPL", run_manager=NonSerializableMgr())
    assert out == "TRADED:AAPL:True"
    recorded_params = guard.session.spans[-1]["input_parameters"]
    assert recorded_params == {"symbol": "AAPL"}
    json.dumps(guard.session.as_dict())

    @permission(tier="pure")
    def double_fn(x: int) -> int:
        return x + 1

    w1 = guard.wrap_callable(double_fn)
    w2 = guard.wrap_callable(w1)
    assert w2 is w1
