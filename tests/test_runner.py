import json
import logging
import threading
from pathlib import Path
from typing import Any

import jsonschema
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from secagent.agent.state import AgentState
from secagent.harness import MOCK_RESPONSE, ExecutionHarness, build_initial_state
from secagent.harness.introspector import graph_tool_dicts
from secagent.sdk import permission

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "trace_event.schema.json").read_text(encoding="utf-8"))


def _call_graph(tool, args=None, loop=False, stall=None):
    """Tiny agent: [stall] -> planner (asks for ``tool``) -> tools -> END (or back to planner)."""

    def planner(state: AgentState) -> dict[str, Any]:
        call = {"name": tool.__name__, "args": args or {}, "id": "call_1"}
        return {"messages": [AIMessage(content="", tool_calls=[call])]}

    def wait(state: AgentState) -> dict[str, Any]:
        stall.wait(30)
        return {}

    graph = StateGraph(AgentState)
    graph.add_node("planner", planner)
    graph.add_node("tools", ToolNode([tool]))
    if stall is not None:
        graph.add_node("wait", wait)
        graph.add_edge(START, "wait")
        graph.add_edge("wait", "planner")
    else:
        graph.add_edge(START, "planner")
    graph.add_edge("planner", "tools")
    graph.add_edge("tools", "planner" if loop else END)
    return graph.compile()


def test_timeout_returns_error_span_instead_of_hanging():
    gate = threading.Event()
    harness = ExecutionHarness(timeout_s=0.3)
    result = harness.execute(lambda: gate.wait(30), scenario_id="loop")
    gate.set()
    assert result.status == "timeout"
    assert result.error_message == "Execution timeout"
    assert result.duration_ms < 2000
    span = result.error_span()
    assert span["is_error"] is True
    assert span["error_message"] == "Execution timeout"


def test_unhandled_exception_is_trapped():
    def boom() -> None:
        raise ValueError("Corrupted parameter")

    result = ExecutionHarness().execute(boom, scenario_id="boom")
    assert result.status == "error"
    assert result.error_message == "Corrupted parameter"
    assert result.error_span()["error_message"] == "Corrupted parameter"


def test_successful_run_has_no_error_span():
    result = ExecutionHarness().execute(lambda: 42)
    assert (result.status, result.output, result.error_span()) == ("completed", 42, None)


def test_error_span_conforms_to_trace_schema():
    result = ExecutionHarness(timeout_s=0.1).execute(lambda: threading.Event().wait(5))
    trace = {
        "scenario_id": "S-1",
        "execution_id": "exec-1",
        "timestamp": "2026-10-24T12:00:00Z",
        "caller_role": "guest",
        "task_context": "general_inquiry",
        "spans": [result.error_span()],
    }
    jsonschema.validate(instance=trace, schema=SCHEMA)


def test_initial_state_from_dict_and_defaults():
    state = build_initial_state(
        {
            "id": "S-1",
            "user_prompt": "buy",
            "target_tool": "execute_trade",
            "approval_granted": True,
            "injected_parameters": {"symbol": "AAPL"},
        }
    )
    assert state["current_intent"] == "execute_trade"
    assert state["approval_granted"] is True
    assert state["task_context"] == "unspecified"
    assert state["caller_role"] == "guest"
    assert state["messages"][0].content == "buy"
    assert state["messages"][0].additional_kwargs["injected_parameters"] == {"symbol": "AAPL"}


def test_initial_state_reads_session_context_and_objects():
    class Scenario:
        id = "S-2"
        user_prompt = "hi"
        target_tool = "query_db"
        approval_granted = False
        injected_parameters = None
        session_context = {"task_context": "general_inquiry", "caller_role": "admin"}

    state = build_initial_state(Scenario())
    assert state["task_context"] == "general_inquiry"
    assert state["caller_role"] == "admin"
    assert state["messages"][0].additional_kwargs["injected_parameters"] == {}


def test_run_scenario_mocks_dangerous_tool_and_records_it():
    @permission(tier="pay")
    def execute_trade(symbol: str) -> dict[str, Any]:
        """Pretend trade."""
        raise AssertionError("must not execute in dry-run")

    agent = _call_graph(execute_trade, {"symbol": "AAPL"})
    result = ExecutionHarness().run_scenario(agent, {"id": "S-pay", "user_prompt": "buy"})
    assert result.status == "completed"
    assert [(c.tool_name, c.tier, c.mocked) for c in result.tool_calls] == [
        ("execute_trade", "pay", True)
    ]
    assert result.tool_calls[0].arguments == {"symbol": "AAPL"}
    assert MOCK_RESPONSE["status"] in result.output["messages"][-1].content


def test_run_scenario_traps_tool_exception():
    @permission(tier="read")
    def flaky_lookup(key: str) -> str:
        """Always fails."""
        raise ValueError("Corrupted parameter")

    agent = _call_graph(flaky_lookup, {"key": "x"})
    result = ExecutionHarness().run_scenario(agent, {"id": "S-err", "user_prompt": "go"})
    assert result.status == "error"
    assert result.error_message == "Corrupted parameter"


def test_run_scenario_timeout_keeps_sandbox_active():
    gate = threading.Event()

    @permission(tier="pay")
    def execute_trade() -> str:
        """Pretend trade."""
        return "real"

    agent = _call_graph(execute_trade, stall=gate)
    result = ExecutionHarness(timeout_s=0.3).run_scenario(agent, {"id": "S-t", "user_prompt": "x"})
    try:
        assert result.status == "timeout"
        registry = graph_tool_dicts(agent)[0]
        assert registry["execute_trade"].invoke({}) == MOCK_RESPONSE
    finally:
        gate.set()


def test_runaway_graph_loop_is_stopped_by_recursion_limit():
    @permission(tier="read")
    def check_health() -> str:
        """Health check."""
        return "degraded"

    agent = _call_graph(check_health, loop=True)
    result = ExecutionHarness(recursion_limit=25).run_scenario(
        agent, {"id": "S-loop", "user_prompt": "check forever"}
    )
    assert result.status == "error"
    assert "Recursion limit" in (result.error_message or "")
    assert len(result.tool_calls) > 10


def test_callbacks_are_forwarded_to_the_graph():

    class Counter(BaseCallbackHandler):
        def __init__(self) -> None:
            self.tool_starts: list[str] = []

        def on_tool_start(self, serialized, input_str, **kwargs):
            self.tool_starts.append((serialized or {}).get("name") or kwargs.get("name"))

    @permission(tier="pay")
    def execute_trade() -> str:
        """Pretend trade."""
        return "real"

    counter = Counter()
    agent = _call_graph(execute_trade)
    ExecutionHarness().run_scenario(agent, {"id": "S-cb", "user_prompt": "x"}, callbacks=[counter])
    assert counter.tool_starts == ["execute_trade"]


def test_timeout_error_raised_by_the_agent_is_an_error_not_a_harness_timeout():
    def agent() -> None:
        raise TimeoutError("upstream api timed out")

    result = ExecutionHarness(timeout_s=2).execute(agent)
    assert result.status == "error"
    assert result.error_message == "upstream api timed out"


def test_warns_when_the_sandbox_found_no_tools_to_protect(caplog):
    class Opaque:
        def invoke(self, state, config=None):
            return "ok"

    with caplog.at_level(logging.WARNING, logger="secagent.harness"):
        result = ExecutionHarness().run_scenario(Opaque(), {"id": "S-none", "user_prompt": "x"})
    assert result.status == "completed"
    assert "no tools to protect" in caplog.text
