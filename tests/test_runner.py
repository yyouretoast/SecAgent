import json
import logging
import threading
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.messages import AIMessage
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from secagent.agent.state import AgentState
from secagent.harness import (
    MOCK_RESPONSE,
    ExecutionHarness,
    VirtualizedToolWrapper,
    build_initial_state,
)
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


def test_system_exit_is_captured_as_harness_error():
    def exit_agent() -> None:
        raise SystemExit(7)

    result = ExecutionHarness().execute(exit_agent)
    assert result.status == "error"
    assert result.error_message == "SystemExit: 7"


def test_strict_sandbox_raises_when_no_tools_are_patched():
    import pytest

    from secagent.harness import SandboxError

    class Opaque:
        def invoke(self, state, config=None):
            return "ok"

    with pytest.raises(SandboxError, match="no tools to protect"):
        ExecutionHarness(strict_sandbox=True).run_scenario(
            Opaque(), {"id": "S-strict", "user_prompt": "x"}
        )


def test_harness_supports_checkpointer_memory_saver_and_interrupt():
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.types import interrupt

    @permission(tier="pay")
    def execute_trade(symbol: str) -> dict[str, str]:
        """Execute a trade."""
        return {"symbol": symbol}

    def gate_node(state: AgentState) -> dict[str, Any]:
        decision = interrupt({"operation": "execute_trade", "question": "Approve trade?"})
        return {"approval_granted": bool(decision)}

    graph = StateGraph(AgentState)
    graph.add_node("approval_gate", gate_node)
    graph.add_node("tools", ToolNode([execute_trade]))
    graph.add_edge(START, "approval_gate")
    graph.add_edge("approval_gate", END)
    compiled = graph.compile(checkpointer=MemorySaver())

    result = ExecutionHarness(strict_sandbox=True).run_scenario(
        compiled, {"id": "S-ckpt", "user_prompt": "Buy AAPL"}
    )
    assert result.status == "completed"
    assert "__interrupt__" in result.output


def test_harness_falls_back_to_ainvoke_for_async_only_targets():
    @permission(tier="pay")
    async def async_pay(amount: float) -> dict[str, float]:
        return {"amount": amount}

    class AsyncOnlyAgent:
        tools = [async_pay]

        async def ainvoke(self, state: dict[str, Any], config: dict[str, Any] | None = None):
            out = await self.tools[0](50.0)
            return {
                "res": out,
                "thread_id": (config or {}).get("configurable", {}).get("thread_id"),
            }

    result = ExecutionHarness(strict_sandbox=True).run_scenario(
        AsyncOnlyAgent(), {"id": "S-async", "user_prompt": "pay 50"}
    )
    assert result.status == "completed"
    assert result.output["res"] == MOCK_RESPONSE
    assert result.output["thread_id"].startswith("secagent-S-async-")


def test_double_wrapped_unclassified_basetool_stays_mocked_and_restore_works():
    from langchain_core.tools import StructuredTool

    ran: list[str] = []

    def mystery_action(x: str) -> str:
        """Mystery tool."""
        ran.append(x)
        return f"LIVE:{x}"

    st = StructuredTool.from_function(func=mystery_action, name="mystery_action")
    w1 = VirtualizedToolWrapper(mock_unclassified=True)
    st1 = w1.wrap(st)
    assert st1.invoke({"x": "a"}) == MOCK_RESPONSE
    w2 = VirtualizedToolWrapper(mock_unclassified=True)
    st2 = w2.wrap(st1)
    assert st2.invoke({"x": "b"}) == MOCK_RESPONSE
    assert ran == []


def test_virtualize_keep_patched_restore_and_clean_subsequent_scenario():
    class Holder:
        def __init__(self, tools):
            self.tools = tools

    def lookup(x: str) -> str:
        return f"ok:{x}"

    holder = Holder([lookup])
    w1 = VirtualizedToolWrapper(dry_run=True, taint_read_outputs="TAINT1")
    with w1.virtualize(holder):
        w1.keep_patched = True
    # Scenario 2 wraps holder cleanly without inheriting TAINT1
    w2 = VirtualizedToolWrapper(dry_run=True)
    with w2.virtualize(holder):
        assert holder.tools[0]("hi") == "ok:hi"
    # After w2 exits, original lookup is restored
    assert holder.tools[0] is lookup
    w1.restore()


@pytest.mark.asyncio
async def test_harness_execute_works_inside_running_event_loop():
    harness = ExecutionHarness(timeout_s=2.0)
    res = harness.execute(lambda: "from-loop", scenario_id="S-loop")
    assert res.status == "completed"
    assert res.output == "from-loop"


def test_strict_sandbox_handles_set_alias_and_subgraph_tools():
    import types

    @permission(tier="pay")
    def orig_pay(x: str = "a") -> str:
        return f"LIVE:{x}"

    # 1. set container on agent
    class SetAgent:
        tools = {orig_pay}

        def invoke(self, state, config=None):
            tool = next(iter(self.tools))
            return {"res": tool("set")}

    res_set = ExecutionHarness(dry_run=True, strict_sandbox=True).run_scenario(
        SetAgent(), {"id": "S-set"}
    )
    assert res_set.status == "completed"
    assert res_set.output["res"] == MOCK_RESPONSE

    # 2. module alias pointing to orig_pay
    fake_mod = types.ModuleType("alias_mod")
    fake_mod.aliased_pay = orig_pay  # type: ignore[attr-defined]

    class AliasAgent:
        def invoke(self, state, config=None):
            return {"res": fake_mod.aliased_pay("alias")}

    res_alias = ExecutionHarness(dry_run=True, strict_sandbox=True).run_scenario(
        AliasAgent(), {"id": "S-alias"}, mod=fake_mod
    )
    assert res_alias.status == "completed"
    assert res_alias.output["res"] == MOCK_RESPONSE

    # 3. LangGraph nested subgraph ToolNode
    @permission(tier="admin")
    def sub_nuke(x: str) -> str:
        """Subgraph nuke."""
        return f"NUKED:{x}"

    sub = _call_graph(sub_nuke, args={"x": "prod"})
    sub_compiled = sub

    parent = StateGraph(AgentState)
    parent.add_node("sub", sub_compiled)
    parent.add_edge(START, "sub")
    parent.add_edge("sub", END)
    parent_compiled = parent.compile()

    res_sub = ExecutionHarness(dry_run=True, strict_sandbox=True).run_scenario(
        parent_compiled,
        {
            "id": "S-sub",
            "target_tool": "sub_nuke",
            "user_prompt": "run sub",
        },
    )
    assert res_sub.status == "completed", res_sub.error_message
    assert [c.tool_name for c in res_sub.tool_calls] == ["sub_nuke"]
    assert res_sub.tool_calls[0].mocked is True
    assert sub_nuke("live") == "NUKED:live"
