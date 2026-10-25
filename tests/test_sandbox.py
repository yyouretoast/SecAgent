import asyncio
import types
from typing import Any

import pytest
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from secagent.agent.state import AgentState
from secagent.harness import MOCK_RESPONSE, VirtualizedToolWrapper
from secagent.harness.introspector import graph_tool_dicts
from secagent.sdk import permission


def test_dry_run_blocks_pay_tool_and_records_call():
    executed: list[str] = []

    @permission(tier="pay")
    def execute_trade(symbol: str, quantity: int) -> dict[str, Any]:
        executed.append(symbol)
        return {"status": "filled"}

    sandbox = VirtualizedToolWrapper()
    wrapped = sandbox.wrap_callable(execute_trade)
    assert wrapped("AAPL", quantity=5) == MOCK_RESPONSE
    assert executed == [], "real function body must not run in dry-run"
    call = sandbox.calls[0]
    assert (call.tool_name, call.tier, call.mocked) == ("execute_trade", "pay", True)
    assert call.arguments == {"symbol": "AAPL", "quantity": 5}


@pytest.mark.parametrize("tier", ["pay", "admin", "write", "net"])
def test_every_risky_tier_is_mocked(tier):
    @permission(tier=tier)
    def risky() -> str:
        raise AssertionError("must not execute")

    assert VirtualizedToolWrapper().wrap_callable(risky)() == MOCK_RESPONSE


@pytest.mark.parametrize("tier", ["read", "pure"])
def test_safe_tiers_run_for_real_but_are_recorded(tier):
    @permission(tier=tier)
    def get_stock_quote(symbol: str) -> dict[str, Any]:
        return {"price": 1.0}

    sandbox = VirtualizedToolWrapper()
    assert sandbox.wrap_callable(get_stock_quote)("AAPL") == {"price": 1.0}
    assert sandbox.calls[0].mocked is False


def test_mock_response_is_a_fresh_copy_each_time():
    @permission(tier="pay")
    def pay() -> None: ...

    wrapped = VirtualizedToolWrapper().wrap_callable(pay)
    first = wrapped()
    first["status"] = "tampered"
    assert wrapped() == MOCK_RESPONSE
    assert MOCK_RESPONSE["status"] == "mock_success"


def test_dry_run_can_be_disabled():
    @permission(tier="pay")
    def pay() -> str:
        return "real"

    assert VirtualizedToolWrapper(dry_run=False).wrap_callable(pay)() == "real"


def test_policy_override_makes_untagged_tool_mocked():
    def drop_database() -> str:
        return "real"

    sandbox = VirtualizedToolWrapper(overrides={"drop_database": "admin"})
    assert sandbox.wrap_callable(drop_database)() == MOCK_RESPONSE


def test_async_tools_are_mocked_too():
    @permission(tier="admin")
    async def restart() -> str:
        raise AssertionError("must not execute")

    assert asyncio.run(VirtualizedToolWrapper().wrap_callable(restart)()) == MOCK_RESPONSE


def test_wrapping_twice_does_not_stack_wrappers():
    @permission(tier="pay")
    def pay() -> str:
        return "real"

    sandbox = VirtualizedToolWrapper()
    twice = sandbox.wrap_callable(sandbox.wrap_callable(pay))
    assert twice() == MOCK_RESPONSE
    assert len(sandbox.calls) == 1


def _graph_with_tools(tools):
    graph = StateGraph(AgentState)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def test_virtualize_patches_graph_and_restores_afterwards():
    @permission(tier="pay")
    def execute_trade(symbol: str) -> dict[str, Any]:
        """Pretend trade."""
        return {"status": "filled"}

    graph = _graph_with_tools([execute_trade])
    registry = graph_tool_dicts(graph)[0]
    args = {"symbol": "AAPL"}
    assert registry["execute_trade"].invoke(args)["status"] == "filled"  # real, before

    sandbox = VirtualizedToolWrapper()
    with sandbox.virtualize(graph):
        assert registry["execute_trade"].invoke(args) == MOCK_RESPONSE  # mocked, inside
    assert registry["execute_trade"].invoke(args)["status"] == "filled"  # restored, after
    assert [c.tool_name for c in sandbox.calls] == ["execute_trade"]


def test_virtualize_patches_module_functions_and_restores():
    @permission(tier="admin")
    def restart_server() -> str:
        return "real"

    fake_module = types.ModuleType("fake_agent_module")
    fake_module.restart_server = restart_server
    sandbox = VirtualizedToolWrapper()
    with sandbox.virtualize(fake_module, fake_module):
        assert fake_module.restart_server() == MOCK_RESPONSE
    assert fake_module.restart_server() == "real"


def test_virtualize_patches_a_tools_list_in_place():
    @permission(tier="pay")
    def pay() -> str:
        return "real"

    class Agent:
        tools = [pay]

    agent = Agent()
    sandbox = VirtualizedToolWrapper()
    with sandbox.virtualize(agent):
        assert agent.tools[0]() == MOCK_RESPONSE
    assert agent.tools[0]() == "real"


def test_custom_basetool_subclass_is_mocked_and_recorded():
    """A BaseTool that implements _run itself (no func/coroutine) must not run for real."""
    real = {"n": 0}

    class TransferFunds(BaseTool):
        name: str = "transfer_funds"
        description: str = "Move money."

        def _run(self, amount: int = 0) -> str:
            real["n"] += 1
            return "REAL TRANSFER"

    graph = _graph_with_tools([TransferFunds()])
    registry = graph_tool_dicts(graph)[0]
    sandbox = VirtualizedToolWrapper()
    with sandbox.virtualize(graph):
        assert registry["transfer_funds"].invoke({"amount": 5}) == MOCK_RESPONSE
    assert real["n"] == 0
    assert [(c.tool_name, c.tier, c.mocked) for c in sandbox.calls] == [
        ("transfer_funds", "pay", True)
    ]
    assert registry["transfer_funds"].invoke({"amount": 5}) == "REAL TRANSFER"  # restored


def test_virtualize_reports_which_tools_it_covered():
    @permission(tier="pay")
    def execute_trade(symbol: str) -> dict[str, Any]:
        """Pretend trade."""
        return {"status": "filled"}

    sandbox = VirtualizedToolWrapper()
    with sandbox.virtualize(_graph_with_tools([execute_trade])):
        assert sandbox.patched == ["execute_trade"]
