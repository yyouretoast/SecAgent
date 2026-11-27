from typing import Any

import pytest
from langgraph.graph import END, START, StateGraph

import examples.finance_agent.agent as finance
import examples.multi_agent_ops.agent as ops
from secagent.agent.state import AgentState
from secagent.harness import ExecutionHarness
from secagent.harness.introspector import discover_tools, tool_name
from secagent.harness.scripted import build_scripted_agent
from secagent.harness.threat_router import route_threat_model
from secagent.harness.topology import (
    SIGNAL_DELEGATION,
    SIGNAL_MULTIPLE_AGENTS,
    SIGNAL_SHARED_TOOLS,
    classify_topology,
)

REFUND = {"customer_id": "c_1", "amount_usd": 40.0, "reason": "duplicate charge"}
RESTART = {"server_id": "srv_7"}


def run(agent, tool, params=None, approved=False, context="ops_request"):
    scenario = {
        "id": f"OPS-{tool}",
        "user_prompt": f"Please run {tool}",
        "target_tool": tool,
        "approval_granted": approved,
        "task_context": context,
        "injected_parameters": params or {},
    }
    return ExecutionHarness().run_scenario(agent, scenario, ops)


def calls(result):
    return [(c.tool_name, c.mocked) for c in result.tool_calls]


@pytest.mark.parametrize("agent", [ops.app, ops.vulnerable_app], ids=["app", "vulnerable_app"])
def test_both_variants_are_classified_multi_agent(agent):
    profile = classify_topology(agent)
    assert profile.kind == "multi_agent"
    assert profile.agent_nodes == ("billing_worker", "ops_worker")
    assert profile.supervisors == ("supervisor",)
    assert profile.shared_tools == ("memory_read",)
    assert profile.signals == (SIGNAL_MULTIPLE_AGENTS, SIGNAL_DELEGATION, SIGNAL_SHARED_TOOLS)


def test_auto_routes_the_fixture_to_maestro_and_finance_to_owasp():
    assert route_threat_model(classify_topology(ops.app), "auto").route == "maestro"
    assert route_threat_model(classify_topology(finance.app), "auto").route == "owasp"


def test_explicit_override_beats_the_fixture_topology():
    assert route_threat_model(classify_topology(ops.app), "owasp").route == "owasp"
    assert route_threat_model(classify_topology(finance.app), "maestro").route == "maestro"


def test_discovery_finds_tools_inside_worker_subgraphs():
    names = {tool_name(t) for t in discover_tools(ops.app, ops)}
    assert names == {
        "check_service_health",
        "restart_server",
        "get_account_balance",
        "issue_refund",
        "memory_read",
    }


def test_safe_agent_runs_mocked_refund_after_approval():
    result = run(ops.app, "issue_refund", REFUND, approved=True)
    assert result.status == "completed"
    assert calls(result) == [("issue_refund", True)]
    assert result.tool_calls[0].arguments == REFUND


def test_safe_agent_runs_mocked_restart_after_approval():
    result = run(ops.app, "restart_server", RESTART, approved=True)
    assert calls(result) == [("restart_server", True)]


@pytest.mark.parametrize(
    ("tool", "params"), [("issue_refund", REFUND), ("restart_server", RESTART)]
)
def test_safe_agent_blocks_privileged_tools_when_approval_is_denied(tool, params):
    result = run(ops.app, tool, params, approved=False)
    assert result.tool_calls == []
    assert result.output["error"] == "approval denied"


@pytest.mark.parametrize(
    ("tool", "params"), [("issue_refund", REFUND), ("restart_server", RESTART)]
)
def test_vulnerable_agent_skips_approval_but_still_mocks(tool, params):
    result = run(ops.vulnerable_app, tool, params, approved=False)
    assert calls(result) == [(tool, True)]


def test_safe_agent_refuses_payment_in_a_general_inquiry_context():
    safe = run(ops.app, "issue_refund", REFUND, approved=True, context="general_inquiry")
    assert safe.tool_calls == []
    unsafe = run(
        ops.vulnerable_app, "issue_refund", REFUND, approved=True, context="general_inquiry"
    )
    assert calls(unsafe) == [("issue_refund", True)]


@pytest.mark.parametrize(
    ("tool", "params"),
    [
        ("check_service_health", {"service_name": "api"}),
        ("get_account_balance", {"account_id": "acc_1"}),
        ("memory_read", {"key": "notes"}),
    ],
)
def test_read_tools_run_for_real_through_either_worker(tool, params):
    result = run(ops.app, tool, params)
    assert result.status == "completed"
    assert calls(result) == [(tool, False)]


def test_unknown_intent_makes_no_tool_call():
    result = run(ops.app, "does_not_exist")
    assert result.status == "completed"
    assert result.tool_calls == []


def test_sandbox_mocks_tools_in_the_second_of_two_identical_workers():
    """Two workers with identical tool sets must both be virtualised, not just the first."""

    def delegate(state: AgentState) -> str:
        return "second"

    def supervisor(state: AgentState) -> dict[str, Any]:
        return {}

    graph = StateGraph(AgentState)
    graph.add_node("supervisor", supervisor)
    graph.add_node("first", build_scripted_agent([ops.issue_refund]))
    graph.add_node("second", build_scripted_agent([ops.issue_refund]))
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", delegate, ["first", "second"])
    graph.add_edge("first", END)
    graph.add_edge("second", END)

    result = run(graph.compile(), "issue_refund", REFUND, approved=True)
    assert calls(result) == [("issue_refund", True)]
