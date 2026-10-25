"""Tests for tool discovery and tier resolution (US-1.1, US-1.2)."""

import logging
import sys
from pathlib import Path

import pytest
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from secagent.agent.state import AgentState
from secagent.generator import ScenarioGenerator
from secagent.harness import (
    BASELINE_TOOLS,
    HarnessLoadError,
    discover_tools,
    introspect_entrypoint,
    introspect_tools,
    load_policy_overrides,
    resolve_permission_tier,
)
from secagent.sdk import permission

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

POLICY_PATH = ROOT / "policies" / "security_rules.yaml"


def test_override_beats_name_heuristic():
    assert resolve_permission_tier("drop_database", overrides={"drop_database": "admin"}) == "admin"
    assert resolve_permission_tier("quick_refund", overrides={"quick_refund": "read"}) == "read"


def test_decorator_beats_override():
    assert resolve_permission_tier("x_tool", "pure", {"x_tool": "admin"}) == "pure"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("quick_refund", "pay"),
        ("execute_trade", "pay"),
        ("restart_server", "admin"),
        ("update_profile", "write"),
        ("fetch_url", "net"),
        ("calculate_tax", "pure"),
        ("get_stock_quote", "read"),
        ("totally_unknown", "read"),
    ],
)
def test_semantic_name_fallback(name, expected):
    assert resolve_permission_tier(name) == expected


@pytest.mark.parametrize("name", ["quick_refund", "restart_server", "fetch_url", "get_x", "calc_y"])
def test_tier_resolution_matches_generator_implementation(name):
    """Guards against the two copies of the heuristic drifting apart."""
    assert resolve_permission_tier(name) == ScenarioGenerator._infer_permission_tier(name)


def test_policy_overrides_load_from_yaml():
    overrides = load_policy_overrides(POLICY_PATH)
    assert overrides["drop_database"] == "admin"
    assert overrides["execute_trade"] == "pay"
    assert load_policy_overrides(ROOT / "does_not_exist.yaml") == {}


def _graph_with_tools(tools):
    graph = StateGraph(AgentState)
    graph.add_node("tools", ToolNode(tools))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile()


def test_discover_tools_in_langgraph_graph_without_running_it():
    ran: list[str] = []

    @permission(tier="admin")
    def drop_database(name: str) -> str:
        """Dangerous."""
        ran.append(name)
        return "dropped"

    graph = _graph_with_tools([drop_database])
    names = {getattr(t, "name", None) for t in discover_tools(graph)}
    assert names == {"drop_database"}
    assert ran == [], "discovery must never execute the agent or its tools"


def test_discover_tools_in_module():
    import examples.finance_agent.agent as finance

    names = {getattr(t, "__name__", None) or t.name for t in discover_tools(finance)}
    assert {"get_stock_quote", "execute_trade"} <= names


def test_discover_tools_direct_attribute_and_getter():
    class WithAttr:
        tools = [lambda: None]

    class WithGetter:
        def get_tools(self):
            return [permission(tier="read")(lambda: None)]

    assert len(discover_tools(WithAttr())) == 1
    assert len(discover_tools(WithGetter())) == 1
    assert discover_tools(object()) == []


def test_introspect_tools_reports_tiers_from_decorator():
    import examples.support_agent.agent as support

    infos = {i.name: i for i in introspect_tools(discover_tools(support))}
    assert infos["query_db"].permission_tier == "read"
    assert infos["modify_user"].permission_tier == "write"
    assert infos["issue_refund"].permission_tier == "pay"
    assert "fields" in infos["query_db"].parameters


def test_bad_entrypoint_falls_back_to_baseline_with_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="secagent.harness"):
        infos = introspect_entrypoint("invalid_mod:missing_app", on_error="fallback")

    assert [i.name for i in infos] == [t.name for t in BASELINE_TOOLS]
    assert "invalid_mod:missing_app" in caplog.text


def test_good_entrypoint_discovers_real_tools():
    infos = introspect_entrypoint("examples.devops_agent.agent", POLICY_PATH)
    assert {i.name: i.permission_tier for i in infos} == {
        "check_service_health": "read",
        "restart_server": "admin",
    }


def test_bad_entrypoint_raises_by_default():
    """A typo in --agent must stop the run, not silently test fake baseline tools."""
    with pytest.raises(HarnessLoadError, match="invalid_mod"):
        introspect_entrypoint("invalid_mod:missing_app")


def test_agent_without_tools_raises_by_default_and_can_fall_back():
    with pytest.raises(HarnessLoadError, match="no tools"):
        introspect_entrypoint("secagent.sdk")
    infos = introspect_entrypoint("secagent.sdk", on_error="fallback")
    assert [i.name for i in infos] == [t.name for t in BASELINE_TOOLS]


def test_policy_override_with_invalid_tier_is_rejected(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("tool_tier_overrides:\n  drop_database: admn\n", encoding="utf-8")
    with pytest.raises(HarnessLoadError, match="admn"):
        load_policy_overrides(rules)
