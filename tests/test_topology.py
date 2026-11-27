import json
import types
from typing import Any, NamedTuple

import pytest
from langgraph.graph import END, START, StateGraph

import examples.devops_agent.agent as devops
import examples.finance_agent.agent as finance
import examples.support_agent.agent as support
from secagent.agent.state import AgentState
from secagent.harness.scripted import build_scripted_agent
from secagent.harness.topology import (
    AGENT_METADATA_KEY,
    SIGNAL_DELEGATION,
    SIGNAL_HANDOFF,
    SIGNAL_MULTIPLE_AGENTS,
    SIGNAL_SHARED_MEMORY,
    SIGNAL_SHARED_TOOLS,
    TopologyProfile,
    classify_topology,
)
from secagent.sdk import permission


class Edge(NamedTuple):
    source: str
    target: str
    conditional: bool = False


class Drawable:
    def __init__(self, edges: list[Edge]) -> None:
        self.edges = edges


class Bound:
    def __init__(self, tools: tuple[str, ...]) -> None:
        self.tools_by_name = {name: object() for name in tools}


class Node:
    def __init__(
        self,
        *,
        subgraph: Any = None,
        tools: tuple[str, ...] = (),
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.subgraphs = [subgraph] if subgraph is not None else []
        self.bound = Bound(tools) if tools else None
        self.metadata = metadata


class Graph:
    def __init__(
        self,
        nodes: dict[str, Node],
        edges: list[Edge] | None = None,
        *,
        store: Any = None,
        drawable_error: bool = False,
    ) -> None:
        self.nodes = nodes
        self._edges = edges or []
        self.store = store
        self._drawable_error = drawable_error

    def get_graph(self) -> Drawable:
        if self._drawable_error:
            raise RuntimeError("cannot draw")
        return Drawable(self._edges)

    def get_subgraphs(self) -> Any:
        for name, node in self.nodes.items():
            if node.subgraphs:
                yield name, node.subgraphs[0]


class GraphWithoutSubgraphGetter(Graph):
    get_subgraphs = None  # type: ignore[assignment]


def worker(*tools: str) -> Graph:
    """A worker agent sub-graph that owns a tool node exposing ``tools``."""
    return Graph({"tools": Node(tools=tools)})


def single_agent_graph() -> Graph:
    nodes = {
        "__start__": Node(),
        "planner": Node(),
        "approval_gate": Node(),
        "tools": Node(tools=("execute_trade",)),
    }
    edges = [
        Edge("__start__", "planner"),
        Edge("planner", "approval_gate", True),
        Edge("planner", "tools", True),
        Edge("planner", "__end__", True),
        Edge("approval_gate", "tools", True),
        Edge("tools", "__end__"),
    ]
    return Graph(nodes, edges)


def team(
    *,
    handoff: bool = False,
    store: Any = None,
    billing_tools: tuple[str, ...] = ("lookup_account", "memory_read"),
    ops_tools: tuple[str, ...] = ("check_status", "memory_read"),
) -> Graph:
    nodes = {
        "__start__": Node(),
        "supervisor": Node(),
        "billing": Node(subgraph=worker(*billing_tools)),
        "ops": Node(subgraph=worker(*ops_tools)),
    }
    edges = [
        Edge("__start__", "supervisor"),
        Edge("supervisor", "billing", True),
        Edge("supervisor", "ops", True),
        Edge("billing", "__end__"),
        Edge("ops", "__end__"),
    ]
    if handoff:
        edges.append(Edge("billing", "ops"))
    return Graph(nodes, edges, store=store)


# ------------------------------------------------------------------- unit tests


@pytest.mark.parametrize("target", [object(), types.ModuleType("not_a_graph"), None])
def test_non_graph_targets_default_to_single_agent(target):
    profile = classify_topology(target)
    assert profile.kind == "single_agent"
    assert profile.inspectable is False
    assert profile.signals == ()
    assert not profile.is_multi_agent


def test_plain_single_agent_graph_has_no_signals():
    profile = classify_topology(single_agent_graph())
    assert profile.kind == "single_agent"
    assert profile.inspectable is True
    assert profile.agent_nodes == ()
    assert profile.signals == ()


def test_supervisor_with_two_worker_subgraphs_is_multi_agent():
    profile = classify_topology(team())
    assert profile.kind == "multi_agent"
    assert profile.is_multi_agent
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.supervisors == ("supervisor",)
    assert profile.handoffs == ()
    assert profile.signals == (SIGNAL_MULTIPLE_AGENTS, SIGNAL_DELEGATION, SIGNAL_SHARED_TOOLS)


def test_direct_agent_to_agent_edge_is_a_handoff():
    profile = classify_topology(team(handoff=True))
    assert profile.handoffs == (("billing", "ops"),)
    assert SIGNAL_HANDOFF in profile.signals


def test_agent_self_loop_is_not_a_handoff():
    nodes = {"billing": Node(subgraph=worker("a")), "ops": Node(subgraph=worker("b"))}
    profile = classify_topology(Graph(nodes, [Edge("billing", "billing", True)]))
    assert profile.handoffs == ()
    assert SIGNAL_HANDOFF not in profile.signals


def test_only_tools_exposed_by_two_or_more_agents_are_shared():
    profile = classify_topology(team())
    assert profile.shared_tools == ("memory_read",)

    disjoint = classify_topology(team(billing_tools=("a",), ops_tools=("b",)))
    assert disjoint.shared_tools == ()
    assert SIGNAL_SHARED_TOOLS not in disjoint.signals
    assert disjoint.is_multi_agent  # still two agents


def test_single_worker_subgraph_is_below_the_multi_agent_threshold():
    nodes = {"__start__": Node(), "supervisor": Node(), "worker": Node(subgraph=worker("t"))}
    edges = [Edge("__start__", "supervisor"), Edge("supervisor", "worker", True)]
    profile = classify_topology(Graph(nodes, edges))
    assert profile.kind == "single_agent"
    assert profile.agent_nodes == ("worker",)
    assert profile.signals == ()


def test_metadata_marked_function_nodes_count_as_agents():
    marked = {AGENT_METADATA_KEY: True}
    nodes = {
        "__start__": Node(),
        "billing": Node(metadata=marked),
        "ops": Node(metadata=marked),
    }
    profile = classify_topology(Graph(nodes, [Edge("billing", "ops")]))
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.handoffs == (("billing", "ops"),)
    assert profile.shared_tools == ()  # a function node exposes no inspectable tools
    assert profile.is_multi_agent


def test_falsy_or_unrelated_metadata_does_not_mark_an_agent():
    nodes = {
        "a": Node(metadata={AGENT_METADATA_KEY: False}),
        "b": Node(metadata={"other": True}),
        "c": Node(metadata=None),
    }
    assert classify_topology(Graph(nodes)).agent_nodes == ()


def test_shared_store_with_two_agents_signals_shared_memory():
    profile = classify_topology(team(store=object()))
    assert SIGNAL_SHARED_MEMORY in profile.signals


def test_store_alone_does_not_make_a_single_agent_multi_agent():
    graph = single_agent_graph()
    graph.store = object()
    profile = classify_topology(graph)
    assert profile.signals == ()
    assert profile.kind == "single_agent"


def test_start_and_end_edges_are_not_delegation():
    nodes = {
        "__start__": Node(),
        "billing": Node(subgraph=worker("a")),
        "ops": Node(subgraph=worker("b")),
    }
    edges = [Edge("__start__", "billing"), Edge("__start__", "ops")]
    profile = classify_topology(Graph(nodes, edges))
    assert profile.supervisors == ()
    assert SIGNAL_DELEGATION not in profile.signals
    assert profile.signals == (SIGNAL_MULTIPLE_AGENTS,)


def test_unavailable_edge_information_degrades_gracefully():
    graph = team()
    broken = Graph(graph.nodes, drawable_error=True)
    profile = classify_topology(broken)
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.supervisors == ()
    assert profile.handoffs == ()
    assert SIGNAL_MULTIPLE_AGENTS in profile.signals


def test_falls_back_to_node_subgraphs_without_get_subgraphs():
    base = team()
    graph = GraphWithoutSubgraphGetter(base.nodes, base._edges)
    profile = classify_topology(graph)
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.is_multi_agent


def test_profile_is_deterministic_and_json_serialisable():
    first = classify_topology(team(handoff=True, store=object()))
    second = classify_topology(team(handoff=True, store=object()))
    assert first == second
    payload = json.loads(json.dumps(first.to_dict()))
    assert payload["kind"] == "multi_agent"
    assert payload["agent_nodes"] == ["billing", "ops"]
    assert payload["handoffs"] == [["billing", "ops"]]
    assert payload["signals"] == list(first.signals)


def test_profile_is_immutable():
    profile = TopologyProfile(kind="single_agent")
    with pytest.raises(AttributeError):
        profile.kind = "multi_agent"  # type: ignore[misc]


# ------------------------------------------------------- real LangGraph graphs


@permission(tier="read")
def lookup_account(account_id: str) -> dict[str, Any]:
    """Look up an account."""
    return {"account_id": account_id}


@permission(tier="read")
def check_status(service: str) -> dict[str, Any]:
    """Check the status of a service."""
    return {"service": service, "status": "ok"}


@permission(tier="read")
def memory_read(key: str) -> dict[str, Any]:
    """Read from the memory shared by the agents."""
    return {"key": key, "value": None}


def _supervisor(state: AgentState) -> dict[str, Any]:
    return {}


def _route(state: AgentState) -> str:
    return "billing" if state["current_intent"] == "lookup_account" else "ops"


def _noop(state: AgentState) -> dict[str, Any]:
    return {}


@pytest.mark.parametrize(
    "app",
    [finance.app, finance.vulnerable_app, devops.app, devops.vulnerable_app],
)
def test_existing_single_agent_fixtures_stay_single_agent(app):
    profile = classify_topology(app)
    assert profile.kind == "single_agent"
    assert profile.signals == ()
    assert profile.inspectable is True


@pytest.mark.parametrize("attr", ["app", "vulnerable_app"])
def test_support_agent_graphs_stay_single_agent_once_exposed(attr):
    graph = getattr(support, attr, None)
    if graph is None:
        pytest.skip("support_agent exposes no :app/:vulnerable_app on this branch")
    profile = classify_topology(graph)
    assert profile.kind == "single_agent"
    assert profile.signals == ()
    assert profile.inspectable is True


def test_a_module_target_has_no_graph_to_inspect():
    profile = classify_topology(support)
    assert profile.kind == "single_agent"
    assert profile.inspectable is False
    assert profile.signals == ()


def test_real_supervisor_with_worker_subgraphs_is_multi_agent():
    graph = StateGraph(AgentState)
    graph.add_node("supervisor", _supervisor)
    graph.add_node("billing", build_scripted_agent([lookup_account, memory_read]))
    graph.add_node("ops", build_scripted_agent([check_status, memory_read]))
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", _route, ["billing", "ops"])
    graph.add_edge("billing", END)
    graph.add_edge("ops", END)

    profile = classify_topology(graph.compile())

    assert profile.kind == "multi_agent"
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.supervisors == ("supervisor",)
    assert profile.shared_tools == ("memory_read",)
    assert profile.signals == (SIGNAL_MULTIPLE_AGENTS, SIGNAL_DELEGATION, SIGNAL_SHARED_TOOLS)


def test_real_marked_function_nodes_are_agents_with_a_handoff():
    graph = StateGraph(AgentState)
    graph.add_node("billing", _noop, metadata={AGENT_METADATA_KEY: True})
    graph.add_node("ops", _noop, metadata={AGENT_METADATA_KEY: True})
    graph.add_edge(START, "billing")
    graph.add_edge("billing", "ops")
    graph.add_edge("ops", END)

    profile = classify_topology(graph.compile())

    assert profile.kind == "multi_agent"
    assert profile.agent_nodes == ("billing", "ops")
    assert profile.handoffs == (("billing", "ops"),)
