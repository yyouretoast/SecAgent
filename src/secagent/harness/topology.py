from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

logger = logging.getLogger("secagent.harness")

AGENT_METADATA_KEY = "secagent_agent"

SIGNAL_MULTIPLE_AGENTS = "multiple_agent_nodes"
SIGNAL_DELEGATION = "supervisor_delegation"
SIGNAL_HANDOFF = "agent_handoff"
SIGNAL_SHARED_TOOLS = "shared_tools"
SIGNAL_SHARED_MEMORY = "shared_memory"

TopologyKind = Literal["single_agent", "multi_agent"]

_BOUNDARY_NODES = frozenset({"__start__", "__end__"})


@dataclass(frozen=True)
class TopologyProfile:
    kind: TopologyKind
    agent_nodes: tuple[str, ...] = ()
    supervisors: tuple[str, ...] = ()
    handoffs: tuple[tuple[str, str], ...] = ()
    shared_tools: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    inspectable: bool = True

    @property
    def is_multi_agent(self) -> bool:
        return self.kind == "multi_agent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "inspectable": self.inspectable,
            "agent_nodes": list(self.agent_nodes),
            "supervisors": list(self.supervisors),
            "handoffs": [list(pair) for pair in self.handoffs],
            "shared_tools": list(self.shared_tools),
            "signals": list(self.signals),
        }


def _nodes_of(graph: Any) -> Mapping[str, Any]:
    nodes = getattr(graph, "nodes", None)
    return nodes if isinstance(nodes, Mapping) else {}


def _subgraphs_of(graph: Any) -> dict[str, Any]:
    """Immediate sub-graphs by node name (LangGraph's own detection, incl. closed-over ones)."""
    getter = getattr(graph, "get_subgraphs", None)
    if callable(getter):
        try:
            return {str(name): sub for name, sub in getter()}
        except Exception as exc:
            logger.debug("get_subgraphs() raised %r; falling back to node.subgraphs", exc)
    found: dict[str, Any] = {}
    for name, node in _nodes_of(graph).items():
        subs = getattr(node, "subgraphs", None)
        if subs:
            found[str(name)] = subs[0]
    return found


def _is_marked_agent(node: Any) -> bool:
    metadata = getattr(node, "metadata", None)
    return isinstance(metadata, Mapping) and bool(metadata.get(AGENT_METADATA_KEY))


def _tool_names(graph: Any) -> set[str]:
    names: set[str] = set()
    for node in _nodes_of(graph).values():
        for holder in (node, getattr(node, "bound", None)):
            tools_by_name = getattr(holder, "tools_by_name", None)
            if isinstance(tools_by_name, Mapping):
                names.update(str(name) for name in tools_by_name)
    return names


def _edges_of(graph: Any) -> list[tuple[str, str]]:
    """Declared edges between real nodes (``__start__`` / ``__end__`` excluded)."""
    try:
        raw_edges = graph.get_graph().edges
    except Exception as exc:
        logger.debug("get_graph() unavailable (%r); edge signals disabled", exc)
        return []
    pairs: set[tuple[str, str]] = set()
    for edge in raw_edges:
        source, target = getattr(edge, "source", None), getattr(edge, "target", None)
        if (
            isinstance(source, str)
            and isinstance(target, str)
            and source not in _BOUNDARY_NODES
            and target not in _BOUNDARY_NODES
        ):
            pairs.add((source, target))
    return sorted(pairs)


def classify_topology(target: Any) -> TopologyProfile:
    """Classify ``target`` as ``single_agent`` or ``multi_agent`` from observable signals."""
    nodes = _nodes_of(target)
    if not nodes:
        return TopologyProfile(kind="single_agent", inspectable=False)

    subgraphs = _subgraphs_of(target)
    agents = {name for name, node in nodes.items() if name in subgraphs or _is_marked_agent(node)}
    edges = _edges_of(target)

    targets_by_source: dict[str, set[str]] = {}
    for source, dest in edges:
        targets_by_source.setdefault(source, set()).add(dest)
    supervisors = sorted(
        source for source, dests in targets_by_source.items() if len(dests & agents) >= 2
    )
    handoffs = sorted((s, d) for s, d in edges if s in agents and d in agents and s != d)

    tool_counts = Counter(
        tool for agent in agents if agent in subgraphs for tool in _tool_names(subgraphs[agent])
    )
    shared_tools = sorted(tool for tool, count in tool_counts.items() if count >= 2)
    shared_memory = len(agents) >= 2 and getattr(target, "store", None) is not None

    signals: list[str] = []
    if len(agents) >= 2:
        signals.append(SIGNAL_MULTIPLE_AGENTS)
    if supervisors:
        signals.append(SIGNAL_DELEGATION)
    if handoffs:
        signals.append(SIGNAL_HANDOFF)
    if shared_tools:
        signals.append(SIGNAL_SHARED_TOOLS)
    if shared_memory:
        signals.append(SIGNAL_SHARED_MEMORY)

    return TopologyProfile(
        kind="multi_agent" if signals else "single_agent",
        agent_nodes=tuple(sorted(agents)),
        supervisors=tuple(supervisors),
        handoffs=tuple(handoffs),
        shared_tools=tuple(shared_tools),
        signals=tuple(signals),
    )


__all__ = [
    "AGENT_METADATA_KEY",
    "SIGNAL_DELEGATION",
    "SIGNAL_HANDOFF",
    "SIGNAL_MULTIPLE_AGENTS",
    "SIGNAL_SHARED_MEMORY",
    "SIGNAL_SHARED_TOOLS",
    "TopologyKind",
    "TopologyProfile",
    "classify_topology",
]
