"""Deterministic (zero-LLM) LangGraph agents used as reference fixtures (US-1.5).
The planner is plain Python: it reads the scenario from the graph state and decides which
tool to call. That keeps CI deterministic (no API keys, no flakiness) while still running
through a real LangGraph graph + ToolNode, so callbacks and introspection behave like they
would on a production agent.
Graph shape::
    START -> planner -> [approval_gate] -> tools -> (planner | END)
"""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable
from typing import Any

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode

from secagent.agent.state import AgentState
from secagent.harness.introspector import explicit_tier_of, resolve_permission_tier

GATED_TIERS = ("pay", "admin")
CONTEXT_FORBIDDEN_TIERS = ("write", "pay")
LOOP_WORDS = ("repeatedly", "indefinitely", "until the flag")
SAFE_REPEAT_LIMIT = 2


def _default_for(annotation: Any) -> Any:
    origin = typing.get_origin(annotation) or annotation
    if origin is list:
        return ["name"]
    if origin is dict:
        return {}
    if origin is bool:
        return True
    if origin is int:
        return 1
    if origin is float:
        return 1.0
    return "test"


def _coerce(value: Any, annotation: Any) -> Any:
    """Make an injected payload fit the parameter type so the tool body is reached."""
    origin = typing.get_origin(annotation) or annotation
    if origin is list:
        return value if isinstance(value, list) else [value]
    if origin in (int, float, bool, dict):
        return value if isinstance(value, origin) else _default_for(annotation)
    return value if isinstance(value, str) else str(value)


def build_tool_args(fn: Callable[..., Any], injected: dict[str, Any]) -> dict[str, Any]:
    """Arguments for ``fn``: injected values (type-coerced) where given, defaults elsewhere."""
    args: dict[str, Any] = {}
    for param in inspect.signature(fn).parameters.values():
        annotation = param.annotation if param.annotation is not inspect.Parameter.empty else str
        if param.name in injected:
            args[param.name] = _coerce(injected[param.name], annotation)
        else:
            args[param.name] = _default_for(annotation)
    return args


def build_scripted_agent(
    functions: list[Callable[..., Any]],
    *,
    vulnerable: bool = False,
    loop_tool: str | None = None,
) -> Any:
    """Compile a deterministic agent exposing ``functions`` as tools.

    Safe behaviours (all disabled when ``vulnerable=True``):
      * pay/admin tools are routed through ``approval_gate`` first (POL-ASI03-001)
      * write/pay tools are refused when ``task_context == 'general_inquiry'`` (POL-ASI03-002)
      * a loop is stopped after ``SAFE_REPEAT_LIMIT`` calls to ``loop_tool`` (POL-ASI08-001)
    """
    by_name = {fn.__name__: fn for fn in functions}
    tiers = {
        name: resolve_permission_tier(name, explicit_tier_of(fn)) for name, fn in by_name.items()
    }

    def planner(state: AgentState) -> dict[str, Any]:
        intent = state["current_intent"]
        first = state["messages"][0]
        prompt = str(first.content).lower()
        injected = dict(getattr(first, "additional_kwargs", {}).get("injected_parameters", {}))
        done_calls = sum(isinstance(m, ToolMessage) for m in state["messages"])

        wants_loop = loop_tool is not None and any(word in prompt for word in LOOP_WORDS)
        if wants_loop:
            intent = loop_tool or intent
            if not vulnerable and done_calls >= SAFE_REPEAT_LIMIT:
                return {"messages": [AIMessage(content="Stopping: retry limit reached.")]}
        elif done_calls > 0:  # one-shot agents finish after their single tool call
            return {"messages": [AIMessage(content="Done.")]}

        if intent not in by_name:
            return {"messages": [AIMessage(content="No matching tool; nothing to do.")]}
        if (
            not vulnerable
            and state["task_context"] == "general_inquiry"
            and tiers[intent] in CONTEXT_FORBIDDEN_TIERS
        ):
            return {"messages": [AIMessage(content="Refused: not allowed in this context.")]}

        call = {
            "name": intent,
            "args": build_tool_args(by_name[intent], injected),
            "id": f"call_{done_calls}",
        }
        return {"messages": [AIMessage(content="", tool_calls=[call])]}

    def approval_gate(state: AgentState) -> dict[str, Any]:
        """Simulated human approver: the scenario decides (state['approval_granted'])."""
        if state["approval_granted"]:
            return {}
        return {"error": "approval denied", "messages": [AIMessage(content="Approval denied.")]}

    def after_planner(state: AgentState) -> str:
        last = state["messages"][-1]
        calls = getattr(last, "tool_calls", None)
        if not calls:
            return END
        gated = tiers.get(calls[0]["name"]) in GATED_TIERS and not vulnerable
        return "approval_gate" if gated else "tools"

    def after_gate(state: AgentState) -> str:
        return "tools" if state["approval_granted"] else END

    def after_tools(state: AgentState) -> str:
        return "planner" if loop_tool else END

    graph = StateGraph(AgentState)
    graph.add_node("planner", planner)
    graph.add_node("approval_gate", approval_gate)
    graph.add_node("tools", ToolNode(functions))
    graph.add_edge(START, "planner")
    graph.add_conditional_edges("planner", after_planner, ["approval_gate", "tools", END])
    graph.add_conditional_edges("approval_gate", after_gate, ["tools", END])
    graph.add_conditional_edges("tools", after_tools, ["planner", END])
    return graph.compile()


__all__ = ["build_scripted_agent", "build_tool_args"]
