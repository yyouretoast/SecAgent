from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph

from secagent.agent.state import AgentState
from secagent.harness.scripted import build_scripted_agent
from secagent.sdk import permission


@permission(tier="read")
def check_service_health(service_name: str) -> dict[str, Any]:
    """Inspect status of a target service."""
    return {"service": service_name, "status": "degraded", "uptime_sec": 1420}


@permission(tier="admin")
def restart_server(server_id: str) -> dict[str, Any]:
    """Admin command requiring approval."""
    return {"server_id": server_id, "action": "restarted", "status": "ok"}


@permission(tier="read")
def get_account_balance(account_id: str) -> dict[str, Any]:
    """Retrieve the cash balance of an account."""
    return {"account_id": account_id, "balance_usd": 12500.00}


@permission(tier="pay")
def issue_refund(customer_id: str, amount_usd: float, reason: str) -> dict[str, Any]:
    """Financial transaction requiring the human approval gate."""
    return {
        "customer_id": customer_id,
        "amount_usd": amount_usd,
        "reason": reason,
        "status": "processed",
    }


@permission(tier="read")
def memory_read(key: str) -> dict[str, Any]:
    """Read from the memory shared by both worker agents."""
    return {"key": key, "value": "note"}


OPS_WORKER = "ops_worker"
BILLING_WORKER = "billing_worker"

_OPS_TOOLS = [check_service_health, restart_server, memory_read]
_BILLING_TOOLS = [get_account_balance, issue_refund, memory_read]
_OPS_INTENTS = frozenset({"check_service_health", "restart_server", "memory_read"})
_BILLING_INTENTS = frozenset({"get_account_balance", "issue_refund"})


def _supervisor(state: AgentState) -> dict[str, Any]:
    """Pure router node: the delegation decision is made by ``_delegate`` below."""
    return {}


def _delegate(state: AgentState) -> str:
    """Send the request to the worker that owns the intent (``memory_read`` goes to ops)."""
    intent = state["current_intent"]
    if intent in _OPS_INTENTS:
        return OPS_WORKER
    if intent in _BILLING_INTENTS:
        return BILLING_WORKER
    return END


def build_multi_agent_ops(*, vulnerable: bool = False) -> Any:
    """Compile the supervisor + workers graph; ``vulnerable`` disables each worker's safeguards."""
    graph = StateGraph(AgentState)
    graph.add_node("supervisor", _supervisor)
    graph.add_node(OPS_WORKER, build_scripted_agent(_OPS_TOOLS, vulnerable=vulnerable))
    graph.add_node(BILLING_WORKER, build_scripted_agent(_BILLING_TOOLS, vulnerable=vulnerable))
    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges("supervisor", _delegate, [OPS_WORKER, BILLING_WORKER, END])
    graph.add_edge(OPS_WORKER, END)
    graph.add_edge(BILLING_WORKER, END)
    return graph.compile()


app = build_multi_agent_ops()
vulnerable_app = build_multi_agent_ops(vulnerable=True)
