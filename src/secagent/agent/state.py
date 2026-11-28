import operator
from typing import Annotated, Any, TypedDict

try:
    from langchain_core.messages import BaseMessage
except ImportError:  # pragma: no cover - optional langgraph extra
    BaseMessage = Any  # type: ignore[misc,assignment]


class AgentState(TypedDict):
    """Runtime state dictionary passed across LangGraph nodes."""

    messages: Annotated[list[BaseMessage], operator.add]
    user_id: str
    caller_role: str
    task_context: str
    approval_granted: bool
    current_intent: str
    error: str | None
