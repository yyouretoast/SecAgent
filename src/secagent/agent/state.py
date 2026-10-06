import operator
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """Runtime state dictionary passed across LangGraph nodes."""

    messages: Annotated[list[BaseMessage], operator.add]
    user_id: str
    caller_role: str
    task_context: str
    approval_granted: bool
    current_intent: str
    error: str | None
