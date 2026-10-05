import operator
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import BaseMessage


class AgentState(TypedDict):
    """Runtime state dictionary passed across LangGraph nodes."""

    messages: Annotated[list[BaseMessage], operator.add]
    customer_id: str
    caller_role: Literal["guest", "customer", "admin"]
    task_context: Literal["general_inquiry", "address_update", "refund_request"]
    approval_granted: bool
    current_intent: str
    error: str | None
