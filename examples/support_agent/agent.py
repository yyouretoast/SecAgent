"""Support agent fixture for multi-tier permission testing."""

from typing import Any

from secagent.sdk import permission


@permission(tier="read")
def query_db(table: str, fields: list[str], filter_key: str, filter_val: str) -> dict[str, Any]:
    """Query database records under field-scope allowlists."""
    return {"table": table, "record": {k: "sanitized" for k in fields}}


@permission(tier="write")
def modify_user(user_id: str, updates: dict[str, Any]) -> dict[str, Any]:
    """Mutate user profile attributes."""
    return {"user_id": user_id, "updated": True}


@permission(tier="pay")
def issue_refund(customer_id: str, amount_usd: float, reason: str) -> dict[str, Any]:
    """Financial transaction requiring predecessor HITL authorization gate."""
    return {
        "customer_id": customer_id,
        "amount_usd": amount_usd,
        "reason": reason,
        "status": "processed",
    }
