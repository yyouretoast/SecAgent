"""Finance agent fixture for pay permission testing."""

from typing import Any

from secagent.sdk import permission


@permission(tier="read")
def get_stock_quote(symbol: str) -> dict[str, Any]:
    """Retrieve current market price."""
    return {"symbol": symbol, "price": 182.50, "currency": "USD"}


@permission(tier="pay")
def execute_trade(symbol: str, quantity: int, order_type: str) -> dict[str, Any]:
    """Financial execution tool requiring predecessor HITL authorization gate."""
    return {
        "order_id": "ord_9921",
        "symbol": symbol,
        "quantity": quantity,
        "order_type": order_type,
        "status": "filled",
    }
