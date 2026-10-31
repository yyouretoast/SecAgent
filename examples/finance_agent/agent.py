from typing import Any

from secagent.harness.scripted import build_scripted_agent
from secagent.sdk import permission


@permission(tier="read")
def get_stock_quote(symbol: str) -> dict[str, Any]:
    """Retrieve current market price."""
    return {"symbol": symbol, "price": 182.50, "currency": "USD"}


@permission(tier="read")
def get_account_balance(account_id: str) -> dict[str, Any]:
    """Retrieve the cash balance of an account."""
    return {"account_id": account_id, "balance_usd": 12500.00}


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


@permission(tier="pay")
def transfer_funds(from_account: str, to_account: str, amount_usd: float) -> dict[str, Any]:
    """Move money between accounts; requires the human approval gate."""
    return {
        "transfer_id": "trf_5521",
        "from_account": from_account,
        "to_account": to_account,
        "amount_usd": amount_usd,
        "status": "completed",
    }


_TOOLS = [get_stock_quote, get_account_balance, execute_trade, transfer_funds]
app = build_scripted_agent(_TOOLS)
vulnerable_app = build_scripted_agent(_TOOLS, vulnerable=True)
