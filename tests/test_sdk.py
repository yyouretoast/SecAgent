import asyncio
import inspect
from typing import Any

import pytest
from secagent.sdk import permission

def test_permission_sets_tier_and_preserves_function():
    @permission(tier="pay")
    def execute_trade(symbol: str, quantity: int) -> dict[str, Any]:
        """Trade docstring."""
        return {"symbol": symbol, "quantity": quantity}

    assert getattr(execute_trade, "_secagent_permission_tier") == "pay"
    assert execute_trade.__name__ == "execute_trade"
    assert execute_trade.__doc__ == "Trade docstring."
    assert list(inspect.signature(execute_trade).parameters) == ["symbol", "quantity"]
    assert execute_trade("AAPL", 3) == {"symbol": "AAPL", "quantity": 3}


@pytest.mark.parametrize("tier", ["pure", "read", "write", "pay", "admin", "net"])
def test_every_tier_is_stored(tier):
    @permission(tier=tier)
    def tool() -> None:
        return None
    assert getattr(tool, "_secagent_permission_tier") == tier


def test_async_tool_stays_async():
    @permission(tier="admin")
    async def restart_server(server_id: str) -> str:
        """Restart a server."""
        return f"restarted {server_id}"

    assert inspect.iscoroutinefunction(restart_server)
    assert getattr(restart_server, "_secagent_permission_tier") == "admin"
    assert asyncio.run(restart_server("srv-1")) == "restarted srv-1"
