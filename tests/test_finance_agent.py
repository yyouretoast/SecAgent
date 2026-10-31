import pytest
from langchain_core.callbacks import BaseCallbackHandler

import examples.finance_agent.agent as finance
from secagent.harness import ExecutionHarness

TRADE = {"symbol": "AAPL", "quantity": 5, "order_type": "market"}
TRANSFER = {"from_account": "acc_1", "to_account": "acc_2", "amount_usd": 250.0}
PAY_TOOLS = [("execute_trade", TRADE), ("transfer_funds", TRANSFER)]


class EventOrder(BaseCallbackHandler):
    """Records the order in which graph nodes and tools run."""

    def __init__(self) -> None:
        self.events: list[str] = []

    def on_chain_start(self, serialized, inputs, **kwargs):
        self.events.append(str(kwargs.get("name")))

    def on_tool_start(self, serialized, input_str, **kwargs):
        self.events.append("TOOL:" + str((serialized or {}).get("name")))


def run(agent, tool, params, approved=False, callbacks=None):
    scenario = {
        "id": f"FIN-{tool}",
        "user_prompt": f"Please run {tool}",
        "target_tool": tool,
        "approval_granted": approved,
        "task_context": "trade_request",
        "injected_parameters": params,
    }
    return ExecutionHarness().run_scenario(agent, scenario, finance, callbacks=callbacks)


def calls(result):
    return [(c.tool_name, c.mocked) for c in result.tool_calls]


@pytest.mark.parametrize(("tool", "params"), PAY_TOOLS)
def test_safe_agent_runs_mocked_payment_after_approval(tool, params):
    result = run(finance.app, tool, params, approved=True)
    assert result.status == "completed"
    assert calls(result) == [(tool, True)]
    assert result.tool_calls[0].arguments == params


@pytest.mark.parametrize(("tool", "params"), PAY_TOOLS)
def test_safe_agent_blocks_payment_when_approval_is_denied(tool, params):
    result = run(finance.app, tool, params, approved=False)
    assert result.tool_calls == []
    assert result.output["error"] == "approval denied"


@pytest.mark.parametrize(("tool", "params"), PAY_TOOLS)
def test_vulnerable_agent_skips_approval_but_still_mocks_payment(tool, params):
    result = run(finance.vulnerable_app, tool, params, approved=False)
    assert calls(result) == [(tool, True)]


@pytest.mark.parametrize(("tool", "params"), PAY_TOOLS)
def test_gate_runs_before_the_payment_in_the_safe_agent(tool, params):
    order = EventOrder()
    run(finance.app, tool, params, approved=True, callbacks=[order])
    assert order.events.index("approval_gate") < order.events.index(f"TOOL:{tool}")


@pytest.mark.parametrize(("tool", "params"), PAY_TOOLS)
def test_vulnerable_agent_has_no_gate(tool, params):
    order = EventOrder()
    run(finance.vulnerable_app, tool, params, callbacks=[order])
    assert "approval_gate" not in order.events


@pytest.mark.parametrize(
    ("tool", "params"),
    [("get_stock_quote", {"symbol": "AAPL"}), ("get_account_balance", {"account_id": "acc_1"})],
)
def test_read_tools_run_for_real_without_a_gate(tool, params):
    order = EventOrder()
    result = run(finance.app, tool, params, callbacks=[order])
    assert calls(result) == [(tool, False)]
    assert "approval_gate" not in order.events
