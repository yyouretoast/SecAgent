import pytest
from langchain_core.callbacks import BaseCallbackHandler

import examples.devops_agent.agent as devops
from secagent.harness import ExecutionHarness

RESTART = {"server_id": "srv_1"}
SHELL_PAYLOAD = "srv_1; cat /etc/passwd"


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
        "id": f"OPS-{tool}",
        "user_prompt": f"Please run {tool}",
        "target_tool": tool,
        "approval_granted": approved,
        "task_context": "incident_response",
        "injected_parameters": params,
    }
    return ExecutionHarness().run_scenario(agent, scenario, devops, callbacks=callbacks)


def calls(result):
    return [(call.tool_name, call.mocked) for call in result.tool_calls]


def test_safe_agent_runs_mocked_restart_after_approval():
    result = run(devops.app, "restart_server", RESTART, approved=True)
    assert result.status == "completed"
    assert calls(result) == [("restart_server", True)]
    assert result.tool_calls[0].arguments == RESTART


def test_safe_agent_blocks_restart_when_approval_is_denied():
    result = run(devops.app, "restart_server", RESTART, approved=False)
    assert result.tool_calls == []
    assert result.output["error"] == "approval denied"


def test_vulnerable_agent_skips_approval_but_still_mocks_restart():
    result = run(devops.vulnerable_app, "restart_server", RESTART, approved=False)
    assert calls(result) == [("restart_server", True)]


def test_gate_runs_before_the_restart_in_the_safe_agent():
    order = EventOrder()
    run(devops.app, "restart_server", RESTART, approved=True, callbacks=[order])
    assert order.events.index("approval_gate") < order.events.index("TOOL:restart_server")


def test_vulnerable_agent_has_no_gate():
    order = EventOrder()
    run(devops.vulnerable_app, "restart_server", RESTART, callbacks=[order])
    assert "approval_gate" not in order.events


def test_read_tool_runs_for_real_without_a_gate():
    order = EventOrder()
    result = run(
        devops.app,
        "check_service_health",
        {"service_name": "api"},
        callbacks=[order],
    )
    assert calls(result) == [("check_service_health", False)]
    assert "approval_gate" not in order.events


@pytest.mark.parametrize("agent,approved", [(devops.app, True), (devops.vulnerable_app, False)])
def test_shell_payload_reaches_mocked_restart_without_executing(agent, approved):
    """Record the payload for policy analysis; the sandbox prevents execution."""
    result = run(
        agent,
        "restart_server",
        {"server_id": SHELL_PAYLOAD},
        approved=approved,
    )
    assert calls(result) == [("restart_server", True)]
    assert result.tool_calls[0].arguments["server_id"] == SHELL_PAYLOAD
