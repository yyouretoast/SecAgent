from __future__ import annotations

import asyncio
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from langchain_core.messages import HumanMessage

from secagent.harness.sandbox import ToolCallRecord, VirtualizedToolWrapper

logger = logging.getLogger("secagent.harness")
DEFAULT_TIMEOUT_S = 5.0
TIMEOUT_MESSAGE = "Execution timeout"


@dataclass
class HarnessResult:
    scenario_id: str
    status: Literal["completed", "timeout", "error"]
    output: Any = None
    error_message: str | None = None
    duration_ms: float = 0.0
    tool_calls: list[ToolCallRecord] = field(default_factory=list)

    def error_span(self, step_index: int = 0) -> dict[str, Any] | None:
        if self.status == "completed":
            return None
        now = time.time_ns()
        return {
            "span_id": f"harness-error-{uuid.uuid4().hex[:8]}",
            "step_index": step_index,
            "span_type": "agent.run",
            "name": "execution_harness",
            "start_time_ns": now - int(self.duration_ms * 1_000_000),
            "end_time_ns": now,
            "permission_tier": "none",
            "is_error": True,
            "error_message": self.error_message,
        }


def _get(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def build_initial_state(scenario: Any) -> dict[str, Any]:
    """Convert a scenario (dict or GeneratedScenario) into the AgentState dict."""
    ctx = _get(scenario, "session_context", None) or {}
    prompt = _get(scenario, "user_prompt", "") or ""
    injected = _get(scenario, "injected_parameters", None) or {}
    return {
        "messages": [
            HumanMessage(content=prompt, additional_kwargs={"injected_parameters": injected})
        ],
        "user_id": _get(scenario, "user_id", None) or ctx.get("user_id", "user_001"),
        "caller_role": _get(scenario, "caller_role", None) or ctx.get("caller_role", "guest"),
        "task_context": _get(scenario, "task_context", None)
        or ctx.get("task_context", "unspecified"),
        "approval_granted": bool(_get(scenario, "approval_granted", False)),
        "current_intent": _get(scenario, "target_tool", "") or "",
        "error": None,
    }


class ExecutionHarness:
    def __init__(
        self,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        dry_run: bool = True,
        policy_overrides: dict[str, str] | None = None,
        recursion_limit: int = 25,
    ) -> None:
        self.timeout_s = timeout_s
        self.dry_run = dry_run
        self.policy_overrides = policy_overrides
        self.recursion_limit = recursion_limit

    async def aexecute(self, fn: Callable[[], Any], scenario_id: str = "adhoc") -> HarnessResult:
        """Run ``fn`` in a daemon thread; give up after ``timeout_s`` seconds."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()

        def deliver(setter: Callable[[Any], None], value: Any) -> None:
            if not future.done():
                setter(value)

        def worker() -> None:
            try:
                value = fn()
            except BaseException as exc:
                outcome: tuple[Callable[[Any], None], Any] = (future.set_exception, exc)
            else:
                outcome = (future.set_result, value)
            try:
                loop.call_soon_threadsafe(deliver, *outcome)
            except RuntimeError:
                pass

        started = time.perf_counter()
        threading.Thread(target=worker, daemon=True, name=f"secagent-{scenario_id}").start()
        try:
            output = await asyncio.wait_for(future, timeout=self.timeout_s)
            status: Literal["completed", "timeout", "error"] = "completed"
            message = None

        except TimeoutError as exc:
            if future.cancelled():
                output, status, message = None, "timeout", TIMEOUT_MESSAGE
            else:
                output, status, message = None, "error", str(exc)

        except Exception as exc:
            output, status, message = None, "error", str(exc)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return HarnessResult(scenario_id, status, output, message, elapsed_ms)

    def execute(self, fn: Callable[[], Any], scenario_id: str = "adhoc") -> HarnessResult:
        return asyncio.run(self.aexecute(fn, scenario_id))

    # full scenario run
    def run_scenario(
        self,
        target: Any,
        scenario: Any,
        mod: Any = None,
        callbacks: list[Any] | None = None,
    ) -> HarnessResult:

        scenario_id = str(_get(scenario, "id", "adhoc"))
        wrapper = VirtualizedToolWrapper(overrides=self.policy_overrides, dry_run=self.dry_run)
        state = build_initial_state(scenario)
        config: dict[str, Any] = {"recursion_limit": self.recursion_limit}
        if callbacks:
            config["callbacks"] = callbacks

        with wrapper.virtualize(target, mod):
            if self.dry_run and not wrapper.patched:
                logger.warning(
                    "Sandbox found no tools to protect for scenario %s: dangerous tools "
                    "may run for real. Expose them via a graph ToolNode, a 'tools' list "
                    "or @permission-decorated module functions.",
                    scenario_id,
                )
            result = self.execute(lambda: target.invoke(state, config=config), scenario_id)

            if result.status == "timeout":
                wrapper.keep_patched = True
        result.tool_calls = list(wrapper.calls)
        return result
