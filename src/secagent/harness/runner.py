from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from langchain_core.messages import HumanMessage

from secagent.harness.introspector import discover_tools, tool_name
from secagent.harness.sandbox import ToolCallRecord, VirtualizedToolWrapper

logger = logging.getLogger("secagent.harness")
DEFAULT_TIMEOUT_S = 5.0
TIMEOUT_MESSAGE = "Execution timeout"


class SandboxError(RuntimeError):
    """Raised when strict dry-run sandboxing cannot protect any tools on the target."""


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


def _adapt_state_for_target(target: Any, state: dict[str, Any]) -> dict[str, Any]:
    """Filter initial state keys to match the target graph's declared channels when available."""
    channels = getattr(target, "channels", None)
    if isinstance(channels, dict) and "messages" in channels:
        return {key: value for key, value in state.items() if key in channels}
    return state


def _has_async_graph_nodes(target: Any) -> bool:
    """Detect LangGraph nodes/tools that are async-only so we prefer ainvoke upfront."""
    import inspect

    nodes = getattr(target, "nodes", None)
    if not isinstance(nodes, dict):
        return False
    for node in nodes.values():
        bound = getattr(node, "bound", None)
        afunc = getattr(bound, "afunc", None)
        func = getattr(bound, "func", None)
        if callable(afunc) and not callable(func):
            return True
        if inspect.iscoroutinefunction(bound):
            return True
        tbn = getattr(bound, "tools_by_name", None)
        if isinstance(tbn, dict):
            for tool in tbn.values():
                if (
                    getattr(tool, "coroutine", None) is not None
                    and getattr(tool, "func", None) is None
                ):
                    return True
    return False


def _with_fresh_thread_id(config: dict[str, Any]) -> dict[str, Any]:
    copied = dict(config)
    configurable = dict(copied.get("configurable") or {})
    if "thread_id" in configurable:
        configurable["thread_id"] = f"{configurable['thread_id']}-async-{uuid.uuid4().hex[:6]}"
        copied["configurable"] = configurable
    return copied


def _invoke_target(target: Any, state: dict[str, Any], config: dict[str, Any]) -> Any:
    """Invoke a target runnable, preferring ``ainvoke`` for async-only graphs."""
    invoke = getattr(target, "invoke", None)
    ainvoke = getattr(target, "ainvoke", None)
    if callable(ainvoke) and (not callable(invoke) or _has_async_graph_nodes(target)):
        return asyncio.run(ainvoke(state, config=config))
    if callable(invoke):
        try:
            return invoke(state, config=config)
        except (TypeError, NotImplementedError, RuntimeError) as exc:
            msg = str(exc).lower()
            if callable(ainvoke) and (
                "async" in msg
                or "sync" in msg
                or "coroutine" in msg
                or isinstance(exc, NotImplementedError)
            ):
                return asyncio.run(ainvoke(state, config=_with_fresh_thread_id(config)))
            raise
    if callable(ainvoke):
        return asyncio.run(ainvoke(state, config=config))
    raise TypeError(f"Target {target!r} exposes neither invoke() nor ainvoke()")


class ExecutionHarness:
    def __init__(
        self,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        dry_run: bool = True,
        policy_overrides: dict[str, str] | None = None,
        recursion_limit: int = 25,
        *,
        strict_sandbox: bool = False,
        mock_unclassified: bool = False,
        mock_mode: Literal["minimal", "rich"] = "minimal",
        taint_read_outputs: str | None = None,
    ) -> None:
        self.timeout_s = timeout_s
        self.dry_run = dry_run
        self.policy_overrides = policy_overrides
        self.recursion_limit = recursion_limit
        self.strict_sandbox = strict_sandbox
        self.mock_unclassified = mock_unclassified
        self.mock_mode = mock_mode
        self.taint_read_outputs = taint_read_outputs

    async def aexecute(self, fn: Callable[[], Any], scenario_id: str = "adhoc") -> HarnessResult:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()

        def deliver(setter: Callable[[Any], None], value: Any) -> None:
            if not future.done():
                setter(value)

        def worker() -> None:
            try:
                value = fn()
            except BaseException as exc:
                error = (
                    exc
                    if isinstance(exc, Exception)
                    else RuntimeError(f"{type(exc).__name__}: {exc}")
                )
                outcome = (future.set_exception, error)
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
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.aexecute(fn, scenario_id))

        result_box: list[HarnessResult] = []
        err_box: list[BaseException] = []

        ctx = contextvars.copy_context()

        def _runner() -> None:
            try:
                result_box.append(ctx.run(asyncio.run, self.aexecute(fn, scenario_id)))
            except BaseException as exc:  # pragma: no cover
                err_box.append(exc)

        thread = threading.Thread(target=_runner, daemon=True, name=f"secagent-loop-{scenario_id}")
        thread.start()
        thread.join()
        if err_box:
            raise err_box[0]
        return result_box[0]

    def run_scenario(
        self,
        target: Any,
        scenario: Any,
        mod: Any = None,
        callbacks: list[Any] | None = None,
    ) -> HarnessResult:

        scenario_id = str(_get(scenario, "id", "adhoc"))
        scenario_taint = _get(scenario, "taint_payload", None) or self.taint_read_outputs
        wrapper = VirtualizedToolWrapper(
            overrides=self.policy_overrides,
            dry_run=self.dry_run,
            mock_unclassified=self.mock_unclassified,
            mock_mode=self.mock_mode,
            taint_read_outputs=str(scenario_taint) if scenario_taint else None,
        )
        state = _adapt_state_for_target(target, build_initial_state(scenario))
        config: dict[str, Any] = {
            "recursion_limit": self.recursion_limit,
            "configurable": {"thread_id": f"secagent-{scenario_id}-{uuid.uuid4().hex[:8]}"},
        }
        if callbacks:
            config["callbacks"] = callbacks

        discovered_names = {tool_name(t) for t in discover_tools(target, mod)}
        with wrapper.virtualize(target, mod):
            patched_set = set(wrapper.patched)
            unpatched = sorted(discovered_names - patched_set)
            if self.dry_run and (not wrapper.patched or (self.strict_sandbox and unpatched)):
                if self.strict_sandbox:
                    detail = (
                        f"unpatched tool(s): {', '.join(unpatched)}"
                        if unpatched
                        else "no tools to protect"
                    )
                    raise SandboxError(
                        f"Sandbox could not protect target for scenario {scenario_id} ({detail}). "
                        "Expose tools via a graph ToolNode, a 'tools' list, or @permission-decorated "
                        "functions, or pass --allow-live-tools to opt out."
                    )
                logger.warning(
                    "Sandbox found no tools to protect for scenario %s: dangerous tools "
                    "may run for real. Expose them via a graph ToolNode, a 'tools' list "
                    "or @permission-decorated module functions.",
                    scenario_id,
                )
            result = self.execute(lambda: _invoke_target(target, state, config), scenario_id)

            if result.status == "timeout":
                wrapper.keep_patched = True
        result.tool_calls = list(wrapper.calls)
        return result
