"""Dual-mode runtime guardrail middleware reusing SecAgent's deterministic PolicyEngine."""

from __future__ import annotations

import functools
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from secagent.engine.evaluator import PolicyEngine
from secagent.engine.models import EvaluationResult, PolicyViolation
from secagent.telemetry.callbacks import TraceSession, _json_value
from secagent.telemetry.hitl import HITLNormalizer

_INTERNAL_CALLBACK_KWARGS = frozenset({"run_manager", "callbacks", "config"})
_WRAPPED_MARKER = "_secagent_guardrail_wrapped"


def _sanitize_bound_args(bound: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(k): _json_value(v) for k, v in bound.items() if str(k) not in _INTERNAL_CALLBACK_KWARGS
    }


class PolicyViolationError(RuntimeError):
    """Raised by ``SecAgentGuardrail(mode='enforce')`` before a violating tool call runs."""

    def __init__(self, tool: str, violations: list[PolicyViolation]) -> None:
        self.tool_name = tool
        self.violations = list(violations)
        rule_ids = ", ".join(sorted({v.rule_id for v in violations}))
        super().__init__(
            f"SecAgent guardrail blocked tool '{tool}' due to policy violation(s): {rule_ids}"
        )


class SecAgentGuardrail:
    """Deterministic runtime guardrail wrapping tools with pre-execution PolicyEngine checks."""

    def __init__(
        self,
        *,
        policy_path: str | Path | None = None,
        engine: PolicyEngine | None = None,
        mode: Literal["enforce", "audit"] = "enforce",
        task_context: str = "default",
        caller_role: str = "user",
        overrides: Mapping[str, str] | None = None,
    ) -> None:
        self.engine = engine or PolicyEngine(policy_path=policy_path)
        self.mode = mode
        self.overrides = {**self.engine.ruleset.tool_tier_overrides, **dict(overrides or {})}
        self.session = TraceSession(
            scenario_id="runtime-session",
            caller_role=caller_role,
            task_context=task_context,
            metadata={"framework": "secagent_guardrail"},
        )
        self.audit_violations: list[PolicyViolation] = []
        self._lock = threading.RLock()

    def record_approval(
        self,
        operation: str,
        *,
        approved: bool = True,
        arguments: dict[str, Any] | None = None,
        approver: str | None = None,
    ) -> dict[str, Any]:
        """Record an explicit HITL approval decision on the active runtime session."""
        extra = {"arguments": dict(arguments)} if arguments else None
        with self._lock:
            return HITLNormalizer(self.session).record(
                approved,
                operation=operation,
                approver=approver,
                input_parameters=extra,
            )

    def check_call(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        tier: str | None = None,
    ) -> tuple[EvaluationResult, dict[str, Any]]:
        """Evaluate a proposed tool call against the rolling trace before execution."""
        from secagent.harness.introspector import resolve_permission_tier

        resolved_tier = tier or resolve_permission_tier(name, overrides=self.overrides)
        now = time.time_ns()
        candidate_span: dict[str, Any] = {
            "span_id": f"rt-{uuid.uuid4().hex[:8]}",
            "step_index": len(self.session.spans),
            "span_type": "tool.call",
            "name": name,
            "start_time_ns": now,
            "end_time_ns": now,
            "permission_tier": resolved_tier,
            "approval_granted": None,
            "input_parameters": _sanitize_bound_args(arguments),
            "output_result": None,
            "is_error": False,
            "error_message": None,
        }
        snapshot = self.session.as_dict()
        candidate_span["step_index"] = len(snapshot["spans"])
        snapshot["spans"].append(candidate_span)
        raw_result = self.engine.evaluate_trace(snapshot)
        scoped = [
            v for v in raw_result.violations if v.offending_span_id == candidate_span["span_id"]
        ]
        result = EvaluationResult(
            status="FAIL" if scoped else "PASS",
            total_spans_evaluated=raw_result.total_spans_evaluated,
            violations=scoped,
            execution_time_ms=raw_result.execution_time_ms,
        )
        return result, candidate_span

    def _enforce_or_audit(
        self,
        name: str,
        arguments: dict[str, Any],
        tier: str,
    ) -> dict[str, Any]:
        with self._lock:
            evaluation, candidate = self.check_call(name, arguments, tier=tier)
            if evaluation.violations:
                self.audit_violations.extend(evaluation.violations)
                if self.mode == "enforce" and evaluation.has_blocking_violations:
                    raise PolicyViolationError(name, evaluation.violations)
            return self.session.append(candidate)

    def _finish_span(
        self,
        span: dict[str, Any],
        *,
        output: Any = None,
        error: BaseException | None = None,
    ) -> None:
        end_ns = time.time_ns()
        if error is not None:
            self.session.update_span(
                span,
                {
                    "end_time_ns": end_ns,
                    "is_error": True,
                    "error_message": str(error),
                },
            )
            return
        self.session.update_span(
            span,
            {
                "end_time_ns": end_ns,
                "output_result": _json_value(output),
            },
        )

    def wrap_callable(
        self,
        fn: Callable[..., Any],
        name: str | None = None,
        tier: str | None = None,
    ) -> Callable[..., Any]:
        from secagent.harness.introspector import explicit_tier_of, resolve_permission_tier
        from secagent.harness.sandbox import _bind_arguments, _is_async_callable

        if getattr(fn, _WRAPPED_MARKER, False):
            return fn

        label = str(name or getattr(fn, "__name__", "unknown_tool"))
        resolved_tier = tier or resolve_permission_tier(label, explicit_tier_of(fn), self.overrides)

        if _is_async_callable(fn):

            @functools.wraps(fn)
            async def awrapper(*args: Any, **kwargs: Any) -> Any:
                bound = _sanitize_bound_args(_bind_arguments(fn, args, kwargs))
                span = self._enforce_or_audit(label, bound, resolved_tier)
                try:
                    output = await fn(*args, **kwargs)
                except BaseException as exc:
                    self._finish_span(span, error=exc)
                    raise
                self._finish_span(span, output=output)
                return output

            setattr(awrapper, _WRAPPED_MARKER, True)
            return awrapper

        @functools.wraps(fn)
        def swrapper(*args: Any, **kwargs: Any) -> Any:
            bound = _sanitize_bound_args(_bind_arguments(fn, args, kwargs))
            span = self._enforce_or_audit(label, bound, resolved_tier)
            try:
                output = fn(*args, **kwargs)
            except BaseException as exc:
                self._finish_span(span, error=exc)
                raise
            self._finish_span(span, output=output)
            return output

        setattr(swrapper, _WRAPPED_MARKER, True)
        return swrapper

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap either a plain Python callable or a LangChain ``BaseTool`` (including ``_run``/``_arun``)."""
        from secagent.harness.introspector import (
            explicit_tier_of,
            resolve_permission_tier,
            tool_name,
        )
        from secagent.harness.sandbox import BaseTool

        if isinstance(tool, BaseTool):
            label = tool_name(tool)
            resolved_tier = resolve_permission_tier(label, explicit_tier_of(tool), self.overrides)
            update: dict[str, Any] = {}
            func = getattr(tool, "func", None)
            coroutine = getattr(tool, "coroutine", None)
            if callable(func) and not getattr(func, _WRAPPED_MARKER, False):
                update["func"] = self.wrap_callable(func, label, resolved_tier)
            if callable(coroutine) and not getattr(coroutine, _WRAPPED_MARKER, False):
                update["coroutine"] = self.wrap_callable(coroutine, label, resolved_tier)
            if not update and not callable(func) and not callable(coroutine):
                for attr in ("_run", "_arun"):
                    if getattr(type(tool), attr, None) is not getattr(BaseTool, attr, None):
                        raw_method = getattr(tool, attr)
                        if not getattr(raw_method, _WRAPPED_MARKER, False):
                            update[attr] = self.wrap_callable(raw_method, label, resolved_tier)
            return tool.model_copy(update=update) if update else tool
        return self.wrap_callable(tool)

    def wrap_tools(self, tools: Sequence[Any]) -> list[Any]:
        """Wrap a sequence of tools for direct use in a LangGraph ``ToolNode``."""
        return [self.wrap_tool(t) for t in tools]
