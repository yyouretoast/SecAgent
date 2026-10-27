"""LangChain callback adapter and in-memory trace session."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # pragma: no cover - supports contract use without LangChain installed

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Compatibility base for environments that install LangChain later."""


def _json_value(value: Any) -> Any:
    """Convert common callback payloads to values accepted by the trace schema."""
    if value is None or isinstance(value, (dict, list, str, int, float, bool)):
        return value
    return str(value)


def _input_parameters(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            import json

            parsed = json.loads(value)
        except (TypeError, ValueError):
            parsed = value
        return parsed if isinstance(parsed, dict) else {"input": parsed}
    return {"input": _json_value(value)}


def _tool_name(serialized: Any, kwargs: dict[str, Any]) -> str:
    if isinstance(serialized, dict):
        name = serialized.get("name")
        if name:
            return str(name)
        identifier = serialized.get("id")
        if isinstance(identifier, list) and identifier:
            return str(identifier[-1])
    return str(kwargs.get("name") or kwargs.get("tool_name") or "unknown_tool")


def _permission_tier(serialized: Any, kwargs: dict[str, Any]) -> str:
    candidates = [serialized, kwargs.get("metadata"), kwargs]
    if isinstance(serialized, dict):
        candidates.append(serialized.get("kwargs"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            tier = candidate.get("permission_tier") or candidate.get("_secagent_permission_tier")
            if tier:
                return str(tier)
    return "none"


@dataclass
class TraceSession:
    """Mutable trace document shared by callbacks and the exporter."""

    scenario_id: str = "unknown"
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    caller_role: str = "unknown"
    task_context: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)
    spans: list[dict[str, Any]] = field(default_factory=list)

    def append(self, span: dict[str, Any]) -> dict[str, Any]:
        span["step_index"] = len(self.spans)
        self.spans.append(span)
        return span

    def as_dict(self) -> dict[str, Any]:
        result = {
            "scenario_id": self.scenario_id,
            "execution_id": self.execution_id,
            "timestamp": self.timestamp,
            "caller_role": self.caller_role,
            "task_context": self.task_context,
            "spans": self.spans,
        }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class SecAgentTelemetryCallback(BaseCallbackHandler):
    """Capture LangChain tool lifecycle callbacks as trace spans."""

    def __init__(self, session: TraceSession | None = None) -> None:
        self.session = session or TraceSession()
        self._active: dict[str, dict[str, Any]] = {}
        self._last_active: dict[str, Any] | None = None

    @property
    def spans(self) -> list[dict[str, Any]]:
        return self.session.spans

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        start_time = time.time_ns()
        span = self.session.append(
            {
                "span_id": str(run_id or uuid.uuid4()),
                "span_type": "tool.call",
                "name": _tool_name(serialized, kwargs),
                "start_time_ns": start_time,
                "end_time_ns": start_time,
                "permission_tier": _permission_tier(serialized, kwargs),
                "approval_granted": None,
                "input_parameters": _input_parameters(kwargs.get("inputs", input_str)),
                "output_result": None,
                "is_error": False,
                "error_message": None,
            }
        )
        if parent_run_id:
            span["parent_span_id"] = str(parent_run_id)
        if run_id is not None:
            self._active[str(run_id)] = span
        self._last_active = span

    def _find_active(self, run_id: Any) -> dict[str, Any] | None:
        if run_id is not None:
            return self._active.get(str(run_id))
        return self._last_active

    def _close(self, run_id: Any) -> dict[str, Any] | None:
        span = self._find_active(run_id)
        if run_id is not None:
            self._active.pop(str(run_id), None)
        if span is self._last_active:
            self._last_active = None
        return span

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        span = self._close(run_id)
        if span is None:
            return
        span["end_time_ns"] = time.time_ns()
        span["output_result"] = _json_value(output)

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        span = self._close(run_id)
        if span is None:
            return
        span["end_time_ns"] = time.time_ns()
        span["is_error"] = True
        span["error_message"] = str(error)

    def record_hitl(self, approval_granted: bool, **kwargs: Any) -> dict[str, Any]:
        """Append a normalized approval event to this callback's trace session."""
        from secagent.telemetry.hitl import HITLNormalizer

        return HITLNormalizer(self.session).record(approval_granted, **kwargs)

    def record_interrupt(self, event: Any, **kwargs: Any) -> dict[str, Any]:
        """Normalize a framework interrupt on this callback's trace session."""
        from secagent.telemetry.hitl import HITLNormalizer

        return HITLNormalizer(self.session).normalize_interrupt(event, **kwargs)
