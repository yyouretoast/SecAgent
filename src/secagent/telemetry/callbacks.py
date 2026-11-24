"""LangChain callback adapter and in-memory trace session."""

from __future__ import annotations

import copy
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from opentelemetry import trace
from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from secagent.telemetry.redactor import PIIRedactor

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:  # pragma: no cover - supports contract use without LangChain installed

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Compatibility base for environments that install LangChain later."""


def _json_safe(value: Any) -> Any:
    """Recursively coerce nested callback payloads to JSON-safe primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _json_value(value: Any) -> Any:
    """Convert common callback payloads to values accepted by the trace schema."""
    if isinstance(value, list):
        return json.dumps(value, default=str)
    if isinstance(value, dict):
        return _json_safe(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _input_parameters(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return _json_safe(value)
    if isinstance(value, str):
        try:
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


def _model_name(serialized: Any, kwargs: dict[str, Any]) -> str:
    if isinstance(serialized, dict):
        name = serialized.get("name")
        if name:
            return str(name)
        identifier = serialized.get("id")
        if isinstance(identifier, list) and identifier:
            return str(identifier[-1])
    return str(kwargs.get("name") or kwargs.get("model_name") or kwargs.get("model") or "model")


def _model_input(value: Any, field_name: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return _json_safe(value)
    return {field_name: _json_value(value)}


def _permission_tier(
    serialized: Any,
    kwargs: dict[str, Any],
    *,
    tool_name: str,
    tier_by_tool: Mapping[str, str] | None = None,
) -> str:
    """Resolve metadata first, then configured and semantic tool tiers."""
    candidates = [serialized, kwargs.get("metadata"), kwargs]
    if isinstance(serialized, dict):
        candidates.append(serialized.get("kwargs"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            tier = candidate.get("permission_tier") or candidate.get("_secagent_permission_tier")
            if tier and str(tier) != "none":
                return str(tier)
    from secagent.harness.introspector import resolve_permission_tier

    return resolve_permission_tier(tool_name, overrides=dict(tier_by_tool or {}))


def _attribute_value(value: Any) -> str | int | float | bool:
    """Convert redacted values to OpenTelemetry-compatible attribute values."""
    scrubbed = PIIRedactor.scrub_container(value)
    if isinstance(scrubbed, (str, int, float, bool)):
        return scrubbed
    return json.dumps(scrubbed, default=str, sort_keys=True)


def _otel_attributes(span: dict[str, Any]) -> dict[str, str | int | float | bool]:
    """Project a SecAgent span into safe, scalar OpenTelemetry attributes."""
    attributes: dict[str, str | int | float | bool] = {
        "secagent.span_type": str(span["span_type"]),
        "secagent.permission_tier": str(span.get("permission_tier", "none")),
        "secagent.input_parameters": _attribute_value(span.get("input_parameters", {})),
        "secagent.is_error": bool(span.get("is_error", False)),
    }
    if span.get("approval_granted") is not None:
        attributes["secagent.approval_granted"] = bool(span["approval_granted"])
    if span.get("output_result") is not None:
        attributes["secagent.output_result"] = _attribute_value(span["output_result"])
    if span.get("error_message") is not None:
        attributes["secagent.error_message"] = _attribute_value(span["error_message"])
    if span.get("attributes") is not None:
        attributes["secagent.attributes"] = _attribute_value(span["attributes"])
    return attributes


class OTelRuntime:
    """Own the local OTel tracer and the shared trace context for one session."""

    def __init__(
        self,
        *,
        tracer_provider: TracerProvider | None = None,
        span_processor: SpanProcessor | None = None,
        span_exporter: SpanExporter | None = None,
    ) -> None:
        self.tracer_provider = tracer_provider or TracerProvider()
        self.span_exporter: SpanExporter | None = span_exporter

        processors: list[SpanProcessor] = []
        if span_processor is not None:
            processors.append(span_processor)
        if span_exporter is not None:
            processors.append(SimpleSpanProcessor(span_exporter))
        if tracer_provider is None and not processors:
            self.span_exporter = InMemorySpanExporter()
            processors.append(SimpleSpanProcessor(self.span_exporter))

        for processor in processors:
            self.tracer_provider.add_span_processor(processor)

        self.tracer = self.tracer_provider.get_tracer("secagent.telemetry")
        root_context = trace.SpanContext(
            trace_id=uuid.uuid4().int,
            span_id=uuid.uuid4().int & ((1 << 64) - 1) or 1,
            is_remote=False,
            trace_flags=trace.TraceFlags(trace.TraceFlags.SAMPLED),
        )
        self._session_context = trace.set_span_in_context(trace.NonRecordingSpan(root_context))

    def start_span(
        self,
        name: str,
        *,
        start_time_ns: int,
        trace_span: dict[str, Any],
        parent: trace.Span | None = None,
    ) -> trace.Span:
        context = trace.set_span_in_context(parent) if parent is not None else self._session_context
        return self.tracer.start_span(
            name,
            context=context,
            start_time=start_time_ns,
            attributes=_otel_attributes(trace_span),
        )

    @staticmethod
    def trace_id(span: trace.Span) -> str:
        return f"{span.get_span_context().trace_id:032x}"

    @staticmethod
    def finish_span(
        span: trace.Span,
        trace_span: dict[str, Any],
        *,
        end_time_ns: int,
    ) -> None:
        span.set_attributes(_otel_attributes(trace_span))
        if trace_span.get("is_error"):
            span.set_status(
                trace.Status(
                    trace.StatusCode.ERROR,
                    str(trace_span.get("error_message") or "SecAgent tool error"),
                )
            )
        span.end(end_time=end_time_ns)


@dataclass
class _ActiveSpan:
    trace_span: dict[str, Any]
    otel_span: trace.Span


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

    def __post_init__(self) -> None:
        self.metadata = PIIRedactor.scrub_container(self.metadata)

    def append(self, span: dict[str, Any]) -> dict[str, Any]:
        safe_span = copy.deepcopy(span)
        for field_name in ("input_parameters", "output_result", "error_message", "attributes"):
            if field_name in safe_span:
                safe_span[field_name] = PIIRedactor.scrub_container(safe_span[field_name])
        safe_span["step_index"] = len(self.spans)
        self.spans.append(safe_span)
        return safe_span

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "scenario_id": self.scenario_id,
            "execution_id": self.execution_id,
            "timestamp": self.timestamp,
            "caller_role": self.caller_role,
            "task_context": self.task_context,
            "spans": copy.deepcopy(self.spans),
        }
        if self.metadata:
            result["metadata"] = copy.deepcopy(self.metadata)
        return result


class SecAgentTelemetryCallback(BaseCallbackHandler):
    """Capture LangChain tool lifecycle callbacks as SecAgent and OTel spans."""

    def __init__(
        self,
        session: TraceSession | None = None,
        *,
        tier_by_tool: Mapping[str, str] | None = None,
        tracer_provider: TracerProvider | None = None,
        span_processor: SpanProcessor | None = None,
        span_exporter: SpanExporter | None = None,
    ) -> None:
        self.session = session or TraceSession()
        self.tier_by_tool = dict(tier_by_tool or {})
        self.otel = OTelRuntime(
            tracer_provider=tracer_provider,
            span_processor=span_processor,
            span_exporter=span_exporter,
        )
        self.span_exporter = self.otel.span_exporter
        self._active: dict[str, _ActiveSpan] = {}
        self._last_active: _ActiveSpan | None = None

    @property
    def spans(self) -> list[dict[str, Any]]:
        return self.session.spans

    def _start_span(
        self,
        span: dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
    ) -> dict[str, Any]:
        recorded = self.session.append(span)
        if parent_run_id:
            recorded["parent_span_id"] = str(parent_run_id)
        parent = self._active.get(str(parent_run_id)) if parent_run_id is not None else None
        otel_span = self.otel.start_span(
            recorded["name"],
            start_time_ns=recorded["start_time_ns"],
            trace_span=recorded,
            parent=parent.otel_span if parent is not None else None,
        )
        recorded["trace_id"] = self.otel.trace_id(otel_span)
        active_span = _ActiveSpan(trace_span=recorded, otel_span=otel_span)
        if run_id is not None:
            self._active[str(run_id)] = active_span
        self._last_active = active_span
        return recorded

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
        name = _tool_name(serialized, kwargs)
        self._start_span(
            {
                "span_id": str(run_id or uuid.uuid4()),
                "span_type": "tool.call",
                "name": name,
                "start_time_ns": start_time,
                "end_time_ns": start_time,
                "permission_tier": _permission_tier(
                    serialized,
                    kwargs,
                    tool_name=name,
                    tier_by_tool=self.tier_by_tool,
                ),
                "approval_granted": None,
                "input_parameters": _input_parameters(kwargs.get("inputs", input_str)),
                "output_result": None,
                "is_error": False,
                "error_message": None,
            },
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Capture the start of a chat-model invocation."""
        self._start_model_span(
            serialized,
            _model_input(messages, "messages"),
            run_id=run_id,
            parent_run_id=parent_run_id,
            kwargs=kwargs,
        )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Capture the start of a completion-model invocation."""
        self._start_model_span(
            serialized,
            _model_input(prompts, "prompts"),
            run_id=run_id,
            parent_run_id=parent_run_id,
            kwargs=kwargs,
        )

    def _start_model_span(
        self,
        serialized: Any,
        input_parameters: dict[str, Any],
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        kwargs: dict[str, Any],
    ) -> None:
        start_time = time.time_ns()
        self._start_span(
            {
                "span_id": str(run_id or uuid.uuid4()),
                "span_type": "model.inference",
                "name": _model_name(serialized, kwargs),
                "start_time_ns": start_time,
                "end_time_ns": start_time,
                "permission_tier": "none",
                "approval_granted": None,
                "input_parameters": input_parameters,
                "output_result": None,
                "is_error": False,
                "error_message": None,
            },
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

    def _find_active(self, run_id: Any) -> _ActiveSpan | None:
        if run_id is not None:
            return self._active.get(str(run_id))
        return self._last_active

    def _close(self, run_id: Any) -> _ActiveSpan | None:
        span = self._find_active(run_id)
        if run_id is not None:
            self._active.pop(str(run_id), None)
        if span is self._last_active:
            self._last_active = None
        return span

    def _close_if_type(self, run_id: Any, span_type: str) -> _ActiveSpan | None:
        active_span = self._find_active(run_id)
        if active_span is None or active_span.trace_span["span_type"] != span_type:
            return None
        return self._close(run_id)

    def on_tool_end(self, output: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        active_span = self._close(run_id)
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["output_result"] = PIIRedactor.scrub_container(_json_value(output))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def on_tool_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        active_span = self._close(run_id)
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["is_error"] = True
        span["error_message"] = PIIRedactor.scrub_text(str(error))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def on_llm_end(self, response: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        """Complete a model span with a redacted model response."""
        active_span = self._close_if_type(run_id, "model.inference")
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["output_result"] = PIIRedactor.scrub_container(_json_value(response))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def on_llm_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        """Complete a model span with redacted error metadata."""
        active_span = self._close_if_type(run_id, "model.inference")
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["is_error"] = True
        span["error_message"] = PIIRedactor.scrub_text(str(error))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def on_chain_start(
        self,
        serialized: dict[str, Any] | None,
        inputs: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Capture a root chain as an optional enclosing agent span."""
        if parent_run_id is not None:
            return
        start_time = time.time_ns()
        self._start_span(
            {
                "span_id": str(run_id or uuid.uuid4()),
                "span_type": "agent.run",
                "name": _model_name(serialized, kwargs) if serialized or kwargs else "agent",
                "start_time_ns": start_time,
                "end_time_ns": start_time,
                "permission_tier": "none",
                "approval_granted": None,
                "input_parameters": _input_parameters(inputs),
                "output_result": None,
                "is_error": False,
                "error_message": None,
            },
            run_id=run_id,
        )

    def on_chain_end(self, outputs: Any, *, run_id: Any = None, **kwargs: Any) -> None:
        """Complete a root agent span with a redacted result."""
        active_span = self._close_if_type(run_id, "agent.run")
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["output_result"] = PIIRedactor.scrub_container(_json_value(outputs))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def on_chain_error(self, error: BaseException, *, run_id: Any = None, **kwargs: Any) -> None:
        """Complete a root agent span with redacted error metadata."""
        active_span = self._close_if_type(run_id, "agent.run")
        if active_span is None:
            return
        span = active_span.trace_span
        span["end_time_ns"] = time.time_ns()
        span["is_error"] = True
        span["error_message"] = PIIRedactor.scrub_text(str(error))
        self.otel.finish_span(
            active_span.otel_span,
            span,
            end_time_ns=span["end_time_ns"],
        )

    def record_hitl(self, approval_granted: bool, **kwargs: Any) -> dict[str, Any]:
        """Append a normalized approval event to this callback's trace session."""
        from secagent.telemetry.hitl import HITLNormalizer

        return HITLNormalizer(self.session, otel=self.otel).record(approval_granted, **kwargs)

    def record_interrupt(self, event: Any, **kwargs: Any) -> dict[str, Any]:
        """Normalize a framework interrupt on this callback's trace session."""
        from secagent.telemetry.hitl import HITLNormalizer

        return HITLNormalizer(self.session, otel=self.otel).normalize_interrupt(event, **kwargs)
