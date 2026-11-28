"""Normalize framework approval events into trace-compatible HITL spans."""

from __future__ import annotations

import time
import uuid
from typing import Any

from opentelemetry.sdk.trace import SpanProcessor, TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter

from secagent.telemetry.callbacks import OTelRuntime, TraceSession, resolve_maestro_layer
from secagent.telemetry.redactor import PIIRedactor


class HITLNormalizer:
    """Append an approval decision while preserving session ordering."""

    def __init__(
        self,
        session: TraceSession,
        *,
        otel: OTelRuntime | None = None,
        tracer_provider: TracerProvider | None = None,
        span_processor: SpanProcessor | None = None,
        span_exporter: SpanExporter | None = None,
        maestro_layer: str | None = "L6",
        layer_tagging: bool = True,
    ) -> None:
        self.session = session
        self.otel = otel or OTelRuntime(
            tracer_provider=tracer_provider,
            span_processor=span_processor,
            span_exporter=span_exporter,
        )
        self.span_exporter = self.otel.span_exporter
        self.maestro_layer = (
            resolve_maestro_layer("gate.hitl", maestro_layer=maestro_layer)
            if layer_tagging
            else None
        )

    def record(
        self,
        approval_granted: bool,
        *,
        operation: str = "unknown_operation",
        approver: str | None = None,
        input_parameters: dict[str, Any] | None = None,
        maestro_layer: str | None = None,
    ) -> dict[str, Any]:
        now = time.time_ns()
        output_result: dict[str, Any] | None = None
        if approver is not None:
            output_result = {"approver": approver}

        resolved_layer = (
            self.maestro_layer
            if maestro_layer is None
            else resolve_maestro_layer("gate.hitl", maestro_layer=maestro_layer)
        )
        span = {
            "span_id": str(uuid.uuid4()),
            "span_type": "gate.hitl",
            "name": "approval_gate",
            "start_time_ns": now,
            "end_time_ns": now,
            "permission_tier": "gate",
            "approval_granted": bool(approval_granted),
            "input_parameters": {"operation": operation, **(input_parameters or {})},
            "output_result": output_result,
            "is_error": False,
            "error_message": None,
        }
        if resolved_layer is not None:
            span["maestro_layer"] = resolved_layer
        trace_span = self.session.append(PIIRedactor.scrub_container(span))
        otel_span = self.otel.start_span(
            trace_span["name"],
            start_time_ns=now,
            trace_span=dict(trace_span),
        )
        updated_span = self.session.update_span(
            trace_span, {"trace_id": self.otel.trace_id(otel_span)}
        )
        self.otel.finish_span(otel_span, updated_span, end_time_ns=now)
        return updated_span

    def normalize_interrupt(
        self,
        event: Any,
        *,
        operation: str | None = None,
        approver: str | None = None,
        input_parameters: dict[str, Any] | None = None,
        maestro_layer: str | None = None,
    ) -> dict[str, Any]:
        """Adapt a framework interrupt/checkpoint payload into a HITL span.

        Frameworks commonly expose the decision as ``approval_granted``,
        ``approved``, or a boolean ``value``. The adapter keeps the framework
        payload out of the trace contract while preserving useful metadata.
        """
        payload = event if isinstance(event, dict) else {"value": event}
        decision = payload.get("approval_granted", payload.get("approved"))
        if decision is None:
            decision = payload.get("value")
        if not isinstance(decision, bool):
            raise ValueError("HITL interrupt payload must contain a boolean approval decision")

        resolved_operation = (
            operation or payload.get("operation") or payload.get("target_operation")
        )
        resolved_approver = approver or payload.get("approver")
        resolved_parameters = input_parameters or payload.get("input_parameters")
        return self.record(
            decision,
            operation=str(resolved_operation or "unknown_operation"),
            approver=resolved_approver,
            input_parameters=resolved_parameters,
            maestro_layer=maestro_layer,
        )


def normalize_hitl(
    session: TraceSession,
    approval_granted: bool,
    **kwargs: Any,
) -> dict[str, Any]:
    """Convenience adapter for LangGraph/harness integration points."""
    return HITLNormalizer(session).record(approval_granted, **kwargs)


def normalize_interrupt(session: TraceSession, event: Any, **kwargs: Any) -> dict[str, Any]:
    """Normalize a framework interrupt payload using a shared trace session."""
    return HITLNormalizer(session).normalize_interrupt(event, **kwargs)
