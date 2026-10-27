"""Normalize framework approval events into trace-compatible HITL spans."""

from __future__ import annotations

import time
import uuid
from typing import Any

from secagent.telemetry.callbacks import TraceSession


class HITLNormalizer:
    """Append an approval decision while preserving session ordering."""

    def __init__(self, session: TraceSession) -> None:
        self.session = session

    def record(
        self,
        approval_granted: bool,
        *,
        operation: str = "unknown_operation",
        approver: str | None = None,
        input_parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = time.time_ns()
        output_result: dict[str, Any] | None = None
        if approver is not None:
            output_result = {"approver": approver}

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
        return self.session.append(span)

    def normalize_interrupt(
        self,
        event: Any,
        *,
        operation: str | None = None,
        approver: str | None = None,
        input_parameters: dict[str, Any] | None = None,
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
