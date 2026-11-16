"""POL-ASI03-001: predecessor HITL approval-gate enforcement."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule

_OPERATIONAL_SPAN_TYPES = frozenset({"tool.call", "gate.hitl"})


def _matches_required_gate(span: Mapping[str, Any], required_gate: Mapping[str, Any]) -> bool:
    return (
        span.get("span_type") == required_gate.get("span_type", "gate.hitl")
        and span.get("name") == required_gate.get("name", "approval_gate")
        and span.get("approval_granted") is required_gate.get("approval_granted", True)
    )


def _failure_reason(
    window: list[tuple[int, Mapping[str, Any]]],
    required_gate: Mapping[str, Any],
    consumed: set[int],
) -> str:
    if not window:
        return "no_predecessor"
    expected_type = required_gate.get("span_type", "gate.hitl")
    expected_name = required_gate.get("name", "approval_gate")
    saw_consumed = False
    for op_idx, candidate in window:
        if _matches_required_gate(candidate, required_gate) and op_idx in consumed:
            saw_consumed = True
            continue
        if candidate.get("span_type") == expected_type and candidate.get("name") == expected_name:
            return "gate_not_approved"
    return "gate_already_consumed" if saw_consumed else "missing_required_gate"


class PredecessorGateRule(BaseRule):
    """Require high-privilege tool calls to follow an unconsumed approved HITL gate."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tiers = set(condition.get("target_tiers", ()))
        target_tools = set(condition.get("target_tools", ()))
        required_gate = condition.get("required_gate", {})
        lookback = int(condition.get("max_lookback_operational_steps", 1))

        operational = [
            span
            for span in trace.get("spans", [])
            if isinstance(span, Mapping) and span.get("span_type") in _OPERATIONAL_SPAN_TYPES
        ]

        consumed: set[int] = set()
        violations: list[PolicyViolation] = []

        for idx, span in enumerate(operational):
            if span.get("span_type") != "tool.call":
                continue
            if (
                span.get("permission_tier") not in target_tiers
                and span.get("name") not in target_tools
            ):
                continue

            lower = max(0, idx - lookback)
            window = [(pos, operational[pos]) for pos in range(idx - 1, lower - 1, -1)]
            matched_pos = next(
                (
                    pos
                    for pos, candidate in window
                    if pos not in consumed and _matches_required_gate(candidate, required_gate)
                ),
                None,
            )
            if matched_pos is not None:
                consumed.add(matched_pos)
                continue

            prev = window[0][1] if window else None
            evidence: dict[str, Any] = {
                "reason": _failure_reason(window, required_gate, consumed),
                "observed_permission_tier": span.get("permission_tier"),
                "target_tiers": sorted(target_tiers),
                "target_tools": sorted(target_tools),
                "max_lookback_operational_steps": lookback,
                "required_gate": dict(required_gate),
            }
            if prev is not None:
                evidence["preceding_span"] = {
                    "span_id": prev.get("span_id"),
                    "step_index": prev.get("step_index"),
                    "span_type": prev.get("span_type"),
                    "name": prev.get("name"),
                    "approval_granted": prev.get("approval_granted"),
                }
            violations.append(self.violation(span, evidence))

        return violations
