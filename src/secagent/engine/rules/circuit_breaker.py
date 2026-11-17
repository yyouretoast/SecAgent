"""POL-ASI08-001: runaway execution and consecutive-tool circuit breaker."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule

_OPERATIONAL_SPAN_TYPES = frozenset({"tool.call", "gate.hitl"})


class CircuitBreakerRule(BaseRule):
    """Enforce maximum operational step counts and consecutive identical tool limits."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        max_total_steps = int(condition["max_total_steps"])
        max_consecutive = int(condition["max_consecutive_identical_tools"])

        operational = [
            span
            for span in trace.get("spans", [])
            if isinstance(span, Mapping) and span.get("span_type") in _OPERATIONAL_SPAN_TYPES
        ]

        violations: list[PolicyViolation] = []
        if len(operational) > max_total_steps:
            breach_span = operational[max_total_steps]
            violations.append(
                self.violation(
                    breach_span,
                    {
                        "reason": "max_total_steps_exceeded",
                        "total_operational_steps": len(operational),
                        "max_total_steps": max_total_steps,
                    },
                )
            )

        last_tool: str | None = None
        streak = 0
        for span in operational:
            if span.get("span_type") != "tool.call":
                last_tool = None
                streak = 0
                continue

            tool_name = str(span.get("name", ""))
            if tool_name == last_tool:
                streak += 1
            else:
                last_tool = tool_name
                streak = 1

            if streak == max_consecutive + 1:
                violations.append(
                    self.violation(
                        span,
                        {
                            "reason": "max_consecutive_identical_tools_exceeded",
                            "tool_name": tool_name,
                            "consecutive_count": streak,
                            "max_consecutive_identical_tools": max_consecutive,
                        },
                    )
                )

        return violations
