"""POL-ASI08-001: runaway step and repeated-call detection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, operational_spans


class CircuitBreakerRule(BaseRule):
    """Detect traces that exceed total-step or consecutive-call limits."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        max_steps = int(condition.get("max_total_steps", 10))
        max_consecutive = int(condition.get("max_consecutive_identical_tools", 2))
        operations = operational_spans(trace)
        violations: list[PolicyViolation] = []

        if len(operations) > max_steps:
            offending = operations[max_steps] if len(operations) > max_steps else None
            violations.append(
                self.violation(
                    offending,
                    {
                        "reason": "max_total_steps_exceeded",
                        "observed_total_steps": len(operations),
                        "max_total_steps": max_steps,
                    },
                )
            )

        previous_name: str | None = None
        run_length = 0
        reported_run = False
        for span in operations:
            if span.get("span_type") != "tool.call":
                previous_name = None
                run_length = 0
                reported_run = False
                continue

            name = str(span.get("name", ""))
            if name == previous_name:
                run_length += 1
            else:
                previous_name = name
                run_length = 1
                reported_run = False

            if run_length > max_consecutive and not reported_run:
                violations.append(
                    self.violation(
                        span,
                        {
                            "reason": "max_consecutive_identical_tools_exceeded",
                            "tool_name": name,
                            "observed_consecutive_calls": run_length,
                            "max_consecutive_identical_tools": max_consecutive,
                        },
                    )
                )
                reported_run = True

        return violations
