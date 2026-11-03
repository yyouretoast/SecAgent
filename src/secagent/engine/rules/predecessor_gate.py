"""POL-ASI03-001: approved human gate predecessor enforcement."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, operational_spans


class PredecessorGateRule(BaseRule):
    """Require a recent approved gate before payment or admin tools."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tiers = set(condition.get("target_tiers", []))
        target_tools = set(condition.get("target_tools", []))
        gate = condition.get("required_gate", {})
        max_lookback = max(int(condition.get("max_lookback_operational_steps", 1)), 1)
        spans = operational_spans(trace)
        violations: list[PolicyViolation] = []

        for index, span in enumerate(spans):
            if span.get("span_type") != "tool.call":
                continue
            if (
                span.get("permission_tier") not in target_tiers
                and span.get("name") not in target_tools
            ):
                continue

            previous = spans[max(0, index - max_lookback) : index]
            approved = any(
                candidate.get("span_type") == gate.get("span_type", "gate.hitl")
                and candidate.get("name") == gate.get("name", "approval_gate")
                and candidate.get("approval_granted") is gate.get("approval_granted", True)
                for candidate in previous
            )
            if approved:
                continue

            violations.append(
                self.violation(
                    span,
                    {
                        "required_gate": gate,
                        "max_lookback_operational_steps": max_lookback,
                        "previous_operational_spans": [
                            {
                                "span_id": item.get("span_id"),
                                "span_type": item.get("span_type"),
                                "name": item.get("name"),
                                "approval_granted": item.get("approval_granted"),
                            }
                            for item in previous
                        ],
                    },
                )
            )

        return violations
