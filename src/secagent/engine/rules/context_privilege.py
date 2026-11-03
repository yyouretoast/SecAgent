"""POL-ASI03-002: task-context privilege boundary enforcement."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule


class ContextPrivilegeRule(BaseRule):
    """Forbid mutating or privileged tools in a read-only task context."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        expected_context = condition.get("task_context")
        if trace.get("task_context") != expected_context:
            return []

        forbidden_tiers = set(condition.get("forbidden_tiers", []))
        forbidden_tools = set(condition.get("forbidden_tools", []))
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue
            tier = span.get("permission_tier")
            tool = span.get("name")
            if tier not in forbidden_tiers and tool not in forbidden_tools:
                continue
            violations.append(
                self.violation(
                    span,
                    {
                        "task_context": expected_context,
                        "observed_permission_tier": tier,
                        "forbidden_tiers": sorted(forbidden_tiers),
                        "forbidden_tools": sorted(forbidden_tools),
                    },
                )
            )

        return violations
