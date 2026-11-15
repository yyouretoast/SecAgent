"""POL-ASI01-001: deterministic goal-hijack sequence detection."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


class GoalHijackRule(BaseRule):
    """Flag instruction overrides followed by an out-of-scope tool call."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        protected_contexts = condition["protected_contexts"]
        context_rule = protected_contexts.get(str(trace.get("task_context", "")))
        if not isinstance(context_rule, Mapping):
            return []

        forbidden_tiers = set(context_rule["forbidden_tiers"])
        forbidden_tools = set(context_rule["forbidden_tools"])
        patterns = [(raw, re.compile(raw)) for raw in condition["injection_patterns"]]

        suspicious: list[dict[str, Any]] = []
        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping):
                continue

            searchable = {
                "input_parameters": span.get("input_parameters", {}),
                "output_result": span.get("output_result"),
                "attributes": span.get("attributes", {}),
            }
            for path, value in iter_string_values(searchable):
                for raw, pattern in patterns:
                    match = pattern.search(value)
                    if match is not None:
                        suspicious.append(
                            {
                                "span_id": span.get("span_id"),
                                "step_index": span.get("step_index"),
                                "path": path,
                                "pattern": raw,
                                "match": match.group(0),
                            }
                        )
                        break

            if span.get("span_type") != "tool.call" or not suspicious:
                continue
            if (
                span.get("permission_tier") not in forbidden_tiers
                and span.get("name") not in forbidden_tools
            ):
                continue

            violations.append(
                self.violation(
                    span,
                    {
                        "task_context": trace.get("task_context"),
                        "suspicious_instruction": suspicious[-1],
                        "observed_permission_tier": span.get("permission_tier"),
                        "forbidden_tiers": sorted(forbidden_tiers),
                        "forbidden_tools": sorted(forbidden_tools),
                    },
                )
            )

        return violations
