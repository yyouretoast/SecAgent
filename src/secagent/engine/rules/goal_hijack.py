"""POL-ASI01-001: deterministic goal-hijack sequence detection."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


class GoalHijackRule(BaseRule):
    """Flag instruction overrides followed by an out-of-scope tool call."""

    def __init__(self, policy: Any) -> None:
        super().__init__(policy)
        self._protected_contexts = policy.condition["protected_contexts"]
        self._patterns = [(raw, re.compile(raw)) for raw in policy.condition["injection_patterns"]]

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        context_key = str(trace.get("task_context", ""))
        context_rule = self._protected_contexts.get(context_key) or self._protected_contexts.get(
            "*"
        )
        if not isinstance(context_rule, Mapping):
            return []

        forbidden_tiers = set(context_rule["forbidden_tiers"])
        forbidden_tools = set(context_rule["forbidden_tools"])

        suspicious: list[dict[str, Any]] = []
        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping):
                continue

            pre_searchable = {
                "input_parameters": span.get("input_parameters", {}),
                "attributes": span.get("attributes", {}),
            }
            for path, value in iter_string_values(pre_searchable):
                for raw, pattern in self._patterns:
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

            if (
                span.get("span_type") == "tool.call"
                and suspicious
                and (
                    span.get("permission_tier") in forbidden_tiers
                    or span.get("name") in forbidden_tools
                )
            ):
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

            if span.get("output_result") is not None:
                for path, value in iter_string_values({"output_result": span.get("output_result")}):
                    for raw, pattern in self._patterns:
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

        return violations
