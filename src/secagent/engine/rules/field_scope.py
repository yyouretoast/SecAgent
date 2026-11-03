"""POL-ASI06-001: need-to-know sensitive field enforcement."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule


def _field_tokens(value: Any) -> set[str]:
    """Collect case-insensitive field names from nested keys and string values."""
    tokens: set[str] = set()
    if isinstance(value, str):
        tokens.add(value.casefold())
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            tokens.add(str(key).casefold())
            tokens.update(_field_tokens(nested))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            tokens.update(_field_tokens(nested))
    return tokens


class FieldScopeRule(BaseRule):
    """Detect restricted PII fields in database projections and results."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        if trace.get("task_context") != condition.get("task_context"):
            return []

        target_tools = set(condition.get("target_tools", []))
        target_locations = set(condition.get("target_locations", ["input_parameters"]))
        parameter_key = str(condition.get("parameter_key", "fields"))
        forbidden = {str(item).casefold() for item in condition.get("forbidden_fields", [])}
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue
            if target_tools and span.get("name") not in target_tools:
                continue

            observed: set[str] = set()
            if "input_parameters" in target_locations:
                inputs = span.get("input_parameters", {})
                if isinstance(inputs, Mapping) and parameter_key in inputs:
                    observed.update(_field_tokens(inputs[parameter_key]))
            if "output_result" in target_locations:
                observed.update(_field_tokens(span.get("output_result")))

            detected = sorted(observed & forbidden)
            if detected:
                violations.append(
                    self.violation(
                        span,
                        {
                            "forbidden_fields_detected": detected,
                            "target_locations": sorted(target_locations),
                        },
                    )
                )

        return violations
