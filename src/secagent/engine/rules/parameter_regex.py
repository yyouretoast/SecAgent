"""POL-ASI02-001 / POL-ASI05-001: nested parameter regex checks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


class ParameterRegexRule(BaseRule):
    """Detect configured SQL and shell payloads in nested tool parameters."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tools = set(condition.get("target_tools", []))
        patterns = [(raw, re.compile(raw)) for raw in condition.get("regex_patterns", [])]
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue
            if target_tools and span.get("name") not in target_tools:
                continue

            for path, value in iter_string_values(
                span.get("input_parameters", {}), "$.input_parameters"
            ):
                for raw_pattern, pattern in patterns:
                    match = pattern.search(value)
                    if match is None:
                        continue
                    violations.append(
                        self.violation(
                            span,
                            {
                                "argument_path": path,
                                "matched_pattern": raw_pattern,
                                "matched_substring": match.group(0),
                            },
                        )
                    )
                    break

        return violations
