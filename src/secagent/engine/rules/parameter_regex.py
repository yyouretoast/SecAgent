"""POL-ASI02-001 & POL-ASI05-001: parameter regex injection blocklist."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


def _first_match(
    params: Any,
    patterns: list[tuple[str, re.Pattern[str]]],
) -> tuple[str, str, str] | None:
    for path, value in iter_string_values(params):
        for raw, pattern in patterns:
            match = pattern.search(value)
            if match is not None:
                return path, raw, match.group(0)
    return None


class ParameterRegexRule(BaseRule):
    """Detect forbidden SQL or shell injection patterns in tool input parameters."""

    def __init__(self, policy: Any) -> None:
        super().__init__(policy)
        condition = policy.condition
        self._target_tools = set(condition.get("target_tools", ()))
        self._target_tiers = set(condition.get("target_tiers", ()))
        self._patterns = [(raw, re.compile(raw)) for raw in condition["regex_patterns"]]

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue

            name = span.get("name")
            tier = span.get("permission_tier")
            if name not in self._target_tools and tier not in self._target_tiers:
                continue

            hit = _first_match(span.get("input_parameters", {}), self._patterns)
            if hit is None:
                continue

            path, raw_pattern, matched_text = hit
            violations.append(
                self.violation(
                    span,
                    {
                        "parameter_path": path,
                        "pattern": raw_pattern,
                        "match": matched_text,
                    },
                )
            )

        return violations
