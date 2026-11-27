"""POL-ASI06-001: need-to-know field scope allowlist verifier."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


def _iter_mapping_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_iter_mapping_keys(nested))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            keys.extend(_iter_mapping_keys(nested))
    return keys


def _matched_forbidden_fields(
    target: Any,
    forbidden_patterns: dict[str, re.Pattern[str]],
) -> set[str]:
    hits: set[str] = set()
    for key in _iter_mapping_keys(target):
        lowered = key.strip().lower()
        if lowered in forbidden_patterns:
            hits.add(lowered)
            continue
        for field_key, pattern in forbidden_patterns.items():
            if pattern.search(lowered) is not None:
                hits.add(field_key)
    for _, text in iter_string_values(target):
        for field_key, pattern in forbidden_patterns.items():
            if pattern.search(text) is not None:
                hits.add(field_key)
    return hits


class FieldScopeRule(BaseRule):
    """Detect forbidden PII or credential fields requested or returned by scoped tools."""

    def __init__(self, policy: Any) -> None:
        super().__init__(policy)
        condition = policy.condition
        self._expected_context = str(condition["task_context"])
        self._target_tools = set(condition.get("target_tools", ()))
        self._target_tiers = set(condition.get("target_tiers", ()))
        self._parameter_key = str(condition.get("parameter_key", "fields"))
        self._target_locations = tuple(
            condition.get("target_locations", ("input_parameters", "output_result"))
        )
        self._forbidden_map = {str(f).lower(): str(f) for f in condition["forbidden_fields"]}
        self._forbidden_patterns = {}
        for key in self._forbidden_map:
            escaped = re.escape(key)
            # Allow snake_case compound keys like user_ssn while preserving shipping_pin.
            boundary = r"[A-Za-z0-9]" if (len(key) >= 4 or key == "ssn") else r"[A-Za-z0-9_]"
            self._forbidden_patterns[key] = re.compile(
                rf"(?:(?<!{boundary}){escaped}(?!{boundary})|REDACTED_{escaped}(?![A-Za-z0-9_]))",
                re.IGNORECASE,
            )

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        observed_context = str(trace.get("task_context", ""))
        if self._expected_context != "*" and observed_context != self._expected_context:
            return []

        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue

            if (
                span.get("name") not in self._target_tools
                and span.get("permission_tier") not in self._target_tiers
            ):
                continue

            matched_by_location: dict[str, list[str]] = {}
            all_hits: set[str] = set()

            if "input_parameters" in self._target_locations:
                params = span.get("input_parameters")
                if isinstance(params, Mapping):
                    hits = _matched_forbidden_fields(params, self._forbidden_patterns)
                    if hits:
                        resolved = sorted(self._forbidden_map[h] for h in hits)
                        matched_by_location["input_parameters"] = resolved
                        all_hits.update(resolved)

            if "output_result" in self._target_locations and span.get("output_result") is not None:
                hits = _matched_forbidden_fields(
                    span.get("output_result"), self._forbidden_patterns
                )
                if hits:
                    resolved = sorted(self._forbidden_map[h] for h in hits)
                    matched_by_location["output_result"] = resolved
                    all_hits.update(resolved)

            if "attributes" in self._target_locations and span.get("attributes") is not None:
                hits = _matched_forbidden_fields(span.get("attributes"), self._forbidden_patterns)
                if hits:
                    resolved = sorted(self._forbidden_map[h] for h in hits)
                    matched_by_location["attributes"] = resolved
                    all_hits.update(resolved)

            if not all_hits:
                continue

            violations.append(
                self.violation(
                    span,
                    {
                        "task_context": observed_context,
                        "parameter_key": self._parameter_key,
                        "forbidden_fields_found": sorted(all_hits),
                        "locations": matched_by_location,
                    },
                )
            )

        return violations
