"""POL-ASI01-002: deterministic Toxic Flow (untrusted source -> privileged sink) detector."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values


def _is_clearing_gate(span: Mapping[str, Any], required_gate: Mapping[str, Any]) -> bool:
    return (
        span.get("span_type") == required_gate.get("span_type", "gate.hitl")
        and span.get("name") == required_gate.get("name", "approval_gate")
        and span.get("approval_granted") is required_gate.get("approval_granted", True)
    )


class ToxicFlowRule(BaseRule):
    """Detect tainted data from read/net tools steering unapproved privileged sinks."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        source_tiers = set(condition.get("taint_source_tiers", ()))
        sink_tiers = set(condition.get("sink_tiers", ()))
        sink_tools = set(condition.get("sink_tools", ()))
        required_gate = condition.get(
            "required_gate",
            {"span_type": "gate.hitl", "name": "approval_gate", "approval_granted": True},
        )
        patterns = [(raw, re.compile(raw)) for raw in condition.get("taint_patterns", ())]

        active_taint: dict[str, Any] | None = None
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping):
                continue

            if _is_clearing_gate(span, required_gate):
                active_taint = None
                continue

            if span.get("span_type") != "tool.call":
                continue

            tier = span.get("permission_tier")
            name = span.get("name")

            if active_taint is not None and (tier in sink_tiers or name in sink_tools):
                violations.append(
                    self.violation(
                        span,
                        {
                            "taint_source": dict(active_taint),
                            "sink_tool": name,
                            "sink_tier": tier,
                        },
                    )
                )

            if tier in source_tiers:
                output = span.get("output_result")
                if output is not None:
                    for path, text in iter_string_values(output):
                        hit: tuple[str, str] | None = None
                        for raw, pattern in patterns:
                            match = pattern.search(text)
                            if match is not None:
                                hit = (raw, match.group(0))
                                break
                        if hit is not None:
                            active_taint = {
                                "source_span_id": span.get("span_id"),
                                "source_step_index": span.get("step_index"),
                                "source_tool": name,
                                "path": path,
                                "pattern": hit[0],
                                "match": hit[1],
                            }
                            break

        return violations
