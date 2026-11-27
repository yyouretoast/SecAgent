"""POL-ASI01-002: deterministic Toxic Flow (untrusted source -> privileged sink) detector."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values

_GENERIC_GATE_OPS = frozenset({"", "unknown_operation", "interrupt"})
_ENTITY_TOKEN_RE = re.compile(
    r"(?:https?://[^\s\"'<>]+"
    r"|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"|/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+"
    r"|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s\"'<>]*)?"
    r"|[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)+"
    r"|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{8,})"
)
_TRAILING_TOKEN_PUNCT = ".,;:)]}\"'"


def _is_clearing_gate(span: Mapping[str, Any], required_gate: Mapping[str, Any]) -> bool:
    return (
        not span.get("is_error", False)
        and span.get("span_type") == required_gate.get("span_type", "gate.hitl")
        and span.get("name") == required_gate.get("name", "approval_gate")
        and span.get("approval_granted") is required_gate.get("approval_granted", True)
    )


def _gate_operation(span: Mapping[str, Any]) -> str | None:
    params = span.get("input_parameters")
    if not isinstance(params, Mapping):
        return None
    op = str(params.get("operation") or "").strip()
    return op if op not in _GENERIC_GATE_OPS else None


class ToxicFlowRule(BaseRule):
    """Detect tainted data from read/net tools steering unapproved privileged sinks."""

    def __init__(self, policy: Any) -> None:
        super().__init__(policy)
        condition = policy.condition
        self._source_tiers = set(condition.get("taint_source_tiers", ()))
        self._sink_tiers = set(condition.get("sink_tiers", ()))
        self._sink_tools = set(condition.get("sink_tools", ()))
        self._required_gate = condition.get(
            "required_gate",
            {"span_type": "gate.hitl", "name": "approval_gate", "approval_granted": True},
        )
        self._patterns = [(raw, re.compile(raw)) for raw in condition.get("taint_patterns", ())]
        self._structural = bool(condition.get("structural_provenance", False))
        self._min_overlap = int(condition.get("min_overlap_length", 8))

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        active_taint: dict[str, Any] | None = None
        cleared_ops: set[str] = set()
        tainted_tokens: dict[str, dict[str, Any]] = {}
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping):
                continue

            if _is_clearing_gate(span, self._required_gate):
                gate_op = _gate_operation(span)
                if gate_op is None:
                    active_taint = None
                    tainted_tokens.clear()
                    cleared_ops.clear()
                else:
                    cleared_ops.add(gate_op)
                continue

            if span.get("span_type") != "tool.call":
                continue

            tier = span.get("permission_tier")
            name = str(span.get("name") or "")

            if tier in self._sink_tiers or name in self._sink_tools:
                if name in cleared_ops:
                    cleared_ops.discard(name)
                elif active_taint is not None:
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
                elif self._structural and tainted_tokens:
                    params = span.get("input_parameters", {})
                    for p_path, p_text in iter_string_values(params):
                        p_lower = p_text.lower()
                        matched_tok = next(
                            (tok for tok in tainted_tokens if tok in p_lower),
                            None,
                        )
                        if matched_tok is not None:
                            violations.append(
                                self.violation(
                                    span,
                                    {
                                        "reason": "structural_taint_propagation",
                                        "taint_source": dict(tainted_tokens[matched_tok]),
                                        "propagated_token": matched_tok,
                                        "sink_parameter_path": p_path,
                                        "sink_tool": name,
                                        "sink_tier": tier,
                                    },
                                )
                            )
                            break

            if tier in self._source_tiers:
                output = span.get("output_result")
                if output is not None:
                    added_structural = False
                    for path, text in iter_string_values(output):
                        hit: tuple[str, str] | None = None
                        for raw, pattern in self._patterns:
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
                            cleared_ops.clear()
                            break
                        if self._structural:
                            for raw_token in _ENTITY_TOKEN_RE.findall(text):
                                token = raw_token.rstrip(_TRAILING_TOKEN_PUNCT)
                                if len(token) >= self._min_overlap:
                                    tainted_tokens.setdefault(
                                        token.lower(),
                                        {
                                            "source_span_id": span.get("span_id"),
                                            "source_step_index": span.get("step_index"),
                                            "source_tool": name,
                                            "path": path,
                                        },
                                    )
                                    added_structural = True
                    if added_structural:
                        cleared_ops.clear()

        return violations
