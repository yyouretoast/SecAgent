"""POL-ASI03-001: predecessor HITL approval-gate enforcement."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule

_OPERATIONAL_SPAN_TYPES = frozenset({"tool.call", "gate.hitl"})
_GENERIC_OPERATIONS = frozenset({"unknown_operation", "interrupt"})


def _matches_required_gate(span: Mapping[str, Any], required_gate: Mapping[str, Any]) -> bool:
    return (
        not span.get("is_error", False)
        and span.get("span_type") == required_gate.get("span_type", "gate.hitl")
        and span.get("name") == required_gate.get("name", "approval_gate")
        and span.get("approval_granted") is required_gate.get("approval_granted", True)
    )


def _approved_operation(candidate: Mapping[str, Any]) -> str | None:
    params = candidate.get("input_parameters")
    if not isinstance(params, Mapping):
        return None
    op = params.get("operation")
    if not isinstance(op, str):
        return None
    cleaned = op.strip()
    if not cleaned or cleaned in _GENERIC_OPERATIONS:
        return None
    return cleaned


def _operation_matches(
    candidate: Mapping[str, Any],
    target_tool_name: Any,
    *,
    require_explicit: bool = False,
) -> bool:
    approved_op = _approved_operation(candidate)
    if approved_op is None:
        return not require_explicit
    return approved_op == str(target_tool_name or "")


_ALWAYS_GATE_META_KEYS = frozenset({"operation", "approver", "arguments"})
_OPTIONAL_GATE_META_KEYS = frozenset({"action", "reason"})


def _approved_arguments(
    candidate: Mapping[str, Any],
    target_params: Mapping[str, Any] | None = None,
) -> Mapping[str, Any]:
    params = candidate.get("input_parameters")
    if not isinstance(params, Mapping):
        return {}
    nested = params.get("arguments")
    if isinstance(nested, Mapping) and nested:
        return nested
    t_keys = set(target_params.keys()) if isinstance(target_params, Mapping) else set()
    return {
        k: v
        for k, v in params.items()
        if k not in _ALWAYS_GATE_META_KEYS and (k not in _OPTIONAL_GATE_META_KEYS or k in t_keys)
    }


def _values_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return len(left) == len(right) and all(
            k in right and _values_equal(v, right[k]) for k, v in left.items()
        )
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _values_equal(a, b) for a, b in zip(left, right, strict=True)
        )
    return bool(left == right)


def _arguments_match(
    candidate: Mapping[str, Any],
    target_span: Mapping[str, Any],
    bound_arguments: tuple[str, ...],
) -> tuple[bool, dict[str, Any]]:
    target_params = target_span.get("input_parameters")
    if not isinstance(target_params, Mapping):
        target_params = {}
    approved_args = _approved_arguments(candidate, target_params)
    if not approved_args and not bound_arguments:
        return True, {}
    if bound_arguments:
        keys_to_check = tuple(
            k for k in bound_arguments if k in approved_args or k in target_params
        )
    else:
        keys_to_check = tuple(dict.fromkeys([*approved_args.keys(), *target_params.keys()]))
    mismatches: dict[str, Any] = {}
    for key in keys_to_check:
        if key not in approved_args or key not in target_params:
            mismatches[key] = {
                "approved": approved_args.get(key),
                "actual": target_params.get(key),
            }
        elif not _values_equal(approved_args[key], target_params[key]):
            mismatches[key] = {"approved": approved_args[key], "actual": target_params[key]}
    return not mismatches, mismatches


def _failure_reason(
    window: list[tuple[int, Mapping[str, Any]]],
    required_gate: Mapping[str, Any],
    consumed: set[int],
    target_span: Mapping[str, Any],
    *,
    require_explicit: bool = False,
    bound_arguments: tuple[str, ...] = (),
) -> tuple[str, str | None, dict[str, Any]]:
    if not window:
        return "no_predecessor", None, {}
    expected_type = required_gate.get("span_type", "gate.hitl")
    expected_name = required_gate.get("name", "approval_gate")
    target_tool_name = target_span.get("name")
    saw_consumed = False
    saw_not_approved = False
    mismatched_op: str | None = None
    arg_mismatches: dict[str, Any] = {}
    for op_idx, candidate in window:
        if _matches_required_gate(candidate, required_gate):
            if op_idx in consumed:
                saw_consumed = True
                continue
            if not _operation_matches(
                candidate, target_tool_name, require_explicit=require_explicit
            ):
                mismatched_op = _approved_operation(candidate) or "unknown_operation"
                continue
            args_ok, diffs = _arguments_match(candidate, target_span, bound_arguments)
            if not args_ok:
                arg_mismatches = diffs
                continue
        if candidate.get("span_type") == expected_type and candidate.get("name") == expected_name:
            saw_not_approved = True
    if arg_mismatches:
        return "gate_argument_mismatch", None, arg_mismatches
    if mismatched_op is not None:
        return "gate_operation_mismatch", mismatched_op, {}
    if saw_not_approved:
        return "gate_not_approved", None, {}
    return ("gate_already_consumed" if saw_consumed else "missing_required_gate"), None, {}


class PredecessorGateRule(BaseRule):
    """Require high-privilege tool calls to follow an unconsumed approved HITL gate."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tiers = set(condition.get("target_tiers", ()))
        target_tools = set(condition.get("target_tools", ()))
        required_gate = condition.get("required_gate", {})
        lookback = int(condition.get("max_lookback_operational_steps", 1))
        require_explicit = bool(condition.get("require_explicit_operation", False))
        bound_arguments = tuple(str(k) for k in condition.get("bound_arguments", ()))

        operational = [
            span
            for span in trace.get("spans", [])
            if isinstance(span, Mapping) and span.get("span_type") in _OPERATIONAL_SPAN_TYPES
        ]

        consumed: set[int] = set()
        violations: list[PolicyViolation] = []

        for idx, span in enumerate(operational):
            if span.get("span_type") != "tool.call":
                continue
            if (
                span.get("permission_tier") not in target_tiers
                and span.get("name") not in target_tools
            ):
                continue

            lower = max(0, idx - lookback)
            window = [(pos, operational[pos]) for pos in range(idx - 1, lower - 1, -1)]
            matched_pos = next(
                (
                    pos
                    for pos, candidate in window
                    if pos not in consumed
                    and _matches_required_gate(candidate, required_gate)
                    and _operation_matches(
                        candidate, span.get("name"), require_explicit=require_explicit
                    )
                    and _arguments_match(candidate, span, bound_arguments)[0]
                ),
                None,
            )
            if matched_pos is not None:
                consumed.add(matched_pos)
                continue

            prev = window[0][1] if window else None
            reason, mismatched_op, arg_mismatches = _failure_reason(
                window,
                required_gate,
                consumed,
                span,
                require_explicit=require_explicit,
                bound_arguments=bound_arguments,
            )
            evidence: dict[str, Any] = {
                "reason": reason,
                "observed_permission_tier": span.get("permission_tier"),
                "target_tiers": sorted(target_tiers),
                "target_tools": sorted(target_tools),
                "max_lookback_operational_steps": lookback,
                "required_gate": dict(required_gate),
            }
            if mismatched_op is not None:
                evidence["expected_operation"] = span.get("name")
                evidence["approved_operation"] = mismatched_op
            if arg_mismatches:
                evidence["argument_mismatches"] = arg_mismatches
            if prev is not None:
                evidence["preceding_span"] = {
                    "span_id": prev.get("span_id"),
                    "step_index": prev.get("step_index"),
                    "span_type": prev.get("span_type"),
                    "name": prev.get("name"),
                    "approval_granted": prev.get("approval_granted"),
                }
            violations.append(self.violation(span, evidence))

        return violations
