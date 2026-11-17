"""Deterministic multi-rule evaluation engine."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from secagent.engine.loader import PolicyLoader, PolicyRuleset
from secagent.engine.models import EvaluationResult, PolicyViolation
from secagent.engine.rules import (
    BaseRule,
    CircuitBreakerRule,
    ContextPrivilegeRule,
    FieldScopeRule,
    GoalHijackRule,
    NetworkEgressRule,
    ParameterRegexRule,
    PredecessorGateRule,
)

RULE_REGISTRY: dict[str, type[BaseRule]] = {
    "goal_hijack": GoalHijackRule,
    "predecessor_gate": PredecessorGateRule,
    "context_privilege": ContextPrivilegeRule,
    "parameter_regex_blocklist": ParameterRegexRule,
    "field_scope_allowlist": FieldScopeRule,
    "circuit_breaker": CircuitBreakerRule,
    "network_egress_allowlist": NetworkEgressRule,
}


class PolicyEngine:
    """Evaluate execution traces deterministically against loaded security policies."""

    def __init__(
        self,
        ruleset: PolicyRuleset | None = None,
        *,
        policy_path: str | Path | None = None,
    ) -> None:
        self.ruleset = ruleset if ruleset is not None else PolicyLoader(policy_path).load()
        self.rules: list[BaseRule] = [
            RULE_REGISTRY[policy.rule_type](policy)
            for policy in self.ruleset.policies
            if policy.rule_type in RULE_REGISTRY
        ]

    def evaluate_trace(self, trace: Mapping[str, Any]) -> EvaluationResult:
        """Evaluate a single trace document across all configured rules."""
        return self.evaluate_traces([trace])

    def evaluate_traces(self, traces: Sequence[Mapping[str, Any]]) -> EvaluationResult:
        """Evaluate a sequence of traces and return an aggregate EvaluationResult."""
        started = time.perf_counter()
        violations: list[PolicyViolation] = []
        scenario_ids: list[str | None] = []
        total_spans = 0

        for trace in traces:
            spans = trace.get("spans", ())
            if isinstance(spans, Sequence) and not isinstance(spans, (str, bytes, bytearray)):
                total_spans += len(spans)

            raw_sid = trace.get("scenario_id")
            scenario_id = str(raw_sid) if raw_sid else None
            for rule in self.rules:
                found = rule.evaluate(trace)
                violations.extend(found)
                scenario_ids.extend(scenario_id for _ in found)

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        status = "FAIL" if violations else "PASS"
        return EvaluationResult(
            status=status,
            total_spans_evaluated=total_spans,
            violations=violations,
            execution_time_ms=elapsed_ms,
            violation_scenario_ids=tuple(scenario_ids),
        )
