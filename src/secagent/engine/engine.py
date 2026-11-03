"""Policy orchestration for deterministic SecAgent trace verification."""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from secagent.engine.loader import PolicyLoader, PolicyRuleset
from secagent.engine.models import EvaluationResult
from secagent.engine.rules import (
    CircuitBreakerRule,
    ContextPrivilegeRule,
    FieldScopeRule,
    GoalHijackRule,
    NetworkEgressRule,
    ParameterRegexRule,
    PredecessorGateRule,
)
from secagent.engine.rules.base import BaseRule

RULE_TYPES: dict[str, type[BaseRule]] = {
    "goal_hijack": GoalHijackRule,
    "predecessor_gate": PredecessorGateRule,
    "context_privilege": ContextPrivilegeRule,
    "parameter_regex_blocklist": ParameterRegexRule,
    "field_scope_allowlist": FieldScopeRule,
    "circuit_breaker": CircuitBreakerRule,
    "network_egress_allowlist": NetworkEgressRule,
}


class PolicyEngine:
    """Evaluate standardized trace documents against a validated policy ruleset."""

    def __init__(
        self,
        policies: str | Path | PolicyRuleset = "policies/security_rules.yaml",
    ) -> None:
        self.ruleset = (
            policies if isinstance(policies, PolicyRuleset) else PolicyLoader(policies).load()
        )
        self.rules = [RULE_TYPES[policy.rule_type](policy) for policy in self.ruleset.policies]

    def evaluate(self, trace: Mapping[str, Any]) -> EvaluationResult:
        if not isinstance(trace.get("spans"), list):
            raise ValueError("Trace must contain a 'spans' list")

        started = time.perf_counter()
        violations = [violation for rule in self.rules for violation in rule.evaluate(trace)]
        blocking = any(item.failure_action == "BLOCK_PR" for item in violations)
        elapsed_ms = (time.perf_counter() - started) * 1000
        return EvaluationResult(
            status="FAIL" if blocking else "PASS",
            total_spans_evaluated=len(trace["spans"]),
            violations=violations,
            execution_time_ms=round(elapsed_ms, 3),
        )

    def evaluate_file(self, trace_path: str | Path) -> EvaluationResult:
        path = Path(trace_path)
        with path.open(encoding="utf-8") as handle:
            trace = json.load(handle)
        if not isinstance(trace, dict):
            raise ValueError(f"Trace file must contain a JSON object: {path}")
        return self.evaluate(trace)
