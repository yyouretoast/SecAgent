"""Deterministic policy rule evaluators."""

from secagent.engine.loader import PolicyDefinition
from secagent.engine.rules.base import BaseRule
from secagent.engine.rules.goal_hijack import GoalHijackRule

RULE_TYPES: dict[str, type[BaseRule]] = {"goal_hijack": GoalHijackRule}


def build_rule(policy: PolicyDefinition) -> BaseRule:
    """Build a registered evaluator for one validated policy definition."""
    evaluator = RULE_TYPES.get(policy.rule_type)
    if evaluator is None:
        raise NotImplementedError(f"No evaluator registered for rule_type {policy.rule_type!r}")
    return evaluator(policy)


__all__ = ["GoalHijackRule", "RULE_TYPES", "build_rule"]
