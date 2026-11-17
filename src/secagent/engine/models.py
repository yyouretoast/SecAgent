"""Typed result models shared by deterministic policy evaluators."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import zip_longest
from typing import Any, Literal


@dataclass(frozen=True, slots=True)
class PolicyViolation:
    """A single piece of deterministic evidence that a policy was violated."""

    rule_id: str
    rule_name: str
    owasp_category: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    offending_span_id: str
    offending_step_index: int
    offending_tool_name: str
    failure_action: Literal["BLOCK_PR", "WARN"]
    evidence: dict[str, Any]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Aggregate result returned by PolicyEngine across one or more traces."""

    status: Literal["PASS", "FAIL"]
    total_spans_evaluated: int
    violations: list[PolicyViolation]
    execution_time_ms: float
    violation_scenario_ids: tuple[str | None, ...] = ()

    @property
    def has_blocking_violations(self) -> bool:
        """Return True if any violation requires blocking the PR gate."""
        return any(violation.failure_action == "BLOCK_PR" for violation in self.violations)

    def serialized_violations(self) -> list[dict[str, Any]]:
        """Serialize violations with optional per-trace scenario attribution."""
        records: list[dict[str, Any]] = []
        for violation, scenario_id in zip_longest(
            self.violations,
            self.violation_scenario_ids,
            fillvalue=None,
        ):
            if violation is None:
                continue
            item = violation.to_dict()
            if scenario_id:
                item["scenario_id"] = scenario_id
            records.append(item)
        return records

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable evaluation summary."""
        return {
            "status": self.status,
            "total_spans_evaluated": self.total_spans_evaluated,
            "violations_detected": len(self.violations),
            "violations": self.serialized_violations(),
            "execution_time_ms": round(self.execution_time_ms, 3),
        }
