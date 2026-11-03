"""Typed result models shared by the policy engine and reporting layer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
FailureAction = Literal["BLOCK_PR", "WARN"]


@dataclass(frozen=True, slots=True)
class PolicyViolation:
    """A single piece of deterministic evidence that a policy was violated."""

    rule_id: str
    rule_name: str
    owasp_category: str
    severity: Severity
    offending_span_id: str
    offending_step_index: int
    offending_tool_name: str
    failure_action: FailureAction
    evidence: dict[str, Any]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Aggregate result returned after every configured policy is evaluated."""

    status: Literal["PASS", "FAIL"]
    total_spans_evaluated: int
    violations: list[PolicyViolation]
    execution_time_ms: float

    @property
    def violations_detected(self) -> int:
        return len(self.violations)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "status": self.status,
            "total_spans_evaluated": self.total_spans_evaluated,
            "violations_detected": self.violations_detected,
            "violations": [violation.to_dict() for violation in self.violations],
            "execution_time_ms": self.execution_time_ms,
        }
