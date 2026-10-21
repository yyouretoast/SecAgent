"""SecAgent Invariant Verification Engine package."""

from dataclasses import asdict, dataclass
from typing import Any, Literal


@dataclass
class PolicyViolation:
    """Diagnostic violation record emitted when an invariant policy is breached."""

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
        """Serialize violation to dictionary."""
        return asdict(self)


@dataclass
class EvaluationResult:
    """Summary verdict emitted by the Policy Verification Engine."""

    status: Literal["PASS", "FAIL"]
    total_spans_evaluated: int
    violations: list[PolicyViolation]
    execution_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        """Serialize evaluation result to dictionary."""
        return {
            "status": self.status,
            "total_spans_evaluated": self.total_spans_evaluated,
            "violations": [v.to_dict() for v in self.violations],
            "execution_time_ms": self.execution_time_ms,
        }


__all__ = ["EvaluationResult", "PolicyViolation"]
