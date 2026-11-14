"""Typed result models shared by deterministic policy evaluators."""

from __future__ import annotations

from dataclasses import asdict, dataclass
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
