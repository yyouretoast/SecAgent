"""Base interface and utilities used by deterministic policy rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from secagent.engine.loader import PolicyDefinition
from secagent.engine.models import PolicyViolation


class BaseRule(ABC):
    """Common interface implemented by every policy rule evaluator."""

    def __init__(self, policy: PolicyDefinition) -> None:
        self.policy = policy

    @abstractmethod
    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        """Return deterministic violations found in ``trace``."""

    def violation(
        self,
        span: Mapping[str, Any] | None,
        evidence: dict[str, Any],
        *,
        tool_name: str | None = None,
    ) -> PolicyViolation:
        span = span or {}
        return PolicyViolation(
            rule_id=self.policy.id,
            rule_name=self.policy.name,
            owasp_category=self.policy.owasp_category,
            severity=self.policy.severity,
            offending_span_id=str(span.get("span_id", "trace")),
            offending_step_index=int(span.get("step_index", -1)),
            offending_tool_name=tool_name or str(span.get("name", "trace")),
            failure_action=self.policy.failure_action,
            evidence=evidence,
            remediation=self.policy.remediation,
        )


def iter_string_values(value: Any, path: str = "$") -> Iterator[tuple[str, str]]:
    """Yield ``(path, value)`` for every nested string without mutating input."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            yield from iter_string_values(nested, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            yield from iter_string_values(nested, f"{path}[{index}]")


def operational_spans(trace: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return tool and approval spans in their recorded order."""
    return [
        span
        for span in trace.get("spans", [])
        if isinstance(span, Mapping) and span.get("span_type") in {"tool.call", "gate.hitl"}
    ]
