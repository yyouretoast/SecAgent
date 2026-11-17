"""Structured report generation from PolicyEngine evaluation results (US-4.8)."""

from __future__ import annotations

from typing import Any

from secagent.engine.models import EvaluationResult


class PolicyReporter:
    """Format PolicyEngine results into structured JSON-ready audit reports."""

    def generate_report(
        self,
        result: EvaluationResult,
        *,
        agent_name: str = "default_fixture",
        scenarios_evaluated: int = 0,
        traces: list[dict[str, Any]] | None = None,
        generation_mode: str = "dynamic_synthetic",
    ) -> dict[str, Any]:
        """Build a report dictionary consumable by the CLI, Markdown formatter, and dashboard."""
        trace_list = traces if traces is not None else []
        effective_scenarios = scenarios_evaluated or len(trace_list)
        serialized = result.serialized_violations()

        message = (
            f"Evaluated {len(trace_list)} trace(s) across {effective_scenarios} scenarios: "
            f"{len(serialized)} policy violation(s) detected."
            if serialized
            else (
                f"Evaluated {len(trace_list)} trace(s) across {effective_scenarios} scenarios: "
                "all security policies satisfied."
            )
        )

        return {
            "status": result.status,
            "agent": agent_name or "default_fixture",
            "scenarios_evaluated": effective_scenarios,
            "total_spans_evaluated": result.total_spans_evaluated,
            "violations_detected": len(serialized),
            "violations": serialized,
            "execution_time_ms": round(result.execution_time_ms, 3),
            "traces": trace_list,
            "generation_mode": generation_mode,
            "message": message,
        }
