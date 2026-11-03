"""Structured JSON report generation for policy evaluation results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secagent.engine.models import EvaluationResult


class PolicyReporter:
    """Convert evaluation results to stable report objects and JSON files."""

    @staticmethod
    def generate_report(
        result: EvaluationResult,
        *,
        agent: str = "",
        scenario_id: str = "",
    ) -> dict[str, Any]:
        report = result.to_dict()
        if agent:
            report["agent"] = agent
        if scenario_id:
            report["scenario_id"] = scenario_id
        return report

    @classmethod
    def write_json(
        cls,
        result: EvaluationResult,
        output_path: str | Path,
        *,
        agent: str = "",
        scenario_id: str = "",
    ) -> dict[str, Any]:
        report = cls.generate_report(result, agent=agent, scenario_id=scenario_id)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
