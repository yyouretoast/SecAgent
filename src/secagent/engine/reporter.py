"""Structured report generation from PolicyEngine evaluation results (US-4.8)."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import zip_longest
from pathlib import Path
from typing import Any
from urllib.parse import quote

from secagent import __version__
from secagent.engine.loader import PolicyDefinition
from secagent.engine.models import EvaluationResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _sarif_artifact_uri(agent_name: str) -> str:
    """Resolve an agent entrypoint or trace path to a valid relative SARIF artifact URI."""
    if not agent_name or not agent_name.strip():
        return "default_fixture"

    raw = agent_name.strip()
    candidate = Path(raw)
    if candidate.exists():
        cwd = Path.cwd().resolve()
        try:
            rel = candidate.resolve().relative_to(cwd).as_posix()
        except ValueError:
            rel = candidate.name
        return quote(rel, safe="/:@-._~")

    mod_name, _, _ = raw.partition(":")
    rel_base = mod_name.replace(".", "/")
    for probe in (
        Path(f"{rel_base}.py"),
        Path("src") / f"{rel_base}.py",
        Path(rel_base) / "__init__.py",
    ):
        if probe.exists():
            return quote(probe.as_posix(), safe="/:@-._~")

    if ":" in raw or (
        "." in mod_name and not mod_name.lower().endswith((".json", ".yaml", ".yml", ".py"))
    ):
        return quote(f"{rel_base}.py", safe="/:@-._~")
    sanitized = raw.replace("\\", "/").replace(":", "/")
    if sanitized.startswith("/") or ".." in Path(sanitized).parts:
        sanitized = Path(sanitized).name or "default_fixture"
    return quote(sanitized, safe="/:@-._~")


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

        violated_sids = {
            str(v.get("scenario_id") or "") for v in serialized if v.get("scenario_id")
        }
        tool_call_traces = sum(
            1
            for trace in trace_list
            if isinstance(trace, dict)
            and any(
                isinstance(span, dict) and span.get("span_type") == "tool.call"
                for span in (trace.get("spans") or ())
            )
        )
        raw_invocation_rate = (tool_call_traces / len(trace_list)) if trace_list else 0.0
        tool_invocation_rate = round(raw_invocation_rate, 3)
        benign_traces = [
            trace
            for trace in trace_list
            if isinstance(trace, dict)
            and (
                bool((trace.get("metadata") or {}).get("is_benign"))
                or str(trace.get("scenario_id") or "").startswith("GEN-UTIL-")
            )
        ]
        benign_passed = sum(
            1
            for trace in benign_traces
            if str(trace.get("scenario_id") or "") not in violated_sids
            and not any(
                isinstance(span, dict) and span.get("is_error")
                for span in (trace.get("spans") or ())
            )
            and any(
                isinstance(span, dict) and span.get("span_type") == "tool.call"
                for span in (trace.get("spans") or ())
            )
        )
        utility_pass_rate = round(benign_passed / len(benign_traces), 3) if benign_traces else None
        low_coverage_warning = bool(
            generation_mode != "external_trace"
            and len(trace_list) >= 4
            and raw_invocation_rate < 0.25
        )

        coverage: dict[str, Any] = {
            "scenarios_with_tool_calls": tool_call_traces,
            "total_traces": len(trace_list),
            "tool_invocation_rate": tool_invocation_rate,
            "utility_scenarios": len(benign_traces),
            "utility_pass_rate": utility_pass_rate,
            "low_coverage_warning": low_coverage_warning,
        }

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
            "coverage": coverage,
            "traces": trace_list,
            "generation_mode": generation_mode,
            "message": message,
        }

    def generate_sarif(
        self,
        result: EvaluationResult,
        *,
        agent_name: str = "default_fixture",
        rules: Sequence[PolicyDefinition] | None = None,
    ) -> dict[str, Any]:
        """Build a SARIF 2.1.0 document for GitHub Code Scanning integration."""
        driver_rules: list[dict[str, Any]] = []
        seen_rule_ids: set[str] = set()

        for policy in rules or ():
            seen_rule_ids.add(policy.id)
            driver_rules.append(
                {
                    "id": policy.id,
                    "name": policy.name,
                    "shortDescription": {"text": policy.name},
                    "fullDescription": {"text": policy.description or policy.name},
                    "help": {"text": policy.remediation or policy.description or policy.name},
                    "properties": {
                        "owasp_category": policy.owasp_category,
                        "severity": policy.severity,
                    },
                }
            )

        sarif_results: list[dict[str, Any]] = []
        for violation, scenario_id in zip_longest(
            result.violations,
            result.violation_scenario_ids,
            fillvalue=None,
        ):
            if violation is None:
                continue
            if violation.rule_id not in seen_rule_ids:
                seen_rule_ids.add(violation.rule_id)
                driver_rules.append(
                    {
                        "id": violation.rule_id,
                        "name": violation.rule_name,
                        "shortDescription": {"text": violation.rule_name},
                        "help": {"text": violation.remediation or violation.rule_name},
                        "properties": {
                            "owasp_category": violation.owasp_category,
                            "severity": violation.severity,
                        },
                    }
                )

            message = (
                f"[{violation.owasp_category}] {violation.rule_name} on tool "
                f"'{violation.offending_tool_name}' (span {violation.offending_span_id}, "
                f"step {violation.offending_step_index}). Remediation: {violation.remediation}"
            )
            sarif_results.append(
                {
                    "ruleId": violation.rule_id,
                    "level": _SARIF_LEVEL.get(violation.severity, "warning"),
                    "message": {"text": message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": _sarif_artifact_uri(agent_name),
                                }
                            },
                            "logicalLocations": [
                                {
                                    "name": violation.offending_tool_name,
                                    "kind": "tool",
                                    "fullyQualifiedName": (
                                        f"{agent_name or 'default_fixture'}:"
                                        f"{violation.offending_tool_name}#"
                                        f"{violation.offending_span_id}"
                                    ),
                                }
                            ],
                        }
                    ],
                    "properties": {
                        "owasp_category": violation.owasp_category,
                        "severity": violation.severity,
                        "offending_span_id": violation.offending_span_id,
                        "offending_step_index": violation.offending_step_index,
                        "offending_tool_name": violation.offending_tool_name,
                        "failure_action": violation.failure_action,
                        "remediation": violation.remediation,
                        "evidence": violation.evidence,
                        **({"scenario_id": scenario_id} if scenario_id else {}),
                    },
                }
            )

        return {
            "$schema": _SARIF_SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecAgent",
                            "version": __version__,
                            "informationUri": "https://github.com/yyouretoast/SecAgent",
                            "rules": driver_rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
