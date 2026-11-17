"""Tests for US-4.6 runaway execution circuit breaker verifier (POL-ASI08-001)."""

from __future__ import annotations

import json
from pathlib import Path

from secagent.engine import CircuitBreakerRule, PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"


def _rule() -> CircuitBreakerRule:
    ruleset = PolicyLoader(POLICY_PATH).load()
    policy = next(item for item in ruleset.policies if item.id == "POL-ASI08-001")
    return CircuitBreakerRule(policy)


def test_loop_violation_fixture_triggers_pol_asi08():
    trace = json.loads((FIXTURES_DIR / "trace_loop_violation.json").read_text(encoding="utf-8"))

    violations = _rule().evaluate(trace)

    reasons = {v.evidence["reason"] for v in violations}
    assert all(v.rule_id == "POL-ASI08-001" and v.severity == "HIGH" for v in violations)
    assert "max_total_steps_exceeded" in reasons
    assert "max_consecutive_identical_tools_exceeded" in reasons


def test_three_consecutive_identical_tool_calls_fail():
    trace = {
        "spans": [
            {
                "span_id": f"span-{i}",
                "step_index": i,
                "span_type": "tool.call",
                "name": "check_service_health",
            }
            for i in range(3)
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].offending_step_index == 2
    assert violations[0].evidence["reason"] == "max_consecutive_identical_tools_exceeded"


def test_total_step_limit_exceeded_without_consecutive_repeats():
    trace = {
        "spans": [
            {
                "span_id": f"span-{i}",
                "step_index": i,
                "span_type": "tool.call",
                "name": f"tool_{i % 3}",
            }
            for i in range(12)
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].offending_step_index == 10
    assert violations[0].evidence["reason"] == "max_total_steps_exceeded"


def test_bounded_alternating_trace_with_inference_spans_passes():
    spans = []
    for i in range(4):
        spans.append(
            {
                "span_id": f"llm-{i}",
                "step_index": len(spans),
                "span_type": "model.inference",
                "name": "reasoner",
            }
        )
        spans.append(
            {
                "span_id": f"tool-{i}",
                "step_index": len(spans),
                "span_type": "tool.call",
                "name": f"tool_{i % 2}",
            }
        )

    assert _rule().evaluate({"spans": spans}) == []
