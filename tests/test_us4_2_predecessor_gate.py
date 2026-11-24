"""Tests for US-4.2 predecessor HITL gate verifier (POL-ASI03-001)."""

from __future__ import annotations

import json
from pathlib import Path

from secagent.engine import PolicyDefinition, PolicyLoader, PredecessorGateRule

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"


def _policy() -> PolicyDefinition:
    ruleset = PolicyLoader(POLICY_PATH).load()
    return next(item for item in ruleset.policies if item.id == "POL-ASI03-001")


def _rule() -> PredecessorGateRule:
    return PredecessorGateRule(_policy())


def test_sample_trace_with_approved_gate_passes():
    trace = json.loads((FIXTURES_DIR / "sample_trace.json").read_text(encoding="utf-8"))

    assert _rule().evaluate(trace) == []


def test_privilege_violation_fixture_is_flagged_as_critical():
    trace = json.loads(
        (FIXTURES_DIR / "trace_privilege_violation.json").read_text(encoding="utf-8")
    )

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI03-001"
    assert violations[0].severity == "CRITICAL"
    assert violations[0].failure_action == "BLOCK_PR"
    assert violations[0].offending_tool_name == "issue_refund"
    assert violations[0].offending_step_index == 1
    assert violations[0].evidence["reason"] == "missing_required_gate"


def test_privileged_call_at_step_zero_is_flagged():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "restart_server",
                "permission_tier": "admin",
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "no_predecessor"


def test_denied_gate_does_not_authorize_privileged_call():
    trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": False,
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "gate_not_approved"


def test_non_operational_inference_span_does_not_break_lookback():
    trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
            },
            {
                "span_id": "llm-1",
                "step_index": 1,
                "span_type": "model.inference",
                "name": "reasoner",
            },
            {
                "span_id": "span-2",
                "step_index": 2,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }

    assert _rule().evaluate(trace) == []


def test_mislabeled_tier_on_target_tool_still_requires_gate():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "issue_refund",
                "permission_tier": "read",
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].offending_tool_name == "issue_refund"


def test_single_gate_cannot_be_replayed_across_two_calls_when_lookback_widened():
    policy = _policy().model_copy(
        update={
            "condition": {
                **_policy().condition,
                "max_lookback_operational_steps": 3,
            }
        }
    )
    rule = PredecessorGateRule(policy)
    trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
            {
                "span_id": "span-2",
                "step_index": 2,
                "span_type": "tool.call",
                "name": "transfer_funds",
                "permission_tier": "pay",
            },
        ]
    }

    violations = rule.evaluate(trace)

    assert len(violations) == 1
    assert violations[0].offending_tool_name == "transfer_funds"
    assert violations[0].evidence["reason"] == "gate_already_consumed"


def test_argument_bound_hitl_rejects_mismatched_operation_and_allows_matching():
    rule = _rule()
    mismatched_trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
                "input_parameters": {"operation": "get_stock_quote"},
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }
    violations = rule.evaluate(mismatched_trace)
    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "gate_operation_mismatch"
    assert violations[0].evidence["approved_operation"] == "get_stock_quote"
    assert violations[0].evidence["expected_operation"] == "execute_trade"

    matching_trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
                "input_parameters": {"operation": "execute_trade"},
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }
    assert rule.evaluate(matching_trace) == []

    generic_trace = {
        "spans": [
            {
                "span_id": "gate-1",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
                "input_parameters": {"operation": "unknown_operation"},
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }
    assert rule.evaluate(generic_trace) == []


def test_errored_gate_does_not_grant_approval():
    rule = PredecessorGateRule(_policy())
    trace = {
        "spans": [
            {
                "span_id": "gate-err",
                "step_index": 0,
                "span_type": "gate.hitl",
                "name": "approval_gate",
                "approval_granted": True,
                "is_error": True,
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "execute_trade",
                "permission_tier": "pay",
            },
        ]
    }
    violations = rule.evaluate(trace)
    assert len(violations) == 1
    assert violations[0].offending_tool_name == "execute_trade"
