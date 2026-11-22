"""Tests for US-4.5 need-to-know field scope allowlist verifier (POL-ASI06-001)."""

from __future__ import annotations

from pathlib import Path

from secagent.engine import FieldScopeRule, PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def _rule() -> FieldScopeRule:
    ruleset = PolicyLoader(POLICY_PATH).load()
    policy = next(item for item in ruleset.policies if item.id == "POL-ASI06-001")
    return FieldScopeRule(policy)


def test_overfetched_input_fields_are_flagged():
    trace = {
        "task_context": "address_update",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {
                    "table": "users",
                    "fields": ["address", "password_hash", "ssn"],
                },
            }
        ],
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI06-001"
    assert violations[0].severity == "HIGH"
    assert violations[0].evidence["forbidden_fields_found"] == ["password_hash", "ssn"]


def test_sensitive_output_keys_are_flagged_even_when_input_is_clean():
    trace = {
        "task_context": "address_update",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"fields": ["address", "city"]},
                "output_result": {"record": {"address": "1 Main St", "salary": 150000}},
            }
        ],
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["forbidden_fields_found"] == ["salary"]
    assert "output_result" in violations[0].evidence["locations"]


def test_allowlisted_fields_and_unrelated_substrings_pass():
    trace = {
        "task_context": "address_update",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"fields": ["address", "shipping_pin", "postal_code"]},
                "output_result": {"record": {"shipping_opinion": "ok", "address": "1 Main St"}},
            }
        ],
    }

    assert _rule().evaluate(trace) == []


def test_other_task_context_is_not_evaluated():
    trace = {
        "task_context": "payroll_audit",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"fields": ["ssn", "salary"]},
            }
        ],
    }

    assert _rule().evaluate(trace) == []


def test_attributes_location_is_scanned_when_configured():
    base_policy = _rule().policy
    policy = base_policy.model_copy(
        update={
            "condition": {
                **base_policy.condition,
                "target_locations": ["input_parameters", "output_result", "attributes"],
            }
        }
    )
    rule = FieldScopeRule(policy)
    trace = {
        "task_context": "address_update",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"fields": ["address"]},
                "attributes": {"user.ssn": "123-45-6789", "ssn": "redacted"},
            }
        ],
    }

    violations = rule.evaluate(trace)
    assert len(violations) == 1
    assert "attributes" in violations[0].evidence["locations"]
    assert "ssn" in violations[0].evidence["forbidden_fields_found"]
