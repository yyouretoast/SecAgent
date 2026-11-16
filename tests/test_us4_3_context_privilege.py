"""Tests for US-4.3 context privilege boundary verifier (POL-ASI03-002)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secagent.engine import ContextPrivilegeRule, PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def _rule() -> ContextPrivilegeRule:
    ruleset = PolicyLoader(POLICY_PATH).load()
    policy = next(item for item in ruleset.policies if item.id == "POL-ASI03-002")
    return ContextPrivilegeRule(policy)


@pytest.mark.parametrize(
    ("tool_name", "tier"),
    [
        ("modify_user", "write"),
        ("issue_refund", "pay"),
        ("restart_server", "admin"),
        ("post_webhook", "net"),
    ],
)
def test_effectful_tiers_are_blocked_in_general_inquiry(tool_name: str, tier: str):
    trace = {
        "task_context": "general_inquiry",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": tool_name,
                "permission_tier": tier,
            }
        ],
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI03-002"
    assert violations[0].severity == "HIGH"
    assert violations[0].failure_action == "BLOCK_PR"
    assert violations[0].offending_tool_name == tool_name


def test_read_only_tool_in_general_inquiry_is_allowed():
    trace = {
        "task_context": "general_inquiry",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
            }
        ],
    }

    assert _rule().evaluate(trace) == []


def test_mislabeled_forbidden_tool_is_still_blocked():
    trace = {
        "task_context": "general_inquiry",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "modify_user",
                "permission_tier": "read",
            }
        ],
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].offending_tool_name == "modify_user"


def test_non_matching_context_is_not_flagged():
    trace = {
        "task_context": "refund_request",
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "issue_refund",
                "permission_tier": "pay",
            }
        ],
    }

    assert _rule().evaluate(trace) == []
