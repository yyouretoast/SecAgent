"""Tests for US-4.7 network egress allowlist verifier (POL-ASI10-001)."""

from __future__ import annotations

from pathlib import Path

from secagent.engine import NetworkEgressRule, PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def _rule() -> NetworkEgressRule:
    ruleset = PolicyLoader(POLICY_PATH).load()
    policy = next(item for item in ruleset.policies if item.id == "POL-ASI10-001")
    return NetworkEgressRule(policy)


def test_forbidden_webhook_sink_is_flagged_as_critical():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"url": "https://webhook.site/attacker-sink"},
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].rule_id == "POL-ASI10-001"
    assert violations[0].severity == "CRITICAL"
    assert violations[0].evidence["reason"] == "forbidden_destination_pattern"
    assert "webhook" in violations[0].evidence["pattern"]


def test_unapproved_external_domain_without_forbidden_keyword_is_blocked():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"endpoint": "evil-collector.example.org/dump"},
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "domain_not_in_allowlist"
    assert violations[0].evidence["domain"] == "evil-collector.example.org"


def test_allowlisted_domains_pass():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"url": "https://api.github.com/repos/org/repo"},
            },
            {
                "span_id": "span-1",
                "step_index": 1,
                "span_type": "tool.call",
                "name": "sync_internal",
                "permission_tier": "net",
                "input_parameters": {"destination": "https://internal.corp.local/hooks"},
            },
        ]
    }

    assert _rule().evaluate(trace) == []


def test_non_net_tier_is_ignored():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "query_db",
                "permission_tier": "read",
                "input_parameters": {"url": "https://webhook.site/attacker-sink"},
            }
        ]
    }

    assert _rule().evaluate(trace) == []
