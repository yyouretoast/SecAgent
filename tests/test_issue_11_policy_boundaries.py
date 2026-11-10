"""Regression coverage for issue #11 policy boundary fixes."""

import re
from pathlib import Path

from secagent.engine import PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def _policy(policy_id: str):
    ruleset = PolicyLoader(POLICY_PATH).load()
    return next(policy for policy in ruleset.policies if policy.id == policy_id)


def test_benign_punctuation_does_not_match_sqli_policy():
    policy = _policy("POL-ASI02-001")
    patterns = [re.compile(pattern) for pattern in policy.condition["regex_patterns"]]
    benign = "Order #12; see notes -- urgent"

    assert not any(pattern.search(benign) for pattern in patterns)


def test_sql_statements_and_trailing_comments_still_match_sqli_policy():
    policy = _policy("POL-ASI02-001")
    patterns = [re.compile(pattern) for pattern in policy.condition["regex_patterns"]]

    assert any(pattern.search("status = 1; DROP TABLE users") for pattern in patterns)
    assert any(pattern.search("SELECT * FROM users --") for pattern in patterns)


def test_general_inquiry_forbids_all_mutating_and_external_tiers():
    policy = _policy("POL-ASI03-002")

    assert set(policy.condition["forbidden_tiers"]) == {"write", "pay", "admin", "net"}
