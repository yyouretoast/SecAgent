"""Regression coverage for issue #11 policy boundary fixes."""

import re
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def _policy(policy_id: str) -> dict:
    document = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    return next(policy for policy in document["policies"] if policy["id"] == policy_id)


def test_sqli_patterns_ignore_benign_punctuation():
    policy = _policy("POL-ASI02-001")
    patterns = [re.compile(pattern) for pattern in policy["condition"]["regex_patterns"]]

    text = "Order #12; see notes -- urgent"

    assert not any(pattern.search(text) for pattern in patterns)


def test_sqli_patterns_still_detect_statements_comments_and_tautologies():
    policy = _policy("POL-ASI02-001")
    patterns = [re.compile(pattern) for pattern in policy["condition"]["regex_patterns"]]
    attacks = [
        "users; DROP TABLE users",
        "SELECT * FROM users --",
        "' OR '1'='1",
        "admin 1 = 1",
    ]

    assert all(any(pattern.search(text) for pattern in patterns) for text in attacks)


def test_general_inquiry_forbids_all_effectful_tiers():
    policy = _policy("POL-ASI03-002")

    assert set(policy["condition"]["forbidden_tiers"]) == {
        "write",
        "pay",
        "admin",
        "net",
    }
