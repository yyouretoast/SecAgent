"""US-4.1 policy ruleset loader tests."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from secagent.engine import PolicyLoader

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"


def test_loader_parses_configured_policy_types():
    ruleset = PolicyLoader(POLICY_PATH).load()

    assert ruleset.policies
    assert all(policy.id and policy.rule_type for policy in ruleset.policies)
    assert any(policy.condition for policy in ruleset.policies)


def test_loader_rejects_unknown_rule_type(tmp_path: Path):
    policy = tmp_path / "invalid.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: BAD-1
    name: Invalid
    owasp_category: ASI00
    severity: HIGH
    rule_type: made_up_rule
    condition: {}
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="Unsupported rule_type"):
        PolicyLoader(policy).load()


def test_loader_rejects_invalid_policy_regex(tmp_path: Path):
    policy = tmp_path / "invalid-regex.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: BAD-REGEX
    name: Invalid regex
    owasp_category: ASI02
    severity: CRITICAL
    rule_type: parameter_regex_blocklist
    condition:
      target_tools: [query_db]
      regex_patterns: ["("]
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="invalid regex"):
        PolicyLoader(policy).load()
