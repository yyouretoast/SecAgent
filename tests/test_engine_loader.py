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
  - id: POL-ASI02-BAD
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


def test_loader_rejects_invalid_tool_tier_override(tmp_path: Path):
    policy = tmp_path / "invalid-tier.yaml"
    policy.write_text(
        """
version: "1"
tool_tier_overrides:
  unsafe_tool: root
policies:
  - id: POL-ASI08-001
    name: Circuit breaker
    owasp_category: ASI08
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="invalid permission tiers: root"):
        PolicyLoader(policy).load()


def test_loader_rejects_unknown_condition_field(tmp_path: Path):
    policy = tmp_path / "unknown-condition-field.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI08-001
    name: Circuit breaker
    owasp_category: ASI08
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
      ignored_limit: 99
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="unknown condition fields.*ignored_limit"):
        PolicyLoader(policy).load()


def test_loader_type_checks_condition_fields(tmp_path: Path):
    policy = tmp_path / "wrong-condition-type.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI08-001
    name: Circuit breaker
    owasp_category: ASI08
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: "ten"
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="max_total_steps must be a positive integer"):
        PolicyLoader(policy).load()


def test_loader_rejects_rule_type_id_prefix_mismatch(tmp_path: Path):
    policy = tmp_path / "wrong-id-prefix.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI03-001
    name: Circuit breaker
    owasp_category: ASI08
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="expected id prefix POL-ASI08-"):
        PolicyLoader(policy).load()


def test_loader_default_path_is_independent_of_cwd(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    ruleset = PolicyLoader().load()

    assert ruleset.version == "1.0.0"


def test_loader_accepts_typed_goal_hijack_contexts(tmp_path: Path):
    policy = tmp_path / "goal-hijack.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI01-001
    name: Goal hijack guard
    owasp_category: ASI01
    severity: CRITICAL
    rule_type: goal_hijack
    condition:
      injection_patterns: ["(?i)ignore previous instructions"]
      protected_contexts:
        general_inquiry:
          forbidden_tiers: [write, pay, admin]
          forbidden_tools: [modify_user, issue_refund]
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    ruleset = PolicyLoader(policy).load()

    assert ruleset.policies[0].rule_type == "goal_hijack"
