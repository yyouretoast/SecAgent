"""US-4.1 policy ruleset loader tests."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from secagent.engine import PolicyLoader, PolicyLoadError

ROOT_DIR = Path(__file__).resolve().parent.parent
POLICY_PATH = ROOT_DIR / "policies" / "security_rules.yaml"
EXPECTED_POLICY_IDS = {
    "POL-ASI02-001",
    "POL-ASI03-001",
    "POL-ASI03-002",
    "POL-ASI05-001",
    "POL-ASI06-001",
    "POL-ASI08-001",
    "POL-ASI10-001",
}


def test_loader_parses_configured_policy_types():
    ruleset = PolicyLoader(POLICY_PATH).load()

    assert {policy.id for policy in ruleset.policies} == EXPECTED_POLICY_IDS
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

    with pytest.raises(PolicyLoadError, match="Unsupported rule_type"):
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

    with pytest.raises(PolicyLoadError, match="invalid regex"):
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

    with pytest.raises(PolicyLoadError, match="invalid permission tiers: root"):
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

    with pytest.raises(PolicyLoadError, match="unknown condition fields.*ignored_limit"):
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

    with pytest.raises(PolicyLoadError, match="max_total_steps must be a positive integer"):
        PolicyLoader(policy).load()


def test_loader_rejects_rule_type_id_prefix_mismatch(tmp_path: Path):
    policy = tmp_path / "wrong-id-prefix.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI03-001
    name: Circuit breaker
    owasp_category: ASI03
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError, match="expected id prefix POL-ASI08-"):
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


def test_loader_rejects_duplicate_policy_ids(tmp_path: Path):
    policy = tmp_path / "duplicate-ids.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - &circuit_breaker
    id: POL-ASI08-001
    name: Circuit breaker
    owasp_category: ASI08
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
  - <<: *circuit_breaker
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError, match="Duplicate policy ids: POL-ASI08-001"):
        PolicyLoader(policy).load()


def test_loader_rejects_missing_required_condition_field(tmp_path: Path):
    policy = tmp_path / "missing-condition-field.yaml"
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
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(
        PolicyLoadError,
        match="missing condition fields: max_consecutive_identical_tools",
    ):
        PolicyLoader(policy).load()


def test_loader_rejects_owasp_category_that_disagrees_with_id(tmp_path: Path):
    policy = tmp_path / "wrong-owasp-category.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI08-001
    name: Circuit breaker
    owasp_category: ASI99
    severity: HIGH
    rule_type: circuit_breaker
    condition:
      max_total_steps: 10
      max_consecutive_identical_tools: 2
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError, match="owasp_category 'ASI99'.*id category 'ASI08'"):
        PolicyLoader(policy).load()


def test_loader_rejects_unknown_target_location(tmp_path: Path):
    policy = tmp_path / "unknown-target-location.yaml"
    policy.write_text(
        """
version: "1"
policies:
  - id: POL-ASI06-001
    name: Field scope
    owasp_category: ASI06
    severity: HIGH
    rule_type: field_scope_allowlist
    condition:
      task_context: address_update
      target_tools: [query_db]
      target_locations: [bogus_field]
      forbidden_fields: [ssn]
    failure_action: BLOCK_PR
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError, match="invalid span locations: bogus_field"):
        PolicyLoader(policy).load()


def test_loader_wraps_missing_file_with_path_and_cause(tmp_path: Path):
    missing = tmp_path / "missing.yaml"

    with pytest.raises(PolicyLoadError, match="Policy file does not exist") as captured:
        PolicyLoader(missing).load()

    assert captured.value.path == str(missing)
    assert isinstance(captured.value.__cause__, FileNotFoundError)


def test_loader_wraps_pydantic_validation_error(tmp_path: Path):
    policy = tmp_path / "invalid-model.yaml"
    policy.write_text(
        """
version: "1"
policies: []
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(PolicyLoadError, match="List should have at least 1 item") as captured:
        PolicyLoader(policy).load()

    assert isinstance(captured.value.__cause__, ValidationError)


def test_loader_wraps_malformed_yaml_error(tmp_path: Path):
    policy = tmp_path / "malformed.yaml"
    policy.write_text("version: [unterminated", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="Cannot load policy file") as captured:
        PolicyLoader(policy).load()

    assert isinstance(captured.value.__cause__, yaml.YAMLError)


def test_loader_wraps_non_mapping_document_error(tmp_path: Path):
    policy = tmp_path / "list.yaml"
    policy.write_text("- not\n- a\n- mapping", encoding="utf-8")

    with pytest.raises(PolicyLoadError, match="must contain a YAML mapping") as captured:
        PolicyLoader(policy).load()

    assert isinstance(captured.value.__cause__, ValueError)
