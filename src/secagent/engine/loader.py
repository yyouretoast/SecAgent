"""YAML loader and validation models for SecAgent security policies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SUPPORTED_RULE_TYPES = {
    "goal_hijack",
    "predecessor_gate",
    "context_privilege",
    "parameter_regex_blocklist",
    "field_scope_allowlist",
    "circuit_breaker",
    "network_egress_allowlist",
}

REQUIRED_CONDITION_FIELDS = {
    "goal_hijack": {"injection_patterns", "protected_contexts"},
    "predecessor_gate": {"target_tiers", "required_gate"},
    "context_privilege": {"task_context", "forbidden_tiers"},
    "parameter_regex_blocklist": {"target_tools", "regex_patterns"},
    "field_scope_allowlist": {"task_context", "target_tools", "forbidden_fields"},
    "circuit_breaker": {"max_total_steps", "max_consecutive_identical_tools"},
    "network_egress_allowlist": {"target_tiers", "allowed_domains"},
}


class PolicyDefinition(BaseModel):
    """Validated representation of one declarative policy."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    owasp_category: str = Field(min_length=1)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    description: str = ""
    rule_type: str = Field(min_length=1)
    condition: dict[str, Any]
    failure_action: Literal["BLOCK_PR", "WARN"]
    remediation: str = ""

    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, value: str) -> str:
        if value not in SUPPORTED_RULE_TYPES:
            supported = ", ".join(sorted(SUPPORTED_RULE_TYPES))
            raise ValueError(f"Unsupported rule_type '{value}'. Expected one of: {supported}")
        return value

    @model_validator(mode="after")
    def validate_condition_shape(self) -> PolicyDefinition:
        required = REQUIRED_CONDITION_FIELDS[self.rule_type]
        missing = sorted(required - self.condition.keys())
        if missing:
            raise ValueError(f"Policy {self.id} is missing condition fields: {', '.join(missing)}")

        pattern_fields = {
            "goal_hijack": "injection_patterns",
            "parameter_regex_blocklist": "regex_patterns",
            "network_egress_allowlist": "forbidden_destination_patterns",
        }
        pattern_field = pattern_fields.get(self.rule_type)
        if pattern_field:
            patterns = self.condition.get(pattern_field, [])
            if not isinstance(patterns, list) or not all(
                isinstance(pattern, str) for pattern in patterns
            ):
                raise ValueError(
                    f"Policy {self.id} field {pattern_field} must be a list of strings"
                )
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError(
                        f"Policy {self.id} contains invalid regex in {pattern_field}: {exc}"
                    ) from exc

        return self


class PolicyRuleset(BaseModel):
    """Top-level policy bundle loaded from ``security_rules.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1)
    description: str = ""
    tool_tier_overrides: dict[str, str] = Field(default_factory=dict)
    policies: list[PolicyDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_unique_policy_ids(self) -> PolicyRuleset:
        policy_ids = [policy.id for policy in self.policies]
        duplicates = sorted({item for item in policy_ids if policy_ids.count(item) > 1})
        if duplicates:
            raise ValueError(f"Duplicate policy ids: {', '.join(duplicates)}")
        return self


class PolicyLoader:
    """Load and validate a declarative SecAgent policy bundle."""

    def __init__(self, path: str | Path = "policies/security_rules.yaml") -> None:
        self.path = Path(path)

    def load(self) -> PolicyRuleset:
        if not self.path.exists():
            raise FileNotFoundError(f"Policy file does not exist: {self.path}")

        with self.path.open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)

        if not isinstance(raw, dict):
            raise ValueError(f"Policy file must contain a YAML mapping: {self.path}")

        return PolicyRuleset.model_validate(raw)
