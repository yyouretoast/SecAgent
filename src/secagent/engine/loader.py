"""YAML loader and validation models for SecAgent security policies."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal, get_args

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from secagent.sdk import PermissionTier

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "policies" / "security_rules.yaml"

PERMISSION_TIERS = frozenset(get_args(PermissionTier))

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

CONDITION_FIELD_TYPES = {
    "goal_hijack": {
        "injection_patterns": "string_list",
        "protected_contexts": "protected_contexts",
    },
    "predecessor_gate": {
        "target_tiers": "tier_list",
        "target_tools": "string_list",
        "required_gate": "approval_gate",
        "max_lookback_operational_steps": "positive_int",
    },
    "context_privilege": {
        "task_context": "string",
        "forbidden_tiers": "tier_list",
        "forbidden_tools": "string_list",
    },
    "parameter_regex_blocklist": {
        "target_tools": "string_list",
        "regex_patterns": "string_list",
    },
    "field_scope_allowlist": {
        "task_context": "string",
        "target_tools": "string_list",
        "parameter_key": "string",
        "target_locations": "string_list",
        "forbidden_fields": "string_list",
    },
    "circuit_breaker": {
        "max_total_steps": "positive_int",
        "max_consecutive_identical_tools": "positive_int",
    },
    "network_egress_allowlist": {
        "target_tiers": "tier_list",
        "allowed_domains": "string_list",
        "forbidden_destination_patterns": "string_list",
    },
}

RULE_ID_PREFIXES = {
    "goal_hijack": ("POL-ASI01-",),
    "predecessor_gate": ("POL-ASI03-",),
    "context_privilege": ("POL-ASI03-",),
    "parameter_regex_blocklist": ("POL-ASI02-", "POL-ASI05-"),
    "field_scope_allowlist": ("POL-ASI06-",),
    "circuit_breaker": ("POL-ASI08-",),
    "network_egress_allowlist": ("POL-ASI10-",),
}


def _is_non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_string_list(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(_is_non_empty_string(item) for item in value)
    )


def _validate_condition_field(policy_id: str, field: str, kind: str, value: Any) -> None:
    if kind == "string" and not _is_non_empty_string(value):
        raise ValueError(f"Policy {policy_id} field {field} must be a non-empty string")

    if kind == "string_list" and not _is_string_list(value):
        raise ValueError(f"Policy {policy_id} field {field} must be a non-empty list of strings")

    if kind == "positive_int" and (
        not isinstance(value, int) or isinstance(value, bool) or value < 1
    ):
        raise ValueError(f"Policy {policy_id} field {field} must be a positive integer")

    if kind == "tier_list":
        if not _is_string_list(value):
            raise ValueError(f"Policy {policy_id} field {field} must be a non-empty list of tiers")
        invalid = sorted(set(value) - PERMISSION_TIERS)
        if invalid:
            raise ValueError(
                f"Policy {policy_id} field {field} contains invalid permission tiers: "
                f"{', '.join(invalid)}"
            )

    if kind == "approval_gate":
        if not isinstance(value, dict):
            raise ValueError(f"Policy {policy_id} field {field} must be a mapping")
        expected = {"span_type", "name", "approval_granted"}
        missing = sorted(expected - value.keys())
        unknown = sorted(value.keys() - expected)
        if missing:
            raise ValueError(
                f"Policy {policy_id} field {field} is missing fields: {', '.join(missing)}"
            )
        if unknown:
            raise ValueError(
                f"Policy {policy_id} field {field} contains unknown fields: {', '.join(unknown)}"
            )
        if not _is_non_empty_string(value["span_type"]):
            raise ValueError(f"Policy {policy_id} field {field}.span_type must be a string")
        if not _is_non_empty_string(value["name"]):
            raise ValueError(f"Policy {policy_id} field {field}.name must be a string")
        if not isinstance(value["approval_granted"], bool):
            raise ValueError(f"Policy {policy_id} field {field}.approval_granted must be a boolean")

    if kind == "protected_contexts":
        if not isinstance(value, dict) or not value:
            raise ValueError(f"Policy {policy_id} field {field} must be a non-empty mapping")
        for context, limits in value.items():
            if not _is_non_empty_string(context) or not isinstance(limits, dict):
                raise ValueError(
                    f"Policy {policy_id} field {field} must map context names to mappings"
                )
            expected = {"forbidden_tiers", "forbidden_tools"}
            missing = sorted(expected - limits.keys())
            unknown = sorted(limits.keys() - expected)
            if missing:
                raise ValueError(
                    f"Policy {policy_id} field {field}.{context} is missing fields: "
                    f"{', '.join(missing)}"
                )
            if unknown:
                raise ValueError(
                    f"Policy {policy_id} field {field}.{context} contains unknown fields: "
                    f"{', '.join(unknown)}"
                )
            _validate_condition_field(
                policy_id,
                f"{field}.{context}.forbidden_tiers",
                "tier_list",
                limits["forbidden_tiers"],
            )
            _validate_condition_field(
                policy_id,
                f"{field}.{context}.forbidden_tools",
                "string_list",
                limits["forbidden_tools"],
            )


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
        expected_prefixes = RULE_ID_PREFIXES[self.rule_type]
        if not self.id.startswith(expected_prefixes):
            expected = " or ".join(expected_prefixes)
            raise ValueError(
                f"Policy {self.id} does not match rule_type {self.rule_type}; "
                f"expected id prefix {expected}"
            )

        required = REQUIRED_CONDITION_FIELDS[self.rule_type]
        missing = sorted(required - self.condition.keys())
        if missing:
            raise ValueError(f"Policy {self.id} is missing condition fields: {', '.join(missing)}")

        field_types = CONDITION_FIELD_TYPES[self.rule_type]
        unknown = sorted(self.condition.keys() - field_types.keys())
        if unknown:
            raise ValueError(
                f"Policy {self.id} contains unknown condition fields for {self.rule_type}: "
                f"{', '.join(unknown)}"
            )

        for field, value in self.condition.items():
            _validate_condition_field(self.id, field, field_types[field], value)

        pattern_fields = {
            "goal_hijack": "injection_patterns",
            "parameter_regex_blocklist": "regex_patterns",
            "network_egress_allowlist": "forbidden_destination_patterns",
        }
        pattern_field = pattern_fields.get(self.rule_type)
        if pattern_field:
            patterns = self.condition.get(pattern_field, [])
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

    @field_validator("tool_tier_overrides")
    @classmethod
    def validate_tool_tier_overrides(cls, value: dict[str, str]) -> dict[str, str]:
        invalid = sorted({tier for tier in value.values() if tier not in PERMISSION_TIERS})
        if invalid:
            allowed = ", ".join(sorted(PERMISSION_TIERS))
            raise ValueError(
                f"tool_tier_overrides contains invalid permission tiers: {', '.join(invalid)}; "
                f"expected one of: {allowed}"
            )
        return value

    @model_validator(mode="after")
    def validate_unique_policy_ids(self) -> PolicyRuleset:
        policy_ids = [policy.id for policy in self.policies]
        duplicates = sorted({item for item in policy_ids if policy_ids.count(item) > 1})
        if duplicates:
            raise ValueError(f"Duplicate policy ids: {', '.join(duplicates)}")
        return self


class PolicyLoader:
    """Load and validate a declarative SecAgent policy bundle."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else DEFAULT_POLICY_PATH

    def load(self) -> PolicyRuleset:
        if not self.path.exists():
            raise FileNotFoundError(f"Policy file does not exist: {self.path}")

        with self.path.open(encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)

        if not isinstance(raw, dict):
            raise ValueError(f"Policy file must contain a YAML mapping: {self.path}")

        return PolicyRuleset.model_validate(raw)
