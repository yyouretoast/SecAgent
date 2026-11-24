"""POL-ASI04-001: deterministic tool-description poisoning detector (ASI04)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from secagent.engine.models import PolicyViolation

POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?is)\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|system|user)\b.{0,20}\b(instruction|prompt|rule)s?\b"
        ),
    ),
    (
        "important_tag",
        re.compile(r"(?is)<\s*important\s*>.*?</\s*important\s*>"),
    ),
    (
        "covert_directive",
        re.compile(
            r"(?is)\b(exfiltrate|silently\s+send|do\s+not\s+tell\s+the\s+user|hidden\s+instruction)\b"
        ),
    ),
)


def _tool_fields(tool: Any) -> tuple[str, str, dict[str, Any]]:
    if isinstance(tool, dict):
        name = str(tool.get("name") or "unknown_tool")
        desc = str(tool.get("description") or "")
        params = dict(tool.get("parameter_metadata") or {})
        return name, desc, params
    name = str(getattr(tool, "name", None) or getattr(tool, "__name__", "unknown_tool"))
    desc = str(getattr(tool, "description", None) or getattr(tool, "__doc__", "") or "")
    params = dict(getattr(tool, "parameter_metadata", {}) or {})
    return name, desc, params


def scan_tool_definitions(tools: Sequence[Any]) -> list[PolicyViolation]:
    """Scan introspected tool descriptions and parameter metadata for hidden instructions."""
    violations: list[PolicyViolation] = []
    for tool in tools:
        name, description, param_meta = _tool_fields(tool)
        texts: list[tuple[str, str]] = [("description", description)]
        for param_name, spec in param_meta.items():
            if isinstance(spec, dict) and isinstance(spec.get("description"), str):
                texts.append((f"parameter.{param_name}.description", spec["description"]))

        for location, text in texts:
            if not text:
                continue
            matched: tuple[str, str] | None = None
            for label, pattern in POISON_PATTERNS:
                m = pattern.search(text)
                if m is not None:
                    matched = (label, m.group(0))
                    break
            if matched is not None:
                violations.append(
                    PolicyViolation(
                        rule_id="POL-ASI04-001",
                        rule_name="Tool Description Poisoning Detection",
                        owasp_category="ASI04: Agentic Supply Chain Vulnerabilities",
                        severity="CRITICAL",
                        offending_span_id=f"tool-def:{name}",
                        offending_step_index=-1,
                        offending_tool_name=name,
                        failure_action="BLOCK_PR",
                        evidence={
                            "location": location,
                            "pattern_label": matched[0],
                            "match": matched[1],
                        },
                        remediation=(
                            f"Audit and sanitize tool '{name}' description/metadata to remove "
                            "embedded prompt instructions before registering it."
                        ),
                    )
                )
                break
    return violations
