"""POL-ASI04-001: deterministic tool-description poisoning detector (ASI04)."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from secagent.engine.models import PolicyViolation

_INVISIBLE_CHARS_RE = re.compile(
    r"(?:[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff\ufe00-\ufe0e\U000E0100-\U000E01EF]|(?<=[A-Za-z0-9])\ufe0f(?=[A-Za-z0-9]))+"
)
_STRIP_INVISIBLE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff\ufe00-\ufe0f\U000E0100-\U000E01EF]+"
)

POISON_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?is)\b(ignore|disregard|override)\b.{0,40}\b(previous|prior|system|user)\b.{0,20}\b(instruction|prompt|rule)s?\b"
        ),
    ),
    (
        "important_tag",
        re.compile(r"(?is)<\s*important\s*>"),
    ),
    (
        "covert_directive",
        re.compile(
            r"(?is)\b(exfiltrate|silently\s+send|do\s+not\s+tell\s+the\s+user|hidden\s+instruction)\b"
        ),
    ),
    (
        "unicode_tag_chars",
        re.compile(r"[\U000E0000-\U000E007F]+"),
    ),
    (
        "zero_width_obfuscation",
        _INVISIBLE_CHARS_RE,
    ),
    (
        "cross_tool_shadowing",
        re.compile(
            r"(?is)(?:\bbefore\s+calling\b.{0,60}\bread\b|\bpass\s+its\s+contents\b|~/\.ssh/|~/\.aws/credentials|/etc/passwd|\bread\s+(?:the\s+)?\.env\b)"
        ),
    ),
)


def _iter_nested_strings(value: Any, prefix: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(value, str):
        out.append((prefix, value))
    elif isinstance(value, Mapping):
        for key, item in value.items():
            out.append((f"{prefix}.{key}.<key>", str(key)))
            out.extend(_iter_nested_strings(item, f"{prefix}.{key}"))
    elif isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            out.extend(_iter_nested_strings(item, f"{prefix}[{idx}]"))
    return out


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


def scan_tool_definitions(
    tools: Sequence[Any],
    *,
    extra_patterns: Mapping[str, str] | None = None,
) -> list[PolicyViolation]:
    """Scan introspected tool descriptions and parameter metadata for hidden instructions."""
    compiled_patterns: list[tuple[str, re.Pattern[str]]] = list(POISON_PATTERNS)
    if extra_patterns:
        for label, raw in extra_patterns.items():
            if not str(raw).strip():
                raise ValueError(f"tool_poisoning pattern '{label}' must not be empty")
            compiled_patterns.append((str(label), re.compile(raw)))

    violations: list[PolicyViolation] = []
    for tool in tools:
        name, description, param_meta = _tool_fields(tool)
        texts: list[tuple[str, str]] = [("name", name), ("description", description)]
        for param_name, spec in param_meta.items():
            texts.append((f"parameter.{param_name}.<key>", str(param_name)))
            texts.extend(_iter_nested_strings(spec, f"parameter.{param_name}"))

        for location, text in texts:
            if not text:
                continue
            normalized = _STRIP_INVISIBLE_RE.sub("", text)
            matched: tuple[str, str] | None = None
            for label, pattern in compiled_patterns:
                m = pattern.search(text)
                if m is None and normalized != text and label != "zero_width_obfuscation":
                    m = pattern.search(normalized)
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
