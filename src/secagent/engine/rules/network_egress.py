"""POL-ASI10-001: network egress allowlist and forbidden-sink enforcement."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values

_DESTINATION_KEYS = frozenset({"url", "endpoint", "destination", "host", "uri", "webhook"})


def _leaf_key(path: str) -> str:
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0].strip().lower()


def _extract_hostname(value: str, path: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlparse(candidate)
        return parsed.hostname.lower() if parsed.hostname else None
    if _leaf_key(path) in _DESTINATION_KEYS and "." in candidate and " " not in candidate:
        parsed = urlparse(f"https://{candidate}")
        return parsed.hostname.lower() if parsed.hostname else None
    return None


class NetworkEgressRule(BaseRule):
    """Restrict network-tier tool calls to approved external or internal domains."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tiers = set(condition.get("target_tiers", ("net",)))
        target_tools = set(condition.get("target_tools", ()))
        allowed_domains = {str(d).strip().lower() for d in condition.get("allowed_domains", ())}
        forbidden_patterns = [
            (raw, re.compile(raw)) for raw in condition.get("forbidden_destination_patterns", ())
        ]

        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue

            if (
                span.get("permission_tier") not in target_tiers
                and span.get("name") not in target_tools
            ):
                continue

            evidence: dict[str, Any] | None = None
            for path, value in iter_string_values(span.get("input_parameters", {})):
                for raw, pattern in forbidden_patterns:
                    match = pattern.search(value)
                    if match is not None:
                        evidence = {
                            "reason": "forbidden_destination_pattern",
                            "parameter_path": path,
                            "destination": value,
                            "domain": _extract_hostname(value, path),
                            "pattern": raw,
                            "match": match.group(0),
                        }
                        break
                if evidence is not None:
                    break

                domain = _extract_hostname(value, path)
                if domain is not None and domain not in allowed_domains:
                    evidence = {
                        "reason": "domain_not_in_allowlist",
                        "parameter_path": path,
                        "destination": value,
                        "domain": domain,
                        "allowed_domains": sorted(allowed_domains),
                    }
                    break

            if evidence is not None:
                violations.append(self.violation(span, evidence))

        return violations
