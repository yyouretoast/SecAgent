"""POL-ASI10-001: network egress allowlist and forbidden-sink enforcement."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values

_DESTINATION_KEYS = frozenset({"url", "endpoint", "destination", "host", "uri", "webhook"})
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")


def _leaf_key(path: str) -> str:
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0].strip().lower()


def _extract_hostnames(value: str, path: str) -> list[str]:
    candidate = value.strip()
    if not candidate:
        return []

    urls = _URL_RE.findall(candidate)
    if urls:
        hosts: list[str] = []
        for raw_url in urls:
            hostname = urlparse(raw_url).hostname
            if hostname:
                hosts.append(hostname.lower())
        return hosts

    if _leaf_key(path) in _DESTINATION_KEYS and " " not in candidate:
        bare_host = candidate.split("/", 1)[0].split(":", 1)[0].lower()
        if "." in candidate or bare_host == "localhost" or candidate.startswith("["):
            hostname = urlparse(f"https://{candidate}").hostname
            return [hostname.lower()] if hostname else []
    return []


def _find_egress_violation(
    params: Any,
    allowed_domains: set[str],
    forbidden_patterns: list[tuple[str, re.Pattern[str]]],
) -> dict[str, Any] | None:
    items = list(iter_string_values(params))

    for path, value in items:
        for raw, pattern in forbidden_patterns:
            match = pattern.search(value)
            if match is not None:
                hosts = _extract_hostnames(value, path)
                return {
                    "reason": "forbidden_destination_pattern",
                    "parameter_path": path,
                    "destination": value,
                    "domain": hosts[0] if hosts else None,
                    "pattern": raw,
                    "match": match.group(0),
                }

    for path, value in items:
        for domain in _extract_hostnames(value, path):
            if domain not in allowed_domains:
                return {
                    "reason": "domain_not_in_allowlist",
                    "parameter_path": path,
                    "destination": value,
                    "domain": domain,
                    "allowed_domains": sorted(allowed_domains),
                }

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

            evidence = _find_egress_violation(
                span.get("input_parameters", {}),
                allowed_domains,
                forbidden_patterns,
            )
            if evidence is not None:
                violations.append(self.violation(span, evidence))

        return violations
