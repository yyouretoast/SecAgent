"""POL-ASI10-001: outbound network destination enforcement."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule

DESTINATION_KEYS = {"url", "endpoint", "host", "hostname", "destination"}


def _destinations(value: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).casefold() in DESTINATION_KEYS and isinstance(nested, str):
                found.append((str(key), nested))
            else:
                found.extend(_destinations(nested))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for nested in value:
            found.extend(_destinations(nested))
    return found


def _hostname(destination: str) -> str | None:
    parsed = urlparse(destination if "://" in destination else f"//{destination}")
    return parsed.hostname.casefold() if parsed.hostname else None


class NetworkEgressRule(BaseRule):
    """Reject network destinations outside the configured exact domain allowlist."""

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        condition = self.policy.condition
        target_tiers = set(condition.get("target_tiers", ["net"]))
        allowed = {str(item).casefold() for item in condition.get("allowed_domains", [])}
        forbidden_patterns = [
            (raw, re.compile(raw)) for raw in condition.get("forbidden_destination_patterns", [])
        ]
        violations: list[PolicyViolation] = []

        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue
            if span.get("permission_tier") not in target_tiers:
                continue

            for key, destination in _destinations(span.get("input_parameters", {})):
                host = _hostname(destination)
                forbidden_match = next(
                    (
                        {"pattern": raw, "match": match.group(0)}
                        for raw, pattern in forbidden_patterns
                        if (match := pattern.search(destination)) is not None
                    ),
                    None,
                )
                if host in allowed and forbidden_match is None:
                    continue

                violations.append(
                    self.violation(
                        span,
                        {
                            "destination_parameter": key,
                            "destination": destination,
                            "parsed_hostname": host,
                            "allowed_domains": sorted(allowed),
                            "forbidden_match": forbidden_match,
                        },
                    )
                )

        return violations
