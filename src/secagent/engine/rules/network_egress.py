"""POL-ASI10-001: network egress allowlist and forbidden-sink enforcement."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

from secagent.engine.models import PolicyViolation
from secagent.engine.rules.base import BaseRule, iter_string_values

_DESTINATION_KEYS = frozenset(
    {"url", "endpoint", "destination", "host", "uri", "webhook", "callback"}
)
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")
_PROTO_RELATIVE_URL_RE = re.compile(r"(?<![A-Za-z0-9+.-:])//[A-Za-z0-9.\[\]:-]+(?:[^\s\"'<>]*)?")
_IPV4_RE = re.compile(r"(?<![A-Za-z0-9_./])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_BRACKET_IPV6_RE = re.compile(r"\[([0-9a-fA-F:]+)\]")
_BARE_IPV6_RE = re.compile(
    r"(?<![0-9a-fA-F:\[])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])"
)
_TRAILING_URL_PUNCT = ".,;:)]}"
_INT_IP_RE = re.compile(r"^(?:\d+|0x[0-9a-fA-F]+)$")


def _leaf_key(path: str) -> str:
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0].strip().lower()


def _domain_allowed(domain: str, allowed_domains: set[str]) -> bool:
    """Support exact domain matches and ``*.example.com`` subdomain wildcards."""
    normalized = domain.strip().lower().rstrip(".")
    if normalized in allowed_domains:
        return True
    for entry in allowed_domains:
        if entry.startswith("*."):
            suffix = entry[1:]  # ".example.com"
            if normalized.endswith(suffix) and len(normalized) > len(suffix):
                return True
    return False


def _extract_hostnames(value: str, path: str, *, scan_all_ips: bool = True) -> list[str]:
    candidate = re.sub(r"[\t\r\n]+", "", value).strip()
    if not candidate:
        return []

    hosts: list[str] = []
    seen: set[str] = set()

    def _add(host: str) -> None:
        cleaned = host.strip().lower().rstrip(".")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            hosts.append(cleaned)

    urls = _URL_RE.findall(candidate)
    proto_urls = _PROTO_RELATIVE_URL_RE.findall(candidate)
    if urls or proto_urls:
        for raw_url in urls:
            cleaned_url = raw_url.rstrip(_TRAILING_URL_PUNCT)
            try:
                parsed = urlparse(cleaned_url)
            except ValueError:
                continue
            if parsed.hostname:
                _add(parsed.hostname)
            # Detect backslash authority confusion (e.g. https://evil.com\@api.github.com/).
            scheme_sep = cleaned_url.find("://")
            if scheme_sep != -1 and "\\" in cleaned_url[scheme_sep + 3 :]:
                authority_prefix = cleaned_url[scheme_sep + 3 :].split("\\", 1)[0]
                try:
                    alt_host = urlparse(f"https://{authority_prefix}").hostname
                except ValueError:
                    alt_host = None
                if alt_host:
                    _add(alt_host)
        for raw_proto in proto_urls:
            cleaned_proto = raw_proto.rstrip(_TRAILING_URL_PUNCT)
            try:
                parsed_proto = urlparse(f"https:{cleaned_proto}")
            except ValueError:
                continue
            if parsed_proto.hostname:
                _add(parsed_proto.hostname)

    if (
        not urls
        and not proto_urls
        and _leaf_key(path) in _DESTINATION_KEYS
        and " " not in candidate
    ):
        bare_host = candidate.split("/", 1)[0].split(":", 1)[0].lower()
        if _INT_IP_RE.fullmatch(bare_host):
            try:
                int_val = int(bare_host, 0)
            except ValueError:
                int_val = -1
            if 0 <= int_val <= 0xFFFFFFFF:
                _add(str(ipaddress.IPv4Address(int_val)))
        elif (
            "." in candidate
            or bare_host == "localhost"
            or candidate.startswith("[")
            or ":" in candidate
        ):
            try:
                ipaddress.ip_address(candidate)
                _add(candidate)
            except ValueError:
                try:
                    hostname = urlparse(f"https://{candidate}").hostname
                except ValueError:
                    hostname = None
                if hostname:
                    _add(hostname)

    if scan_all_ips:
        for match in _IPV4_RE.findall(candidate):
            try:
                ipaddress.ip_address(match)
            except ValueError:
                continue
            _add(match)
        for inner in _BRACKET_IPV6_RE.findall(candidate):
            try:
                ipaddress.IPv6Address(inner)
            except ValueError:
                continue
            _add(inner)
        for match in _BARE_IPV6_RE.findall(candidate):
            if "::" not in match and match.count(":") < 3:
                continue
            try:
                ipaddress.IPv6Address(match)
            except ValueError:
                continue
            _add(match)
    return hosts


def _find_egress_violation(
    params: Any,
    allowed_domains: set[str],
    forbidden_patterns: list[tuple[str, re.Pattern[str]]],
    *,
    scan_all_ips: bool = True,
) -> dict[str, Any] | None:
    items = list(iter_string_values(params))

    for path, value in items:
        for raw, pattern in forbidden_patterns:
            match = pattern.search(value)
            if match is not None:
                hosts = _extract_hostnames(value, path, scan_all_ips=scan_all_ips)
                return {
                    "reason": "forbidden_destination_pattern",
                    "parameter_path": path,
                    "destination": value,
                    "domain": hosts[0] if hosts else None,
                    "pattern": raw,
                    "match": match.group(0),
                }

    for path, value in items:
        for domain in _extract_hostnames(value, path, scan_all_ips=scan_all_ips):
            if not _domain_allowed(domain, allowed_domains):
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

    def __init__(self, policy: Any) -> None:
        super().__init__(policy)
        condition = policy.condition
        self._target_tiers = set(condition.get("target_tiers", ("net",)))
        self._target_tools = set(condition.get("target_tools", ()))
        self._allowed_domains = {
            str(d).strip().lower().rstrip(".") for d in condition.get("allowed_domains", ())
        }
        self._forbidden_patterns = [
            (raw, re.compile(raw)) for raw in condition.get("forbidden_destination_patterns", ())
        ]
        self._scan_all_ips = bool(condition.get("scan_all_string_ips", True))

    def evaluate(self, trace: Mapping[str, Any]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for span in trace.get("spans", []):
            if not isinstance(span, Mapping) or span.get("span_type") != "tool.call":
                continue

            if (
                span.get("permission_tier") not in self._target_tiers
                and span.get("name") not in self._target_tools
            ):
                continue

            evidence = _find_egress_violation(
                span.get("input_parameters", {}),
                self._allowed_domains,
                self._forbidden_patterns,
                scan_all_ips=self._scan_all_ips,
            )
            if evidence is not None:
                violations.append(self.violation(span, evidence))

        return violations
