from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, get_args

from secagent.harness.topology import TopologyProfile

ThreatModelChoice = Literal["auto", "owasp", "maestro"]
Route = Literal["owasp", "maestro"]

DEFAULT_THREAT_MODEL: ThreatModelChoice = "auto"
THREAT_MODEL_CHOICES: tuple[str, ...] = get_args(ThreatModelChoice)

_CHOICES: dict[str, ThreatModelChoice] = {choice: choice for choice in get_args(ThreatModelChoice)}


@dataclass(frozen=True)
class ThreatRoute:
    requested: ThreatModelChoice
    route: Route
    forced: bool
    reason: str
    signals: tuple[str, ...] = ()

    @property
    def uses_maestro(self) -> bool:
        return self.route == "maestro"

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for reports."""
        return {
            "requested": self.requested,
            "route": self.route,
            "forced": self.forced,
            "uses_maestro": self.uses_maestro,
            "reason": self.reason,
            "signals": list(self.signals),
        }


def parse_threat_model(value: str | None) -> ThreatModelChoice:

    if value is None:
        return DEFAULT_THREAT_MODEL
    choice = _CHOICES.get(value.strip().lower())
    if choice is None:
        allowed = ", ".join(THREAT_MODEL_CHOICES)
        raise ValueError(f"Invalid threat model {value!r}; expected one of: {allowed}")
    return choice


def route_threat_model(
    profile: TopologyProfile, requested: str | None = DEFAULT_THREAT_MODEL
) -> ThreatRoute:
    choice = parse_threat_model(requested)
    signals = profile.signals

    if choice == "owasp":
        return ThreatRoute(choice, "owasp", True, "explicit --threat-model owasp", signals)

    if choice == "maestro":
        reason = "explicit --threat-model maestro"
        if not profile.is_multi_agent:
            reason += " (target was not classified as multi-agent)"
        return ThreatRoute(choice, "maestro", True, reason, signals)

    if profile.is_multi_agent:
        reason = f"multi-agent topology detected ({', '.join(signals)})"
        return ThreatRoute(choice, "maestro", False, reason, signals)
    if not profile.inspectable:
        reason = "target graph not inspectable; keeping the OWASP baseline"
        return ThreatRoute(choice, "owasp", False, reason, signals)
    return ThreatRoute(choice, "owasp", False, "single-agent topology", signals)


__all__ = [
    "DEFAULT_THREAT_MODEL",
    "THREAT_MODEL_CHOICES",
    "Route",
    "ThreatModelChoice",
    "ThreatRoute",
    "parse_threat_model",
    "route_threat_model",
]
