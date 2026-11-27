"""Tests for threat-model routing (US-1.6): pure, no LangGraph needed."""

import json

import pytest

from secagent.harness.threat_router import (
    DEFAULT_THREAT_MODEL,
    THREAT_MODEL_CHOICES,
    ThreatRoute,
    parse_threat_model,
    route_threat_model,
)
from secagent.harness.topology import SIGNAL_MULTIPLE_AGENTS, TopologyProfile

SINGLE = TopologyProfile(kind="single_agent")
MULTI = TopologyProfile(
    kind="multi_agent",
    agent_nodes=("billing", "ops"),
    signals=(SIGNAL_MULTIPLE_AGENTS,),
)
UNINSPECTABLE = TopologyProfile(kind="single_agent", inspectable=False)


def test_auto_is_the_default():
    assert DEFAULT_THREAT_MODEL == "auto"
    assert route_threat_model(SINGLE).requested == "auto"
    assert route_threat_model(MULTI, None).requested == "auto"


def test_auto_keeps_single_agent_on_owasp():
    route = route_threat_model(SINGLE, "auto")
    assert route.route == "owasp"
    assert not route.uses_maestro
    assert not route.forced


def test_auto_sends_multi_agent_to_maestro():
    route = route_threat_model(MULTI, "auto")
    assert route.route == "maestro"
    assert route.uses_maestro
    assert not route.forced
    assert SIGNAL_MULTIPLE_AGENTS in route.reason
    assert route.signals == (SIGNAL_MULTIPLE_AGENTS,)


def test_auto_keeps_uninspectable_targets_on_owasp():
    route = route_threat_model(UNINSPECTABLE, "auto")
    assert route.route == "owasp"
    assert "not inspectable" in route.reason


@pytest.mark.parametrize("profile", [SINGLE, MULTI, UNINSPECTABLE], ids=["single", "multi", "raw"])
def test_explicit_owasp_wins_over_topology(profile):
    route = route_threat_model(profile, "owasp")
    assert route.route == "owasp"
    assert route.forced


@pytest.mark.parametrize("profile", [SINGLE, MULTI, UNINSPECTABLE], ids=["single", "multi", "raw"])
def test_explicit_maestro_wins_over_topology(profile):
    route = route_threat_model(profile, "maestro")
    assert route.route == "maestro"
    assert route.forced


def test_explicit_maestro_on_single_agent_says_so():
    assert "not classified as multi-agent" in route_threat_model(SINGLE, "maestro").reason
    assert "not classified" not in route_threat_model(MULTI, "maestro").reason


def test_values_are_case_and_whitespace_insensitive():
    assert parse_threat_model(" MAESTRO ") == "maestro"
    assert route_threat_model(SINGLE, "OWASP").route == "owasp"


@pytest.mark.parametrize("bad", ["", "stride", "owasp+maestro", "none"])
def test_invalid_values_are_rejected_with_the_allowed_list(bad):
    with pytest.raises(ValueError, match="auto, owasp, maestro"):
        parse_threat_model(bad)
    with pytest.raises(ValueError):
        route_threat_model(SINGLE, bad)


def test_choices_are_exactly_the_documented_ones():
    assert THREAT_MODEL_CHOICES == ("auto", "owasp", "maestro")


def test_routing_is_deterministic_and_json_serialisable():
    first = route_threat_model(MULTI, "auto")
    assert first == route_threat_model(MULTI, "auto")
    payload = json.loads(json.dumps(first.to_dict()))
    assert payload == {
        "requested": "auto",
        "route": "maestro",
        "forced": False,
        "uses_maestro": True,
        "reason": first.reason,
        "signals": [SIGNAL_MULTIPLE_AGENTS],
    }


def test_route_is_immutable():
    route = route_threat_model(SINGLE)
    assert isinstance(route, ThreatRoute)
    with pytest.raises(AttributeError):
        route.route = "maestro"  # type: ignore[misc]
