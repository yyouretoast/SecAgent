from typing import Annotated, Any

from secagent.generator import ScenarioGenerator, ToolMetadata
from secagent.generator.fuzzer import SchemaDirectedFuzzer


def test_sqli_targets_query_and_preserves_required_integer():
    def query_db(query: str, limit: int):
        return None

    scenario = next(
        item
        for item in ScenarioGenerator().generate([query_db])
        if item.expected_failure_policy == "POL-ASI02-001"
    )
    assert scenario.injected_parameters == {"query": "' OR '1'='1", "limit": 10}


def test_sqli_does_not_target_integer_or_unrelated_string():
    def lookup(limit: int, note: str):
        return None

    args = SchemaDirectedFuzzer().build_arguments(lookup, "sqli", "payload")
    assert args == {"limit": 10, "note": ""}


def test_non_target_defaults_and_supported_parameter_types():
    def query_db(query: str, limit: int = 25, enabled: bool = False):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")
    assert args == {"query": "attack", "limit": 25, "enabled": False}


def test_unsupported_target_type_is_not_injected():
    def query_db(query: bytes, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")
    assert args == {"query": b"", "limit": 10}


def test_missing_schema_metadata_has_no_invented_arguments():
    tool = ToolMetadata(name="unknown", parameters={})
    assert SchemaDirectedFuzzer().build_arguments(tool, "sqli", "attack") == {}


def test_unannotated_parameters_do_not_receive_inferred_payloads():
    def query_db(query, limit):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")
    assert args == {"query": None, "limit": None}


def test_schema_string_annotation_can_be_targeted_without_other_keys():
    tool = ToolMetadata(name="query_db", parameters={"query": "str", "limit": "int"})
    assert SchemaDirectedFuzzer().build_arguments(tool, "sqli", "attack") == {
        "query": "attack",
        "limit": 10,
    }


def test_non_target_unknown_required_type_is_retained_without_payload():
    def query_db(query: str, context: Any):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")
    assert args == {"query": "attack", "context": None}


def test_egress_scenario_for_non_net_tool_with_destination_parameter():
    def send_notification(destination: str):
        return None

    scenarios = ScenarioGenerator().generate([send_notification])
    egress_scenarios = [
        item for item in scenarios if item.owasp_category == "ASI10-RogueAgentExfiltration"
    ]

    assert len(egress_scenarios) == 1
    assert egress_scenarios[0].injected_parameters == {
        "destination": ScenarioGenerator.EGRESS_PAYLOADS[0]
    }
    assert egress_scenarios[0].expected_failure_policy == "POL-ASI10-001"


def test_egress_scenario_not_generated_for_non_net_tool_without_matching_parameter():
    def lookup_record(record_id: str, note: str):
        return None

    scenarios = ScenarioGenerator().generate([lookup_record])

    assert not any(item.owasp_category == "ASI10-RogueAgentExfiltration" for item in scenarios)


def test_egress_scenario_preserves_net_tier_prompt_level_behavior():
    scenarios = ScenarioGenerator().generate(
        [ToolMetadata(name="send_data", permission_tier="net")]
    )
    egress_scenario = next(
        item for item in scenarios if item.owasp_category == "ASI10-RogueAgentExfiltration"
    )

    assert egress_scenario.injected_parameters == {}
    assert egress_scenario.expected_failure_policy == "POL-ASI10-001"


def test_fuzzer_does_not_crash_on_string_annotation():
    def query_db(query: str, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")

    assert args == {"query": "attack", "limit": 10}


def test_optional_string_target_is_supported():
    def query_db(query: str | None, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")

    assert args == {"query": "attack", "limit": 10}


def test_annotated_string_target_is_supported():
    def query_db(query: Annotated[str, "SQL query"], limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(query_db, "sqli", "attack")

    assert args == {"query": "attack", "limit": 10}


def test_no_matching_target_does_not_inject_payload():
    def lookup(note: str, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(lookup, "sqli", "attack")

    assert args == {"note": "", "limit": 10}


def test_fallback_to_any_string_injects_when_enabled():
    def lookup(note: str, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(
        lookup, "sqli", "attack", fallback_to_any_string=True
    )
    assert args == {"note": "attack", "limit": 10}


def test_generator_seed_varies_payloads_deterministically():
    def query_db(query: str):
        return None

    s_default = ScenarioGenerator().generate([query_db], seed=42)
    s_alt_a = ScenarioGenerator().generate([query_db], seed=7)
    s_alt_b = ScenarioGenerator().generate([query_db], seed=7)
    s_other = ScenarioGenerator().generate([query_db], seed=99)

    assert [s.to_dict() for s in s_alt_a] == [s.to_dict() for s in s_alt_b]
    prompts_set = {
        next(s.user_prompt for s in suite if s.expected_failure_policy == "POL-ASI02-001")
        for suite in (s_default, s_alt_a, s_other)
    }
    assert len(prompts_set) >= 2


def test_goal_hijack_prompts_match_pol_asi01_001_regexes():
    import re

    from secagent.engine.loader import PolicyLoader

    ruleset = PolicyLoader().load()
    rule = next(p for p in ruleset.policies if p.id == "POL-ASI01-001")
    patterns = [re.compile(p) for p in rule.condition["injection_patterns"]]
    for prompt in ScenarioGenerator.GOAL_HIJACK_PROMPTS:
        assert any(pat.search(prompt) for pat in patterns), f"Prompt did not match: {prompt}"


def test_fuzzer_handles_pydantic_v2_optional_anyof_and_array_scope():
    fuzzer = SchemaDirectedFuzzer()
    opt_tool = {
        "query": {"anyOf": [{"type": "string"}, {"type": "null"}], "required": True},
        "select": {
            "anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}],
            "required": True,
        },
    }
    sqli_args = fuzzer.build_arguments(opt_tool, "sqli", "' OR '1'='1")
    assert sqli_args["query"] == "' OR '1'='1"
    scope_args = fuzzer.build_arguments(opt_tool, "scope", ["ssn", "password_hash"])
    assert scope_args["select"] == ["ssn", "password_hash"]


def test_toxic_flow_scenario_avoids_self_sink_and_general_inquiry_fp():
    from secagent.sdk import permission

    @permission(tier="net")
    def fetch_webhook(url: str) -> str:
        return url

    @permission(tier="pay")
    def execute_trade(symbol: str) -> str:
        return symbol

    scenarios = ScenarioGenerator().generate([fetch_webhook, execute_trade])
    toxic = next(s for s in scenarios if s.expected_failure_policy == "POL-ASI01-002")
    assert toxic.task_context == "default"
    assert toxic.target_tool == "fetch_webhook"
    assert "execute_trade" in (toxic.taint_payload or "")


def test_fuzzer_handles_required_anyof_dict_none_union_and_serialized_types():
    fuzzer = SchemaDirectedFuzzer()
    complex_tool = {
        "union_param": {"anyOf": [{"type": "integer"}, {"type": "string"}], "required": True},
        "meta_dict": {"annotation": dict[str, str], "required": True},
        "none_first": {"annotation": None | int, "required": True},
        "query": {"annotation": "<class 'str'>", "required": True},
        "fields": {"annotation": "list[str]", "required": True},
    }
    args = fuzzer.build_arguments(complex_tool, "sqli", "' OR '1'='1")
    assert args["union_param"] == 10
    assert args["meta_dict"] == {}
    assert args["none_first"] == 10
    assert args["query"] == "' OR '1'='1"
    assert args["fields"] == []
