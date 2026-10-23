from typing import Any

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


#added new tests 

from typing import Annotated, Optional


def test_fuzzer_does_not_crash_on_string_annotation():
    def query_db(query: str, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(
        query_db, "sqli", "attack"
    )

    assert args == {"query": "attack", "limit": 10}


def test_optional_string_target_is_supported():
    def query_db(query: Optional[str], limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(
        query_db, "sqli", "attack"
    )

    assert args == {"query": "attack", "limit": 10}


def test_annotated_string_target_is_supported():
    def query_db(query: Annotated[str, "SQL query"], limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(
        query_db, "sqli", "attack"
    )

    assert args == {"query": "attack", "limit": 10}


def test_no_matching_target_does_not_inject_payload():
    def lookup(note: str, limit: int):
        return None

    args = SchemaDirectedFuzzer().build_arguments(
        lookup, "sqli", "attack"
    )

    assert args == {"note": "", "limit": 10}
