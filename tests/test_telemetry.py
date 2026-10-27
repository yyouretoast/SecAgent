import json
from pathlib import Path

import jsonschema

from secagent.telemetry import (
    HITLNormalizer,
    PIIRedactor,
    SecAgentTelemetryCallback,
    TraceExporter,
    TraceSession,
)

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_trace_session_has_required_metadata_and_empty_spans():
    session = TraceSession(
        scenario_id="SCN-01",
        execution_id="exec-01",
        timestamp="2026-10-27T12:00:00Z",
        caller_role="customer",
        task_context="general_inquiry",
    )

    trace = session.as_dict()

    assert trace == {
        "scenario_id": "SCN-01",
        "execution_id": "exec-01",
        "timestamp": "2026-10-27T12:00:00Z",
        "caller_role": "customer",
        "task_context": "general_inquiry",
        "spans": [],
    }


def test_trace_session_assigns_incremental_step_indices():
    session = TraceSession()

    first = session.append({"span_id": "span-1", "span_type": "agent.run"})
    second = session.append({"span_id": "span-2", "span_type": "tool.call"})

    assert first["step_index"] == 0
    assert second["step_index"] == 1
    assert session.spans == [first, second]


def test_trace_session_document_matches_frozen_schema():
    schema = json.loads((ROOT_DIR / "schemas/trace_event.schema.json").read_text())
    session = TraceSession(
        scenario_id="SCN-01",
        execution_id="exec-01",
        timestamp="2026-10-27T12:00:00Z",
        caller_role="customer",
        task_context="general_inquiry",
    )
    session.append(
        {
            "span_id": "span-1",
            "span_type": "agent.run",
            "name": "agent",
            "start_time_ns": 1,
            "end_time_ns": 2,
        }
    )

    jsonschema.validate(session.as_dict(), schema)


def test_callback_records_tool_start_and_end_with_metadata():
    callback = SecAgentTelemetryCallback(
        TraceSession(
            scenario_id="SCN-02",
            execution_id="exec-02",
            timestamp="2026-10-27T12:00:00Z",
            caller_role="operator",
            task_context="address_update",
        )
    )

    callback.on_tool_start(
        {"name": "query_db", "kwargs": {"_secagent_permission_tier": "read"}},
        '{"fields": ["address"]}',
        run_id="run-1",
    )
    callback.on_tool_end({"rows": 1}, run_id="run-1")

    span = callback.spans[0]
    assert span["span_type"] == "tool.call"
    assert span["name"] == "query_db"
    assert span["permission_tier"] == "read"
    assert span["step_index"] == 0
    assert span["start_time_ns"] <= span["end_time_ns"]
    assert span["input_parameters"] == {"fields": ["address"]}
    assert span["output_result"] == {"rows": 1}


def test_callback_correlates_concurrent_tool_runs_and_errors():
    callback = SecAgentTelemetryCallback()
    callback.on_tool_start({"name": "first"}, "{}", run_id="run-1")
    callback.on_tool_start({"name": "second"}, "{}", run_id="run-2")

    callback.on_tool_error(RuntimeError("failed"), run_id="run-1")
    callback.on_tool_end("ok", run_id="run-2")

    first, second = callback.spans
    assert first["name"] == "first"
    assert first["is_error"] is True
    assert first["error_message"] == "failed"
    assert second["name"] == "second"
    assert second["is_error"] is False
    assert second["output_result"] == "ok"


def test_hitl_normalizer_records_approved_gate_after_tool_call():
    session = TraceSession()
    session.append(
        {
            "span_id": "tool-1",
            "span_type": "tool.call",
            "name": "prepare_refund",
            "start_time_ns": 1,
            "end_time_ns": 2,
        }
    )

    span = HITLNormalizer(session).record(
        True,
        operation="issue_refund",
        approver="manager_sim",
        input_parameters={"amount": 50.0},
    )

    assert span["span_type"] == "gate.hitl"
    assert span["name"] == "approval_gate"
    assert span["permission_tier"] == "gate"
    assert span["approval_granted"] is True
    assert span["step_index"] == 1
    assert span["input_parameters"] == {"operation": "issue_refund", "amount": 50.0}
    assert span["output_result"] == {"approver": "manager_sim"}


def test_hitl_normalizer_preserves_rejected_decision():
    span = HITLNormalizer(TraceSession()).record(False, operation="execute_trade")

    assert span["approval_granted"] is False
    assert span["permission_tier"] == "gate"


def test_callback_exposes_hitl_normalization_on_same_session():
    callback = SecAgentTelemetryCallback()

    span = callback.record_hitl(True, operation="issue_refund")

    assert callback.spans == [span]
    assert span["span_type"] == "gate.hitl"
    assert span["approval_granted"] is True


def test_callback_normalizes_framework_interrupt_payload():
    callback = SecAgentTelemetryCallback()

    span = callback.record_interrupt(
        {
            "approved": True,
            "target_operation": "issue_refund",
            "approver": "manager_sim",
        }
    )

    assert span["span_type"] == "gate.hitl"
    assert span["permission_tier"] == "gate"
    assert span["approval_granted"] is True
    assert span["input_parameters"]["operation"] == "issue_refund"
    assert span["output_result"] == {"approver": "manager_sim"}


def test_redactor_scrubs_ssn_token_and_valid_card_in_text():
    text = "ssn=123-45-6789; card=4111 1111 1111 1111; auth=Bearer sk-proj-1234567890abcdef12345678"

    scrubbed = PIIRedactor.scrub_text(text)

    assert "123-45-6789" not in scrubbed
    assert "[REDACTED_SSN]" in scrubbed
    assert "[REDACTED_CARD]" in scrubbed
    assert "[REDACTED_TOKEN]" in scrubbed


def test_redactor_preserves_invalid_card_and_recurses_without_mutating():
    original = {
        "nested": ["123-45-6789", {"card": "4111 1111 1111 1112"}],
        "count": 3,
    }

    scrubbed = PIIRedactor.scrub_container(original)

    assert original["nested"][0] == "123-45-6789"
    assert scrubbed["nested"][0] == "[REDACTED_SSN]"
    assert scrubbed["nested"][1]["card"] == "4111 1111 1111 1112"
    assert scrubbed["count"] == 3


def test_redactor_scrubs_github_token_and_tuple_values():
    token = "ghp_" + "a" * 36

    scrubbed = PIIRedactor.scrub_container((token, "safe"))

    assert scrubbed == ("[REDACTED_TOKEN]", "safe")


def test_exporter_redacts_and_writes_schema_valid_trace(tmp_path):
    session = TraceSession(
        scenario_id="SCN-03",
        execution_id="exec-03",
        timestamp="2026-10-27T12:00:00Z",
        caller_role="customer",
        task_context="general_inquiry",
    )
    session.append(
        {
            "span_id": "span-1",
            "span_type": "tool.call",
            "name": "query_db",
            "start_time_ns": 1,
            "end_time_ns": 2,
            "input_parameters": {"query": "ssn=123-45-6789"},
            "output_result": {"status": "ok"},
        }
    )

    output_path = tmp_path / "trace.json"
    exported = TraceExporter().export(session.as_dict(), output_path)

    assert exported["spans"][0]["input_parameters"]["query"] == "ssn=[REDACTED_SSN]"
    assert json.loads(output_path.read_text())["scenario_id"] == "SCN-03"
    assert session.spans[0]["input_parameters"]["query"] == "ssn=123-45-6789"


def test_exporter_rejects_missing_required_trace_fields():
    import pytest

    with pytest.raises(jsonschema.ValidationError):
        TraceExporter().validate({"spans": []})
