import json
from pathlib import Path

import jsonschema
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

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


def test_callback_resolves_tier_mapping_before_semantic_fallback():
    callback = SecAgentTelemetryCallback(tier_by_tool={"custom_transfer": "admin"})

    callback.on_tool_start({"name": "custom_transfer"}, "{}", run_id="run-mapped")
    callback.on_tool_end("ok", run_id="run-mapped")

    assert callback.spans[0]["permission_tier"] == "admin"


def test_callback_resolves_semantic_tier_when_langchain_metadata_is_missing():
    callback = SecAgentTelemetryCallback()

    callback.on_tool_start({"name": "issue_refund"}, "{}", run_id="run-semantic")
    callback.on_tool_end("ok", run_id="run-semantic")

    assert callback.spans[0]["permission_tier"] == "pay"


def test_callback_prefers_serialized_permission_tier_over_mapping():
    callback = SecAgentTelemetryCallback(tier_by_tool={"issue_refund": "read"})

    callback.on_tool_start(
        {"name": "issue_refund", "permission_tier": "pay"},
        "{}",
        run_id="run-explicit",
    )
    callback.on_tool_end("ok", run_id="run-explicit")

    assert callback.spans[0]["permission_tier"] == "pay"


def test_callback_falls_back_when_explicit_permission_tier_is_none():
    callback = SecAgentTelemetryCallback(tier_by_tool={"issue_refund": "pay"})

    callback.on_tool_start(
        {"name": "issue_refund", "permission_tier": "none"},
        "{}",
        run_id="run-none-tier",
    )
    callback.on_tool_end("ok", run_id="run-none-tier")

    assert callback.spans[0]["permission_tier"] == "pay"


def test_callback_captures_chat_model_span_with_agent_parent_and_redaction():
    callback = SecAgentTelemetryCallback()

    callback.on_chain_start(
        {"name": "support_agent"},
        {"prompt": "Find the account for ssn=123-45-6789"},
        run_id="agent-1",
    )
    callback.on_chat_model_start(
        {"name": "chat-model"},
        [[{"role": "user", "content": "ssn=123-45-6789"}]],
        run_id="model-1",
        parent_run_id="agent-1",
    )
    callback.on_llm_end(
        {"content": "Bearer sk-proj-1234567890abcdef12345678"},
        run_id="model-1",
    )
    callback.on_chain_end({"answer": "safe"}, run_id="agent-1")

    agent_span, model_span = callback.spans
    assert agent_span["span_type"] == "agent.run"
    assert model_span["span_type"] == "model.inference"
    assert model_span["parent_span_id"] == "agent-1"
    assert model_span["step_index"] == 1
    assert "123-45-6789" not in model_span["input_parameters"]["messages"]
    assert "[REDACTED_SSN]" in model_span["input_parameters"]["messages"]
    assert model_span["output_result"]["content"] == "[REDACTED_TOKEN]"

    assert isinstance(callback.span_exporter, InMemorySpanExporter)
    finished = callback.span_exporter.get_finished_spans()
    assert [s.name for s in finished] == ["chat-model", "support_agent"]
    otel_model, otel_agent = finished
    assert model_span["trace_id"] == f"{otel_model.context.trace_id:032x}"
    assert agent_span["trace_id"] == f"{otel_agent.context.trace_id:032x}"
    assert otel_model.parent is not None
    assert otel_model.parent.span_id == otel_agent.context.span_id
    assert "123-45-6789" not in str(otel_model.attributes)
    assert "sk-proj-1234567890abcdef12345678" not in str(otel_model.attributes)
    assert "[REDACTED_SSN]" in otel_model.attributes["secagent.input_parameters"]
    assert "[REDACTED_TOKEN]" in otel_model.attributes["secagent.output_result"]
    TraceExporter().validate(callback.session.as_dict())


def test_callback_captures_llm_error_as_model_inference_span():
    callback = SecAgentTelemetryCallback()

    callback.on_llm_start(
        {"name": "completion-model"},
        ["Look up card=4111 1111 1111 1111"],
        run_id="model-error",
    )
    callback.on_llm_error(
        RuntimeError("provider rejected ssn=123-45-6789"),
        run_id="model-error",
    )

    span = callback.spans[0]
    assert span["span_type"] == "model.inference"
    assert span["name"] == "completion-model"
    assert span["is_error"] is True
    assert span["error_message"] == "provider rejected ssn=[REDACTED_SSN]"
    assert span["start_time_ns"] <= span["end_time_ns"]

    assert isinstance(callback.span_exporter, InMemorySpanExporter)
    finished = callback.span_exporter.get_finished_spans()
    assert len(finished) == 1
    otel_span = finished[0]
    assert otel_span.name == "completion-model"
    assert span["trace_id"] == f"{otel_span.context.trace_id:032x}"
    assert "4111 1111 1111 1111" not in str(otel_span.attributes)
    assert "123-45-6789" not in str(otel_span.attributes)
    assert "[REDACTED_CARD]" in otel_span.attributes["secagent.input_parameters"]
    assert "[REDACTED_SSN]" in otel_span.attributes["secagent.error_message"]
    TraceExporter().validate(callback.session.as_dict())


def test_callback_coerces_nested_non_json_objects_in_chain_spans():
    class _DummyMessage:
        def __init__(self, text: str) -> None:
            self.text = text

        def __str__(self) -> str:
            return f"Message({self.text})"

    callback = SecAgentTelemetryCallback()
    callback.on_chain_start(
        {"name": "support_agent"},
        {"messages": [_DummyMessage("ssn=123-45-6789")]},
        run_id="agent-nested",
    )
    callback.on_chain_end(
        {"messages": [_DummyMessage("token=Bearer sk-proj-1234567890abcdef12345678")]},
        run_id="agent-nested",
    )

    doc = callback.session.as_dict()
    serialized = json.dumps(doc)
    assert "123-45-6789" not in serialized
    assert "sk-proj-1234567890abcdef12345678" not in serialized
    assert "[REDACTED_SSN]" in doc["spans"][0]["input_parameters"]["messages"][0]
    assert "[REDACTED_TOKEN]" in doc["spans"][0]["output_result"]["messages"][0]
    TraceExporter().validate(doc)


def test_callback_redacts_payloads_before_storing_them():
    session = TraceSession(metadata={"token": "Bearer sk-proj-1234567890abcdef12345678"})
    callback = SecAgentTelemetryCallback(session)

    callback.on_tool_start(
        {"name": "lookup"},
        '{"ssn": "123-45-6789"}',
        run_id="run-redact",
    )
    callback.on_tool_end({"card": "4111 1111 1111 1111"}, run_id="run-redact")

    assert session.spans[0]["input_parameters"] == {"ssn": "[REDACTED_SSN]"}
    assert session.spans[0]["output_result"] == {"card": "[REDACTED_CARD]"}
    assert session.metadata["token"] == "[REDACTED_TOKEN]"


def test_callback_emits_redacted_otel_span_with_trace_id_and_nanosecond_timestamps():
    callback = SecAgentTelemetryCallback()
    callback.on_tool_start(
        {"name": "lookup"},
        '{"ssn": "123-45-6789"}',
        run_id="run-otel",
    )
    callback.on_tool_end({"card": "4111 1111 1111 1111"}, run_id="run-otel")

    assert isinstance(callback.span_exporter, InMemorySpanExporter)
    readable_spans = callback.span_exporter.get_finished_spans()
    assert len(readable_spans) == 1

    trace_span = callback.spans[0]
    readable_span = readable_spans[0]
    assert readable_span.name == "lookup"
    assert readable_span.start_time == trace_span["start_time_ns"]
    assert readable_span.end_time == trace_span["end_time_ns"]
    assert trace_span["trace_id"] == f"{readable_span.context.trace_id:032x}"
    assert "123-45-6789" not in str(readable_span.attributes)
    assert "4111 1111 1111 1111" not in str(readable_span.attributes)
    assert "[REDACTED_SSN]" in readable_span.attributes["secagent.input_parameters"]
    assert "[REDACTED_CARD]" in readable_span.attributes["secagent.output_result"]
    assert TraceExporter().validate(callback.session.as_dict()) == callback.session.as_dict()


def test_callback_supports_injected_otel_provider_and_exporter():
    exporter = InMemorySpanExporter()
    callback = SecAgentTelemetryCallback(
        tracer_provider=TracerProvider(),
        span_exporter=exporter,
    )

    callback.on_tool_start({"name": "lookup"}, "{}", run_id="run-injected")
    callback.on_tool_end("ok", run_id="run-injected")

    assert callback.span_exporter is exporter
    assert [span.name for span in exporter.get_finished_spans()] == ["lookup"]


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


def test_hitl_normalizer_emits_redacted_otel_span():
    exporter = InMemorySpanExporter()
    normalizer = HITLNormalizer(TraceSession(), span_exporter=exporter)

    trace_span = normalizer.record(
        True,
        operation="issue_refund",
        approver="Bearer sk-proj-1234567890abcdef12345678",
        input_parameters={"ssn": "123-45-6789"},
    )

    readable_spans = exporter.get_finished_spans()
    assert len(readable_spans) == 1
    readable_span = readable_spans[0]
    assert readable_span.name == "approval_gate"
    assert readable_span.start_time == trace_span["start_time_ns"]
    assert readable_span.end_time == trace_span["end_time_ns"]
    assert trace_span["trace_id"] == f"{readable_span.context.trace_id:032x}"
    assert "123-45-6789" not in str(readable_span.attributes)
    assert "sk-proj-1234567890abcdef12345678" not in str(readable_span.attributes)
    assert "[REDACTED_SSN]" in readable_span.attributes["secagent.input_parameters"]
    assert "[REDACTED_TOKEN]" in readable_span.attributes["secagent.output_result"]


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


def test_redactor_scrubs_valid_15_digit_card():
    scrubbed = PIIRedactor.scrub_text("card=3782 822463 10005")

    assert scrubbed == "card=[REDACTED_CARD]"


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
    assert session.spans[0]["input_parameters"]["query"] == "ssn=[REDACTED_SSN]"


def test_exporter_redacts_metadata_and_span_attributes_added_after_capture():
    session = TraceSession()
    trace = session.as_dict()
    trace["metadata"] = {"api_key": "Bearer sk-proj-1234567890abcdef12345678"}
    trace["spans"] = [
        {
            "span_id": "span-attributes",
            "step_index": 0,
            "span_type": "tool.call",
            "name": "lookup",
            "start_time_ns": 1,
            "end_time_ns": 2,
            "attributes": {"ssn": "123-45-6789"},
        }
    ]

    exported = TraceExporter().validate(trace)

    assert exported["metadata"]["api_key"] == "[REDACTED_TOKEN]"
    assert exported["spans"][0]["attributes"]["ssn"] == "[REDACTED_SSN]"


def test_exporter_coerces_list_tool_output_to_schema_compatible_json():
    callback = SecAgentTelemetryCallback(
        TraceSession(
            scenario_id="SCN-04",
            execution_id="exec-04",
            timestamp="2026-10-27T12:00:00Z",
            caller_role="customer",
            task_context="general_inquiry",
        )
    )
    callback.on_tool_start({"name": "list_items"}, "{}", run_id="run-list")
    callback.on_tool_end(["one", "two"], run_id="run-list")

    exported = TraceExporter().validate(callback.session.as_dict())

    assert exported["spans"][0]["output_result"] == '["one", "two"]'


def test_callback_serializes_non_json_objects_inside_list_output():
    class ToolResult:
        def __str__(self):
            return "tool-result"

    callback = SecAgentTelemetryCallback()
    callback.on_tool_start({"name": "list_items"}, "{}", run_id="run-object-list")
    callback.on_tool_end([ToolResult()], run_id="run-object-list")

    exported = TraceExporter().validate(callback.session.as_dict())

    assert exported["spans"][0]["output_result"] == '["tool-result"]'


def test_exporter_rejects_missing_required_trace_fields():
    import pytest

    with pytest.raises(jsonschema.ValidationError):
        TraceExporter().validate({"spans": []})
