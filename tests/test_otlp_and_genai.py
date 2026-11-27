"""Tests for PR-5: OTel GenAI semconv attributes, OTLP ingestion, thread safety, and expanded redactor."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from typer.testing import CliRunner

from secagent.cli import app
from secagent.telemetry import (
    PIIRedactor,
    SecAgentTelemetryCallback,
    TraceExporter,
    convert_otlp_to_traces,
    is_otlp_payload,
)

ROOT = Path(__file__).resolve().parent.parent


def test_callback_dual_emits_official_otel_genai_semantic_conventions():
    cb = SecAgentTelemetryCallback()
    cb.on_chain_start({"name": "FinanceAgent"}, {"prompt": "hi"}, run_id="ag-1")
    cb.on_chat_model_start(
        {"name": "gpt-4o"},
        [[{"role": "user", "content": "hi"}]],
        run_id="m-1",
        parent_run_id="ag-1",
    )
    cb.on_llm_end({"content": "calling tool"}, run_id="m-1")
    cb.on_tool_start(
        {"name": "execute_trade"}, '{"symbol":"AAPL"}', run_id="t-1", parent_run_id="ag-1"
    )
    cb.on_tool_end({"status": "ok"}, run_id="t-1")
    cb.on_chain_end({"done": True}, run_id="ag-1")

    assert isinstance(cb.span_exporter, InMemorySpanExporter)
    by_name = {s.name: s.attributes for s in cb.span_exporter.get_finished_spans()}
    assert by_name["FinanceAgent"]["gen_ai.operation.name"] == "invoke_agent"
    assert by_name["FinanceAgent"]["gen_ai.agent.name"] == "FinanceAgent"
    assert by_name["gpt-4o"]["gen_ai.operation.name"] == "chat"
    assert by_name["gpt-4o"]["gen_ai.request.model"] == "gpt-4o"
    assert by_name["execute_trade"]["gen_ai.operation.name"] == "execute_tool"
    assert by_name["execute_trade"]["gen_ai.tool.name"] == "execute_trade"
    assert by_name["execute_trade"]["gen_ai.tool.call.id"] == "t-1"


def test_otlp_json_ingestion_evaluates_policies_via_cli(tmp_path: Path):
    otlp_fixture = ROOT / "tests" / "fixtures" / "otlp" / "sample_otlp_trace.json"
    raw = json.loads(otlp_fixture.read_text(encoding="utf-8"))
    assert is_otlp_payload(raw) is True
    traces = convert_otlp_to_traces(raw)
    assert len(traces) == 1
    TraceExporter().validate(traces[0])
    assert traces[0]["spans"][1]["name"] == "execute_trade"
    assert traces[0]["spans"][1]["permission_tier"] == "pay"

    report_path = tmp_path / "otlp_report.json"
    comment_path = tmp_path / "otlp_comment.md"
    res = CliRunner().invoke(
        app,
        [
            "scan",
            "--trace",
            str(otlp_fixture),
            "--output-report",
            str(report_path),
            "--output-markdown",
            str(comment_path),
        ],
    )
    assert res.exit_code == 1
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "FAIL"
    assert any(v["rule_id"] == "POL-ASI03-001" for v in report["violations"])


def test_telemetry_callback_is_thread_safe_under_parallel_tool_calls():
    cb = SecAgentTelemetryCallback()
    errors: list[Exception] = []

    def worker(idx: int) -> None:
        try:
            rid = f"run-{idx}"
            cb.on_tool_start({"name": f"tool_{idx}"}, json.dumps({"idx": idx}), run_id=rid)
            cb.on_tool_end({"ok": idx}, run_id=rid)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(cb.spans) == 20
    assert sorted(s["step_index"] for s in cb.spans) == list(range(20))
    TraceExporter().validate(cb.session.as_dict())


def test_redactor_scrubs_aws_github_pat_gcp_slack_jwt_and_pem_keys():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    gh_pat = "github_pat_" + "A" * 24
    gcp = "AIza" + "B" * 35
    slack = "xoxb-1234567890-abcdef123456"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG\n-----END PRIVATE KEY-----"

    for secret in (aws, gh_pat, gcp, slack, jwt):
        scrubbed = PIIRedactor.scrub_text(f"val={secret}")
        assert secret not in scrubbed
        assert "[REDACTED_TOKEN]" in scrubbed

    scrubbed_pem = PIIRedactor.scrub_text(pem)
    assert "MIIEvQIBADANBgkqhkiG" not in scrubbed_pem
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed_pem


def test_otlp_official_genai_call_attrs_traceloop_and_proto3_nulls():
    doc = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "crew"}}]
                },
                "scopeSpans": [
                    {"spans": None},
                    {
                        "spans": [
                            {
                                "traceId": "abcd1234abcd1234",
                                "spanId": "s2",
                                "parentSpanId": "s1",
                                "name": "query_db",
                                "startTimeUnixNano": "1700000000000000000",
                                "endTimeUnixNano": "1700000000000000000",
                                "attributes": [
                                    {
                                        "key": "gen_ai.operation.name",
                                        "value": {"stringValue": "execute_tool"},
                                    },
                                    {
                                        "key": "gen_ai.tool.name",
                                        "value": {"stringValue": "query_db"},
                                    },
                                    {
                                        "key": "gen_ai.tool.call.arguments",
                                        "value": {"stringValue": '{"sql": "DROP TABLE users"}'},
                                    },
                                    {
                                        "key": "gen_ai.tool.call.result",
                                        "value": {"stringValue": '{"ok": true}'},
                                    },
                                    {"key": "secagent.is_error", "value": {"stringValue": "false"}},
                                ],
                            },
                            {
                                "traceId": "abcd1234abcd1234",
                                "spanId": "s1",
                                "name": "agent",
                                "startTimeUnixNano": "1700000000000000000",
                                "endTimeUnixNano": "1700000001000000000",
                                "attributes": [
                                    {
                                        "key": "traceloop.span.kind",
                                        "value": {"stringValue": "agent"},
                                    },
                                    {
                                        "key": "secagent.task_context",
                                        "value": {"stringValue": "address_update"},
                                    },
                                ],
                            },
                        ]
                    },
                ],
            }
        ]
    }
    traces = convert_otlp_to_traces(doc)
    assert len(traces) == 1
    tr = traces[0]
    TraceExporter().validate(tr)
    assert tr["task_context"] == "address_update"
    # Parent s1 ordered before child s2 despite equal timestamps
    assert [s["span_id"] for s in tr["spans"]] == ["s1", "s2"]
    assert tr["spans"][1]["input_parameters"] == {"sql": "DROP TABLE users"}
    assert tr["spans"][1]["output_result"] == {"ok": True}
    assert tr["spans"][1]["is_error"] is False


def test_redactor_handles_trailing_hyphen_gcp_key_ghs_asia_dict_keys_and_card_spacing():
    gcp_hyphen = "AIza" + "B" * 34 + "-"
    ghs = "ghs_" + "A" * 36
    asia = "ASIA" + "IOSFODNN7EXAMPLE"
    short_jwt = "eyJhbGciOiJub25lIn0.eyJpZCI6MX0.abcdefghijkl"
    for secret in (gcp_hyphen, ghs, asia, short_jwt):
        out = PIIRedactor.scrub_text(f"token={secret} end")
        assert secret not in out
        assert "[REDACTED_TOKEN]" in out
    assert PIIRedactor.scrub_text("4111111111111111 foo") == "[REDACTED_CARD] foo"
    akia = "AKIA" + "IOSFODNN7EXAMPLE"
    scrubbed_dict = PIIRedactor.scrub_container({akia: "ok"})
    assert akia not in scrubbed_dict
    assert "[REDACTED_TOKEN]" in scrubbed_dict


def test_pr5_redactor_otlp_gate_disambiguation_and_thread_safe_spans():
    # Case-insensitive Bearer and non-greedy truncated PEM preserve subsequent text
    bearer_lower = "bearer abcdefghijklmnopqrstuvwxyz12345"
    assert PIIRedactor.scrub_text(f"auth={bearer_lower}") == "auth=[REDACTED_TOKEN]"
    trunc_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\nQIDAQAB\n\nsafe_trailing_text"
    scrubbed_pem = PIIRedactor.scrub_text(trunc_pem)
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed_pem
    assert "safe_trailing_text" in scrubbed_pem
    assert "MIIEowIBAAK" not in scrubbed_pem

    # execute_tool named fetch_approval_gate stays tool.call, and OTLP inputs/attrs get redacted
    doc = {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": "svc"}}]
                },
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "traceId": "deadbeef12345678",
                                "spanId": "s1",
                                "name": "fetch_approval_gate",
                                "startTimeUnixNano": "1700000000000000000",
                                "endTimeUnixNano": "1700000001000000000",
                                "attributes": [
                                    {
                                        "key": "gen_ai.operation.name",
                                        "value": {"stringValue": "execute_tool"},
                                    },
                                    {
                                        "key": "gen_ai.tool.call.arguments",
                                        "value": {
                                            "stringValue": '{"auth": "Bearer SecretTokenValue1234567890"}'
                                        },
                                    },
                                ],
                            }
                        ]
                    }
                ],
            }
        ]
    }
    traces = convert_otlp_to_traces(doc)
    assert len(traces) == 1
    sp = traces[0]["spans"][0]
    assert sp["span_type"] == "tool.call"
    assert sp["input_parameters"]["auth"] == "[REDACTED_TOKEN]"
    assert "SecretTokenValue1234567890" not in str(sp["attributes"])

    cb = SecAgentTelemetryCallback()
    cb.on_tool_start({"name": "lookup"}, {"q": "ok"}, run_id="r1")
    snap = cb.spans
    assert isinstance(snap, list) and len(snap) == 1
    assert snap is not cb.session.spans
