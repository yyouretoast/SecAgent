"""OpenTelemetry OTLP JSON ingestion adapter for SecAgent."""

from __future__ import annotations

import json
import math
import time
import uuid
from collections.abc import Mapping
from typing import Any

from secagent.harness.introspector import resolve_permission_tier
from secagent.telemetry.redactor import PIIRedactor

_VALID_SPAN_TIERS = frozenset({"pure", "read", "write", "pay", "admin", "net", "gate", "none"})
_MAX_UNPACK_DEPTH = 32


def is_otlp_payload(doc: Any) -> bool:
    """Return True if ``doc`` looks like an OTLP JSON trace export."""
    return isinstance(doc, Mapping) and isinstance(doc.get("resourceSpans"), list)


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no", ""}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return None


def _to_int_ns(value: Any, default: int = 0) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            fval = float(value)
            return int(fval) if math.isfinite(fval) else default
        except (TypeError, ValueError):
            return default


def _unpack_any_value(raw: Any, _depth: int = 0) -> Any:
    if _depth > _MAX_UNPACK_DEPTH:
        return None
    if not isinstance(raw, Mapping):
        return raw
    if "stringValue" in raw:
        return str(raw["stringValue"])
    if "boolValue" in raw:
        parsed_bool = _to_bool(raw["boolValue"])
        return parsed_bool if parsed_bool is not None else False
    if "intValue" in raw:
        try:
            return int(raw["intValue"])
        except (TypeError, ValueError):
            return str(raw["intValue"])
    if "doubleValue" in raw:
        try:
            fval = float(raw["doubleValue"])
            return fval if math.isfinite(fval) else str(raw["doubleValue"])
        except (TypeError, ValueError):
            return str(raw["doubleValue"])
    if "bytesValue" in raw:
        return str(raw["bytesValue"])
    if "arrayValue" in raw and isinstance(raw["arrayValue"], Mapping):
        values = raw["arrayValue"].get("values") or ()
        return [_unpack_any_value(item, _depth + 1) for item in values]
    if "kvlistValue" in raw and isinstance(raw["kvlistValue"], Mapping):
        values = raw["kvlistValue"].get("values") or ()
        return {
            str(entry.get("key", "")): _unpack_any_value(entry.get("value"), _depth + 1)
            for entry in values
            if isinstance(entry, Mapping)
        }
    return None


def _unpack_attributes(raw_attrs: Any) -> dict[str, Any]:
    if isinstance(raw_attrs, Mapping):
        return {str(k): v for k, v in raw_attrs.items()}
    if not isinstance(raw_attrs, list):
        return {}
    out: dict[str, Any] = {}
    for item in raw_attrs:
        if isinstance(item, Mapping) and "key" in item:
            out[str(item["key"])] = _unpack_any_value(item.get("value"))
    return out


def _parse_maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            try:
                return json.loads(stripped)
            except ValueError:
                return value
    return value


def _infer_span_type(attrs: Mapping[str, Any], raw_name: str) -> str:
    explicit = str(attrs.get("secagent.span_type") or "").strip()
    if explicit in {"agent.run", "model.inference", "tool.call", "gate.hitl"}:
        return explicit
    if "secagent.approval_granted" in attrs:
        return "gate.hitl"
    op = str(attrs.get("gen_ai.operation.name") or "").strip().lower()
    if op == "execute_tool":
        return "tool.call"
    if op in {"chat", "text_completion", "generate_content", "embeddings"}:
        return "model.inference"
    if op in {"invoke_agent", "invoke_workflow", "create_agent"}:
        return "agent.run"
    oi_kind = str(attrs.get("openinference.span.kind") or "").strip().upper()
    if oi_kind == "TOOL":
        return "tool.call"
    if oi_kind == "LLM":
        return "model.inference"
    if oi_kind in {"AGENT", "CHAIN"}:
        return "agent.run"
    tl_kind = str(attrs.get("traceloop.span.kind") or "").strip().lower()
    if tl_kind == "tool":
        return "tool.call"
    if tl_kind in {"llm", "chat"}:
        return "model.inference"
    if tl_kind in {"agent", "workflow", "task"}:
        return "agent.run"
    if "approval_gate" in raw_name.lower():
        return "gate.hitl"
    if "gen_ai.tool.name" in attrs or "tool.name" in attrs:
        return "tool.call"
    if "gen_ai.request.model" in attrs or "llm.model_name" in attrs:
        return "model.inference"
    return "agent.run"


def _first_present(attrs: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in attrs and attrs[key] is not None:
            return attrs[key]
    return None


def _to_input_dict(value: Any) -> dict[str, Any]:
    parsed = _parse_maybe_json(value)
    if isinstance(parsed, dict):
        return parsed
    if parsed is None:
        return {}
    return {"input": parsed}


def _to_output_value(value: Any) -> Any:
    parsed = _parse_maybe_json(value)
    if isinstance(parsed, list):
        return json.dumps(parsed, default=str)
    if parsed is None or isinstance(parsed, (dict, str, int, float, bool)):
        return parsed
    return str(parsed)


def _topo_sort_spans(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort spans by start_time_ns, ordering parents before children on equal timestamps."""
    by_id = {str(s["span_id"]): s for s in spans if s.get("span_id")}
    depth_cache: dict[str, int] = {}

    def _depth(sid: str, visiting: set[str]) -> int:
        if sid in depth_cache:
            return depth_cache[sid]
        if sid in visiting:
            return 0
        span = by_id.get(sid)
        parent = str(span.get("parent_span_id") or "") if span else ""
        if not parent or parent not in by_id:
            depth_cache[sid] = 0
            return 0
        visiting.add(sid)
        d = 1 + _depth(parent, visiting)
        depth_cache[sid] = d
        return d

    return sorted(
        spans,
        key=lambda s: (
            int(s.get("start_time_ns") or 0),
            _depth(str(s.get("span_id") or ""), set()),
        ),
    )


def convert_otlp_to_traces(
    doc: Mapping[str, Any],
    *,
    tier_overrides: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Convert an OpenTelemetry OTLP JSON export into SecAgent trace documents."""
    grouped: dict[str, dict[str, Any]] = {}
    overrides_dict = dict(tier_overrides or {})
    fallback_trace_id = uuid.uuid4().hex

    for res_span in doc.get("resourceSpans") or ():
        if not isinstance(res_span, Mapping):
            continue
        res_attrs = _unpack_attributes(
            (res_span.get("resource") or {}).get("attributes")
            if isinstance(res_span.get("resource"), Mapping)
            else ()
        )
        service_name = str(res_attrs.get("service.name") or "otlp_agent")
        for scope_span in res_span.get("scopeSpans") or ():
            if not isinstance(scope_span, Mapping):
                continue
            for raw_span in scope_span.get("spans") or ():
                if not isinstance(raw_span, Mapping):
                    continue
                attrs = _unpack_attributes(raw_span.get("attributes"))
                trace_id = str(raw_span.get("traceId") or fallback_trace_id)
                span_id = str(raw_span.get("spanId") or uuid.uuid4().hex[:16])
                parent_id = raw_span.get("parentSpanId") or None
                raw_name = str(raw_span.get("name") or "span")
                span_type = _infer_span_type(attrs, raw_name)

                if span_type == "tool.call":
                    name = str(
                        attrs.get("gen_ai.tool.name")
                        or attrs.get("tool.name")
                        or attrs.get("traceloop.entity.name")
                        or raw_name
                    )
                elif span_type == "model.inference":
                    name = str(
                        attrs.get("gen_ai.request.model") or attrs.get("llm.model_name") or raw_name
                    )
                elif span_type == "agent.run":
                    name = str(
                        attrs.get("gen_ai.agent.name")
                        or attrs.get("traceloop.entity.name")
                        or raw_name
                    )
                else:
                    name = raw_name

                raw_tier = str(attrs.get("secagent.permission_tier") or "")
                if span_type == "tool.call":
                    permission_tier = (
                        raw_tier
                        if raw_tier in _VALID_SPAN_TIERS and raw_tier != "none"
                        else resolve_permission_tier(name, overrides=overrides_dict)
                    )
                elif span_type == "gate.hitl":
                    permission_tier = "gate"
                else:
                    permission_tier = "none"

                start_ns = _to_int_ns(raw_span.get("startTimeUnixNano"), 0)
                end_ns = max(start_ns, _to_int_ns(raw_span.get("endTimeUnixNano"), start_ns))
                status_obj = raw_span.get("status")
                status_code = status_obj.get("code") if isinstance(status_obj, Mapping) else None
                explicit_err = _to_bool(attrs.get("secagent.is_error"))
                is_error = bool(
                    explicit_err is True or status_code in (2, "STATUS_CODE_ERROR", "ERROR")
                )
                error_msg = (
                    attrs.get("secagent.error_message")
                    or (status_obj.get("message") if isinstance(status_obj, Mapping) else None)
                    or None
                )

                raw_inputs = _first_present(
                    attrs,
                    (
                        "gen_ai.tool.call.arguments",
                        "gen_ai.tool.arguments",
                        "tool.parameters",
                        "secagent.input_parameters",
                        "traceloop.entity.input",
                        "input.value",
                        "llm.prompts",
                    ),
                )
                raw_outputs = _first_present(
                    attrs,
                    (
                        "gen_ai.tool.call.result",
                        "gen_ai.tool.results",
                        "secagent.output_result",
                        "traceloop.entity.output",
                        "output.value",
                        "llm.completions",
                    ),
                )
                approval = _to_bool(attrs.get("secagent.approval_granted"))

                span_entry: dict[str, Any] = {
                    "span_id": span_id,
                    "step_index": 0,
                    "span_type": span_type,
                    "name": name,
                    "start_time_ns": start_ns,
                    "end_time_ns": end_ns,
                    "permission_tier": permission_tier,
                    "approval_granted": approval,
                    "input_parameters": PIIRedactor.scrub_container(_to_input_dict(raw_inputs)),
                    "output_result": PIIRedactor.scrub_container(_to_output_value(raw_outputs)),
                    "is_error": is_error,
                    "error_message": PIIRedactor.scrub_text(str(error_msg)) if error_msg else None,
                    "trace_id": trace_id,
                    "parent_span_id": str(parent_id) if parent_id else None,
                    "attributes": PIIRedactor.scrub_container(dict(attrs)),
                }

                bucket = grouped.setdefault(
                    trace_id,
                    {
                        "scenario_id": f"OTLP-{trace_id[:8]}",
                        "execution_id": trace_id,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "caller_role": "unknown",
                        "task_context": "default",
                        "metadata": {"framework": f"otlp:{service_name}"},
                        "spans": [],
                    },
                )
                if attrs.get("secagent.scenario_id") and (
                    not parent_id or bucket["scenario_id"].startswith("OTLP-")
                ):
                    bucket["scenario_id"] = str(attrs["secagent.scenario_id"])
                if attrs.get("secagent.caller_role") and (
                    not parent_id or bucket["caller_role"] == "unknown"
                ):
                    bucket["caller_role"] = str(attrs["secagent.caller_role"])
                if attrs.get("secagent.task_context") and (
                    not parent_id or bucket["task_context"] == "default"
                ):
                    bucket["task_context"] = str(attrs["secagent.task_context"])
                bucket["spans"].append(span_entry)

    traces: list[dict[str, Any]] = []
    for trace_doc in grouped.values():
        trace_doc["spans"] = _topo_sort_spans(trace_doc["spans"])
        positive_starts = [
            int(s["start_time_ns"]) for s in trace_doc["spans"] if s["start_time_ns"] > 0
        ]
        if positive_starts:
            trace_doc["timestamp"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(min(positive_starts) / 1_000_000_000)
            )
        for idx, sp in enumerate(trace_doc["spans"]):
            sp["step_index"] = idx
        traces.append(trace_doc)
    return traces
