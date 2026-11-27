"""Scenario execution & trace loading orchestration extracted from the CLI."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from rich.console import Console

from secagent.ui import make_progress

_VALID_SPAN_TIERS = frozenset({"pure", "read", "write", "pay", "admin", "net", "gate", "none"})
GATE_NODE_NAMES = frozenset({"approval_gate", "human_approval", "hitl_gate", "confirm_action"})


def is_runnable_target(target: Any) -> bool:
    return target is not None and (
        callable(getattr(target, "invoke", None)) or callable(getattr(target, "ainvoke", None))
    )


def extract_interrupt_events(output: Any) -> list[Any]:
    """Extract LangGraph ``__interrupt__`` values from runnable output if present."""
    if not isinstance(output, dict):
        return []
    raw = output.get("__interrupt__")
    if raw is None:
        return []
    items = list(raw) if isinstance(raw, (list, tuple)) else [raw]
    return [getattr(item, "value", item) for item in items]


def record_output_interrupts(callback: Any, output: Any, target_tool: str) -> None:
    """Normalize LangGraph ``__interrupt__`` payloads into ``gate.hitl`` spans."""
    for event in extract_interrupt_events(output):
        if isinstance(event, bool):
            payload: Any = event
        elif isinstance(event, dict) and isinstance(
            event.get("approval_granted", event.get("approved", event.get("value"))),
            bool,
        ):
            payload = event
        else:
            payload = {
                "approval_granted": False,
                "operation": (
                    event.get("operation") or event.get("target_operation")
                    if isinstance(event, dict)
                    else target_tool or "interrupt"
                ),
                "input_parameters": event if isinstance(event, dict) else {"value": event},
            }
        callback.record_interrupt(payload)


def infer_task_context(scenario: dict[str, Any]) -> str:
    """Infer an operational task_context when a scenario omits one."""
    explicit = scenario.get("task_context")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    expected_policy = str(scenario.get("expected_failure_policy") or "").upper()
    owasp = str(scenario.get("owasp_category") or "").upper()
    if expected_policy == "POL-ASI01-002" or scenario.get("taint_payload"):
        return "default"
    if (
        expected_policy == "POL-ASI01-001"
        or expected_policy == "POL-ASI03-002"
        or owasp.startswith("ASI01")
    ):
        return "general_inquiry"
    if expected_policy.startswith("POL-ASI06") or owasp.startswith("ASI06"):
        return "address_update"
    return "default"


def _make_gate_aware_callback(
    session: Any,
    *,
    tier_by_tool: dict[str, str],
    approval_granted: bool,
) -> Any:
    """Create a GateAwareTelemetryCallback capturing multi-tool & dict-message HITL approvals."""
    from secagent.telemetry.callbacks import SecAgentTelemetryCallback

    class GateAwareTelemetryCallback(SecAgentTelemetryCallback):
        def __init__(self) -> None:
            super().__init__(session=session, tier_by_tool=tier_by_tool)
            self._approval_granted = approval_granted

        @staticmethod
        def _extract_pending_tools(inputs: Any) -> list[tuple[str, dict[str, Any]]]:
            if not isinstance(inputs, dict):
                return [("unknown_operation", {})]
            messages = inputs.get("messages")
            if isinstance(messages, list) and messages:
                last_msg = messages[-1]
                tool_calls = (
                    last_msg.get("tool_calls")
                    if isinstance(last_msg, dict)
                    else getattr(last_msg, "tool_calls", None)
                )
                if isinstance(tool_calls, list) and tool_calls:
                    extracted: list[tuple[str, dict[str, Any]]] = []
                    for tc in tool_calls:
                        if isinstance(tc, dict) and tc.get("name"):
                            args = tc.get("args")
                            extracted.append(
                                (str(tc["name"]), dict(args) if isinstance(args, dict) else {})
                            )
                        elif isinstance(tc, dict) and isinstance(tc.get("function"), dict):
                            fn_obj = tc["function"]
                            if fn_obj.get("name"):
                                raw_args = fn_obj.get("arguments")
                                if isinstance(raw_args, str):
                                    try:
                                        parsed = json.loads(raw_args)
                                        args_dict = parsed if isinstance(parsed, dict) else {}
                                    except ValueError:
                                        args_dict = {}
                                elif isinstance(raw_args, dict):
                                    args_dict = dict(raw_args)
                                else:
                                    args_dict = {}
                                extracted.append((str(fn_obj["name"]), args_dict))
                    if extracted:
                        return extracted
            intent = inputs.get("current_intent")
            if isinstance(intent, str) and intent.strip():
                return [(intent.strip(), {})]
            return [("unknown_operation", {})]

        def on_chain_start(
            self,
            serialized: dict[str, Any] | None,
            inputs: dict[str, Any] | Any,
            **kwargs: Any,
        ) -> None:
            super().on_chain_start(serialized, inputs, **kwargs)
            raw_meta = kwargs.get("metadata")
            meta = raw_meta if isinstance(raw_meta, dict) else {}
            node_name = (
                kwargs.get("name")
                or meta.get("langgraph_node")
                or (serialized.get("name") if isinstance(serialized, dict) else None)
            )
            if node_name in GATE_NODE_NAMES:
                for operation, bound_args in self._extract_pending_tools(inputs):
                    extra = {"arguments": bound_args} if bound_args else None
                    self.record_hitl(
                        self._approval_granted,
                        operation=operation,
                        input_parameters=extra,
                    )

    return GateAwareTelemetryCallback()


def execute_scenarios_with_telemetry(
    target: Any,
    mod: Any,
    target_tools: list[Any],
    scenario_dicts: list[dict[str, Any]],
    policy_overrides: dict[str, str],
    *,
    console: Console,
    timeout_s: float = 30.0,
    quiet: bool = False,
    strict_sandbox: bool = True,
    mock_unclassified: bool = True,
    mock_mode: str = "rich",
) -> list[dict[str, Any]]:
    """Run scenarios through Subsystem 1 ExecutionHarness and Subsystem 2 TraceExporter."""
    if not is_runnable_target(target):
        return []

    from secagent.harness.runner import ExecutionHarness
    from secagent.telemetry.callbacks import TraceSession
    from secagent.telemetry.exporter import TraceExporter

    tier_by_tool = {t.name: t.permission_tier for t in target_tools}
    harness = ExecutionHarness(
        timeout_s=timeout_s,
        policy_overrides=policy_overrides,
        dry_run=True,
        strict_sandbox=strict_sandbox,
        mock_unclassified=mock_unclassified,
        mock_mode="rich" if mock_mode == "rich" else "minimal",
    )
    exporter = TraceExporter()
    framework = "langgraph" if hasattr(target, "nodes") else "generic"
    traces: list[dict[str, Any]] = []

    with make_progress(console, quiet=quiet) as progress:
        task_id = progress.add_task("Executing scenarios", total=len(scenario_dicts))
        for idx, scn in enumerate(scenario_dicts):
            scn_id = str(scn.get("id") or scn.get("scenario_id") or f"SCN-{idx + 1:03d}")
            caller_role = str(scn.get("caller_role") or "guest")
            task_context = infer_task_context(scn)
            session = TraceSession(
                scenario_id=scn_id,
                caller_role=caller_role,
                task_context=task_context,
                metadata={"framework": framework, "is_benign": bool(scn.get("is_benign", False))},
            )
            callback = _make_gate_aware_callback(
                session,
                tier_by_tool=tier_by_tool,
                approval_granted=bool(scn.get("approval_granted", False)),
            )
            effective_scn = {**scn, "task_context": task_context}
            result = harness.run_scenario(target, effective_scn, mod, callbacks=[callback])
            record_output_interrupts(
                callback,
                result.output,
                target_tool=str(scn.get("target_tool") or ""),
            )

            if (
                not any(s.get("span_type") == "tool.call" for s in session.spans)
                and result.tool_calls
            ):
                for call_rec in result.tool_calls:
                    now_ns = getattr(call_rec, "timestamp_ns", None) or time.time_ns()
                    raw_tier = getattr(
                        call_rec,
                        "permission_tier",
                        getattr(call_rec, "tier", None),
                    )
                    resolved_tier = (
                        raw_tier
                        if raw_tier in _VALID_SPAN_TIERS
                        else tier_by_tool.get(call_rec.tool_name, "read")
                    )
                    output = getattr(call_rec, "output", None)
                    if isinstance(output, list):
                        output = json.dumps(output, default=str)
                    session.append(
                        {
                            "span_id": f"span-{uuid.uuid4().hex[:8]}",
                            "span_type": "tool.call",
                            "name": call_rec.tool_name,
                            "start_time_ns": now_ns,
                            "end_time_ns": now_ns,
                            "permission_tier": resolved_tier,
                            "approval_granted": None,
                            "input_parameters": call_rec.arguments,
                            "output_result": output,
                            "is_error": False,
                            "error_message": None,
                        }
                    )

            err_span = result.error_span(step_index=len(session.spans))
            if err_span is not None:
                session.append(err_span)

            traces.append(exporter.validate(session.as_dict()))
            progress.advance(task_id)

    return traces


def load_external_traces(
    trace_path: Path,
    *,
    tier_overrides: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Load and schema-validate pre-recorded SecAgent or OTLP JSON trace file(s)."""
    from secagent.telemetry.exporter import TraceExporter
    from secagent.telemetry.otlp_adapter import convert_otlp_to_traces, is_otlp_payload

    if not trace_path.exists():
        raise FileNotFoundError(f"Trace path not found: {trace_path}")

    files = sorted(trace_path.glob("*.json")) if trace_path.is_dir() else [trace_path]
    if not files:
        raise ValueError(f"No JSON trace files found in {trace_path}")

    exporter = TraceExporter()
    traces: list[dict[str, Any]] = []
    for file_path in files:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        if is_otlp_payload(raw):
            for converted in convert_otlp_to_traces(raw, tier_overrides=tier_overrides):
                traces.append(exporter.validate(converted))
            continue
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"Trace entry in {file_path} must be a JSON object")
            if is_otlp_payload(item):
                for converted in convert_otlp_to_traces(item, tier_overrides=tier_overrides):
                    traces.append(exporter.validate(converted))
            else:
                traces.append(exporter.validate(item))
    return traces
