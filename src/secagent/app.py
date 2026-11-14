"""Interactive 1-page Streamlit audit dashboard for SecAgent (US-5.5)."""

from __future__ import annotations

import argparse
import inspect
import json
from pathlib import Path
from typing import Any

_STATUS_COLORS = {
    "VIOLATION": "#d93025",
    "gate.hitl": "#f9ab00",
    "tool.call": "#1a73e8",
    "other": "#5f6368",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _stretch_kwargs(fn: Any) -> dict[str, Any]:
    """Use ``width='stretch'`` on modern Streamlit while keeping 1.35+ compatibility."""
    params = inspect.signature(fn).parameters
    if "width" in params:
        return {"width": "stretch"}
    return {"use_container_width": True}


def parse_app_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse dashboard CLI arguments forwarded after Streamlit's ``--`` separator."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--report", type=Path, default=Path("report.json"))
    parser.add_argument("--trace", type=Path, default=None)
    args, _ = parser.parse_known_args(argv)
    return args


def load_json_document(path: Path) -> dict[str, Any]:
    """Load a JSON object from ``path`` and validate that its root is a mapping."""
    if not path.exists():
        raise FileNotFoundError(f"JSON file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}, got {type(data).__name__}")
    return data


def extract_traces(
    report: dict[str, Any],
    explicit_trace: dict[str, Any] | None = None,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Resolve one or more trace documents from an explicit trace or report payload."""
    if explicit_trace is not None:
        return [explicit_trace]

    if isinstance(report.get("traces"), list):
        return [t for t in report["traces"] if isinstance(t, dict)]

    if isinstance(report.get("trace"), dict):
        return [report["trace"]]

    trace_path_raw = report.get("trace_path")
    if isinstance(trace_path_raw, str) and trace_path_raw.strip():
        candidate = Path(trace_path_raw)
        if not candidate.is_absolute() and base_dir is not None:
            candidate = base_dir / candidate
        if candidate.is_file():
            return [load_json_document(candidate)]

    if isinstance(report.get("spans"), list) and "scenario_id" in report:
        return [report]

    return []


def index_violations(
    violations: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[int, list[dict[str, Any]]]]:
    """Index violation records by ``offending_span_id`` and ``offending_step_index``."""
    by_span_id: dict[str, list[dict[str, Any]]] = {}
    by_step_index: dict[int, list[dict[str, Any]]] = {}

    for violation in violations:
        if not isinstance(violation, dict):
            continue
        span_id = violation.get("offending_span_id")
        if isinstance(span_id, str) and span_id:
            by_span_id.setdefault(span_id, []).append(violation)

        step_index = violation.get("offending_step_index")
        if isinstance(step_index, int) and not isinstance(step_index, bool):
            by_step_index.setdefault(step_index, []).append(violation)

    return by_span_id, by_step_index


def span_violations(
    span: dict[str, Any],
    by_span_id: dict[str, list[dict[str, Any]]],
    by_step_index: dict[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Return deduplicated violations matching ``span`` by ID or step index."""
    matched: list[dict[str, Any]] = []
    seen_keys: set[tuple[Any, Any, Any]] = set()

    span_id = span.get("span_id")
    step_index = span.get("step_index")
    candidates: list[dict[str, Any]] = []
    if isinstance(span_id, str) and span_id in by_span_id:
        candidates.extend(by_span_id[span_id])
    elif (
        isinstance(step_index, int)
        and not isinstance(step_index, bool)
        and step_index in by_step_index
    ):
        candidates.extend(by_step_index[step_index])

    for item in candidates:
        key = (
            item.get("rule_id"),
            item.get("offending_span_id"),
            item.get("offending_step_index"),
        )
        if key not in seen_keys:
            seen_keys.add(key)
            matched.append(item)

    return matched


def build_timeline_rows(
    spans: list[dict[str, Any]],
    violations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalize trace spans into chronological waterfall rows with violation flags."""
    dict_spans = [s for s in spans if isinstance(s, dict)]
    if not dict_spans:
        return []

    ordered = sorted(
        dict_spans,
        key=lambda s: (int(s.get("step_index", 0)), int(s.get("start_time_ns", 0))),
    )
    trace_start_ns = min(int(s.get("start_time_ns", 0)) for s in ordered)

    by_span_id, by_step_index = index_violations(violations)
    rows: list[dict[str, Any]] = []

    for span in ordered:
        step_index = int(span.get("step_index", len(rows)))
        span_id = str(span.get("span_id", f"span-{step_index}"))
        span_type = str(span.get("span_type", "tool.call"))
        name = str(span.get("name", "unknown"))
        permission_tier = str(span.get("permission_tier", "none"))
        start_ns = int(span.get("start_time_ns", trace_start_ns))
        end_ns = int(span.get("end_time_ns", start_ns))
        duration_ns = max(0, end_ns - start_ns)
        offset_ns = max(0, start_ns - trace_start_ns)
        offset_ms = offset_ns / 1_000_000.0
        duration_ms = duration_ns / 1_000_000.0

        matched = span_violations(span, by_span_id, by_step_index)
        violated = bool(matched)
        category = (
            "VIOLATION"
            if violated
            else (span_type if span_type in ("gate.hitl", "tool.call") else "other")
        )

        rows.append(
            {
                "label": f"#{step_index} {name} [{permission_tier}]",
                "step_index": step_index,
                "span_id": span_id,
                "span_type": span_type,
                "name": name,
                "permission_tier": permission_tier,
                "approval_granted": span.get("approval_granted"),
                "is_error": bool(span.get("is_error", False)),
                "error_message": span.get("error_message"),
                "start_time_ns": start_ns,
                "end_time_ns": end_ns,
                "offset_ns": offset_ns,
                "duration_ns": duration_ns,
                "offset_ms": round(offset_ms, 6),
                "duration_ms": round(duration_ms, 6),
                "end_ms": round(offset_ms + max(duration_ms, 0.05), 6),
                "violated": violated,
                "category": category,
                "rule_ids": ", ".join(str(v.get("rule_id", "")) for v in matched) or "None",
                "violations": matched,
                "input_parameters": span.get("input_parameters", {}),
                "output_result": span.get("output_result"),
                "attributes": span.get("attributes", {}),
            }
        )

    return rows


def build_waterfall_chart_spec(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a Vega-Lite specification for an interactive span waterfall timeline."""
    chart_rows = [
        {
            "label": row["label"],
            "step_index": row["step_index"],
            "span_id": row["span_id"],
            "span_type": row["span_type"],
            "name": row["name"],
            "permission_tier": row["permission_tier"],
            "offset_ms": row["offset_ms"],
            "end_ms": row["end_ms"],
            "duration_ms": row["duration_ms"],
            "duration_ns": row["duration_ns"],
            "offset_ns": row["offset_ns"],
            "violated": row["violated"],
            "category": row["category"],
            "rule_ids": row["rule_ids"],
        }
        for row in rows
    ]

    return {
        "data": {"values": chart_rows},
        "mark": {"type": "bar", "cornerRadius": 4, "height": 22},
        "encoding": {
            "y": {
                "field": "label",
                "type": "nominal",
                "sort": None,
                "title": "Execution Span",
            },
            "x": {
                "field": "offset_ms",
                "type": "quantitative",
                "title": "Timeline Offset (ms)",
            },
            "x2": {"field": "end_ms"},
            "color": {
                "field": "category",
                "type": "nominal",
                "title": "Span Status",
                "scale": {
                    "domain": list(_STATUS_COLORS.keys()),
                    "range": list(_STATUS_COLORS.values()),
                },
            },
            "tooltip": [
                {"field": "step_index", "type": "quantitative", "title": "Step"},
                {"field": "name", "type": "nominal", "title": "Span"},
                {"field": "span_type", "type": "nominal", "title": "Type"},
                {"field": "permission_tier", "type": "nominal", "title": "Tier"},
                {"field": "duration_ns", "type": "quantitative", "title": "Duration (ns)"},
                {"field": "duration_ms", "type": "quantitative", "title": "Duration (ms)"},
                {"field": "offset_ns", "type": "quantitative", "title": "Offset (ns)"},
                {"field": "violated", "type": "nominal", "title": "Violated"},
                {"field": "rule_ids", "type": "nominal", "title": "Violated Rules"},
            ],
        },
        "height": max(180, len(chart_rows) * 40),
    }


def _total_trace_duration_ms(rows: list[dict[str, Any]]) -> float | None:
    """Compute total trace wall-clock duration in milliseconds from normalized rows."""
    if not rows:
        return None
    min_start = min(row["start_time_ns"] for row in rows)
    max_end = max(row["end_time_ns"] for row in rows)
    return max(0, max_end - min_start) / 1_000_000.0


def render_dashboard(
    report: dict[str, Any],
    traces: list[dict[str, Any]],
    *,
    violations_only: bool = False,
    selected_types: list[str] | None = None,
    selected_tiers: list[str] | None = None,
) -> None:
    """Render the Streamlit SecAgent audit dashboard from parsed report and trace data."""
    import streamlit as st

    raw_status = report.get("status")
    is_raw_trace = raw_status is None and isinstance(report.get("spans"), list)
    status = "TRACE_ONLY" if is_raw_trace else str(raw_status or "UNKNOWN")
    agent_name = str(
        report.get("agent")
        or report.get("metadata", {}).get("framework")
        or report.get("scenario_id")
        or "unknown"
    )
    violations = sorted(
        [v for v in (report.get("violations") or []) if isinstance(v, dict)],
        key=lambda v: (
            _SEVERITY_ORDER.get(str(v.get("severity", "")), 99),
            int(v.get("offending_step_index", 0) or 0),
        ),
    )
    scenarios_count = int(report.get("scenarios_evaluated") or len(traces))

    st.title("SecAgent Security Audit Dashboard")

    if status == "PASS" and not violations:
        st.success(f"Security Gate Verdict: **PASS** — Target `{agent_name}`")
    elif status == "FAIL" or violations:
        st.error(
            f"Security Gate Verdict: **FAIL** — {len(violations)} policy violation(s) detected on `{agent_name}`"
        )
    elif status == "NOT_EVALUATED":
        st.warning(
            f"Security Gate Verdict: **NOT_EVALUATED** — `{agent_name}` (policy evaluation pending)"
        )
    elif status == "TRACE_ONLY":
        st.info(f"Inspecting Raw Execution Trace — Scenario `{agent_name}` (no evaluation report)")
    else:
        st.info(f"Security Gate Verdict: **{status}** — Target `{agent_name}`")

    selected_trace = traces[0] if traces else None
    all_rows: list[dict[str, Any]] = []
    if selected_trace is not None and len(traces) > 1:
        labels = [
            f"{t.get('scenario_id', f'Trace {idx}')} ({t.get('task_context', 'unknown')})"
            for idx, t in enumerate(traces)
        ]
        selected_label = st.selectbox("Select Scenario Trace", labels)
        selected_trace = traces[labels.index(selected_label)]

    if selected_trace is not None:
        trace_scenario_id = selected_trace.get("scenario_id")
        trace_violations = [
            v
            for v in violations
            if not (
                "scenario_id" in v
                and trace_scenario_id
                and v.get("scenario_id") != trace_scenario_id
            )
        ]
        all_rows = build_timeline_rows(selected_trace.get("spans", []), trace_violations)

    trace_ms = _total_trace_duration_ms(all_rows)
    exec_ms = report.get("execution_time_ms")
    critical_count = sum(1 for v in violations if v.get("severity") == "CRITICAL")

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Verdict", status)
    col2.metric("Scenarios", scenarios_count)
    col3.metric(
        "Violations",
        len(violations),
        delta=f"{critical_count} critical" if critical_count else None,
        delta_color="inverse" if critical_count else "off",
    )
    col4.metric("Trace Duration", f"{trace_ms:.3f} ms" if trace_ms is not None else "N/A")
    col5.metric(
        "Eval Time",
        f"{exec_ms:.2f} ms"
        if isinstance(exec_ms, (int, float)) and not isinstance(exec_ms, bool)
        else "N/A",
    )

    if violations:
        st.subheader("Policy Violations")
        table_rows = [
            {
                "Rule ID": v.get("rule_id", ""),
                "Severity": v.get("severity", ""),
                "OWASP Category": v.get("owasp_category", ""),
                "Tool": v.get("offending_tool_name", ""),
                "Span ID": v.get("offending_span_id", ""),
                "Step": v.get("offending_step_index", ""),
                "Action": v.get("failure_action", ""),
                "Remediation": v.get("remediation", ""),
            }
            for v in violations
        ]
        st.dataframe(table_rows, hide_index=True, **_stretch_kwargs(st.dataframe))

    st.subheader("Execution Trace Waterfall")
    if selected_trace is None:
        st.info(
            "No execution trace spans found in this report. "
            "Provide a trace JSON via `--trace` or the sidebar to inspect spans."
        )
        return

    meta_c1, meta_c2, meta_c3, meta_c4 = st.columns(4)
    meta_c1.caption(f"**Scenario:** `{selected_trace.get('scenario_id', 'unknown')}`")
    meta_c2.caption(f"**Caller Role:** `{selected_trace.get('caller_role', 'unknown')}`")
    meta_c3.caption(f"**Task Context:** `{selected_trace.get('task_context', 'unknown')}`")
    meta_c4.caption(f"**Execution ID:** `{selected_trace.get('execution_id', 'unknown')}`")

    if not all_rows:
        st.info("Selected trace contains no spans.")
        return

    filtered_rows = [
        row
        for row in all_rows
        if (not violations_only or row["violated"])
        and (selected_types is None or row["span_type"] in selected_types)
        and (selected_tiers is None or row["permission_tier"] in selected_tiers)
    ]

    if not filtered_rows:
        st.info("No spans match the current sidebar filters.")
        return

    st.vega_lite_chart(
        build_waterfall_chart_spec(filtered_rows),
        **_stretch_kwargs(st.vega_lite_chart),
    )

    st.subheader("Span Inspector")
    for row in filtered_rows:
        prefix = "[VIOLATION] " if row["violated"] else ""
        header = (
            f"{prefix}Step {row['step_index']}: {row['name']} "
            f"({row['span_type']}, tier={row['permission_tier']}, "
            f"{row['duration_ns']:,} ns / {row['duration_ms']:.3f} ms)"
        )
        with st.expander(header, expanded=row["violated"]):
            if row["violated"]:
                for v in row["violations"]:
                    st.error(
                        f"**{v.get('rule_id', 'UNKNOWN')} ({v.get('severity', 'HIGH')}) — "
                        f"{v.get('rule_name', '')}**\n\n"
                        f"**Remediation:** {v.get('remediation', '')}"
                    )
                    if v.get("evidence"):
                        st.json(v["evidence"])

            if row["is_error"]:
                st.warning(f"Span error: {row['error_message'] or 'Unknown error'}")

            left, right = st.columns(2)
            with left:
                st.markdown("**Span Metadata**")
                st.json(
                    {
                        "span_id": row["span_id"],
                        "step_index": row["step_index"],
                        "span_type": row["span_type"],
                        "permission_tier": row["permission_tier"],
                        "approval_granted": row["approval_granted"],
                        "start_time_ns": row["start_time_ns"],
                        "end_time_ns": row["end_time_ns"],
                        "duration_ns": row["duration_ns"],
                    }
                )
            with right:
                st.markdown("**Input Parameters (Redacted)**")
                st.json(row["input_parameters"] or {})
                st.markdown("**Output Result (Redacted)**")
                if isinstance(row["output_result"], (dict, list)):
                    st.json(row["output_result"])
                else:
                    st.code(str(row["output_result"]))


def main(argv: list[str] | None = None) -> None:
    """Entrypoint executed by ``streamlit run src/secagent/app.py``."""
    import streamlit as st

    st.set_page_config(
        page_title="SecAgent Security Audit Dashboard",
        layout="wide",
    )

    args = parse_app_args(argv)
    with st.sidebar:
        st.header("Audit Inputs")
        report_input = st.text_input("Report JSON path", value=str(args.report))
        trace_input = st.text_input(
            "Trace JSON path (optional)",
            value=str(args.trace) if args.trace else "",
        )
        uploaded_report = st.file_uploader("Upload report.json", type=["json"])
        uploaded_trace = st.file_uploader("Upload trace.json (optional)", type=["json"])

        st.divider()
        st.header("Span Filters")
        violations_only = st.checkbox("Violations only", value=False)
        selected_types = st.multiselect(
            "Span types",
            options=["tool.call", "gate.hitl", "model.inference", "agent.run"],
            default=["tool.call", "gate.hitl", "model.inference", "agent.run"],
        )
        selected_tiers = st.multiselect(
            "Permission tiers",
            options=["pure", "read", "write", "pay", "admin", "net", "gate", "none"],
            default=["pure", "read", "write", "pay", "admin", "net", "gate", "none"],
        )

    report_path = Path(report_input) if report_input.strip() else args.report
    try:
        if uploaded_report is not None:
            report = json.loads(uploaded_report.getvalue().decode("utf-8"))
            if not isinstance(report, dict):
                raise ValueError(f"Expected JSON object, got {type(report).__name__}")
        else:
            report = load_json_document(report_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        st.title("SecAgent Security Audit Dashboard")
        st.error(f"Could not load report `{report_path}`: {exc}")
        return

    explicit_trace: dict[str, Any] | None = None
    if uploaded_trace is not None:
        try:
            loaded = json.loads(uploaded_trace.getvalue().decode("utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError(f"Expected JSON object, got {type(loaded).__name__}")
            explicit_trace = loaded
        except (ValueError, json.JSONDecodeError) as exc:
            st.title("SecAgent Security Audit Dashboard")
            st.error(f"Could not load uploaded trace: {exc}")
            return
    elif trace_input.strip():
        trace_path = Path(trace_input.strip())
        try:
            explicit_trace = load_json_document(trace_path)
        except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
            st.title("SecAgent Security Audit Dashboard")
            st.error(f"Could not load trace `{trace_path}`: {exc}")
            return

    traces = extract_traces(report, explicit_trace=explicit_trace, base_dir=report_path.parent)
    render_dashboard(
        report,
        traces,
        violations_only=violations_only,
        selected_types=selected_types,
        selected_tiers=selected_tiers,
    )


if __name__ == "__main__":
    main()
