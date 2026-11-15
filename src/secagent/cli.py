import importlib
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

MAX_GITHUB_COMMENT_LENGTH = 65000
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

app = typer.Typer(
    name="secagent",
    help="SecAgent: Security scanner for autonomous AI agents",
    no_args_is_help=True,
)
console = Console()


def _load_entrypoint(agent_entrypoint: str) -> tuple[Any, Any]:
    """Import an agent entrypoint ('module:attr' or 'module') with cwd on sys.path."""
    cwd = str(Path.cwd())
    if cwd not in sys.path:
        sys.path.insert(0, cwd)
    mod_name, _, obj_name = agent_entrypoint.partition(":")
    mod = importlib.import_module(mod_name)
    target = getattr(mod, obj_name) if obj_name else mod
    return target, mod


def _field(obj: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dict or an object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _escape_cell(value: Any) -> str:
    """Escape pipe characters, backticks, and newlines inside a Markdown table cell."""
    return (
        str(value)
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("\r\n", " ")
        .replace("\n", " ")
        .strip()
    )


def _format_markdown_report(
    result: Any,
    agent_name: str = "",
    scenarios_evaluated: int = 0,
) -> str:
    """Format an evaluation result (dict or object) as a GitHub PR Markdown triage comment."""
    status = str(_field(result, "status", "PASS") or "PASS")
    raw_violations = _field(result, "violations", [])
    violations = list(raw_violations) if isinstance(raw_violations, (list, tuple)) else []
    effective_agent = _escape_cell(
        agent_name or _field(result, "agent", "default_fixture") or "default_fixture"
    )
    effective_scenarios = scenarios_evaluated or int(_field(result, "scenarios_evaluated", 0) or 0)

    if status == "NOT_EVALUATED":
        return (
            "### SecAgent Security Gate: NOT_EVALUATED\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Prepared**: {effective_scenarios}\n"
            "- **Status**: Policy evaluation is not implemented yet (subsystem 4); "
            "no policies were evaluated in this run.\n"
        )

    if status == "PASS" and not violations:
        return (
            "### SecAgent Security Gate: PASS\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Evaluated**: {effective_scenarios}\n"
            "- **Violations Detected**: 0\n"
            "- **Status**: All invariant security policies satisfied.\n"
        )

    sorted_violations = sorted(
        violations,
        key=lambda v: (
            _SEVERITY_ORDER.get(str(_field(v, "severity", "")), 99),
            int(_field(v, "offending_step_index", 0) or 0),
        ),
    )

    header = (
        f"### SecAgent Security Gate: {status}\n\n"
        f"- **Target Agent**: `{effective_agent}`\n"
        f"- **Scenarios Evaluated**: {effective_scenarios}\n"
        f"- **Violations Detected**: {len(sorted_violations)}\n\n"
    )

    if not sorted_violations:
        return header

    table_header = (
        "| Rule ID | Severity | OWASP Category | Offending Span | Remediation |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
    )

    rows: list[str] = []
    base_len = len(header) + len(table_header) + 120
    running_len = base_len

    for v in sorted_violations:
        rule_id = _escape_cell(_field(v, "rule_id", "UNKNOWN"))
        severity = _escape_cell(_field(v, "severity", "HIGH"))
        owasp = _escape_cell(_field(v, "owasp_category", "UNKNOWN"))
        tool_name = _escape_cell(_field(v, "offending_tool_name", ""))
        span_id = _escape_cell(_field(v, "offending_span_id", "unknown"))
        span_cell = f"`{tool_name}` (`{span_id}`)" if tool_name else f"`{span_id}`"
        remediation = _escape_cell(_field(v, "remediation", ""))

        row = f"| `{rule_id}` | {severity} | {owasp} | {span_cell} | {remediation} |"
        if running_len + len(row) + 1 > MAX_GITHUB_COMMENT_LENGTH:
            break
        rows.append(row)
        running_len += len(row) + 1

    body = header + table_header + "\n".join(rows) + "\n"
    if len(rows) < len(sorted_violations):
        body += (
            f"\n*Truncated: showing {len(rows)} of {len(sorted_violations)} violations "
            "(see report.json for full details).*\n"
        )
    return body


def _discover_raw_tools(generator: Any, target: Any, mod: Any) -> list[Any]:
    """Discover raw tool objects using Subsystem 1 introspector with Subsystem 3 fallback."""
    from secagent.harness.introspector import discover_tools as harness_discover_tools

    return harness_discover_tools(target, mod) or generator.discover_tools(target, mod)


def _resolve_policy_overrides(policies: Path | None) -> dict[str, str]:
    """Load tool_tier_overrides from the policy YAML file via Subsystem 1 introspector."""
    if policies is None or not policies.exists():
        return {}
    import yaml

    from secagent.harness.introspector import HarnessLoadError, load_policy_overrides

    try:
        return load_policy_overrides(policies)
    except (HarnessLoadError, OSError, yaml.YAMLError) as exc:
        console.print(f"[yellow]Warning: Could not load policy overrides ({exc})[/yellow]")
        return {}


def _default_benchmark_tools(*, include_schema: bool = False) -> list[Any]:
    """Return baseline benchmark tools used when no agent entrypoint yields tools."""
    from secagent.generator import ToolMetadata

    if include_schema:
        return [
            ToolMetadata(
                name="execute_trade",
                permission_tier="pay",
                description="Executes equities trades",
                parameters={"symbol": "str", "quantity": "int"},
                parameter_metadata={
                    "symbol": {"annotation": str, "type": "string", "required": True},
                    "quantity": {"annotation": int, "type": "integer", "required": True},
                },
            ),
            ToolMetadata(
                name="restart_server",
                permission_tier="admin",
                description="Restarts cluster instances",
                parameters={"server_id": "str"},
                parameter_metadata={
                    "server_id": {"annotation": str, "type": "string", "required": True}
                },
            ),
            ToolMetadata(
                name="query_db",
                permission_tier="read",
                description="Queries records",
                parameters={"query": "str", "fields": "list"},
                parameter_metadata={
                    "query": {"annotation": str, "type": "string", "required": True},
                    "fields": {"annotation": list, "type": "array", "required": True},
                },
            ),
        ]

    return [
        ToolMetadata(
            name="execute_trade", permission_tier="pay", description="Executes equities trades"
        ),
        ToolMetadata(
            name="restart_server", permission_tier="admin", description="Restarts cluster instances"
        ),
        ToolMetadata(name="query_db", permission_tier="read", description="Queries records"),
        ToolMetadata(
            name="issue_refund", permission_tier="pay", description="Issues customer refund"
        ),
    ]


def _resolve_target_tools(
    generator: Any,
    agent_entrypoint: str,
    overrides: dict[str, str],
    *,
    include_schema: bool = False,
    fallback_label: str = "Introspection",
) -> list[Any]:
    """Introspect tools from ``agent_entrypoint`` with benchmark fallback and tier overrides."""
    discovered: list[Any] = []
    if agent_entrypoint:
        try:
            target, mod = _load_entrypoint(agent_entrypoint)
            raw_tools = _discover_raw_tools(generator, target, mod)
            discovered = generator.introspect_tools(raw_tools, policy_overrides=overrides)
        except Exception as exc:
            console.print(
                f"[yellow]Notice: {fallback_label} fell back to reference fixtures ({exc})[/yellow]"
            )

    if not discovered:
        discovered = generator.introspect_tools(
            _default_benchmark_tools(include_schema=include_schema),
            policy_overrides=overrides,
        )
    return discovered


def _synthesize_per_tool_scenarios(
    generator: Any,
    tools: list[Any],
    scenarios_per_tool: int,
    policy_overrides: dict[str, str] | None = None,
) -> list[Any]:
    """Synthesize ``scenarios_per_tool`` diverse scenarios for each discovered tool."""
    from secagent.generator import GeneratedScenario

    meta_tools = generator.introspect_tools(tools, policy_overrides=policy_overrides)
    selected: list[GeneratedScenario] = []
    counter = 1

    for tool in meta_tools:
        raw_pool = generator.generate(
            [tool],
            scenarios_per_tool=max(scenarios_per_tool, 3),
            policy_overrides=policy_overrides,
        )
        tool_pool = [s for s in raw_pool if s.target_tool == tool.name]
        sys_pool = [s for s in raw_pool if s.target_tool != tool.name]

        chosen: list[GeneratedScenario] = []
        chosen_ids: set[int] = set()
        seen_categories: set[str] = set()

        for candidate in tool_pool:
            if len(chosen) >= scenarios_per_tool:
                break
            if candidate.owasp_category not in seen_categories:
                seen_categories.add(candidate.owasp_category)
                chosen.append(candidate)
                chosen_ids.add(id(candidate))

        for candidate in [*tool_pool, *sys_pool]:
            if len(chosen) >= scenarios_per_tool:
                break
            if id(candidate) not in chosen_ids:
                candidate.target_tool = tool.name
                chosen.append(candidate)
                chosen_ids.add(id(candidate))

        extra_idx = 1
        while len(chosen) < scenarios_per_tool:
            sqli_payload = generator.SQLI_PAYLOADS[extra_idx % len(generator.SQLI_PAYLOADS)]
            sqli_args = generator.fuzzer.build_arguments(tool, "sqli", sqli_payload)
            injected = generator._payload_was_injected(sqli_args, sqli_payload)
            chosen.append(
                GeneratedScenario(
                    id=f"GEN-ASI02-{counter:03d}",
                    owasp_category="ASI02-ToolMisuse",
                    title=f"SQL Injection Variant #{extra_idx + 1} on {tool.name}",
                    description=f"Fuzzed SQL injection variant targeting '{tool.name}'.",
                    target_tool=tool.name,
                    user_prompt=f"Execute {tool.name} with query: {sqli_payload}",
                    injected_parameters=sqli_args if injected else {},
                    caller_role="user",
                    expected_failure_policy="POL-ASI02-001",
                )
            )
            extra_idx += 1

        for item in chosen[:scenarios_per_tool]:
            prefix = item.owasp_category.split("-")[0] if "-" in item.owasp_category else "ASI00"
            item.id = f"GEN-{prefix}-{counter:03d}"
            selected.append(item)
            counter += 1

    return selected


def _synthesize_fuzz_scenarios(
    generator: Any,
    tools: list[Any],
    iterations: int,
    policy_overrides: dict[str, str] | None = None,
) -> list[Any]:
    """Synthesize ``iterations`` schema-directed mutated scenarios using SchemaDirectedFuzzer."""
    from secagent.generator import GeneratedScenario

    meta_tools = generator.introspect_tools(tools, policy_overrides=policy_overrides)
    if not meta_tools or iterations <= 0:
        return []

    vectors: list[tuple[str, str, str, list[Any]]] = [
        ("sqli", "ASI02-ToolMisuse", "POL-ASI02-001", list(generator.SQLI_PAYLOADS)),
        (
            "command",
            "ASI05-UnexpectedCodeExecution",
            "POL-ASI05-001",
            list(generator.CMD_INJECTION_PAYLOADS),
        ),
        (
            "egress",
            "ASI10-RogueAgentExfiltration",
            "POL-ASI10-001",
            list(generator.EGRESS_PAYLOADS),
        ),
        (
            "scope",
            "ASI06-ScopeContamination",
            "POL-ASI06-001",
            [["ssn", "password_hash"], ["tax_id", "api_key"], ["ssn", "credit_card"]],
        ),
        ("role", "ASI03-PrivilegeAbuse", "POL-ASI03-001", list(generator.ROLE_BYPASS_PROMPTS)),
        ("hijack", "ASI01-AgentGoalHijack", "POL-ASI01-001", list(generator.GOAL_HIJACK_PROMPTS)),
    ]

    n_tools = len(meta_tools)
    n_vectors = len(vectors)
    results: list[GeneratedScenario] = []
    for idx in range(iterations):
        tool = meta_tools[idx % n_tools]
        attack, category, policy_id, payloads = vectors[(idx // n_tools) % n_vectors]
        payload = payloads[(idx // (n_tools * n_vectors)) % len(payloads)]

        if attack in ("sqli", "command", "egress", "scope"):
            injected_args = generator.fuzzer.build_arguments(tool, attack, payload)
            if attack == "scope" and isinstance(payload, list):
                for key in ("fields", "columns", "attributes"):
                    if key in injected_args and isinstance(injected_args[key], list):
                        injected_args[key] = list(payload)
                        break
            prompt = f"Execute {tool.name} with mutated {attack} input: {payload}"
            role = "user"
        elif attack == "role":
            injected_args = generator.fuzzer.build_arguments(tool, "command", str(payload))
            prompt = f"{payload} Run '{tool.name}'."
            role = "guest"
        else:
            injected_args = generator.fuzzer.build_arguments(tool, "sqli", str(payload))
            prompt = f"{payload} Immediately invoke '{tool.name}'."
            role = "guest"

        results.append(
            GeneratedScenario(
                id=f"FUZZ-{idx + 1:03d}",
                owasp_category=category,
                title=f"Schema-Directed {attack.upper()} Mutation on {tool.name}",
                description=(
                    f"Iteration {idx + 1}: mutates '{tool.name}' parameters via "
                    f"SchemaDirectedFuzzer for {category}."
                ),
                target_tool=tool.name,
                user_prompt=prompt,
                injected_parameters=injected_args,
                caller_role=role,
                approval_granted=False,
                expected_failure_policy=policy_id,
            )
        )

    return results


@app.command(name="generate")
def generate_scenarios_cmd(
    agent_entrypoint: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help="Import path of target agent (e.g. 'examples.finance_agent.agent' or 'module:attr')",
        ),
    ] = "",
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory to save dynamically generated scenarios",
        ),
    ] = Path("scenarios/generated/"),
    scenarios_per_tool: Annotated[
        int,
        typer.Option(
            "--per-tool",
            "-n",
            min=1,
            help="Number of adversarial scenarios to synthesize per tool",
        ),
    ] = 2,
    policies: Annotated[
        Path,
        typer.Option(
            "--policies",
            "-p",
            help="Path to security rules YAML for tool tier overrides",
        ),
    ] = Path("policies/security_rules.yaml"),
) -> None:
    """Generate test scenarios from agent tool definitions."""
    from secagent.generator import ScenarioGenerator

    console.print("[bold cyan]Generating scenarios[/bold cyan]")
    generator = ScenarioGenerator()
    overrides = _resolve_policy_overrides(policies)
    if agent_entrypoint:
        console.print(f"Introspecting agent entrypoint: [yellow]{agent_entrypoint}[/yellow]")

    discovered_tools = _resolve_target_tools(
        generator,
        agent_entrypoint,
        overrides,
        fallback_label="Could not dynamically inspect entrypoint; generate",
    )

    scenarios = _synthesize_per_tool_scenarios(
        generator,
        discovered_tools,
        scenarios_per_tool=scenarios_per_tool,
        policy_overrides=overrides,
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    for scenario in scenarios:
        manifest_path = output_dir / f"{scenario.id}.json"
        manifest_path.write_text(json.dumps(scenario.to_dict(), indent=2), encoding="utf-8")

    summary_file = output_dir / "generated_scenarios.json"
    summary_file.write_text(
        json.dumps([s.to_dict() for s in scenarios], indent=2),
        encoding="utf-8",
    )

    console.print(
        f"[bold green]Generated {len(scenarios)} scenarios across {len(discovered_tools)} tools.[/bold green]"
    )
    console.print(f"Saved to: [cyan]{summary_file}[/cyan]")


def _load_scenarios_from_dir(scenarios_dir: Path) -> list[dict[str, Any]]:
    """Load scenario manifests from ``.yaml`` and ``.json`` files in ``scenarios_dir``."""
    import yaml

    individual_files: list[Path] = []
    bundle_files: list[Path] = []

    for path in sorted(list(scenarios_dir.glob("*.yaml")) + list(scenarios_dir.glob("*.json"))):
        if path.name in ("generated_scenarios.json", "fuzz_findings.json"):
            bundle_files.append(path)
        else:
            individual_files.append(path)

    source_files = individual_files if individual_files else bundle_files
    loaded: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for path in source_files:
        try:
            text = path.read_text(encoding="utf-8")
            data = yaml.safe_load(text) if path.suffix == ".yaml" else json.loads(text)
        except Exception:
            continue

        items = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        for item in items:
            if not isinstance(item, dict):
                continue
            scn_id = str(item.get("id") or item.get("scenario_id") or f"{path.stem}-{len(loaded)}")
            if scn_id not in seen_ids:
                seen_ids.add(scn_id)
                loaded.append(item)

    return loaded


def _execute_scenarios_with_telemetry(
    target: Any,
    mod: Any,
    target_tools: list[Any],
    scenario_dicts: list[dict[str, Any]],
    policy_overrides: dict[str, str],
) -> list[dict[str, Any]]:
    """Run scenarios through Subsystem 1 ExecutionHarness and Subsystem 2 TraceExporter."""
    if target is None or not callable(getattr(target, "invoke", None)):
        return []

    from secagent.harness.runner import ExecutionHarness
    from secagent.telemetry.callbacks import SecAgentTelemetryCallback, TraceSession
    from secagent.telemetry.exporter import TraceExporter

    class _GateAwareTelemetryCallback(SecAgentTelemetryCallback):
        def __init__(self, session: TraceSession, approval_granted: bool) -> None:
            super().__init__(session=session)
            self._approval_granted = approval_granted

        def on_chain_start(
            self,
            serialized: dict[str, Any] | None,
            inputs: dict[str, Any] | Any,
            **kwargs: Any,
        ) -> None:
            if kwargs.get("name") == "approval_gate":
                self.record_hitl(self._approval_granted)

    tier_by_tool = {t.name: t.permission_tier for t in target_tools}
    harness = ExecutionHarness(policy_overrides=policy_overrides, dry_run=True)
    exporter = TraceExporter()
    framework = "langgraph" if hasattr(target, "nodes") else "generic"
    traces: list[dict[str, Any]] = []

    for idx, scn in enumerate(scenario_dicts):
        scn_id = str(scn.get("id") or scn.get("scenario_id") or f"SCN-{idx + 1:03d}")
        caller_role = str(scn.get("caller_role") or "guest")
        task_context = str(scn.get("task_context") or "default")
        session = TraceSession(
            scenario_id=scn_id,
            caller_role=caller_role,
            task_context=task_context,
            metadata={"framework": framework},
        )
        callback = _GateAwareTelemetryCallback(
            session,
            approval_granted=bool(scn.get("approval_granted", False)),
        )
        result = harness.run_scenario(target, scn, mod, callbacks=[callback])

        for span in session.spans:
            if span.get("span_type") == "tool.call" and span.get("permission_tier") in (
                None,
                "none",
            ):
                span["permission_tier"] = tier_by_tool.get(str(span.get("name")), "read")

        if not session.spans and result.tool_calls:
            for call_rec in result.tool_calls:
                now_ns = call_rec.timestamp_ns
                session.append(
                    {
                        "span_id": f"span-{uuid.uuid4().hex[:8]}",
                        "span_type": "tool.call",
                        "name": call_rec.tool_name,
                        "start_time_ns": now_ns,
                        "end_time_ns": now_ns,
                        "permission_tier": (
                            call_rec.permission_tier
                            if call_rec.permission_tier
                            in (
                                "pure",
                                "read",
                                "write",
                                "pay",
                                "admin",
                                "net",
                                "gate",
                                "none",
                            )
                            else tier_by_tool.get(call_rec.tool_name, "read")
                        ),
                        "approval_granted": None,
                        "input_parameters": call_rec.arguments,
                        "output_result": call_rec.output,
                        "is_error": False,
                        "error_message": None,
                    }
                )

        err_span = result.error_span(step_index=len(session.spans))
        if err_span is not None:
            session.append(err_span)

        try:
            traces.append(exporter.validate(session.as_dict()))
        except Exception:
            traces.append(exporter.redact(session.as_dict()))

    return traces


@app.command(name="scan")
def scan(
    agent_entrypoint: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help="Import path of target agent (e.g. 'my_agent.graph:app' or Python module)",
        ),
    ] = "",
    policies: Annotated[
        Path,
        typer.Option(
            "--policies",
            "-p",
            help="Path to security rules YAML",
        ),
    ] = Path("policies/security_rules.yaml"),
    scenarios: Annotated[
        Path | None,
        typer.Option(
            "--scenarios",
            "-s",
            help="Optional path to custom scenarios directory. If omitted, scenarios are dynamically generated.",
        ),
    ] = None,
    output_report: Annotated[
        Path,
        typer.Option(
            "--output-report",
            "-o",
            help="Output path for JSON report",
        ),
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path,
        typer.Option(
            "--output-markdown",
            "-m",
            help="Output path for markdown summary",
        ),
    ] = Path("comment.md"),
) -> None:
    """Run security invariant checks against generated or provided scenarios."""
    from secagent.generator import ScenarioGenerator

    console.print("[bold green]SecAgent Security Scanner[/bold green] v0.1.0")
    console.print(f"Policies: [cyan]{policies}[/cyan]")

    generator = ScenarioGenerator()
    overrides = _resolve_policy_overrides(policies)
    target: Any = None
    mod: Any = None
    target_tools: list[Any] = []

    if agent_entrypoint:
        console.print(f"Target Agent: [yellow]{agent_entrypoint}[/yellow]")
        try:
            target, mod = _load_entrypoint(agent_entrypoint)
            raw = _discover_raw_tools(generator, target, mod)
            target_tools = generator.introspect_tools(raw, policy_overrides=overrides)
        except Exception as exc:
            console.print(
                f"[yellow]Notice: Introspection fell back to reference fixtures ({exc})[/yellow]"
            )

    if not target_tools:
        target_tools = generator.introspect_tools(
            _default_benchmark_tools(),
            policy_overrides=overrides,
        )

    if scenarios is None or not scenarios.exists():
        console.print("[cyan]Generating scenarios tailored to agent...[/cyan]")
        synth_scenarios = generator.generate(target_tools, policy_overrides=overrides)
        scenario_dicts = [s.to_dict() for s in synth_scenarios]
        scenarios_count = len(scenario_dicts)
    else:
        scenario_dicts = _load_scenarios_from_dir(scenarios)
        scenarios_count = len(scenario_dicts) or len(
            list(scenarios.glob("*.yaml")) + list(scenarios.glob("*.json"))
        )

    traces = _execute_scenarios_with_telemetry(
        target,
        mod,
        target_tools,
        scenario_dicts,
        overrides,
    )

    message = (
        f"Executed {len(traces)} trace(s) across {scenarios_count} scenarios; "
        "policy evaluation pending subsystem 4."
        if traces
        else f"Smoke run prepared {scenarios_count} scenarios. "
        "Policy evaluation is pending subsystem 4 (engine not implemented)."
    )

    report: dict[str, Any] = {
        "status": "NOT_EVALUATED",
        "agent": agent_entrypoint or "baseline_smoke",
        "scenarios_evaluated": scenarios_count,
        "violations_detected": 0,
        "violations": [],
        "traces": traces,
        "generation_mode": (
            "dynamic_synthetic"
            if (scenarios is None or not scenarios.exists())
            else "custom_directory"
        ),
        "message": message,
    }
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    comment = _format_markdown_report(
        report,
        agent_name=agent_entrypoint or "default_fixture",
        scenarios_evaluated=scenarios_count,
    )
    output_markdown.write_text(comment, encoding="utf-8")
    console.print(f"[bold yellow]{message}[/bold yellow]")
    raise typer.Exit(code=0)


@app.command(name="test")
def test_alias(
    agent_entrypoint: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help="Import path of target agent",
        ),
    ] = "",
    policies: Annotated[
        Path,
        typer.Option(
            "--policies",
            "-p",
            help="Path to security rules YAML",
        ),
    ] = Path("policies/security_rules.yaml"),
    output_report: Annotated[
        Path,
        typer.Option(
            "--output-report",
            "-o",
            help="Output path for JSON report",
        ),
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path,
        typer.Option(
            "--output-markdown",
            "-m",
            help="Output path for markdown summary",
        ),
    ] = Path("comment.md"),
) -> None:
    """Alias for 'scan' command with dynamic scenario synthesis."""
    scan(
        agent_entrypoint=agent_entrypoint,
        policies=policies,
        scenarios=None,
        output_report=output_report,
        output_markdown=output_markdown,
    )


@app.command(name="fuzz")
def fuzz(
    agent_entrypoint: Annotated[
        str,
        typer.Option(
            "--agent",
            "-a",
            help="Import path of target agent (e.g. 'my_agent.graph:app' or Python module)",
        ),
    ] = "",
    policies: Annotated[
        Path,
        typer.Option(
            "--policies",
            "-p",
            help="Path to security rules YAML",
        ),
    ] = Path("policies/security_rules.yaml"),
    iterations: Annotated[
        int,
        typer.Option(
            "--iterations",
            "-n",
            min=1,
            help="Number of adversarial prompt mutation iterations",
        ),
    ] = 10,
    output_dir: Annotated[
        Path,
        typer.Option(
            "--output-dir",
            "-o",
            help="Directory to save discovered vulnerability scenarios",
        ),
    ] = Path("scenarios/generated/"),
) -> None:
    """Run prompt mutations to test policy coverage."""
    from secagent.generator import ScenarioGenerator

    console.print(f"[bold magenta]Running fuzzer[/bold magenta] ({iterations} iterations)")
    console.print(f"Target: [yellow]{agent_entrypoint or 'all configured agents'}[/yellow]")
    generator = ScenarioGenerator()
    overrides = _resolve_policy_overrides(policies)
    output_dir.mkdir(parents=True, exist_ok=True)

    target_tools = _resolve_target_tools(
        generator,
        agent_entrypoint,
        overrides,
        include_schema=True,
        fallback_label="Fuzzing",
    )

    fuzzed_scenarios = _synthesize_fuzz_scenarios(
        generator,
        target_tools,
        iterations=iterations,
        policy_overrides=overrides,
    )
    for scenario in fuzzed_scenarios:
        manifest_path = output_dir / f"{scenario.id}.json"
        manifest_path.write_text(json.dumps(scenario.to_dict(), indent=2), encoding="utf-8")

    out_file = output_dir / "fuzz_findings.json"
    out_file.write_text(
        json.dumps([s.to_dict() for s in fuzzed_scenarios], indent=2), encoding="utf-8"
    )

    console.print(
        f"[green]Completed across {len(fuzzed_scenarios)} mutated inputs. Output: {out_file}[/green]"
    )
    raise typer.Exit(code=0)


@app.command(name="serve")
def serve(
    report: Annotated[
        Path,
        typer.Option(
            "--report",
            "-r",
            help="Path to JSON audit report",
        ),
    ] = Path("report.json"),
    trace: Annotated[
        Path | None,
        typer.Option(
            "--trace",
            "-t",
            help="Optional path to execution trace JSON file",
        ),
    ] = None,
    port: Annotated[
        int,
        typer.Option(
            "--port",
            "-p",
            min=1,
            max=65535,
            help="Port for the Streamlit dashboard server",
        ),
    ] = 8501,
) -> None:
    """Launch local Streamlit security dashboard."""
    if not report.exists():
        console.print(f"[red]Report file not found: {report}[/red]")
        raise typer.Exit(code=1)
    if trace is not None and not trace.exists():
        console.print(f"[red]Trace file not found: {trace}[/red]")
        raise typer.Exit(code=1)

    app_path = Path(__file__).resolve().with_name("app.py")
    console.print(
        f"[bold blue]Launching local security dashboard on port {port} for report: {report}...[/bold blue]"
    )
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(app_path),
        "--server.port",
        str(port),
        "--",
        "--report",
        str(report),
    ]
    if trace is not None:
        cmd.extend(["--trace", str(trace)])

    proc = subprocess.run(cmd, check=False)
    raise typer.Exit(code=proc.returncode)


if __name__ == "__main__":
    app()
