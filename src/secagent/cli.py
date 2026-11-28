import importlib
import importlib.util
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape as escape_markup

from secagent import __version__
from secagent.ui import (
    make_progress,
    render_discovered_tools,
    render_scan_header,
    render_summary_card,
    render_violations,
    render_welcome_banner,
)

MAX_GITHUB_COMMENT_LENGTH = 65000
COMMENT_MARKER = "<!-- secagent-security-gate -->"
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_VALID_SPAN_TIERS = frozenset({"pure", "read", "write", "pay", "admin", "net", "gate", "none"})

app = typer.Typer(
    name="secagent",
    help="SecAgent: Security scanner for autonomous AI agents",
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def main_callback(ctx: typer.Context) -> None:
    """Display the SecAgent welcome banner when invoked with no subcommand."""
    if ctx.invoked_subcommand is None:
        render_welcome_banner(console, __version__)
        raise typer.Exit(code=0)


def _load_entrypoint(agent_entrypoint: str) -> tuple[Any, Any]:
    """Import an agent entrypoint ('module:attr' or 'module') via canonical introspector."""
    from secagent.harness.introspector import load_entrypoint

    return load_entrypoint(agent_entrypoint)


def _field(obj: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a dict or an object attribute."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _escape_cell(value: Any) -> str:
    """Escape pipe characters, backticks, HTML angle brackets, and newlines inside a Markdown cell."""
    return (
        str(value)
        .replace("|", "\\|")
        .replace("`", "'")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
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
    status = _escape_cell(_field(result, "status", "PASS") or "PASS")
    raw_violations = _field(result, "violations", [])
    violations = list(raw_violations) if isinstance(raw_violations, (list, tuple)) else []
    effective_agent = _escape_cell(
        agent_name or _field(result, "agent", "default_fixture") or "default_fixture"
    )
    effective_scenarios = scenarios_evaluated or int(_field(result, "scenarios_evaluated", 0) or 0)

    if status == "NOT_EVALUATED":
        return (
            f"{COMMENT_MARKER}\n"
            "### SecAgent Security Gate: NOT_EVALUATED\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Prepared**: {effective_scenarios}\n"
            "- **Status**: No executable agent traces were produced; "
            "no policies were evaluated in this run.\n"
        )

    def _coverage_lines(cov: Any) -> str:
        if not isinstance(cov, dict):
            return ""
        lines: list[str] = []
        util_rate = cov.get("utility_pass_rate")
        if util_rate is not None:
            lines.append(f"- **Utility Pass Rate**: {int(round(float(util_rate) * 100))}%\n")
        if cov.get("low_coverage_warning"):
            rate = int(round(float(cov.get("tool_invocation_rate", 0.0)) * 100))
            lines.append(
                f"- **Coverage Warning**: Only {cov.get('scenarios_with_tool_calls', 0)}/"
                f"{cov.get('total_traces', 0)} scenarios invoked tools ({rate}%). "
                "Verify agent prompts/tools are being exercised.\n"
            )
        return "".join(lines)

    cov_block = _coverage_lines(_field(result, "coverage", None))

    if status == "PASS" and not violations:
        return (
            f"{COMMENT_MARKER}\n"
            "### SecAgent Security Gate: PASS\n\n"
            f"- **Target Agent**: `{effective_agent}`\n"
            f"- **Scenarios Evaluated**: {effective_scenarios}\n"
            "- **Violations Detected**: 0\n"
            f"{cov_block}"
            "- **Status**: All invariant security policies satisfied.\n"
        )

    sorted_violations = sorted(
        violations,
        key=lambda v: (
            _SEVERITY_ORDER.get(str(_field(v, "severity", "")), 99),
            int(_field(v, "offending_step_index", 0) or 0),
        ),
    )

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in sorted_violations:
        sev = str(_field(v, "severity", "HIGH")).upper()
        if sev in counts:
            counts[sev] += 1
    severity_summary = (
        f"CRITICAL: {counts['CRITICAL']} · HIGH: {counts['HIGH']} · "
        f"MEDIUM: {counts['MEDIUM']} · LOW: {counts['LOW']}"
    )

    header = (
        f"{COMMENT_MARKER}\n"
        f"### SecAgent Security Gate: {status}\n\n"
        f"- **Target Agent**: `{effective_agent}`\n"
        f"- **Scenarios Evaluated**: {effective_scenarios}\n"
        f"- **Violations Detected**: {len(sorted_violations)}\n"
        f"- **Severity Breakdown**: {severity_summary}\n"
        f"{cov_block}\n"
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

    evidence_lines: list[str] = []
    for v in sorted_violations[:5]:
        ev = _field(v, "evidence", None)
        if isinstance(ev, dict) and ev:
            rule_id = _escape_cell(_field(v, "rule_id", "UNKNOWN"))
            tool_name = _escape_cell(_field(v, "offending_tool_name", "unknown"))
            span_id = _escape_cell(_field(v, "offending_span_id", "unknown"))
            ev_json = (
                json.dumps(ev, default=str)
                .replace("`", "'")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            if len(ev_json) > 220:
                ev_json = ev_json[:217] + "..."
            evidence_lines.append(f"- **`{rule_id}`** (`{tool_name}` · `{span_id}`): `{ev_json}`")

    if evidence_lines:
        details_block = (
            "\n<details>\n"
            "<summary><b>Detailed Evidence (Top Findings)</b></summary>\n\n"
            + "\n".join(evidence_lines)
            + "\n\n</details>\n"
        )
        if len(body) + len(details_block) <= MAX_GITHUB_COMMENT_LENGTH:
            body += details_block

    footer = "\n*Inspect trace waterfall locally: `secagent serve --report report.json`*\n"
    if len(body) + len(footer) <= MAX_GITHUB_COMMENT_LENGTH:
        body += footer

    return body


def _discover_raw_tools(generator: Any, target: Any, mod: Any) -> list[Any]:
    """Discover raw tool objects using Subsystem 1 introspector with Subsystem 3 fallback."""
    from secagent.harness.introspector import discover_tools as harness_discover_tools

    return harness_discover_tools(target, mod) or generator.discover_tools(target, mod)


def _resolve_policy_overrides(policies: Path | None) -> dict[str, str]:
    """Load tool_tier_overrides from the policy YAML file or packaged defaults."""
    if policies is None or (
        policies == Path("policies/security_rules.yaml") and not policies.exists()
    ):
        from secagent.engine import PolicyLoader, PolicyLoadError

        try:
            return dict(PolicyLoader(None).load().tool_tier_overrides)
        except PolicyLoadError as exc:
            console.print(
                f"[yellow]Warning: Could not load packaged policy overrides ({exc})[/yellow]"
            )
            return {}
    if not policies.exists():
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


def _resolve_agent_target(
    generator: Any,
    agent_entrypoint: str,
    overrides: dict[str, str],
    *,
    include_schema: bool = False,
) -> tuple[Any, Any, list[Any]]:
    """Resolve an explicit agent entrypoint fail-closed, or fall back when omitted."""
    if not agent_entrypoint:
        return (
            None,
            None,
            generator.introspect_tools(
                _default_benchmark_tools(include_schema=include_schema),
                policy_overrides=overrides,
            ),
        )

    try:
        target, mod = _load_entrypoint(agent_entrypoint)
        if callable(target) and not _is_runnable_target(target):
            try:
                built = target()
                if _is_runnable_target(built):
                    target = built
            except TypeError:
                pass
        raw_tools = _discover_raw_tools(generator, target, mod)
        discovered = generator.introspect_tools(raw_tools, policy_overrides=overrides)
    except Exception as exc:
        console.print(
            f"[red]Error loading agent entrypoint '{escape_markup(agent_entrypoint)}': "
            f"{escape_markup(str(exc))}[/red]"
        )
        raise typer.Exit(code=1) from exc

    if not discovered:
        console.print(
            f"[red]No tools discovered for agent entrypoint "
            f"'{escape_markup(agent_entrypoint)}'.[/red]"
        )
        raise typer.Exit(code=1)

    return target, mod, discovered


def _fingerprint_agent_source(module: Any) -> str:
    """Fingerprint agent source and turn unsafe cache identity into a CLI error."""
    from secagent.generator.cache import AgentFingerprintError, agent_source_fingerprint

    try:
        return agent_source_fingerprint(module)
    except AgentFingerprintError as exc:
        console.print(f"[red]Error fingerprinting agent source: {escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc


def _resolve_target_tools(
    generator: Any,
    agent_entrypoint: str,
    overrides: dict[str, str],
    *,
    include_schema: bool = False,
    fallback_label: str = "Introspection",
) -> list[Any]:
    """Introspect tools from ``agent_entrypoint`` with benchmark fallback when omitted."""
    _ = fallback_label
    _, _, discovered = _resolve_agent_target(
        generator,
        agent_entrypoint,
        overrides,
        include_schema=include_schema,
    )
    return discovered


def _synthesize_per_tool_scenarios(
    generator: Any,
    tools: list[Any],
    scenarios_per_tool: int,
    policy_overrides: dict[str, str] | None = None,
    *,
    seed: int = 42,
) -> list[Any]:
    """Synthesize ``scenarios_per_tool`` diverse scenarios for each discovered tool."""
    from secagent.generator import GeneratedScenario

    meta_tools = generator.introspect_tools(tools, policy_overrides=policy_overrides)
    selected: list[GeneratedScenario] = []
    counter = 1

    for tool_idx, tool in enumerate(meta_tools):
        tool_seed = seed if seed == 42 else seed + tool_idx * 997
        raw_pool = generator.generate(
            [tool],
            scenarios_per_tool=max(scenarios_per_tool, 3),
            policy_overrides=policy_overrides,
            seed=tool_seed,
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
            if getattr(item, "is_benign", False) or item.owasp_category.startswith("UTILITY"):
                prefix = "UTIL"
            else:
                prefix = (
                    item.owasp_category.split("-")[0] if "-" in item.owasp_category else "ASI00"
                )
            item.id = f"GEN-{prefix}-{counter:03d}"
            selected.append(item)
            counter += 1

    return selected


def _synthesize_whole_suite_scenarios(
    generator: Any,
    tools: list[Any],
    scenarios_per_tool: int = 2,
    policy_overrides: dict[str, str] | None = None,
    *,
    seed: int = 42,
) -> list[Any]:
    """Synthesize the complete suite in one generator call."""
    return generator.generate(
        tools,
        scenarios_per_tool=scenarios_per_tool,
        policy_overrides=policy_overrides,
        seed=seed,
    )


def _write_generated_scenarios(output_dir: Path, scenario_dicts: list[dict[str, Any]]) -> None:
    """Write generated manifests and remove only stale manifests tracked by the old summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_file = output_dir / "generated_scenarios.json"
    previous_ids: set[str] = set()
    if summary_file.is_file():
        try:
            previous = json.loads(summary_file.read_text(encoding="utf-8"))
            if isinstance(previous, list):
                previous_ids = {
                    str(item["id"])
                    for item in previous
                    if isinstance(item, dict) and item.get("id")
                }
        except (OSError, ValueError):
            pass

    current_ids = {str(item["id"]) for item in scenario_dicts if item.get("id")}
    for stale_id in previous_ids - current_ids:
        if not stale_id.startswith("GEN-") or Path(stale_id).name != stale_id:
            continue
        stale_path = output_dir / f"{stale_id}.json"
        if stale_path.is_file():
            stale_path.unlink()

    output_dir.mkdir(parents=True, exist_ok=True)
    for item in scenario_dicts:
        safe_id = Path(str(item.get("id") or "")).name
        if not safe_id or safe_id in (".", ".."):
            raise ValueError(f"Invalid scenario id: {item.get('id')!r}")
        (output_dir / f"{safe_id}.json").write_text(
            json.dumps(item, sort_keys=True, indent=2), encoding="utf-8"
        )
    summary_file.write_text(json.dumps(scenario_dicts, sort_keys=True, indent=2), encoding="utf-8")


def _synthesize_fuzz_scenarios(
    generator: Any,
    tools: list[Any],
    iterations: int,
    policy_overrides: dict[str, str] | None = None,
    *,
    aggressive: bool = False,
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
            [["ssn", "password_hash"], ["salary", "password_hash"], ["ssn", "credit_card"]],
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
            injected_args = generator.fuzzer.build_arguments(
                tool,
                attack,
                payload,
                fallback_to_any_string=aggressive and attack in ("sqli", "command"),
            )
            if attack == "scope" and isinstance(payload, list):
                for key in ("fields", "columns", "attributes"):
                    if key in injected_args and isinstance(injected_args[key], list):
                        injected_args[key] = list(payload)
                        break
            prompt = f"Execute {tool.name} with mutated {attack} input: {payload}"
            role = "user"
        elif attack == "role":
            injected_args = generator.fuzzer.build_arguments(tool, "__none__", "")
            prompt = f"{payload} Run '{tool.name}'."
            role = "guest"
        else:
            injected_args = generator.fuzzer.build_arguments(tool, "__none__", "")
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
        int | None,
        typer.Option(
            "--per-tool",
            "-n",
            min=1,
            help="Select the existing capped per-tool behavior (default: whole-suite generation)",
        ),
    ] = None,
    policies: Annotated[
        Path,
        typer.Option(
            "--policies",
            "-p",
            help="Path to security rules YAML for tool tier overrides",
        ),
    ] = Path("policies/security_rules.yaml"),
    seed: Annotated[
        int,
        typer.Option("--seed", help="Seed deterministic scenario payload selection and cache key"),
    ] = 42,
) -> None:
    """Generate test scenarios from agent tool definitions."""
    from secagent.generator import ScenarioGenerator

    console.print("[bold cyan]Generating scenarios[/bold cyan]")
    generator = ScenarioGenerator()
    overrides = _resolve_policy_overrides(policies)
    if agent_entrypoint:
        console.print(f"Introspecting agent entrypoint: [yellow]{agent_entrypoint}[/yellow]")

    _, agent_module, discovered_tools = _resolve_agent_target(
        generator,
        agent_entrypoint,
        overrides,
    )
    from secagent.generator.cache import ScenarioCache

    generation_mode = "per_tool" if scenarios_per_tool is not None else "whole_suite"
    effective_scenarios_per_tool = scenarios_per_tool if scenarios_per_tool is not None else 2
    cache = ScenarioCache(Path(".secagent/cache"))
    key = cache.key(
        tools=discovered_tools,
        policy_overrides=overrides,
        seed=seed,
        settings={"mode": generation_mode, "scenarios_per_tool": effective_scenarios_per_tool},
        source_fingerprint=_fingerprint_agent_source(agent_module),
    )
    scenario_dicts = cache.load(key)
    if scenario_dicts is None:
        if generation_mode == "per_tool":
            scenarios = _synthesize_per_tool_scenarios(
                generator,
                discovered_tools,
                scenarios_per_tool=effective_scenarios_per_tool,
                policy_overrides=overrides,
                seed=seed,
            )
        else:
            scenarios = _synthesize_whole_suite_scenarios(
                generator,
                discovered_tools,
                scenarios_per_tool=effective_scenarios_per_tool,
                policy_overrides=overrides,
                seed=seed,
            )
        scenario_dicts = [scenario.to_dict() for scenario in scenarios]
        cache.save(key, scenario_dicts)
    _write_generated_scenarios(output_dir, scenario_dicts)
    summary_file = output_dir / "generated_scenarios.json"
    scenarios = scenario_dicts

    console.print(
        f"[bold green]Prepared {len(scenarios)} scenarios across {len(discovered_tools)} tools.[/bold green]"
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


def _extract_interrupt_events(output: Any) -> list[Any]:
    """Extract LangGraph ``__interrupt__`` values from runnable output if present."""
    if not isinstance(output, dict):
        return []
    raw = output.get("__interrupt__")
    if raw is None:
        return []
    items = list(raw) if isinstance(raw, (list, tuple)) else [raw]
    return [getattr(item, "value", item) for item in items]


def _record_output_interrupts(callback: Any, output: Any, target_tool: str) -> None:
    """Normalize LangGraph ``__interrupt__`` payloads into ``gate.hitl`` spans."""
    for event in _extract_interrupt_events(output):
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


def _infer_task_context(scenario: dict[str, Any]) -> str:
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


def _is_runnable_target(target: Any) -> bool:
    return target is not None and (
        callable(getattr(target, "invoke", None)) or callable(getattr(target, "ainvoke", None))
    )


def _execute_scenarios_with_telemetry(
    target: Any,
    mod: Any,
    target_tools: list[Any],
    scenario_dicts: list[dict[str, Any]],
    policy_overrides: dict[str, str],
    *,
    timeout_s: float = 30.0,
    quiet: bool = False,
    strict_sandbox: bool = True,
    mock_unclassified: bool = True,
    mock_mode: str = "rich",
) -> list[dict[str, Any]]:
    """Run scenarios through Subsystem 1 ExecutionHarness and Subsystem 2 TraceExporter."""
    if not _is_runnable_target(target):
        return []

    from secagent.harness.runner import ExecutionHarness
    from secagent.telemetry.callbacks import SecAgentTelemetryCallback, TraceSession
    from secagent.telemetry.exporter import TraceExporter

    _GATE_NODE_NAMES = frozenset({"approval_gate", "human_approval", "hitl_gate", "confirm_action"})

    class _GateAwareTelemetryCallback(SecAgentTelemetryCallback):
        def __init__(self, session: TraceSession, approval_granted: bool) -> None:
            super().__init__(session=session, tier_by_tool=tier_by_tool)
            self._approval_granted = approval_granted

        @staticmethod
        def _extract_pending_tool(inputs: Any) -> tuple[str, dict[str, Any]]:
            if not isinstance(inputs, dict):
                return "unknown_operation", {}
            messages = inputs.get("messages")
            if isinstance(messages, list):
                for msg in reversed(messages):
                    tool_calls = getattr(msg, "tool_calls", None)
                    if isinstance(tool_calls, list) and tool_calls:
                        first = tool_calls[0]
                        if isinstance(first, dict) and first.get("name"):
                            args = first.get("args")
                            return str(first["name"]), dict(args) if isinstance(args, dict) else {}
            intent = inputs.get("current_intent")
            if isinstance(intent, str) and intent.strip():
                return intent.strip(), {}
            return "unknown_operation", {}

        def on_chain_start(
            self,
            serialized: dict[str, Any] | None,
            inputs: dict[str, Any] | Any,
            **kwargs: Any,
        ) -> None:
            super().on_chain_start(serialized, inputs, **kwargs)
            if kwargs.get("name") in _GATE_NODE_NAMES:
                operation, bound_args = self._extract_pending_tool(inputs)
                extra = {"arguments": bound_args} if bound_args else None
                self.record_hitl(
                    self._approval_granted,
                    operation=operation,
                    input_parameters=extra,
                )

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
            task_context = _infer_task_context(scn)
            session = TraceSession(
                scenario_id=scn_id,
                caller_role=caller_role,
                task_context=task_context,
                metadata={"framework": framework, "is_benign": bool(scn.get("is_benign", False))},
            )
            callback = _GateAwareTelemetryCallback(
                session,
                approval_granted=bool(scn.get("approval_granted", False)),
            )
            effective_scn = {**scn, "task_context": task_context}
            result = harness.run_scenario(target, effective_scn, mod, callbacks=[callback])
            _record_output_interrupts(
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


def _load_external_traces(
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
    trace: Annotated[
        Path | None,
        typer.Option(
            "--trace",
            "-t",
            help="Optional path to pre-recorded trace JSON file or directory to evaluate directly.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.1,
            help="Per-scenario execution timeout in seconds.",
        ),
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live instead of failing closed.",
        ),
    ] = False,
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
    output_sarif: Annotated[
        Path | None,
        typer.Option(
            "--output-sarif",
            help="Optional output path for SARIF 2.1.0 report",
        ),
    ] = None,
    seed: Annotated[
        int,
        typer.Option("--seed", help="Seed deterministic scenario payload selection and cache key"),
    ] = 42,
    save_scenarios: Annotated[
        bool,
        typer.Option(
            "--save-scenarios",
            help="Write dynamically generated scenario manifests into scenarios/generated/",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Reduce terminal output to concise verdict summary"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit raw JSON report to stdout and suppress Rich UI"),
    ] = False,
) -> None:
    """Run security invariant checks against generated or provided scenarios."""
    from jsonschema import ValidationError as JsonSchemaValidationError

    from secagent.engine import (
        EvaluationResult,
        PolicyEngine,
        PolicyLoadError,
        PolicyReporter,
        scan_tool_definitions,
    )
    from secagent.generator import ScenarioGenerator

    effective_quiet = quiet or json_output
    err_console = Console(stderr=True) if json_output else console

    effective_policy_path = (
        None
        if policies == Path("policies/security_rules.yaml") and not policies.exists()
        else policies
    )
    try:
        engine = PolicyEngine(policy_path=effective_policy_path)
    except PolicyLoadError as exc:
        err_console.print(f"[red]{escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc

    if not effective_quiet:
        render_scan_header(
            console,
            version=__version__,
            target=agent_entrypoint or (str(trace) if trace is not None else "baseline_smoke"),
            policies_path=str(policies),
            rule_count=len(engine.ruleset.policies),
            mode="external_trace" if trace is not None else "dry-run sandbox",
        )

    if trace is not None:
        try:
            traces = _load_external_traces(
                trace,
                tier_overrides=dict(engine.ruleset.tool_tier_overrides),
            )
        except JsonSchemaValidationError as exc:
            err_console.print(
                f"[red]Trace schema validation failed: {escape_markup(exc.message)}[/red]"
            )
            raise typer.Exit(code=1) from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            err_console.print(f"[red]{escape_markup(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc

        scenarios_count = len(traces)
        generation_mode = "external_trace"
        tool_def_violations = []
    else:
        if scenarios is not None and not scenarios.exists():
            err_console.print(
                f"[red]Custom scenarios directory not found: {scenarios}. "
                "Provide an existing directory with scenario files.[/red]"
            )
            raise typer.Exit(code=1)

        generator = ScenarioGenerator()
        overrides = dict(engine.ruleset.tool_tier_overrides)
        target, mod, target_tools = _resolve_agent_target(
            generator,
            agent_entrypoint,
            overrides,
        )
        tp_cfg = engine.ruleset.tool_poisoning
        tool_def_violations = (
            []
            if tp_cfg is not None and not tp_cfg.enabled
            else scan_tool_definitions(
                target_tools,
                extra_patterns=tp_cfg.extra_patterns if tp_cfg is not None else None,
            )
        )

        if not effective_quiet:
            render_discovered_tools(console, target_tools)

        if scenarios is None:
            from secagent.generator.cache import ScenarioCache

            cache = ScenarioCache(Path(".secagent/cache"))
            key = cache.key(
                tools=target_tools,
                policy_overrides=overrides,
                seed=seed,
                settings={"mode": "whole_suite", "scenarios_per_tool": 2},
                source_fingerprint=_fingerprint_agent_source(mod),
            )
            scenario_dicts = cache.load(key)
            if scenario_dicts is None:
                if not effective_quiet:
                    console.print("[cyan]Generating scenarios tailored to agent...[/cyan]")
                synth_scenarios = _synthesize_whole_suite_scenarios(
                    generator,
                    target_tools,
                    scenarios_per_tool=2,
                    policy_overrides=overrides,
                    seed=seed,
                )
                scenario_dicts = [s.to_dict() for s in synth_scenarios]
                cache.save(key, scenario_dicts)
            if save_scenarios:
                _write_generated_scenarios(Path("scenarios/generated"), scenario_dicts)
            scenarios_count = len(scenario_dicts)
        else:
            scenario_dicts = _load_scenarios_from_dir(scenarios)
            scenarios_count = len(scenario_dicts) or len(
                list(scenarios.glob("*.yaml")) + list(scenarios.glob("*.json"))
            )

        from secagent.harness.runner import SandboxError

        try:
            traces = _execute_scenarios_with_telemetry(
                target,
                mod,
                target_tools,
                scenario_dicts,
                overrides,
                timeout_s=timeout,
                quiet=effective_quiet,
                strict_sandbox=not allow_live_tools,
                mock_unclassified=not allow_live_tools,
            )
        except SandboxError as exc:
            console.print(f"[red]Sandbox error: {escape_markup(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc
        except JsonSchemaValidationError as exc:
            err_console.print(
                f"[red]Trace schema validation failed: {escape_markup(exc.message)}[/red]"
            )
            raise typer.Exit(code=1) from exc

        generation_mode = "dynamic_synthetic" if scenarios is None else "custom_directory"

    agent_label = agent_entrypoint or (str(trace) if trace is not None else "")

    if traces:
        base_eval = engine.evaluate_traces(traces)
        if tool_def_violations:
            evaluation = EvaluationResult(
                status="FAIL",
                total_spans_evaluated=base_eval.total_spans_evaluated,
                violations=[*tool_def_violations, *base_eval.violations],
                execution_time_ms=base_eval.execution_time_ms,
                violation_scenario_ids=(
                    *(None for _ in tool_def_violations),
                    *base_eval.violation_scenario_ids,
                ),
            )
        else:
            evaluation = base_eval
        report = PolicyReporter().generate_report(
            evaluation,
            agent_name=agent_label or "baseline_smoke",
            scenarios_evaluated=scenarios_count,
            traces=traces,
            generation_mode=generation_mode,
        )
        exit_code = 1 if evaluation.has_blocking_violations else 0
    elif tool_def_violations:
        evaluation = EvaluationResult(
            status="FAIL",
            total_spans_evaluated=0,
            violations=tool_def_violations,
            execution_time_ms=0.0,
        )
        report = PolicyReporter().generate_report(
            evaluation,
            agent_name=agent_label or "baseline_smoke",
            scenarios_evaluated=scenarios_count,
            traces=traces,
            generation_mode=generation_mode,
        )
        exit_code = 1 if evaluation.has_blocking_violations else 0
    else:
        evaluation = EvaluationResult(
            status="PASS",
            total_spans_evaluated=0,
            violations=[],
            execution_time_ms=0.0,
        )
        report = {
            "status": "NOT_EVALUATED",
            "agent": agent_label or "baseline_smoke",
            "scenarios_evaluated": scenarios_count,
            "total_spans_evaluated": 0,
            "violations_detected": 0,
            "violations": [],
            "traces": traces,
            "generation_mode": generation_mode,
            "message": (
                f"Smoke run prepared {scenarios_count} scenarios; "
                "no runnable agent traces were executed (NOT_EVALUATED)."
            ),
        }
        exit_code = 1 if (agent_entrypoint.strip() or trace is not None) else 0

    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if output_sarif is not None:
        sarif = PolicyReporter().generate_sarif(
            evaluation,
            agent_name=agent_label or "baseline_smoke",
            rules=engine.ruleset.policies,
        )
        output_sarif.parent.mkdir(parents=True, exist_ok=True)
        output_sarif.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    comment = _format_markdown_report(
        report,
        agent_name=agent_label or "default_fixture",
        scenarios_evaluated=scenarios_count,
    )
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.write_text(comment, encoding="utf-8")
    message = str(report["message"])
    if json_output:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        if not effective_quiet:
            render_violations(
                console,
                report.get("violations") or [],
                report_path=output_report,
            )
            render_summary_card(
                console,
                status=str(report["status"]),
                scenarios=scenarios_count,
                spans=int(report.get("total_spans_evaluated") or 0),
                violations=int(report.get("violations_detected") or 0),
                report_path=output_report,
                markdown_path=output_markdown,
                sarif_path=output_sarif,
                elapsed_ms=report.get("execution_time_ms"),
                violation_list=report.get("violations") or [],
                coverage=report.get("coverage"),
            )
        if report["status"] == "FAIL":
            console.print(f"[bold red]{message}[/bold red]")
        elif report["status"] == "PASS":
            console.print(f"[bold green]{message}[/bold green]")
        else:
            console.print(f"[bold yellow]{message}[/bold yellow]")
    raise typer.Exit(code=exit_code)


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
    scenarios: Annotated[
        Path | None,
        typer.Option(
            "--scenarios",
            "-s",
            help="Optional path to custom scenarios directory.",
        ),
    ] = None,
    trace: Annotated[
        Path | None,
        typer.Option(
            "--trace",
            "-t",
            help="Optional path to pre-recorded trace JSON file or directory.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.1,
            help="Per-scenario execution timeout in seconds.",
        ),
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live instead of failing closed.",
        ),
    ] = False,
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
    output_sarif: Annotated[
        Path | None,
        typer.Option(
            "--output-sarif",
            help="Optional output path for SARIF 2.1.0 report",
        ),
    ] = None,
    seed: Annotated[
        int,
        typer.Option("--seed", help="Seed deterministic scenario payload selection and cache key"),
    ] = 42,
    save_scenarios: Annotated[
        bool,
        typer.Option(
            "--save-scenarios",
            help="Write dynamically generated scenario manifests into scenarios/generated/",
        ),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Reduce terminal output to concise verdict summary"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit raw JSON report to stdout and suppress Rich UI"),
    ] = False,
) -> None:
    """Alias for 'scan' command with dynamic scenario synthesis."""
    scan(
        agent_entrypoint=agent_entrypoint,
        policies=policies,
        scenarios=scenarios,
        trace=trace,
        timeout=timeout,
        allow_live_tools=allow_live_tools,
        output_report=output_report,
        output_markdown=output_markdown,
        output_sarif=output_sarif,
        seed=seed,
        save_scenarios=save_scenarios,
        quiet=quiet,
        json_output=json_output,
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
    execute: Annotated[
        bool,
        typer.Option(
            "--execute",
            help="Execute mutated scenarios against the target agent and evaluate policies",
        ),
    ] = False,
    output_report: Annotated[
        Path,
        typer.Option(
            "--output-report",
            help="Output path for JSON audit report when --execute is enabled",
        ),
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path,
        typer.Option(
            "--output-markdown",
            help="Output path for markdown summary when --execute is enabled",
        ),
    ] = Path("comment.md"),
    output_sarif: Annotated[
        Path | None,
        typer.Option(
            "--output-sarif",
            help="Optional output path for SARIF 2.1.0 report when --execute is enabled",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            min=0.1,
            help="Per-scenario execution timeout in seconds when --execute is enabled",
        ),
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live when --execute is enabled.",
        ),
    ] = False,
    aggressive: Annotated[
        bool,
        typer.Option(
            "--aggressive",
            help="Fallback to injecting SQLi/command payloads into the first string parameter when no semantic name matches.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit raw JSON report to stdout when --execute is enabled"),
    ] = False,
) -> None:
    """Run prompt mutations to test policy coverage."""
    from secagent.generator import ScenarioGenerator

    if not json_output:
        console.print(f"[bold magenta]Running fuzzer[/bold magenta] ({iterations} iterations)")
        console.print(f"Target: [yellow]{agent_entrypoint or 'all configured agents'}[/yellow]")
    generator = ScenarioGenerator()
    overrides = _resolve_policy_overrides(policies)
    output_dir.mkdir(parents=True, exist_ok=True)

    target, mod, target_tools = _resolve_agent_target(
        generator,
        agent_entrypoint,
        overrides,
        include_schema=True,
    )

    fuzzed_scenarios = _synthesize_fuzz_scenarios(
        generator,
        target_tools,
        iterations=iterations,
        policy_overrides=overrides,
        aggressive=aggressive,
    )
    for scenario in fuzzed_scenarios:
        safe_id = Path(str(scenario.id)).name
        if not safe_id or safe_id in (".", ".."):
            raise ValueError(f"Invalid scenario id: {scenario.id!r}")
        manifest_path = output_dir / f"{safe_id}.json"
        manifest_path.write_text(json.dumps(scenario.to_dict(), indent=2), encoding="utf-8")

    out_file = output_dir / "fuzz_findings.json"
    out_file.write_text(
        json.dumps([s.to_dict() for s in fuzzed_scenarios], indent=2), encoding="utf-8"
    )

    if not json_output:
        console.print(
            f"[green]Completed across {len(fuzzed_scenarios)} mutated inputs. Output: {out_file}[/green]"
        )
    if not execute:
        if json_output:
            sys.stdout.write(json.dumps([s.to_dict() for s in fuzzed_scenarios], indent=2) + "\n")
        raise typer.Exit(code=0)

    from jsonschema import ValidationError as JsonSchemaValidationError

    from secagent.engine import (
        EvaluationResult,
        PolicyEngine,
        PolicyLoadError,
        PolicyReporter,
        scan_tool_definitions,
    )

    err_console = Console(stderr=True) if json_output else console
    effective_policy_path = (
        None
        if policies == Path("policies/security_rules.yaml") and not policies.exists()
        else policies
    )
    try:
        engine = PolicyEngine(policy_path=effective_policy_path)
    except PolicyLoadError as exc:
        err_console.print(f"[red]{escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc

    from secagent.harness.runner import SandboxError

    tool_def_violations = scan_tool_definitions(target_tools)
    scenario_dicts = [s.to_dict() for s in fuzzed_scenarios]
    try:
        traces = _execute_scenarios_with_telemetry(
            target,
            mod,
            target_tools,
            scenario_dicts,
            overrides,
            timeout_s=timeout,
            quiet=json_output,
            strict_sandbox=not allow_live_tools,
            mock_unclassified=not allow_live_tools,
        )
    except SandboxError as exc:
        err_console.print(f"[red]Sandbox error: {escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc
    except JsonSchemaValidationError as exc:
        err_console.print(
            f"[red]Trace schema validation failed: {escape_markup(exc.message)}[/red]"
        )
        raise typer.Exit(code=1) from exc

    agent_label = agent_entrypoint or "fuzz_target"
    report: dict[str, Any]
    if not traces and not tool_def_violations:
        evaluation = EvaluationResult(
            status="PASS",
            total_spans_evaluated=0,
            violations=[],
            execution_time_ms=0.0,
        )
        report = {
            "status": "NOT_EVALUATED",
            "agent": agent_label,
            "scenarios_evaluated": len(scenario_dicts),
            "total_spans_evaluated": 0,
            "violations_detected": 0,
            "violations": [],
            "traces": traces,
            "generation_mode": "schema_fuzz",
            "message": "No executable agent traces produced during fuzz run (NOT_EVALUATED).",
        }
        exit_code = 1 if agent_entrypoint.strip() else 0
    else:
        base_eval = (
            engine.evaluate_traces(traces)
            if traces
            else EvaluationResult(
                status="PASS",
                total_spans_evaluated=0,
                violations=[],
                execution_time_ms=0.0,
            )
        )
        if tool_def_violations:
            evaluation = EvaluationResult(
                status="FAIL",
                total_spans_evaluated=base_eval.total_spans_evaluated,
                violations=[*tool_def_violations, *base_eval.violations],
                execution_time_ms=base_eval.execution_time_ms,
                violation_scenario_ids=(
                    *(None for _ in tool_def_violations),
                    *base_eval.violation_scenario_ids,
                ),
            )
        else:
            evaluation = base_eval

        report = PolicyReporter().generate_report(
            evaluation,
            agent_name=agent_label,
            scenarios_evaluated=len(scenario_dicts),
            traces=traces,
            generation_mode="schema_fuzz",
        )
        exit_code = 1 if evaluation.has_blocking_violations else 0
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if output_sarif is not None:
        sarif = PolicyReporter().generate_sarif(
            evaluation,
            agent_name=agent_label,
            rules=engine.ruleset.policies,
        )
        output_sarif.parent.mkdir(parents=True, exist_ok=True)
        output_sarif.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    output_markdown.parent.mkdir(parents=True, exist_ok=True)
    output_markdown.write_text(
        _format_markdown_report(
            report,
            agent_name=agent_label,
            scenarios_evaluated=len(scenario_dicts),
        ),
        encoding="utf-8",
    )
    if json_output:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        render_violations(console, report.get("violations") or [], report_path=output_report)
        render_summary_card(
            console,
            status=str(report["status"]),
            scenarios=len(scenario_dicts),
            spans=int(report.get("total_spans_evaluated") or 0),
            violations=int(report.get("violations_detected") or 0),
            report_path=output_report,
            markdown_path=output_markdown,
            sarif_path=output_sarif,
            elapsed_ms=report.get("execution_time_ms"),
            violation_list=report.get("violations") or [],
            coverage=report.get("coverage"),
        )
    raise typer.Exit(code=exit_code)


@app.command(name="scan-mcp")
def scan_mcp_cmd(
    manifest: Annotated[
        Path,
        typer.Argument(help="Path to MCP tools/list or mcpServers JSON manifest"),
    ],
    policies: Annotated[
        Path,
        typer.Option("--policies", "-p", help="Optional policy YAML for custom ASI04 patterns"),
    ] = Path("policies/security_rules.yaml"),
    pin_file: Annotated[
        Path | None,
        typer.Option("--pin-file", help="Path to SHA-256 tool pin file for rug-pull detection"),
    ] = None,
    update_pins: Annotated[
        bool,
        typer.Option("--update-pins", help="Write/update the SHA-256 pin file from this manifest"),
    ] = False,
    output_report: Annotated[
        Path,
        typer.Option("--output-report", "-o", help="Output path for JSON audit report"),
    ] = Path("mcp_report.json"),
    output_sarif: Annotated[
        Path | None,
        typer.Option("--output-sarif", help="Optional output path for SARIF 2.1.0 report"),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit raw JSON report to stdout and suppress Rich UI"),
    ] = False,
) -> None:
    """Scan MCP tool manifests for ASI04 poisoning, Unicode tricks, and rug-pull drift."""
    from secagent.engine import PolicyLoader, PolicyLoadError, PolicyReporter
    from secagent.harness.mcp_scanner import compute_tool_pins, load_mcp_manifest, scan_mcp_tools

    err_console = Console(stderr=True) if json_output else console
    if update_pins and pin_file is None:
        err_console.print("[red]--update-pins requires --pin-file <path>.[/red]")
        raise typer.Exit(code=1)

    extra_patterns: dict[str, str] | None = None
    enable_poisoning = True
    effective_policy_path = (
        None
        if policies == Path("policies/security_rules.yaml") and not policies.exists()
        else policies
    )
    try:
        ruleset = PolicyLoader(effective_policy_path).load()
        if ruleset.tool_poisoning is not None:
            enable_poisoning = ruleset.tool_poisoning.enabled
            extra_patterns = dict(ruleset.tool_poisoning.extra_patterns)
    except PolicyLoadError as exc:
        err_console.print(f"[red]{escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc

    try:
        tools = load_mcp_manifest(manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        err_console.print(f"[red]Failed to load MCP manifest: {escape_markup(str(exc))}[/red]")
        raise typer.Exit(code=1) from exc

    if not tools:
        report: dict[str, Any] = {
            "status": "NOT_EVALUATED",
            "agent": str(manifest),
            "scenarios_evaluated": 0,
            "total_spans_evaluated": 0,
            "violations_detected": 0,
            "violations": [],
            "traces": [],
            "generation_mode": "mcp_manifest",
            "mcp_tools_scanned": 0,
            "pins": {},
            "message": f"No MCP tools found in {manifest} (NOT_EVALUATED).",
        }
        output_report.parent.mkdir(parents=True, exist_ok=True)
        output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if json_output:
            sys.stdout.write(json.dumps(report, indent=2) + "\n")
        else:
            err_console.print(f"[bold yellow]{escape_markup(str(report['message']))}[/bold yellow]")
        raise typer.Exit(code=1)

    expected_pins: dict[str, str] | None = None
    if pin_file is not None and not update_pins:
        if not pin_file.is_file():
            err_console.print(
                f"[red]MCP pin file not found: {escape_markup(str(pin_file))}. "
                "Create it first with --update-pins.[/red]"
            )
            raise typer.Exit(code=1)
        try:
            loaded_pins = json.loads(pin_file.read_text(encoding="utf-8"))
            if not isinstance(loaded_pins, dict):
                raise ValueError("Pin file must contain a JSON object mapping tool names to hashes")
            expected_pins = {str(k): str(v) for k, v in loaded_pins.items()}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            err_console.print(f"[red]Failed to load pin file: {escape_markup(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc

    evaluation = scan_mcp_tools(
        tools,
        expected_pins=expected_pins,
        extra_patterns=extra_patterns,
        enable_poisoning_scan=enable_poisoning,
    )
    if update_pins and pin_file is not None:
        if evaluation.has_blocking_violations:
            err_console.print(
                "[red]Refusing to write --update-pins because blocking ASI04 violations were detected.[/red]"
            )
        else:
            pin_file.parent.mkdir(parents=True, exist_ok=True)
            pin_file.write_text(
                json.dumps(compute_tool_pins(tools), sort_keys=True, indent=2),
                encoding="utf-8",
            )

    report = PolicyReporter().generate_report(
        evaluation,
        agent_name=str(manifest),
        scenarios_evaluated=len(tools),
        traces=[],
        generation_mode="mcp_manifest",
    )
    report["mcp_tools_scanned"] = len(tools)
    report["pins"] = compute_tool_pins(tools)
    report["message"] = (
        f"Scanned {len(tools)} MCP tool(s): {len(evaluation.violations)} supply-chain violation(s) detected."
        if evaluation.violations
        else f"Scanned {len(tools)} MCP tool(s): all supply-chain checks satisfied."
    )
    output_report.parent.mkdir(parents=True, exist_ok=True)
    output_report.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if output_sarif is not None:
        sarif = PolicyReporter().generate_sarif(
            evaluation,
            agent_name=str(manifest),
            rules=(),
        )
        output_sarif.parent.mkdir(parents=True, exist_ok=True)
        output_sarif.write_text(json.dumps(sarif, indent=2), encoding="utf-8")

    if json_output:
        sys.stdout.write(json.dumps(report, indent=2) + "\n")
    else:
        render_violations(console, report.get("violations") or [], report_path=output_report)
        render_summary_card(
            console,
            status=str(report["status"]),
            scenarios=len(tools),
            spans=len(tools),
            violations=int(report.get("violations_detected") or 0),
            report_path=output_report,
            markdown_path=None,
            sarif_path=output_sarif,
            elapsed_ms=report.get("execution_time_ms"),
            violation_list=report.get("violations") or [],
        )
    raise typer.Exit(code=1 if evaluation.has_blocking_violations else 0)


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
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            "-b",
            help="Optional path to baseline report JSON for regression diffing",
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
    if importlib.util.find_spec("streamlit") is None:
        console.print(
            "[red]Streamlit is not installed.[/red] Install dashboard extras: "
            "[cyan]pip install 'secagent[dashboard]'[/cyan]"
        )
        raise typer.Exit(code=1)
    if not report.exists():
        console.print(f"[red]Report file not found: {report}[/red]")
        raise typer.Exit(code=1)
    if trace is not None and not trace.exists():
        console.print(f"[red]Trace file not found: {trace}[/red]")
        raise typer.Exit(code=1)
    if baseline is not None and not baseline.exists():
        console.print(f"[red]Baseline report file not found: {baseline}[/red]")
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
        "--server.address",
        "127.0.0.1",
        "--server.port",
        str(port),
        "--",
        "--report",
        str(report),
    ]
    if trace is not None:
        cmd.extend(["--trace", str(trace)])
    if baseline is not None:
        cmd.extend(["--baseline", str(baseline)])

    proc = subprocess.run(cmd, check=False)
    raise typer.Exit(code=proc.returncode)


if __name__ == "__main__":
    app()
