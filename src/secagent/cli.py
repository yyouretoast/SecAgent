"""SecAgent Typer CLI orchestrating scan, generate, fuzz, scan-mcp, and serve."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape as escape_markup

from secagent import __version__
from secagent.generator.synthesis import (
    default_benchmark_tools as _default_benchmark_tools,
)
from secagent.generator.synthesis import (
    load_scenarios_from_dir as _load_scenarios_from_dir,
)
from secagent.generator.synthesis import (
    synthesize_fuzz_scenarios as _synthesize_fuzz_scenarios,
)
from secagent.generator.synthesis import (
    synthesize_per_tool_scenarios as _synthesize_per_tool_scenarios,
)
from secagent.generator.synthesis import (
    synthesize_whole_suite_scenarios as _synthesize_whole_suite_scenarios,
)
from secagent.generator.synthesis import (
    write_generated_scenarios as _write_generated_scenarios,
)
from secagent.harness.executor import (
    execute_scenarios_with_telemetry as _exec_scenarios_impl,
)
from secagent.harness.executor import (
    extract_interrupt_events as _extract_interrupt_events,
)
from secagent.harness.executor import (
    infer_task_context as _infer_task_context,
)
from secagent.harness.executor import (
    is_runnable_target as _is_runnable_target,
)
from secagent.harness.executor import (
    load_external_traces as _load_external_traces,
)
from secagent.harness.executor import (
    record_output_interrupts as _record_output_interrupts,
)
from secagent.reporting.markdown import (
    COMMENT_MARKER,
    MAX_GITHUB_COMMENT_LENGTH,
)
from secagent.reporting.markdown import (
    escape_cell as _escape_cell,
)
from secagent.reporting.markdown import (
    format_markdown_report as _format_markdown_report,
)
from secagent.ui import (
    render_discovered_tools,
    render_scan_header,
    render_summary_card,
    render_violations,
    render_welcome_banner,
)

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
) -> list[Any]:
    """Introspect tools from ``agent_entrypoint`` with benchmark fallback when omitted."""
    _, _, discovered = _resolve_agent_target(
        generator,
        agent_entrypoint,
        overrides,
        include_schema=include_schema,
    )
    return discovered


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
    return _exec_scenarios_impl(
        target,
        mod,
        target_tools,
        scenario_dicts,
        policy_overrides,
        console=console,
        timeout_s=timeout_s,
        quiet=quiet,
        strict_sandbox=strict_sandbox,
        mock_unclassified=mock_unclassified,
        mock_mode=mock_mode,
    )


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
    from secagent.generator.cache import ScenarioCache

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

    console.print(
        f"[bold green]Prepared {len(scenario_dicts)} scenarios across {len(discovered_tools)} tools.[/bold green]"
    )
    console.print(f"Saved to: [cyan]{summary_file}[/cyan]")


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
        typer.Option("--policies", "-p", help="Path to security rules YAML"),
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
            help="Optional path to pre-recorded SecAgent or OTLP JSON trace file or directory.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Per-scenario execution timeout in seconds."),
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live instead of failing closed.",
        ),
    ] = False,
    isolate: Annotated[
        bool,
        typer.Option(
            "--isolate",
            help="Execute agent scenarios in an isolated child subprocess with sanitized env and hard timeout kill.",
        ),
    ] = False,
    block_network: Annotated[
        bool,
        typer.Option(
            "--block-network",
            help="Block outbound Python sockets inside isolated subprocess scans (requires --isolate).",
        ),
    ] = False,
    pass_env: Annotated[
        list[str] | None,
        typer.Option(
            "--pass-env",
            help="Environment variable name(s) allowlisted into isolated subprocesses (repeatable).",
        ),
    ] = None,
    output_report: Annotated[
        Path,
        typer.Option("--output-report", "-o", help="Output path for JSON report"),
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path,
        typer.Option("--output-markdown", "-m", help="Output path for markdown summary"),
    ] = Path("comment.md"),
    output_sarif: Annotated[
        Path | None,
        typer.Option("--output-sarif", help="Optional output path for SARIF 2.1.0 report"),
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
        if (block_network or pass_env) and not isolate:
            err_console.print("[red]--block-network and --pass-env require --isolate.[/red]")
            raise typer.Exit(code=1)

        if scenarios is not None and not scenarios.exists():
            err_console.print(
                f"[red]Custom scenarios directory not found: {scenarios}. "
                "Provide an existing directory with scenario files.[/red]"
            )
            raise typer.Exit(code=1)

        generator = ScenarioGenerator()
        overrides = dict(engine.ruleset.tool_tier_overrides)
        target: Any = None
        mod: Any = None
        isolated_runnable = False
        source_fp: str | None = None

        if isolate and agent_entrypoint.strip():
            from secagent.harness.isolated import introspect_isolated

            try:
                target_tools, isolated_runnable, source_fp = introspect_isolated(
                    agent_entrypoint,
                    overrides,
                    timeout_s=timeout,
                    block_network=block_network,
                    pass_env=pass_env or (),
                )
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                err_console.print(
                    f"[red]Error loading agent entrypoint '{escape_markup(agent_entrypoint)}': "
                    f"{escape_markup(str(exc))}[/red]"
                )
                raise typer.Exit(code=1) from exc
            if not target_tools:
                err_console.print(
                    f"[red]No tools discovered for agent entrypoint "
                    f"'{escape_markup(agent_entrypoint)}'.[/red]"
                )
                raise typer.Exit(code=1)
        else:
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
                source_fingerprint=(
                    source_fp if source_fp is not None else _fingerprint_agent_source(mod)
                ),
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
            if isolate and agent_entrypoint.strip():
                if isolated_runnable:
                    from secagent.harness.isolated import run_isolated_scenarios

                    traces = run_isolated_scenarios(
                        agent_entrypoint,
                        scenario_dicts,
                        overrides,
                        timeout_s=timeout,
                        strict_sandbox=not allow_live_tools,
                        mock_unclassified=not allow_live_tools,
                        block_network=block_network,
                        pass_env=pass_env or (),
                    )
                else:
                    traces = []
            else:
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
            err_console.print(f"[red]Sandbox error: {escape_markup(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc
        except (RuntimeError, json.JSONDecodeError) as exc:
            err_console.print(f"[red]Isolated execution failed: {escape_markup(str(exc))}[/red]")
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
        str, typer.Option("--agent", "-a", help="Import path of target agent")
    ] = "",
    policies: Annotated[
        Path, typer.Option("--policies", "-p", help="Path to security rules YAML")
    ] = Path("policies/security_rules.yaml"),
    scenarios: Annotated[
        Path | None,
        typer.Option("--scenarios", "-s", help="Optional path to custom scenarios directory."),
    ] = None,
    trace: Annotated[
        Path | None,
        typer.Option(
            "--trace", "-t", help="Optional path to pre-recorded trace JSON or directory."
        ),
    ] = None,
    timeout: Annotated[
        float, typer.Option("--timeout", min=0.1, help="Per-scenario execution timeout in seconds.")
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live instead of failing closed.",
        ),
    ] = False,
    isolate: Annotated[
        bool,
        typer.Option(
            "--isolate",
            help="Execute agent scenarios in an isolated child subprocess with sanitized env and hard timeout kill.",
        ),
    ] = False,
    block_network: Annotated[
        bool,
        typer.Option(
            "--block-network",
            help="Block outbound Python sockets inside isolated subprocess scans (requires --isolate).",
        ),
    ] = False,
    pass_env: Annotated[
        list[str] | None,
        typer.Option(
            "--pass-env",
            help="Environment variable name(s) allowlisted into isolated subprocesses (repeatable).",
        ),
    ] = None,
    output_report: Annotated[
        Path, typer.Option("--output-report", "-o", help="Output path for JSON report")
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path, typer.Option("--output-markdown", "-m", help="Output path for markdown summary")
    ] = Path("comment.md"),
    output_sarif: Annotated[
        Path | None,
        typer.Option("--output-sarif", help="Optional output path for SARIF 2.1.0 report"),
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
        bool, typer.Option("--json", help="Emit raw JSON report to stdout and suppress Rich UI")
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
        isolate=isolate,
        block_network=block_network,
        pass_env=pass_env,
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
        Path, typer.Option("--policies", "-p", help="Path to security rules YAML")
    ] = Path("policies/security_rules.yaml"),
    iterations: Annotated[
        int,
        typer.Option("--iterations", "-n", min=1, help="Number of adversarial mutation iterations"),
    ] = 10,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-o", help="Directory to save discovered fuzz scenarios"),
    ] = Path("scenarios/generated/"),
    execute: Annotated[
        bool,
        typer.Option(
            "--execute", help="Execute mutated scenarios against the target agent and evaluate"
        ),
    ] = False,
    output_report: Annotated[
        Path,
        typer.Option("--output-report", help="Output path for JSON audit report with --execute"),
    ] = Path("report.json"),
    output_markdown: Annotated[
        Path,
        typer.Option("--output-markdown", help="Output path for markdown summary with --execute"),
    ] = Path("comment.md"),
    output_sarif: Annotated[
        Path | None,
        typer.Option("--output-sarif", help="Optional output path for SARIF 2.1.0 with --execute"),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", min=0.1, help="Per-scenario execution timeout in seconds"),
    ] = 30.0,
    allow_live_tools: Annotated[
        bool,
        typer.Option(
            "--allow-live-tools",
            help="Allow unclassified or unpatched tools to execute live with --execute.",
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
    from secagent.harness.runner import SandboxError

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

    tp_cfg = engine.ruleset.tool_poisoning
    tool_def_violations = (
        []
        if tp_cfg is not None and not tp_cfg.enabled
        else scan_tool_definitions(
            target_tools,
            extra_patterns=tp_cfg.extra_patterns if tp_cfg is not None else None,
        )
    )
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
        Path, typer.Option("--report", "-r", help="Path to JSON audit report")
    ] = Path("report.json"),
    trace: Annotated[
        Path | None,
        typer.Option("--trace", "-t", help="Optional path to execution trace JSON file"),
    ] = None,
    baseline: Annotated[
        Path | None,
        typer.Option(
            "--baseline", "-b", help="Optional path to baseline report JSON for regression diffing"
        ),
    ] = None,
    port: Annotated[
        int,
        typer.Option(
            "--port", "-p", min=1, max=65535, help="Port for the Streamlit dashboard server"
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


__all__ = [
    "COMMENT_MARKER",
    "MAX_GITHUB_COMMENT_LENGTH",
    "_escape_cell",
    "_execute_scenarios_with_telemetry",
    "_extract_interrupt_events",
    "_format_markdown_report",
    "_infer_task_context",
    "_load_entrypoint",
    "_load_external_traces",
    "_load_scenarios_from_dir",
    "_record_output_interrupts",
    "_resolve_agent_target",
    "_resolve_policy_overrides",
    "_resolve_target_tools",
    "_synthesize_fuzz_scenarios",
    "_synthesize_per_tool_scenarios",
    "_synthesize_whole_suite_scenarios",
    "_write_generated_scenarios",
    "app",
]


if __name__ == "__main__":
    app()
