"""Rich terminal UI components for SecAgent CLI."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.tree import Tree

_TIER_COLORS = {
    "pay": "bold red",
    "admin": "bold magenta",
    "net": "bold yellow",
    "write": "cyan",
    "read": "green",
    "pure": "dim",
}

_SEVERITY_BADGE = {
    "CRITICAL": "[bold white on red] CRIT [/]",
    "HIGH": "[bold black on yellow] HIGH [/]",
    "MEDIUM": "[bold black on cyan] MED  [/]",
    "LOW": "[bold white on blue] LOW  [/]",
}

_WORDMARK = """[bold cyan]  █▀▀ █▀▀ █▀▀ ▄▀█ █▀▀ █▀▀ █▄░█ ▀█▀[/]
[bold blue]  ▄▄█ ██▄ █▄▄ █▀█ █▄█ ██▄ █░▀█ ░█░[/]"""


def _workspace_status() -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    policy_path = Path("policies/security_rules.yaml")
    if policy_path.is_file():
        rows.append(("Policies", f"[cyan]{policy_path}[/] [dim](detected)[/]"))
    else:
        rows.append(("Policies", "[dim]packaged defaults[/]"))

    report_path = Path("report.json")
    if report_path.is_file():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            status = str(data.get("status") or "UNKNOWN")
            violations = int(data.get("violations_detected") or len(data.get("violations") or []))
            color = "green" if status == "PASS" else ("red" if status == "FAIL" else "yellow")
            rows.append(
                (
                    "Last Scan",
                    f"[cyan]{report_path}[/] ([{color}]{status}[/] · {violations} violations)",
                )
            )
        except (OSError, ValueError, TypeError):
            pass
    return rows


def render_welcome_banner(console: Console, version: str) -> None:
    """Render the bare-command welcome banner with auto-detected workspace status."""
    console.print()
    console.print(f"{_WORDMARK}   [dim]v{version} · Deterministic AI Agent Security Gate[/]")
    console.print()

    status_table = Table.grid(padding=(0, 2))
    status_table.add_column(style="dim", justify="right")
    status_table.add_column()
    for label, value in _workspace_status():
        status_table.add_row(label, value)

    status_table.add_row("", "")
    status_table.add_row("[bold]scan[/]", "Run deterministic OWASP security gate")
    status_table.add_row("[bold]generate[/]", "Synthesize & cache adversarial test scenarios")
    status_table.add_row("[bold]fuzz[/]", "Mutate tool inputs and test policy boundaries")
    status_table.add_row("[bold]serve[/]", "Open interactive trace waterfall dashboard")

    console.print(
        Panel(
            status_table,
            title=f"[bold cyan]◆ SecAgent v{version}[/]",
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print(
        "  [dim]Try:[/] [cyan]secagent scan --agent examples.finance_agent.agent:app[/]  "
        "[dim]·[/]  [cyan]secagent --help[/]\n"
    )


def render_scan_header(
    console: Console,
    *,
    version: str,
    target: str,
    policies_path: str,
    rule_count: int | None = None,
    mode: str = "dry-run sandbox",
) -> None:
    """Render a compact rounded header panel at the start of a scan."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", width=10)
    grid.add_column()
    grid.add_row("Target", f"[bold]{escape(target or 'baseline_smoke')}[/]")
    policy_text = f"[cyan]{escape(policies_path)}[/]"
    if rule_count is not None:
        policy_text += f" [dim]({rule_count} rules)[/]"
    grid.add_row("Policies", policy_text)
    grid.add_row("Mode", f"[dim]{escape(mode)}[/]")
    console.print(
        Panel(
            grid,
            title=f"[bold cyan]SecAgent v{version}[/]",
            border_style="dim",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def render_discovered_tools(
    console: Console,
    tools: Sequence[Any],
    dry_run_tiers: frozenset[str] = frozenset({"pay", "admin", "write", "net"}),
) -> None:
    """Render a compact tree of discovered tools, permission tiers, and sandbox mode."""
    if not tools:
        return
    tree = Tree(f"[bold]Discovered Tools[/] [dim]({len(tools)})[/]")
    for tool in tools:
        name = str(getattr(tool, "name", "unknown"))
        tier = str(getattr(tool, "permission_tier", "read"))
        tier_style = _TIER_COLORS.get(tier, "white")
        sandbox_tag = "[dim cyan]MOCKED[/]" if tier in dry_run_tiers else "[dim green]LIVE[/]"
        tree.add(f"{escape(name):<22} [{tier_style}]{escape(tier):<6}[/] {sandbox_tag}")
    console.print(tree)


def render_violations(
    console: Console,
    violations: Sequence[dict[str, Any]],
    *,
    max_display: int = 5,
) -> None:
    """Render Semgrep/Ruff-style diagnostic cards for policy violations."""
    if not violations:
        return
    console.print()
    for v in violations[:max_display]:
        severity = str(v.get("severity") or "HIGH")
        badge = _SEVERITY_BADGE.get(severity, f"[bold]{escape(severity)}[/]")
        rule_id = escape(str(v.get("rule_id") or "UNKNOWN"))
        rule_name = escape(str(v.get("rule_name") or ""))
        owasp = escape(str(v.get("owasp_category") or "UNKNOWN"))
        tool = escape(str(v.get("offending_tool_name") or "unknown"))
        span_id = escape(str(v.get("offending_span_id") or "unknown"))
        step = escape(str(v.get("offending_step_index", "?")))
        remediation = escape(str(v.get("remediation") or ""))

        tree = Tree(f"{badge} [bold]{rule_id}[/] [dim]· {rule_name}[/]")
        tree.add(f"[dim]OWASP   [/] {owasp}")
        tree.add(f"[dim]Span    [/] [cyan]{tool}[/] ([dim]{span_id}[/]) · step #{step}")
        if remediation:
            tree.add(f"[dim]Fix     [/] [green]{remediation}[/]")
        console.print(tree)

    if len(violations) > max_display:
        console.print(
            f"\n  [dim]... showing {max_display} of {len(violations)} violations "
            "(see report.json for full details).[/]"
        )


def render_summary_card(
    console: Console,
    *,
    status: str,
    scenarios: int,
    spans: int,
    violations: int,
    report_path: Path,
    markdown_path: Path,
    sarif_path: Path | None = None,
    elapsed_ms: float | None = None,
) -> None:
    """Render the final verdict summary card with next-step instructions."""
    border = "green" if status == "PASS" else ("red" if status == "FAIL" else "yellow")
    verdict_style = f"bold {border}"
    artifacts = f"{report_path} · {markdown_path}"
    if sarif_path is not None:
        artifacts += f" · {sarif_path}"

    timing = f" · {elapsed_ms:.1f} ms" if elapsed_ms is not None else ""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", width=10)
    grid.add_column()
    grid.add_row(
        "Verdict",
        f"[{verdict_style}]{escape(status)}[/]  [dim]Scenarios: {scenarios} · Spans: {spans} · Violations: {violations}{timing}[/]",
    )
    grid.add_row("Artifacts", f"[cyan]{escape(artifacts)}[/]")
    grid.add_row("Next", f"[cyan]secagent serve --report {escape(str(report_path))}[/]")

    console.print()
    console.print(
        Panel(
            grid,
            title="[bold]Summary[/]",
            border_style=border,
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )


def make_progress(console: Console, *, quiet: bool = False) -> Progress:
    """Create a Rich progress bar disabled automatically in CI/pipes/quiet mode."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
        disable=quiet or not console.is_terminal,
    )
