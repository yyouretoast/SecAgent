"""Generate publication-grade IEEE/USENIX systems architecture diagrams for SecAgent.

Outputs crisp, high-resolution SVG and PNG diagrams adhering to clean systems engineering style:
- Crisp white/light-slate palette
- Formal C4 container boundaries and typed interface connectors
- Distinct color-coded severity/role semantics
"""

from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch, BoxStyle

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

# Styling constants (IEEE/USENIX Systems Palette)
FONT_FAMILY = "sans-serif"
COLOR_BG = "#ffffff"
COLOR_TEXT_PRIMARY = "#0f172a"
COLOR_TEXT_MUTED = "#475569"
COLOR_BORDER = "#cbd5e1"

# Functional Accents
ACCENT_BLUE = "#1d4ed8"  # PR & CI Actions
ACCENT_BLUE_BG = "#eff6ff"
ACCENT_EMERALD = "#047857"  # Verified Telemetry & Contract
ACCENT_EMERALD_BG = "#f0fdf4"
ACCENT_PURPLE = "#6d28d9"  # Adversarial Fuzzing
ACCENT_PURPLE_BG = "#faf5ff"
ACCENT_AMBER = "#b45309"  # Policy Invariants
ACCENT_AMBER_BG = "#fffbeb"
ACCENT_RED = "#be123c"  # Block PR Gate
ACCENT_RED_BG = "#fff1f2"


def draw_card(
    ax,
    x,
    y,
    w,
    h,
    title,
    subtitle,
    details,
    bg_color,
    border_color,
    title_color=COLOR_TEXT_PRIMARY,
    badge=None,
):
    """Draw a publication-grade C4 card with structured typography."""
    box = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0,rounding_size=0.15",
        facecolor=bg_color,
        edgecolor=border_color,
        linewidth=1.2,
        zorder=2,
    )
    ax.add_patch(box)

    # Title text
    ax.text(
        x + 0.15, y + h - 0.22, title, fontsize=10.5, fontweight="bold", color=title_color, zorder=3
    )

    # Badge (if any)
    if badge:
        b_w = len(badge) * 0.11 + 0.2
        badge_box = FancyBboxPatch(
            (x + w - b_w - 0.15, y + h - 0.32),
            b_w,
            0.22,
            boxstyle="round,pad=0,rounding_size=0.08",
            facecolor="#ffffff",
            edgecolor=border_color,
            linewidth=0.8,
            zorder=3,
        )
        ax.add_patch(badge_box)
        ax.text(
            x + w - b_w / 2 - 0.15,
            y + h - 0.23,
            badge,
            fontsize=7.5,
            fontweight="bold",
            color=border_color,
            ha="center",
            zorder=4,
        )

    # Subtitle / Stereotype
    if subtitle:
        ax.text(
            x + 0.15,
            y + h - 0.42,
            subtitle,
            fontsize=8.2,
            style="italic",
            color=COLOR_TEXT_MUTED,
            zorder=3,
        )

    # Details
    if details:
        dy = 0.65
        for line in details:
            ax.text(x + 0.15, y + h - dy, line, fontsize=8.0, color=COLOR_TEXT_PRIMARY, zorder=3)
            dy += 0.21


def draw_container(ax, x, y, w, h, label, stereotype, border_color="#94a3b8", bg_color="#f8fafc"):
    """Draw an outer subsystem boundary container."""
    box = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0,rounding_size=0.2",
        facecolor=bg_color,
        edgecolor=border_color,
        linestyle="--",
        linewidth=1.4,
        zorder=1,
    )
    ax.add_patch(box)
    header = f"{label}  [{stereotype}]" if stereotype else label
    ax.text(
        x + 0.25, y + h - 0.25, header, fontsize=10.0, fontweight="bold", color="#334155", zorder=3
    )


def draw_arrow(ax, x1, y1, x2, y2, label=None, color="#475569", label_pos=(0.5, 0.05), style="-|>"):
    """Draw a clean orthogonal or direct arrow with label."""
    ax.annotate(
        "",
        xy=(x2, y2),
        xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle=style,
            color=color,
            lw=1.4,
            shrinkA=2,
            shrinkB=2,
            mutation_scale=12,
        ),
        zorder=4,
    )
    if label:
        lx = x1 + (x2 - x1) * label_pos[0] + label_pos[1]
        ly = y1 + (y2 - y1) * label_pos[0] + 0.08
        ax.text(
            lx,
            ly,
            label,
            fontsize=7.8,
            fontweight="bold",
            color=color,
            ha="center",
            va="bottom",
            zorder=5,
            bbox=dict(boxstyle="square,pad=0.15", facecolor="#ffffff", edgecolor="none", alpha=0.9),
        )


def generate_architecture_diagram():
    fig, ax = plt.subplots(figsize=(14.5, 9.5), dpi=300)
    ax.set_xlim(0, 14.5)
    ax.set_ylim(0, 9.5)
    ax.axis("off")
    fig.patch.set_facecolor(COLOR_BG)

    # 1. Header Banner
    ax.text(
        0.5,
        9.15,
        "SecAgent: System Architecture & Subsystem Decomposition",
        fontsize=15,
        fontweight="bold",
        color=COLOR_TEXT_PRIMARY,
    )
    ax.text(
        0.5,
        8.85,
        "Universal CI/CD Security Scanner & GitHub Action for Autonomous AI Agent Systems",
        fontsize=9.5,
        color=COLOR_TEXT_MUTED,
    )
    ax.plot([0.5, 14.0], [8.65, 8.65], color=COLOR_BORDER, lw=1.0)

    # 2. Top-Left Trigger: Developer PR
    draw_card(
        ax,
        0.5,
        6.7,
        2.5,
        1.6,
        title="Developer PR",
        subtitle="«Actor: GitHub Event»",
        details=[
            "• Modifies agent prompts",
            "• Adds / alters tool schemas",
            "• Upgrades LLM models",
        ],
        bg_color=ACCENT_BLUE_BG,
        border_color=ACCENT_BLUE,
        badge="Trigger",
    )

    # 3. Subsystem 1: Target Autonomous Agents
    draw_container(
        ax,
        3.4,
        6.4,
        10.6,
        2.0,
        "Subsystem 1: Multi-Domain Target Agents",
        "SUT / examples/",
        border_color="#3b82f6",
    )

    draw_card(
        ax,
        3.6,
        6.6,
        3.2,
        1.4,
        title="DevOps Agent",
        subtitle="examples/devops_agent/",
        details=[
            "• restart_server()",
            "• tier: @permission('admin')",
            "• Critical infra protection",
        ],
        bg_color="#ffffff",
        border_color="#3b82f6",
    )

    draw_card(
        ax,
        7.1,
        6.6,
        3.2,
        1.4,
        title="Finance Agent",
        subtitle="examples/finance_agent/",
        details=["• execute_trade()", "• tier: @permission('pay')", "• Predecessor approval gate"],
        bg_color="#ffffff",
        border_color="#3b82f6",
    )

    draw_card(
        ax,
        10.6,
        6.6,
        3.2,
        1.4,
        title="Support Agent",
        subtitle="examples/support_agent/",
        details=["• query_db() [read]", "• issue_refund() [pay]", "• Scope allowlist projection"],
        bg_color="#ffffff",
        border_color="#3b82f6",
    )

    # Arrow from PR to SUT
    draw_arrow(ax, 3.0, 7.5, 3.4, 7.5, label="git push / PR", color=ACCENT_BLUE)

    # 4. Subsystem 2: Telemetry Pipeline
    draw_container(
        ax,
        0.5,
        4.4,
        13.5,
        1.6,
        "Subsystem 2: Telemetry & Instrumentation Pipeline",
        "src/secagent/telemetry/",
        border_color=ACCENT_EMERALD,
    )

    draw_card(
        ax,
        0.8,
        4.6,
        3.8,
        1.1,
        title="OpenTelemetry GenAI Hooks",
        subtitle="Span Capture Layer",
        details=[
            "• agent.run (context & role)",
            "• tool.call (params & tier)",
            "• gate.hitl (approval booleans)",
        ],
        bg_color="#ffffff",
        border_color=ACCENT_EMERALD,
    )

    draw_card(
        ax,
        5.0,
        4.6,
        3.8,
        1.1,
        title="In-Line PII & Secret Redactor",
        subtitle="Deterministic Sanitizer",
        details=[
            "• SSN, credit card scrubbers",
            "• Token & secret redaction",
            "• Zero leakage to CI logs",
        ],
        bg_color="#ffffff",
        border_color=ACCENT_EMERALD,
    )

    draw_card(
        ax,
        9.2,
        4.6,
        4.5,
        1.1,
        title="Execution Trace JSON",
        subtitle="schemas/trace_event.schema.json",
        details=[
            "• Standardized span hierarchy",
            "• Framework agnostic format",
            "• Ingested by audit engines",
        ],
        bg_color=ACCENT_EMERALD_BG,
        border_color=ACCENT_EMERALD,
        badge="Frozen Contract",
    )

    # Arrows between Subsystems 1 & 2
    draw_arrow(ax, 8.7, 6.4, 8.7, 6.0, label="Runtime Spans", color=ACCENT_EMERALD)
    draw_arrow(ax, 4.6, 5.15, 5.0, 5.15, label="Raw Spans", color=ACCENT_EMERALD)
    draw_arrow(ax, 8.8, 5.15, 9.2, 5.15, label="Sanitized", color=ACCENT_EMERALD)

    # 5. Middle Split: Subsystem 3 (Fuzzer) & Subsystem 4 (Policy Invariants)
    # Left: Fuzzer
    draw_container(
        ax,
        0.5,
        2.3,
        6.3,
        1.8,
        "Subsystem 3: Dynamic Adversarial Fuzzer",
        "src/secagent/fuzzer/",
        border_color=ACCENT_PURPLE,
    )
    draw_card(
        ax,
        0.8,
        2.5,
        5.7,
        1.3,
        title="Combinatorial Mutation Engine (secagent fuzz)",
        subtitle="Dynamic Attack Vector Generation",
        details=[
            "• Automated prompt mutations & role jailbreaks",
            "• SQL / shell metacharacter injection payloads",
            "• Generates adversarial edge-case scenarios on the fly",
            "• Tests agent resilience without static scenario authoring",
        ],
        bg_color=ACCENT_PURPLE_BG,
        border_color=ACCENT_PURPLE,
        badge="Fuzzer",
    )

    # Right: Policy Invariant Verifier
    draw_container(
        ax,
        7.3,
        2.3,
        6.7,
        1.8,
        "Subsystem 4: Invariant Security Engine",
        "src/secagent/engine/",
        border_color=ACCENT_AMBER,
    )
    draw_card(
        ax,
        7.6,
        2.5,
        6.1,
        1.3,
        title="Deterministic OWASP Invariant Verifier",
        subtitle="policies/security_rules.yaml",
        details=[
            "• ASI03: Mandatory HITL predecessor gate on pay / admin",
            "• ASI03: Context boundary enforcement (read-only locks)",
            "• ASI02: Tool parameter SQLi & shell regex blocklists",
            "• ASI08: Circuit breaker (max steps <= 10, duplicate <= 2)",
        ],
        bg_color=ACCENT_AMBER_BG,
        border_color=ACCENT_AMBER,
        badge="OWASP Top 10",
    )

    # Connectors to Fuzzer and Engine
    draw_arrow(ax, 11.45, 4.4, 11.45, 4.1, label="Trace Input", color=ACCENT_AMBER)
    draw_arrow(ax, 3.65, 4.1, 3.65, 4.4, label="Mutated Prompts", color=ACCENT_PURPLE, style="<|-")

    # 6. Bottom: Subsystem 5 (GitHub Action & PR Gate)
    draw_container(
        ax,
        0.5,
        0.3,
        13.5,
        1.7,
        "Subsystem 5: Turnkey GitHub Action & CI/CD Security Gate",
        "action.yml & src/secagent/cli.py",
        border_color=ACCENT_BLUE,
    )

    draw_card(
        ax,
        0.8,
        0.5,
        4.0,
        1.2,
        title="Composite GitHub Action",
        subtitle="action.yml",
        details=[
            "• Runs in any GitHub workflow",
            "• Zero setup: uses: ./action.yml",
            "• Evaluates all tested invariants",
        ],
        bg_color="#ffffff",
        border_color=ACCENT_BLUE,
    )

    draw_card(
        ax,
        5.2,
        0.5,
        4.2,
        1.2,
        title="CI Audit Gate & PR Bot",
        subtitle="Exit Code Decisions",
        details=[
            "• Exit 0: PASS (Allow PR Merge)",
            "• Exit 1: FAIL (BLOCK PR Merge)",
            "• Posts Markdown failure table (comment.md)",
        ],
        bg_color=ACCENT_RED_BG,
        border_color=ACCENT_RED,
        badge="PR Gate",
    )

    draw_card(
        ax,
        9.8,
        0.5,
        3.9,
        1.2,
        title="SecAgent CLI & Web Inspector",
        subtitle="secagent scan | fuzz | serve",
        details=[
            "• Rich terminal reporting",
            "• Streamlit audit visualizer",
            "• Local developer reproduction",
        ],
        bg_color="#ffffff",
        border_color=ACCENT_BLUE,
    )

    # Arrows to Bottom Gate
    draw_arrow(ax, 3.65, 2.3, 3.65, 2.0, color=ACCENT_PURPLE)
    draw_arrow(ax, 10.65, 2.3, 10.65, 2.0, label="Invariant Results", color=ACCENT_AMBER)
    draw_arrow(ax, 4.8, 1.1, 5.2, 1.1, color=ACCENT_BLUE)
    draw_arrow(ax, 9.4, 1.1, 9.8, 1.1, color=ACCENT_BLUE)

    plt.tight_layout()
    output_svg = DOCS / "secagent_architecture.svg"
    output_png = DOCS / "secagent_architecture.png"
    plt.savefig(output_svg, format="svg", bbox_inches="tight")
    plt.savefig(output_png, format="png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {output_svg} and {output_png}")


def generate_execution_flow_diagram():
    fig, ax = plt.subplots(figsize=(14.5, 7.5), dpi=300)
    ax.set_xlim(0, 14.5)
    ax.set_ylim(0, 7.5)
    ax.axis("off")
    fig.patch.set_facecolor(COLOR_BG)

    # 1. Header Banner
    ax.text(
        0.5,
        7.15,
        "SecAgent: CI/CD Security Audit Execution Lifecycle",
        fontsize=15,
        fontweight="bold",
        color=COLOR_TEXT_PRIMARY,
    )
    ax.text(
        0.5,
        6.85,
        "Chronological Pull Request Inspection, Adversarial Fuzzing, and Invariant Gate Verification",
        fontsize=9.5,
        color=COLOR_TEXT_MUTED,
    )
    ax.plot([0.5, 14.0], [6.65, 6.65], color=COLOR_BORDER, lw=1.0)

    # Lifeline Column Coordinates
    cols = {
        "dev": (1.4, "Developer / PR", "#334155", "#f1f5f9"),
        "ci": (4.1, "GitHub Action\n(action.yml)", ACCENT_BLUE, ACCENT_BLUE_BG),
        "fuzz": (6.8, "Adversarial Fuzzer\n(secagent fuzz)", ACCENT_PURPLE, ACCENT_PURPLE_BG),
        "sut": (9.5, "Target Agent\n(SUT / examples/)", ACCENT_EMERALD, ACCENT_EMERALD_BG),
        "verifier": (12.2, "Invariant Engine\n(policies.yaml)", ACCENT_AMBER, ACCENT_AMBER_BG),
    }

    # Draw Lifeline Headers and Dashed Lines
    for key, (cx, title, border, bg) in cols.items():
        box = FancyBboxPatch(
            (cx - 1.1, 5.8),
            2.2,
            0.7,
            boxstyle="round,pad=0,rounding_size=0.12",
            facecolor=bg,
            edgecolor=border,
            linewidth=1.2,
            zorder=2,
        )
        ax.add_patch(box)
        ax.text(
            cx,
            6.15,
            title,
            fontsize=8.5,
            fontweight="bold",
            color=border,
            ha="center",
            va="center",
            zorder=3,
        )
        # Vertical lifeline
        ax.plot([cx, cx], [0.6, 5.8], color="#cbd5e1", linestyle="--", lw=1.2, zorder=1)

    # Sequence Interactions
    def draw_seq_msg(y, c_from, c_to, label, is_return=False, color="#1e293b"):
        x1 = cols[c_from][0]
        x2 = cols[c_to][0]
        ls = "--" if is_return else "-"
        style = "<|-" if is_return else "-|>"
        ax.annotate(
            "",
            xy=(x2, y),
            xytext=(x1, y),
            arrowprops=dict(
                arrowstyle=style,
                linestyle=ls,
                color=color,
                lw=1.3,
                shrinkA=0,
                shrinkB=0,
                mutation_scale=10,
            ),
            zorder=3,
        )
        mid_x = (x1 + x2) / 2
        ax.text(
            mid_x,
            y + 0.1,
            label,
            fontsize=8.2,
            fontweight="bold",
            color=color,
            ha="center",
            va="bottom",
            zorder=4,
            bbox=dict(boxstyle="square,pad=0.1", facecolor="#ffffff", edgecolor="none", alpha=0.9),
        )

    # 1. Developer opens PR
    draw_seq_msg(5.2, "dev", "ci", "1. Open Pull Request / Push Commit", color=ACCENT_BLUE)

    # 2. CI triggers SecAgent
    draw_seq_msg(4.6, "ci", "fuzz", "2. Invoke secagent scan / fuzz", color=ACCENT_PURPLE)

    # 3. Fuzzer mutates prompts and dispatches to agent
    draw_seq_msg(
        4.0,
        "fuzz",
        "sut",
        "3. Mutate Prompts & Inject Payloads (SQLi, Bypass)",
        color=ACCENT_PURPLE,
    )

    # SUT activation box
    sut_x = cols["sut"][0]
    ax.add_patch(
        patches.Rectangle(
            (sut_x - 0.1, 2.7),
            0.2,
            1.3,
            facecolor="#a7f3d0",
            edgecolor=ACCENT_EMERALD,
            lw=1.0,
            zorder=2,
        )
    )
    ax.text(
        sut_x + 0.25,
        3.35,
        "Agent Execution Loop\n• Dispatches Tools (@permission)\n• Evaluates HITL Approval Gate\n• In-line PII Scrubbing",
        fontsize=7.8,
        color="#065f46",
        va="center",
        zorder=3,
    )

    # 4. Agent emits traces
    draw_seq_msg(
        2.7,
        "sut",
        "verifier",
        "4. Emit OpenTelemetry Spans (trace_event.schema.json)",
        color=ACCENT_EMERALD,
    )

    # Verifier activation box
    ver_x = cols["verifier"][0]
    ax.add_patch(
        patches.Rectangle(
            (ver_x - 0.1, 1.8),
            0.2,
            0.9,
            facecolor="#fde68a",
            edgecolor=ACCENT_AMBER,
            lw=1.0,
            zorder=2,
        )
    )
    ax.text(
        ver_x + 0.25,
        2.25,
        "Invariant Verification\n• Check Predecessor Gates\n• Check Regex Injection Blocklist\n• Check Step Circuit Breaker",
        fontsize=7.8,
        color="#78350f",
        va="center",
        zorder=3,
    )

    # 5. Return verdict
    draw_seq_msg(
        1.8,
        "verifier",
        "ci",
        "5. Report Verdict (PASS: Exit 0 | FAIL: Exit 1)",
        is_return=True,
        color=ACCENT_AMBER,
    )

    # 6. Block PR & Comment
    draw_seq_msg(
        1.1,
        "ci",
        "dev",
        "6. Block PR Merge & Post Security Triage Markdown",
        is_return=True,
        color=ACCENT_RED,
    )

    plt.tight_layout()
    output_svg = DOCS / "secagent_execution_flow.svg"
    output_png = DOCS / "secagent_execution_flow.png"
    plt.savefig(output_svg, format="svg", bbox_inches="tight")
    plt.savefig(output_png, format="png", dpi=300, bbox_inches="tight")
    plt.close()
    print(f"Generated: {output_svg} and {output_png}")


if __name__ == "__main__":
    DOCS.mkdir(parents=True, exist_ok=True)
    generate_architecture_diagram()
    generate_execution_flow_diagram()
