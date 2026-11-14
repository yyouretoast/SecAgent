"""Tests for US-5.4 (`secagent generate` and `secagent fuzz`)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from secagent.cli import app


def test_us5_4_generate_creates_six_scenario_manifests_for_devops_agent(tmp_path: Path):
    """Verify US-5.4 Gherkin: `--agent examples.devops_agent.agent --per-tool 3` -> 6 manifests."""
    runner = CliRunner()
    out_dir = tmp_path / "scenarios" / "generated"

    result = runner.invoke(
        app,
        [
            "generate",
            "--agent",
            "examples.devops_agent.agent",
            "--per-tool",
            "3",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert result.exit_code == 0

    manifest_files = sorted(out_dir.glob("GEN-*.json"))
    assert len(manifest_files) == 6

    summary = json.loads((out_dir / "generated_scenarios.json").read_text(encoding="utf-8"))
    assert len(summary) == 6
    by_tool: dict[str, int] = {}
    categories_by_tool: dict[str, set[str]] = {}
    for item in summary:
        tool_name = item["target_tool"]
        by_tool[tool_name] = by_tool.get(tool_name, 0) + 1
        categories_by_tool.setdefault(tool_name, set()).add(item["owasp_category"])

    assert by_tool == {"check_service_health": 3, "restart_server": 3}
    assert len(categories_by_tool["restart_server"]) == 3


def test_us5_4_fuzz_synthesizes_schema_directed_mutations(tmp_path: Path):
    """Verify `secagent fuzz` produces `iterations` schema-directed mutated scenarios."""
    runner = CliRunner()
    out_dir = tmp_path / "fuzz_out"

    result = runner.invoke(
        app,
        [
            "fuzz",
            "--agent",
            "examples.support_agent.agent",
            "--iterations",
            "12",
            "--output-dir",
            str(out_dir),
        ],
    )
    assert result.exit_code == 0

    manifests = sorted(out_dir.glob("FUZZ-*.json"))
    assert len(manifests) == 12

    findings = json.loads((out_dir / "fuzz_findings.json").read_text(encoding="utf-8"))
    assert len(findings) == 12
    assert all(
        isinstance(f["injected_parameters"], dict) and f["injected_parameters"] for f in findings
    )

    scope_query_db = [
        f
        for f in findings
        if f["target_tool"] == "query_db" and f["owasp_category"] == "ASI06-ScopeContamination"
    ]
    assert scope_query_db
    assert any(
        f["injected_parameters"].get("fields") == ["ssn", "password_hash"] for f in scope_query_db
    )


def test_us5_4_cli_respects_policy_tool_tier_overrides(tmp_path: Path):
    """Verify `generate` and `fuzz` apply `tool_tier_overrides` from `--policies`."""
    policy_file = tmp_path / "custom_rules.yaml"
    policy_file.write_text(
        "version: '1.0'\ntool_tier_overrides:\n  check_service_health: admin\npolicies: []\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "override_gen"
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "generate",
            "--agent",
            "examples.devops_agent.agent",
            "--per-tool",
            "2",
            "--policies",
            str(policy_file),
            "--output-dir",
            str(out_dir),
        ],
    )
    assert result.exit_code == 0

    summary = json.loads((out_dir / "generated_scenarios.json").read_text(encoding="utf-8"))
    health_scenarios = [s for s in summary if s["target_tool"] == "check_service_health"]
    assert any(s["owasp_category"] == "ASI03-PrivilegeAbuse" for s in health_scenarios)


def test_us5_4_cli_rejects_invalid_counts(tmp_path: Path):
    """Verify `--per-tool` and `--iterations` enforce minimum bound of 1."""
    runner = CliRunner()

    res_gen = runner.invoke(
        app, ["generate", "--per-tool", "0", "--output-dir", str(tmp_path / "g")]
    )
    assert res_gen.exit_code != 0

    res_fuzz = runner.invoke(
        app, ["fuzz", "--iterations", "0", "--output-dir", str(tmp_path / "f")]
    )
    assert res_fuzz.exit_code != 0
