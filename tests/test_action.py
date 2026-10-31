"""Contract and integration tests for US-5.2 GitHub Action composite runner."""

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_action_yml_contract_and_injection_safety():
    """Verify action.yml defines required inputs, outputs, and avoids raw template interpolation in scripts."""
    action_path = ROOT_DIR / "action.yml"
    assert action_path.exists()

    action = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"

    expected_inputs = {
        "agent_entrypoint",
        "policies",
        "scenarios",
        "output_report",
        "output_markdown",
        "post_comment",
    }
    assert expected_inputs.issubset(set(action.get("inputs", {}).keys()))

    expected_outputs = {"status", "report_path", "markdown_path"}
    assert expected_outputs.issubset(set(action.get("outputs", {}).keys()))

    for step in action["runs"]["steps"]:
        run_script = step.get("run", "")
        js_script = step.get("with", {}).get("script", "")
        assert "${{" not in run_script, (
            f"Raw template expression in bash run step: {step.get('name')}"
        )
        assert "${{" not in js_script, (
            f"Raw template expression in JS script step: {step.get('name')}"
        )

    step_names = [s.get("name") for s in action["runs"]["steps"]]
    scan_idx = step_names.index("Execute SecAgent Security Scan")
    comment_idx = step_names.index("Post PR Security Triage Comment")
    gate_idx = step_names.index("Enforce Security Gate Verdict")
    assert scan_idx < comment_idx < gate_idx, (
        "Action must execute scan, then post PR comment, then enforce exit code 1"
    )
    gate_step = action["runs"]["steps"][gate_idx]
    assert "exit 1" in gate_step["run"]
    assert (
        gate_step.get("env", {}).get("SCAN_STATUS") == "${{ steps.secagent_scan.outputs.status }}"
    )


def test_ci_workflow_uses_composite_action():
    """Verify .github/workflows/secagent-ci.yml invokes ./ composite action with write permissions."""
    wf_path = ROOT_DIR / ".github" / "workflows" / "secagent-ci.yml"
    assert wf_path.exists()

    wf = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
    job = wf["jobs"]["security-and-contract-tests"]
    assert job.get("permissions", {}).get("pull-requests") == "write"

    uses_steps = [s for s in job["steps"] if s.get("uses") == "./"]
    assert len(uses_steps) == 1


def test_cli_subprocess_discovers_workspace_agent(tmp_path: Path):
    """Verify secagent scan resolves workspace modules without PYTHONPATH fallback warnings."""
    report_path = tmp_path / "report.json"
    comment_path = tmp_path / "comment.md"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "secagent.cli",
            "scan",
            "--agent",
            "examples.devops_agent.agent",
            "--output-report",
            str(report_path),
            "--output-markdown",
            str(comment_path),
        ],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "No module named 'examples'" not in proc.stdout
    assert "Notice: Introspection fell back" not in proc.stdout

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["agent"] == "examples.devops_agent.agent"
    # examples.devops_agent.agent has 2 tools (check_service_health: read, restart_server: admin) -> supports 9 scenarios
    assert report["scenarios_evaluated"] == 9
