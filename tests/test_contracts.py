import json
from pathlib import Path

import jsonschema
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent


def test_trace_schema_validity():
    """Verify trace_event.schema.json is a valid Draft 2020-12 JSON Schema."""
    schema_path = ROOT_DIR / "schemas" / "trace_event.schema.json"
    assert schema_path.exists(), "trace_event.schema.json does not exist"

    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)


def test_all_trace_fixtures_validate():
    """Verify all trace fixtures conform strictly to trace_event.schema.json."""
    schema_path = ROOT_DIR / "schemas" / "trace_event.schema.json"
    fixtures_dir = ROOT_DIR / "tests" / "fixtures"
    assert fixtures_dir.exists(), "tests/fixtures directory does not exist"

    with open(schema_path, encoding="utf-8") as f:
        schema = json.load(f)

    fixture_files = list(fixtures_dir.glob("*.json"))
    assert len(fixture_files) >= 4, f"Expected at least 4 test fixtures, found {len(fixture_files)}"

    for fixture_path in fixture_files:
        with open(fixture_path, encoding="utf-8") as f:
            trace_data = json.load(f)
        jsonschema.validate(instance=trace_data, schema=schema)


def test_security_rules_yaml_validity():
    """Verify security_rules.yaml contains all required policy invariant declarations."""
    policy_path = ROOT_DIR / "policies" / "security_rules.yaml"
    assert policy_path.exists(), "security_rules.yaml does not exist"

    with open(policy_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert "policies" in data, "policies key missing from security_rules.yaml"
    assert len(data["policies"]) >= 5, "Must declare at least 5 core policy invariants"

    policy_ids = {p["id"] for p in data["policies"]}
    expected_ids = {
        "POL-ASI03-001",
        "POL-ASI03-002",
        "POL-ASI06-001",
        "POL-ASI02-001",
        "POL-ASI08-001",
        "POL-ASI05-001",
        "POL-ASI10-001",
    }
    assert expected_ids.issubset(policy_ids), (
        f"Missing required policies: {expected_ids - policy_ids}"
    )

    for p in data["policies"]:
        assert "id" in p
        assert "owasp_category" in p
        assert "rule_type" in p
        assert "condition" in p
        assert "failure_action" in p


def test_scenario_template_yaml_validity():
    """Verify TEMPLATE.yaml contains all required fields for scenario authoring."""
    template_path = ROOT_DIR / "scenarios" / "TEMPLATE.yaml"
    assert template_path.exists(), "TEMPLATE.yaml does not exist"

    with open(template_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    required_fields = [
        "id",
        "owasp_category",
        "title",
        "description",
        "expected_verdict",
        "session_context",
        "user_prompt",
    ]
    for field in required_fields:
        assert field in data, f"Required field '{field}' missing from TEMPLATE.yaml"


def test_agent_state_import():
    """Verify AgentState TypedDict can be imported cleanly and contains required keys."""
    from secagent.agent.state import AgentState

    expected_keys = {
        "messages",
        "user_id",
        "caller_role",
        "task_context",
        "approval_granted",
        "current_intent",
        "error",
    }
    assert expected_keys.issubset(set(AgentState.__annotations__.keys()))


def test_sdk_decorator():
    """Verify @permission decorator attaches security tier attributes."""
    from secagent.sdk import permission

    @permission(tier="admin")
    def restart_server(server_id: str) -> str:
        return f"Restarted {server_id}"

    assert hasattr(restart_server, "_secagent_permission_tier")
    assert restart_server._secagent_permission_tier == "admin"
    assert restart_server("srv-1") == "Restarted srv-1"


def test_cli_smoke_execution(tmp_path):
    """Verify secagent CLI scan and test commands run and generate reports."""
    from typer.testing import CliRunner

    from secagent.cli import app

    runner = CliRunner()
    report_file = tmp_path / "report.json"
    comment_file = tmp_path / "comment.md"

    result = runner.invoke(
        app,
        [
            "scan",
            "--output-report",
            str(report_file),
            "--output-markdown",
            str(comment_file),
        ],
    )
    assert result.exit_code == 0
    assert report_file.exists()
    assert comment_file.exists()


def test_scenario_generator_synthesis():
    """Verify ScenarioGenerator dynamically synthesizes OWASP attack vectors from tool metadata."""
    from secagent.generator import ScenarioGenerator, ToolMetadata

    generator = ScenarioGenerator()
    tools = [
        ToolMetadata(name="execute_wire", permission_tier="pay"),
        ToolMetadata(name="restart_host", permission_tier="admin"),
        ToolMetadata(name="read_logs", permission_tier="read"),
        ToolMetadata(name="post_webhook", permission_tier="net"),
    ]
    scenarios = generator.generate(tools, scenarios_per_tool=2)
    assert len(scenarios) > 0

    categories = {s.owasp_category for s in scenarios}
    assert "ASI01-AgentGoalHijack" in categories
    assert "ASI02-ToolMisuse" in categories
    assert "ASI03-PrivilegeAbuse" in categories
    assert "ASI05-UnexpectedCodeExecution" in categories
    assert "ASI06-ScopeContamination" in categories
    assert "ASI08-CascadingFailures" in categories
    assert "ASI10-RogueAgentExfiltration" in categories


def test_cli_generate_command(tmp_path):
    """Verify secagent generate command creates dynamic scenarios JSON."""
    from typer.testing import CliRunner

    from secagent.cli import app

    runner = CliRunner()
    out_dir = tmp_path / "gen_scenarios"

    result = runner.invoke(
        app,
        [
            "generate",
            "--output-dir",
            str(out_dir),
            "--per-tool",
            "1",
        ],
    )
    assert result.exit_code == 0
    assert (out_dir / "generated_scenarios.json").exists()


def test_violating_trace_fixtures_contain_target_anomalies():
    """Verify that violating trace fixtures contain the structural anomalies targeted by policies."""
    fixtures_dir = ROOT_DIR / "tests" / "fixtures"

    # 1. Privilege violation fixture: issue_refund (pay) with no preceding approved gate
    priv_file = fixtures_dir / "trace_privilege_violation.json"
    assert priv_file.exists()
    priv_data = json.loads(priv_file.read_text(encoding="utf-8"))
    tool_spans = [s for s in priv_data["spans"] if s["span_type"] == "tool.call"]
    pay_spans = [s for s in tool_spans if s.get("permission_tier") == "pay"]
    gate_spans = [
        s
        for s in priv_data["spans"]
        if s["span_type"] == "gate.hitl" and s.get("approval_granted") is True
    ]
    assert len(pay_spans) > 0, "Privilege violation fixture must contain high-privilege tool span"
    assert len(gate_spans) == 0, "Privilege violation fixture must have no authorized HITL gate"

    # 2. SQLi violation fixture: query_db contains SQL injection pattern
    sqli_file = fixtures_dir / "trace_sqli_violation.json"
    assert sqli_file.exists()
    sqli_data = json.loads(sqli_file.read_text(encoding="utf-8"))
    sqli_spans = [s for s in sqli_data["spans"] if s["name"] == "query_db"]
    assert len(sqli_spans) > 0
    params = sqli_spans[0].get("input_parameters", {})
    assert any("' OR '1'='1" in str(v) for v in params.values()), (
        "SQLi fixture must contain SQL injection payload"
    )

    # 3. Loop violation fixture: step count exceeds threshold or identical repeats
    loop_file = fixtures_dir / "trace_loop_violation.json"
    assert loop_file.exists()
    loop_data = json.loads(loop_file.read_text(encoding="utf-8"))
    assert len(loop_data["spans"]) > 10, "Loop violation fixture must exceed 10 operational steps"
