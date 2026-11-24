# SecAgent Implementation Plan

* **Target**: DEPI Agentic AI Track Capstone (5-week delivery, 5 engineers)
* **Stack**: Python 3.11+, LangGraph, OpenTelemetry SDK, Pydantic v2, Typer, Rich, Streamlit
* **Architecture & Overview**: [RFC-001](RFC-001-architecture.md) · [README](../README.md)

---

## 1. Design Constraints

1. **Deterministic CI Gate**: Policy evaluation runs on structured execution traces in memory without LLM-as-a-judge calls, keeping PR checks fast, free, and reproducible.
2. **Dry-Run Safety**: Mutating/external tool tiers (`pay`, `admin`, `write`, `net`) are virtualized during scans so CI runs never trigger real payments, host commands, or outbound HTTP requests.
3. **Frozen Contracts**: Cross-team integration relies on two shared schemas:
   - `schemas/trace_event.schema.json` (JSON Schema Draft 2020-12)
   - `policies/security_rules.yaml` (declarative OWASP rule bundle)

---

## 2. Subsystem & Module Map

```text
src/secagent/
├── agent/state.py          # Shared LangGraph AgentState TypedDict
├── sdk/decorators.py       # @permission(tier=...) metadata decorator
├── harness/
│   ├── introspector.py     # Multi-strategy tool discovery & tier resolution
│   ├── sandbox.py          # VirtualizedToolWrapper for dry-run mocking
│   ├── runner.py           # ExecutionHarness with thread/async timeout isolation
│   └── scripted.py         # Deterministic zero-LLM reference graph builder
├── telemetry/
│   ├── callbacks.py        # SecAgentTelemetryCallback + OTelRuntime spans
│   ├── hitl.py             # HITLNormalizer for gate.hitl interrupt spans
│   ├── redactor.py         # PIIRedactor (SSN, Luhn cards, API/Bearer tokens)
│   └── exporter.py         # Draft 2020-12 trace schema validator & JSON writer
├── generator/
│   ├── __init__.py         # ScenarioGenerator & ToolMetadata
│   ├── fuzzer.py           # SchemaDirectedFuzzer for typed parameter injection
│   └── cache.py            # SHA-256 ScenarioCache + source fingerprinting
├── engine/
│   ├── loader.py           # Strict Pydantic PolicyLoader for security_rules.yaml
│   ├── evaluator.py        # PolicyEngine + tool_tier_overrides resolution
│   ├── reporter.py         # PolicyReporter (JSON summary + SARIF 2.1.0)
│   └── rules/              # 8 rule evaluators + ASI04 tool-poisoning scanner
├── schemas/                # Packaged trace_event.schema.json
├── cli.py                  # Typer CLI (scan, test, generate, fuzz, serve)
├── ui.py                   # Rich terminal header, violation cards & summary
└── app.py                  # Streamlit waterfall & --baseline diff dashboard
```

---

## 3. Subsystem Responsibilities

### 3.1 Introspection, Harness & SDK (`harness/`, `sdk/`, `examples/`)
* Discover tools from LangGraph `CompiledStateGraph` nodes, `tools` attributes, getter methods, or module members.
* Resolve privilege tiers in strict precedence: `@permission` decorator > `tool_tier_overrides` in policy YAML > name heuristic (`pay` → `admin` → `write` → `net` → `pure` → `read`).
* Wrap `pay`/`admin`/`write`/`net` tools in `VirtualizedToolWrapper` returning `{"status": "mock_success", "dry_run": True}` and enforce per-scenario timeouts (`DEFAULT_TIMEOUT_S = 5.0`) in `ExecutionHarness`.
* Provide three deterministic reference agents in `examples/` (`finance_agent`, `devops_agent`, `support_agent`), each exporting `:app` (compliant) and `:vulnerable_app` (failing).

### 3.2 Telemetry & Redaction (`telemetry/`)
* Capture `agent.run`, `model.inference`, `tool.call`, and `gate.hitl` spans via `SecAgentTelemetryCallback` and emit OpenTelemetry SDK spans via `OTelRuntime`.
* Normalize LangGraph `approval_gate` / `__interrupt__` events into `gate.hitl` spans with `approval_granted`.
* Scrub SSNs, Luhn-validated card numbers, and `sk-` / `ghp_` / `Bearer` tokens recursively via `PIIRedactor` before trace validation.

### 3.3 Scenario Generator & Fuzzer (`generator/`)
* Synthesize OWASP-mapped scenarios from introspected tool schemas and inject payloads into compatible string parameters via `SchemaDirectedFuzzer`.
* Cache generated suites under `scenarios/.cache/` keyed by tool signatures, policy overrides, seed, settings, and AST/source fingerprint.

### 3.4 Policy Engine & Reporting (`engine/`)
* Validate `policies/security_rules.yaml` with strict Pydantic models (`PolicyLoader`).
* Evaluate traces deterministically across 7 YAML rule categories (`POL-ASI01-001/002`, `POL-ASI02-001`, `POL-ASI03-001/002`, `POL-ASI05-001`, `POL-ASI06-001`, `POL-ASI08-001`, `POL-ASI10-001`) plus static tool-description poisoning (`POL-ASI04-001`).
* Export structured JSON reports and SARIF 2.1.0 documents (`PolicyReporter`).

### 3.5 CLI, GitHub Action & Dashboard (`cli.py`, `ui.py`, `app.py`, `action.yml`)
* Orchestrate `scan` (dynamic or `--trace`), `generate`, `fuzz --execute`, and `serve --baseline`.
* Gate pull requests via `action.yml`: exit `1` on `BLOCK_PR` violations, post sticky PR triage comments (`comment.md`), write `$GITHUB_STEP_SUMMARY`, and emit SARIF for GitHub Code Scanning.
* Render trace waterfalls, OWASP charts, and `--baseline` regression diffs locally in Streamlit.

---

## 4. 5-Week Delivery Milestones

| Week | Milestone | Gate |
| :--- | :--- | :--- |
| **Week 1** | Subsystem scaffolding & isolated unit logic | Unit tests pass per module |
| **Week 2** | Harness + Telemetry integration | Agent runs emit valid `trace_event.schema.json` traces |
| **Week 3** | Generator + Policy Engine integration | Engine flags violating traces with exit `1` |
| **Week 4** | CLI, GitHub Action & Streamlit dashboard | End-to-end `secagent scan` & `secagent serve` working |
| **Week 5** | Multi-agent evaluation, hardening & defense | Full `pytest`, `ruff`, `mypy src/secagent` green on `main` |
