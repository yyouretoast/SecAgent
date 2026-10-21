# Team Implementation Playbook

**Target**: Graduation Project Capstone (DEPI Agentic AI Track)  
**Deadline**: Late November 2026 (~5 Weeks Remaining)  
**Budget**: 4–6 hours/week per student (5 students total)  
**Deliverable**: GitHub Action and CLI scanner that evaluates autonomous AI agents in CI/CD and blocks pull requests on invariant violations.

---

## 1. Project Overview

### Problem
When developers modify system prompts, tool schemas, or models, agents can introduce critical regressions:
* Bypassing required human approval gates before executing sensitive tools (ASI03).
* Passing unvalidated inputs directly into database or shell calls (ASI02, ASI05).
* Exfiltrating sensitive credentials or querying restricted database fields (ASI06, ASI10).
* Getting trapped in non-terminating execution loops (ASI08).

### Solution
1. Single-trace evaluation: SecAgent evaluates a candidate agent's execution trace directly against declarative security rules in `policies/security_rules.yaml`.
2. No LLM judge in CI: Checks are deterministic (caller role, approval gates, regex patterns, step counts).
3. Tool-aware scenario generation: SecAgent inspects the agent's tools and synthesizes attack inputs, caching test suites for deterministic CI replay.
4. If an invariant rule is violated, `action.yml` exits with code 1 and blocks the pull request.

---

## 2. 5-Week Milestone Timeline (Target: Late November 2026)

| Week / Target Date | Milestone Focus | Deliverables & Integration Gates |
| :--- | :--- | :--- |
| **Week 1 (Oct 21 – Oct 27)** | **Subsystem Scaffolding & Isolated Unit Logic** | S1 (Harness runner & timeouts), S2 (Pydantic schema-aware mutation), S3 (OTel callback span recording), S4 (Rule evaluators logic), S5 (CLI integration wiring). |
| **Week 2 (Oct 28 – Nov 03)** | **Subsystem Integration Gate 1 (Harness + Telemetry)** | Merge S1 (`harness/`) and S3 (`telemetry/`). Verify candidate agent runs emit compliant trace JSON passing `jsonschema.validate()`. |
| **Week 3 (Nov 04 – Nov 10)** | **Subsystem Integration Gate 2 (Engine + Generator)** | Merge S2 (`generator/`) and S4 (`engine/`). Verify generated attack scenarios execute against Policy Engine, yielding exit code 1 on violating fixtures. |
| **Week 4 (Nov 11 – Nov 17)** | **End-to-End Pipeline & Dashboard** | Merge S5 (`cli.py`, `action.yml`, `app.py`). Connect `secagent scan` to runner and engine. Build Streamlit trace inspection dashboard. |
| **Week 5 (Nov 18 – Nov 25)** | **Hardening, Benchmarking & Defense Rehearsal** | Multi-agent matrix testing, Promptfoo comparison benchmark, documentation finalization, and live "Broken vs. Fixed" PR demonstration rehearsal. |

---

## 3. Work Breakdown Structure (WBS)

Each student owns a discrete module behind a typed interface contract.

### Student 1: Agent Introspection & Execution Harness Lead
* **Scope**: `src/secagent/harness/`, `src/secagent/sdk/`
* **Tasks**:
  * Build introspector to inspect tool names, docstrings, and parameter schemas from agent entrypoints (`--agent module:app`).
  * Implement `ExecutionHarness` runner that executes the agent safely with timeouts and error trapping.
  * Implement dry-run virtualization so destructive tools (`drop_database`, `execute_trade`) return mock data during testing.
  * Maintain the `@permission(tier=...)` decorator in `src/secagent/sdk/decorators.py`.
  * Maintain smoke-test fixtures in `examples/` for local testing.
* **Success Criteria**: Harness runs candidate agents safely in a dry-run sandbox and extracts tool metadata without crashing on timeouts.

---

### Student 2: Dynamic Scenario Generation Lead
* **Scope**: `src/secagent/generator/`
* **Tasks**:
  * Implement `ScenarioGenerator` to synthesize adversarial test vectors tailored to introspected tools.
  * Generate test cases for:
    * **ASI01**: Persona override and instruction deviation prompts.
    * **ASI02**: SQL injection parameter payloads (`' OR '1'='1`).
    * **ASI03**: Role-spoofing prompts attempting to execute `pay` or `admin` tools without authorization.
    * **ASI05**: Shell command injection payloads (`; cat /etc/passwd`, `& whoami`).
    * **ASI06**: Prompts targeting restricted fields (`ssn`, `password_hash`).
    * **ASI08**: Circular goals testing loop limits.
    * **ASI10**: Prompts attempting network exfiltration to untrusted endpoints.
* **Success Criteria**: `secagent generate` produces valid test suites dynamically without static YAML authoring.

---

### Student 3: Telemetry & OTel Pipeline Lead
* **Scope**: `src/secagent/telemetry/`
* **Tasks**:
  * Implement an OpenTelemetry callback handler capturing:
    * `tool.call` spans (tool name, input parameters, permission tier).
    * `gate.hitl` spans by normalizing framework-native approval interrupts (e.g. LangGraph `interrupt()`).
  * Build an in-line regex PII redactor (scrubbing SSNs, credit cards, API keys).
  * Export trace logs conforming strictly to `schemas/trace_event.schema.json`.
* **Success Criteria**: Agent runs produce trace JSON files that pass `jsonschema.validate()`.

---

### Student 4: Invariant Verification Engine Lead
* **Scope**: `src/secagent/engine/`
* **Tasks**:
  * Implement evaluator that loads `policies/security_rules.yaml` and inspects `trace.json`:
    * Predecessor gate rule: high-risk operations (`pay`, `admin`) require preceding `approval_granted == true`.
    * Parameter blocklist: regex matching on arguments.
    * Circuit breaker: total step count limits and duplicate call thresholds.
    * Egress guard: network tool destination allowlists.
  * Return structured violation records with remediation guidance.
* **Success Criteria**: Engine returns exit code 0 on compliant traces and exit code 1 on violating traces.

---

### Student 5: GitHub Action, CLI & Dashboard Lead
* **Scope**: `action.yml`, `src/secagent/cli.py`, `app.py`, `.github/`
* **Tasks**:
  * Wire `secagent scan` to run Student 4's engine and return exit codes 0 or 1.
  * Generate Markdown summary tables (`comment.md`) on test failure.
  * Test `action.yml` in GitHub Actions workflows.
  * Build a 1-page Streamlit dashboard in `app.py` for trace inspection.
* **Success Criteria**: A pull request triggering a policy breach is automatically blocked with an explanatory comment.

---

## 4. Development Rules

1. **Frozen Contracts**: Do not change `schemas/trace_event.schema.json` or `policies/security_rules.yaml` without team agreement.
2. **Branch Naming**:
   ```bash
   feat/s1-agent-harness
   feat/s2-scenario-generator
   feat/s3-otel-telemetry
   feat/s4-policy-engine
   feat/s5-github-action-cli
   ```
3. **Local Quality Verification**: Run before opening a PR:
   ```bash
   pytest tests/ -v
   ruff check .
   ruff format --check .
   ```
