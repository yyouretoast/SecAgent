# Team Implementation Playbook

**Target**: Graduation Project Capstone (DEPI Agentic AI Track)  
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
3. Automated scenario generation: SecAgent inspects the agent's tools and synthesizes attack inputs on the fly.
4. If an invariant rule is violated, `action.yml` exits with code 1 and blocks the pull request.

---

## 2. Work Breakdown Structure (WBS)

Each student owns a discrete module behind a typed interface contract.

### Student 1: Agent Introspection & SDK Lead
* **Scope**: `src/secagent/harness/`, `src/secagent/sdk/`
* **Tasks**:
  * Build introspector reading tool names, docstrings, and schemas from agent entrypoints (`--agent module:app`).
  * Maintain the `@permission(tier=...)` decorator in `src/secagent/sdk/decorators.py`.
  * Maintain minimal smoke-test fixtures in `examples/` purely for local test verification.
* **Success Criteria**: CLI can dynamically inspect tools and schemas from any agent entrypoint.

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
  * Implement an OpenTelemetry callback/processor capturing:
    * `tool.call` spans (tool name, input parameters, permission tier).
    * `gate.hitl` spans (approval decision booleans).
  * Build an in-line regex PII redactor (scrubbing SSNs, credit cards, API keys).
  * Export trace logs conforming to `schemas/trace_event.schema.json`.
* **Success Criteria**: Agent runs produce trace JSON files that pass `jsonschema.validate()`.

---

### Student 4: Invariant Verification Engine Lead
* **Scope**: `src/secagent/engine/`, `src/secagent/fuzzer/`
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

## 3. Development Rules

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
