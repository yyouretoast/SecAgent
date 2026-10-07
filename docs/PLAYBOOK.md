# Team Kickoff & Implementation Playbook

**Target**: Graduation Project Capstone (DEPI Agentic AI Track)  
**Weekly Budget**: 4–6 hours per student  
**Project Goal**: Deliver a turn-key GitHub Action and CLI scanner that blocks insecure autonomous AI agents on Pull Requests.

---

## 1. Quick Technical Alignment

### The Core Problem We Solve
When developers update prompts or agent tools, agents can bypass human approvals (ASI03), execute SQL/command injections (ASI02), or fall into runaway infinite loops (ASI08).

### How We Solve It (The "Zero-Diff" Approach)
1. We **do not** compare traces to a baseline twin.
2. We **do not** make live LLM calls during CI.
3. We take a single execution trace emitted by any agent (LangGraph, CrewAI, AutoGen) and verify hard, deterministic **OWASP Invariant Rules** defined in `policies/security_rules.yaml`.
4. If an invariant is violated, the **GitHub Action (`action.yml`)** exits with code 1 and blocks the PR.

---

## 2. Student Task Breakdown & Weekly Milestones

Each student has an isolated module and clear interface contracts so nobody is blocked by another team member.

### Student 1: Universal Agent Harness & Introspection Lead
* **Primary Scope**: `src/secagent/harness/`, `src/secagent/sdk/`
* **Week 1–2 Goals**:
  - Implement dynamic agent introspector that reads tools, docstrings, and schemas from any user agent entrypoint (`--agent module:app`).
  - Support `@permission` decorator in `src/secagent/sdk/decorators.py` for fine-grained privilege classification (`read`, `write`, `pay`, `admin`, `net`).
  - Maintain minimal smoke-test fixture agents under `examples/` solely for test verification, without spending dev cycles building full mock agents.
* **Success Criteria**: CLI can dynamically introspect tools and schemas from any arbitrary agent entrypoint.

---

### Student 2: Dynamic Scenario Generation & Adversarial Synthesis Lead
* **Primary Scope**: `src/secagent/generator/`
* **Week 1–2 Goals**:
  - Implement automated scenario synthesizer (`ScenarioGenerator`) that creates adversarial test vectors dynamically based on introspected tools.
  - Automatically synthesize:
    - **ASI01 (Goal Hijack)**: Persona-override and instruction deviation prompts.
    - **ASI02 (Tool Misuse)**: Parameter-level fuzzing with SQL injection (`' OR '1'='1`).
    - **ASI03 (Privilege Abuse)**: Role-spoofing prompts attempting to trigger `pay` or `admin` actions without predecessor approval.
    - **ASI05 (Unexpected Code Execution)**: Shell command injection payloads (`; cat /etc/passwd`, `& whoami`).
    - **ASI06 (Scope Abuse)**: Prompts designed to extract restricted credentials, API tokens, or PII.
    - **ASI08 (Cascading Failures)**: Circular dependencies designed to trigger infinite retry loops.
    - **ASI10 (Rogue Network Exfiltration)**: Egress exfiltration prompts targeting untrusted endpoints.
* **Success Criteria**: Running `secagent generate` or `secagent scan` dynamically synthesizes attack scenarios on the fly without requiring pre-written YAML files.

---

### Student 3: Telemetry & OTel Pipeline Lead
* **Primary Scope**: `src/secagent/telemetry/`
* **Week 1–2 Goals**:
  - Implement a lightweight span collector callback for LangGraph / general agents.
  - Intercept:
    - `tool.call` spans (capturing tool name, arguments, and permission tier).
    - `gate.hitl` spans (capturing human approval booleans).
  - Add an in-line regex PII/secret sanitizer (redacting SSNs, credit cards, API keys).
  - Export spans to a clean JSON file conforming to `schemas/trace_event.schema.json`.
* **Success Criteria**: Running any example agent produces a valid `trace.json` that passes `jsonschema.validate()`.

---

### Student 4: Invariant Verifier & Fuzzer Lead
* **Primary Scope**: `src/secagent/engine/`, `src/secagent/fuzzer/`
* **Week 1–2 Goals**:
  - **Invariant Engine**: Write the pure Python policy checker that parses `trace.json` and evaluates `policies/security_rules.yaml`:
    - Predecessor gate check: `target_tier in ["pay", "admin"]` must have preceding `approval_granted == True`.
    - Injection check: Regex match across `input_parameters`.
    - Circuit breaker: Max step count ($\le 10$) and consecutive duplicate calls ($\le 2$).
  - **Dynamic Fuzzer**: Wire up `secagent fuzz` to mutate prompt payloads on the fly.
* **Success Criteria**: Engine returns exit code 0 on compliant traces, exit code 1 on violated traces.

---

### Student 5: GitHub Action, CLI & Visualizer Lead
* **Primary Scope**: `action.yml`, `src/secagent/cli.py`, `app.py`, `.github/`
* **Week 1–2 Goals**:
  - Wire `secagent scan` in `src/secagent/cli.py` to invoke Student 4's engine on target scenarios.
  - Format the Markdown comment output (`comment.md`) with a clear security triage table.
  - Test `action.yml` in a GitHub workflow so PRs are blocked automatically upon policy violation.
  - Build a clean 1-page Streamlit dashboard in `app.py` for visual demonstrations.
* **Success Criteria**: Opening a PR triggers the GitHub Action, executes `secagent scan`, and posts a summary comment.

---

## 3. Communication & Git Rules

1. **Frozen Contracts**: Do not modify `schemas/trace_event.schema.json` or `policies/security_rules.yaml` without unanimous team agreement.
2. **Branch Workflow**:
   ```bash
   git checkout -b feat/s1-target-agents
   git checkout -b feat/s2-benchmark-scenarios
   git checkout -b feat/s3-otel-telemetry
   git checkout -b feat/s4-policy-fuzzer
   git checkout -b feat/s5-github-action-ui
   ```
3. **Local Quality Gate**: Run before opening any PR:
   ```bash
   ruff check .
   ruff format --check .
   pytest tests/
   ```
